import Foundation

// MARK: - LiveSessionEngine

/// Off-main, incremental session accumulation for a live capture.
///
/// The batch `SessionBuilder.build` re-decodes *every retained frame* on each
/// call. On the live path that ran on the main actor ~1.2×/second over a growing
/// window — decoding history again and again to rebuild the same sessions. This
/// actor keeps the decoded state instead: each frame is decoded **exactly once**
/// as it arrives and folded into a `SessionAccumulator`, and a snapshot is
/// produced on demand by summarizing the accumulator — never by re-decoding, and
/// never by retaining the packets themselves. State grows with conversations and
/// the values required by their published summaries, rather than with a decoded
/// packet-history array.
///
/// Equivalence is the contract. The engine folds through the very same
/// `SessionAccumulator` that `SessionBuilder.build` uses, so a snapshot after
/// ingesting a set of frames equals `SessionBuilder.build` over the same frames in
/// the same order — byte for byte. This milestone changes *where and how often*
/// the work runs, not *what* it produces.
///
/// An `epoch` guards against capture-boundary races: a reset stamps a new epoch,
/// and ingests/snapshots from a superseded capture are dropped rather than
/// allowed to corrupt or overwrite the current one.
actor LiveSessionEngine {
    // MARK: Lifecycle

    /// - Parameters:
    ///   - connectionConfiguration: bounds for the accumulator's connection table,
    ///     injectable at engine initialization so a bounds test can force tiny caps.
    ///   - decode: the per-frame decode step. Injectable so a test can prove each
    ///     frame is decoded exactly once (e.g. by counting calls); defaults to the
    ///     same decode `SessionBuilder` uses.
    init(
        connectionConfiguration: ConnectionTable.Configuration = ConnectionTable.Configuration(),
        decode: @escaping Decode = { SessionBuilder.decodePacket($0, linkType: $1) }
    ) {
        self.decode = decode
        accumulator = SessionAccumulator(connectionConfiguration: connectionConfiguration)
    }

    // MARK: Internal

    typealias Decode = @Sendable (_ frame: CapturedFrame, _ linkType: UInt32) -> DecodedPacket

    /// The current capture generation. Callers pass their token so stale work is
    /// dropped; the coordinator uses its `startGeneration`.
    private(set) var epoch = 0

    /// Distinct five-tuples currently held. Internal debug/telemetry: it lets a
    /// test assert repeated packets fold into existing session entries.
    var accumulatedSessionCount: Int {
        accumulator.sessionCount
    }

    /// Clears all accumulated state and adopts a new epoch. Called at every
    /// capture boundary (start / clear / open-saved) so a new capture starts from
    /// nothing and older in-flight work is invalidated.
    func reset(epoch: Int) {
        self.epoch = epoch
        accumulator.reset()
    }

    /// Decode and fold a batch of frames into the accumulator. Frames from a
    /// superseded epoch are ignored. Each frame is decoded exactly once here and
    /// never again — updating an existing session does not re-decode its earlier
    /// frames, and no earlier frame is retained to be re-decoded.
    ///
    /// `locators`, when non-nil, must line up one-to-one with `frames`: locator
    /// `i` becomes frame `i`'s opaque evidence pointer. A `nil` array means every
    /// frame folds with a nil locator. `loss` is the stage-separated capture-loss
    /// knowledge folded into every frame's connection provenance.
    ///
    /// - Returns: `true` for a current batch with nil or exactly-counted locators;
    ///   `false` for a stale epoch (nothing folded) or a locator-count mismatch. On
    ///   a mismatch every current frame is still decoded and folded exactly once
    ///   with nil locators — the batch is never truncated or mis-paired — and the
    ///   `false` return exposes the mismatch to the caller.
    @discardableResult
    func ingest(
        _ frames: [CapturedFrame],
        linkType: UInt32,
        epoch: Int,
        locators: [SessionEvidenceLocator]? = nil,
        loss: CaptureLossKnowledge = .unknown
    )
        -> Bool
    {
        guard epoch == self.epoch else {
            return false
        }
        // A provided locator array that does not match the batch is a contract
        // violation by the caller; fold every frame with nil locators rather than
        // dropping or mis-pairing any, and report the mismatch via the result.
        let aligned = locators?.count == frames.count ? locators : nil
        let matched = locators == nil || aligned != nil
        for (index, frame) in frames.enumerated() {
            let packet = decode(frame, linkType)
            // Per-frame link type stays intrinsic-first (the frame's own DLT wins,
            // else the source default); no bytes, URL or file identity enter state.
            let context = SessionFrameContext(
                capturedLength: frame.capturedLength,
                linkType: frame.linkType ?? linkType,
                locator: aligned?[index],
                loss: loss
            )
            accumulator.add(packet, context: context)
        }
        return matched
    }

    /// Summarize the accumulator in first-seen order. Returns `nil` when the epoch
    /// has moved on, so a late snapshot from a superseded capture can't overwrite
    /// newer UI state. Does no decoding — summaries are built from the folded
    /// running state.
    func snapshot(epoch: Int) -> [SessionSummary]? {
        guard epoch == self.epoch else {
            return nil
        }
        return accumulator.summaries()
    }

    /// A detailed snapshot: the session summaries plus the connection snapshot for
    /// the same accepted frames, or `nil` when the epoch has moved on. Like
    /// `snapshot(epoch:)` it decodes nothing, so repeated detailed snapshots never
    /// re-decode — the live decode count stays exactly the frame count.
    func detailedSnapshot(epoch: Int) -> SessionFoldSnapshot? {
        guard epoch == self.epoch else {
            return nil
        }
        return accumulator.foldSnapshot()
    }

    /// An investigation snapshot: the same fold `detailedSnapshot(epoch:)` produces,
    /// wrapped with its passive connection analysis assessed once. Returns `nil` when
    /// the epoch has moved on, under the same guard. Like the other snapshots it
    /// decodes nothing, retains no history and touches no `@MainActor` state — it
    /// folds the running accumulator once and constructs the wrapper immediately, so
    /// repeated investigation snapshots never re-decode.
    func investigationSnapshot(epoch: Int) -> InvestigationSnapshot? {
        guard epoch == self.epoch else {
            return nil
        }
        return InvestigationSnapshot(fold: accumulator.foldSnapshot())
    }

    // MARK: Private

    private let decode: Decode
    /// The shared incremental accumulator — the same fold `SessionBuilder.build`
    /// runs, so live snapshots and batch rebuilds stay byte-identical. It also owns
    /// the connection table folded in lock-step. Initialized with the injected
    /// connection configuration.
    private var accumulator: SessionAccumulator
}
