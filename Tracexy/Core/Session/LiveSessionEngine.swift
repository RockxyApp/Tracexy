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

    /// - Parameter decode: the per-frame decode step. Injectable so a test can
    ///   prove each frame is decoded exactly once (e.g. by counting calls);
    ///   defaults to the same decode `SessionBuilder` uses.
    init(decode: @escaping Decode = { SessionBuilder.decodePacket($0, linkType: $1) }) {
        self.decode = decode
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
    func ingest(_ frames: [CapturedFrame], linkType: UInt32, epoch: Int) {
        guard epoch == self.epoch else {
            return
        }
        for frame in frames {
            accumulator.add(decode(frame, linkType))
        }
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

    // MARK: Private

    private let decode: Decode
    /// The shared incremental accumulator — the same fold `SessionBuilder.build`
    /// runs, so live snapshots and batch rebuilds stay byte-identical.
    private var accumulator = SessionAccumulator()
}
