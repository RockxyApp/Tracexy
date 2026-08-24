import Foundation

// MARK: - CaptureEvidenceReference

/// A small, self-contained pointer to one session's representative frame inside an
/// opened capture file. It carries the file identity plus that frame's payload
/// offset, captured/original lengths, timestamp and link type — but never the
/// bytes — so a final saved-open result can retain one per session and reload the
/// exact evidence on demand without holding the whole file in memory.
///
/// The identity is what makes a reopen safe: ``CaptureEvidenceReader`` refuses to
/// read if the file on disk no longer matches, so a replaced or truncated file can
/// never feed a stale offset mismatched bytes.
nonisolated struct CaptureEvidenceReference: Sendable, Equatable {
    /// Identity of the file this offset is valid against.
    let identity: PcapFileIdentity
    /// Absolute offset of the captured payload bytes.
    let payloadOffset: UInt64
    /// Number of bytes actually captured for this frame.
    let capturedLength: Int
    /// The frame's original on-wire length (>= `capturedLength`).
    let originalLength: Int
    /// Decoded capture timestamp.
    let timestamp: Date
    /// Link type of the frame's interface, for decoding the reloaded bytes.
    let linkType: UInt32
}

// MARK: - CaptureEvidenceReader

/// Reopens a capture file and reads exactly one selected frame's bytes by offset,
/// after revalidating that the file on disk still matches the identity captured
/// when the reference was made.
///
/// This is the random-access counterpart to the sequential streaming readers: it
/// never scans the file, never loads it whole, and allocates at most the one
/// selected payload (bounded by the captured-length cap). A replaced file (new
/// inode/mtime) or a truncated one (smaller size) fails a controlled error rather
/// than returning mismatched or short bytes.
nonisolated enum CaptureEvidenceReader {
    /// Read the referenced frame's captured bytes from `url`.
    ///
    /// - Throws: `PacketError.malformed` if the file's identity no longer matches
    ///   the reference, if the captured length exceeds the cap, if the payload
    ///   extends past the current file end (truncation), or if the exact read comes
    ///   up short; rethrows any `FileHandle` open/seek/read error.
    static func read(
        _ reference: CaptureEvidenceReference,
        from url: URL,
        maxCapturedLength: Int = CapturedFrame.maxReasonableLength
    )
        throws -> [UInt8]
    {
        guard reference.capturedLength >= 0, reference.capturedLength <= maxCapturedLength else {
            throw PacketError.malformed(
                "evidence: captured length \(reference.capturedLength) out of bounds"
            )
        }
        guard reference.originalLength >= reference.capturedLength else {
            throw PacketError.malformed(
                "evidence: original length \(reference.originalLength) below captured length "
                    + "\(reference.capturedLength)"
            )
        }

        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }

        let current = PcapFileIdentity.snapshot(of: handle)
        guard current.matches(reference.identity) else {
            throw PacketError.malformed("evidence: file identity changed since it was opened")
        }

        // Even with a matching identity, bound the read against the current size so
        // a corrupt reference can never seek/read past the file.
        let (end, overflow) = reference.payloadOffset.addingReportingOverflow(UInt64(reference.capturedLength))
        guard !overflow, end <= current.size else {
            throw PacketError.malformed("evidence: payload offset/length overruns file")
        }

        try handle.seek(toOffset: reference.payloadOffset)
        var collected = Data()
        collected.reserveCapacity(reference.capturedLength)
        while collected.count < reference.capturedLength {
            guard let chunk = try handle.read(upToCount: reference.capturedLength - collected.count),
                  !chunk.isEmpty else
            {
                break
            }
            collected.append(chunk)
        }
        guard collected.count == reference.capturedLength else {
            throw PacketError.malformed("evidence: short read of selected frame")
        }
        return [UInt8](collected)
    }
}

// MARK: - CaptureLoadCompleteness

/// Whether the saved-open walk reached the file's end cleanly, or stopped on a
/// typed truncated tail after preserving every complete prior session.
nonisolated enum CaptureLoadCompleteness: Sendable, Equatable {
    case complete
    /// The tail was cut mid-record/-block; prior sessions are complete and this
    /// carries the exact terminal reason for an explicit incompleteness warning.
    case incompleteTruncatedTail(CaptureStreamTermination)
}

// MARK: - SavedCaptureLoadResult

/// The single immutable result of a saved-capture load. Everything the app needs
/// to adopt the opened file at once — and nothing frame-sized beyond the bounded
/// retained tail. Session summaries retain their decoded fields but have
/// `representativeBytes` cleared; the exact evidence for each is reloadable on
/// demand from `evidence`.
nonisolated struct SavedCaptureLoadResult: Sendable {
    let format: CaptureStreamFormat
    let identity: PcapFileIdentity
    /// Compatibility-default link type (classic single type or first pcapng IDB).
    let defaultLinkType: UInt32
    /// Sessions in first-seen order, with `representativeBytes` cleared.
    let sessions: [SessionSummary]
    /// The passive connection-table snapshot folded from the same accepted frames.
    /// Additive evidence alongside `sessions`; not yet surfaced in Views.
    let connections: ConnectionTable.Snapshot
    /// The bounded DNS/ICMP datagram evidence folded from the same accepted frames.
    /// Additive evidence alongside `sessions`; not yet surfaced in Views.
    let datagramEvidence: DatagramEvidenceTable.Snapshot
    /// The bounded TLS record evidence folded from the same accepted frames. Additive
    /// evidence alongside `sessions`; not yet surfaced in Views.
    let tlsEvidence: TLSEvidenceTable.Snapshot
    /// The passive connection analysis assessed exactly once from `connections`.
    /// Additive evidence alongside `sessions`; not yet surfaced in Views.
    let connectionAnalysis: ConnectionAnalysisSnapshot
    /// The passive datagram analysis assessed exactly once from `datagramEvidence`.
    /// Additive evidence alongside `sessions`; not yet surfaced in Views.
    let datagramAnalysis: DatagramAnalysisSnapshot
    /// One evidence pointer per session, keyed by session id.
    let evidence: [UUID: CaptureEvidenceReference]
    /// Bounded FIFO of the most recent raw frames, for the inspection window. Its
    /// eviction count is local-window truncation, never captured-packet loss — the
    /// source file remains complete.
    let retainedTail: RetainedFrameBuffer
    /// Bounded activity aggregation over the whole file.
    let activity: CaptureActivity
    let completeness: CaptureLoadCompleteness
    /// Total frames accepted (independent of the retained-tail window size).
    let totalFrames: Int
    /// Final monotonic byte progress at the terminal.
    let finalProgress: PcapStreamProgress
}

// MARK: - SavedCaptureStreamLoader

/// A pure synchronous consumer that folds an entire capture file into one
/// ``SavedCaptureLoadResult``. It is intended to be created and run inside one
/// detached, off-main task (N1C activation owns that task and its lifecycle).
///
/// It decodes each accepted frame **exactly once** through
/// ``SessionBuilder/decodePacket(_:linkType:)`` and folds a local
/// ``SessionAccumulator`` — the same fold the batch `SessionBuilder.build` and the
/// live engine use, so the sessions equal a batch build over the same frames. It
/// deliberately does not touch `LiveSessionEngine`, its spool, or any live
/// `isCapturing` gate.
///
/// Memory stays bounded by the retained-tail window, the activity bucket cap and
/// the accumulator's per-session state — never by file size: raw frame bytes are
/// dropped once folded and staged only into the bounded tail, and the final
/// summaries carry no representative bytes.
nonisolated final class SavedCaptureStreamLoader {
    // MARK: Lifecycle

    /// Open `url` and prepare to load it. Construction sniffs the format and builds
    /// the accepted reader, so a bad magic/header throws here.
    init(contentsOf url: URL, configuration: Configuration = Configuration()) throws {
        self.configuration = configuration
        reader = try CaptureStreamReader(
            contentsOf: url,
            configuration: .init(
                maxCapturedLength: configuration.maxCapturedLength,
                isCancelled: configuration.isCancelled
            )
        )
    }

    // MARK: Internal

    /// Tunables for a load.
    nonisolated struct Configuration: Sendable {
        // MARK: Lifecycle

        init(
            maxCapturedLength: Int = CapturedFrame.maxReasonableLength,
            retainedCapacity: Int = 4_096,
            activityBucketCap: Int = CaptureActivityBuilder.defaultBucketCap,
            progressStride: Int = 256,
            connectionConfiguration: ConnectionTable.Configuration = ConnectionTable.Configuration(),
            isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }
        ) {
            self.maxCapturedLength = maxCapturedLength
            self.retainedCapacity = retainedCapacity
            self.activityBucketCap = activityBucketCap
            self.progressStride = max(1, progressStride)
            self.connectionConfiguration = connectionConfiguration
            self.isCancelled = isCancelled
        }

        // MARK: Internal

        let maxCapturedLength: Int
        /// Capacity of the retained-tail inspection window.
        let retainedCapacity: Int
        /// Upper bound on the activity accumulator's bucket count.
        let activityBucketCap: Int
        /// Emit a coalesced progress callback at most once per this many frames
        /// (plus one final callback at the terminal).
        let progressStride: Int
        /// Bounds for the folded connection table, injectable for bounds tests.
        let connectionConfiguration: ConnectionTable.Configuration
        let isCancelled: @Sendable () -> Bool
    }

    /// Fold the entire file into one result.
    ///
    /// - Parameter onProgress: coalesced, monotonic byte-progress callbacks. Never
    ///   carries a partial session array — only progress. Called on the same
    ///   executor as `load`.
    /// - Throws: `CancellationError` on cancellation, `PacketError.malformed` on
    ///   corrupt metadata. Either throws before returning any result, so the caller
    ///   adopts no partial file state.
    func load(onProgress: (PcapStreamProgress) -> Void = { _ in }) throws -> SavedCaptureLoadResult {
        var accumulator = SessionAccumulator(connectionConfiguration: configuration.connectionConfiguration)
        var evidence: [UUID: CaptureEvidenceReference] = [:]
        var tail = RetainedFrameBuffer(capacity: configuration.retainedCapacity)
        var activity = CaptureActivityAccumulator(maxBuckets: configuration.activityBucketCap)
        var totalFrames = 0
        // A deterministic, opaque per-file token for evidence locators, derived
        // only from the opened file's identity — computed once, never per frame.
        let sourceToken = Self.sourceToken(for: reader.identity)

        let completion = try walk(
            onProgress: onProgress,
            sourceToken: sourceToken,
            accumulator: &accumulator,
            evidence: &evidence,
            tail: &tail,
            activity: &activity,
            totalFrames: &totalFrames
        )
        guard let defaultLinkType = reader.defaultLinkType else {
            throw PacketError.malformed("capture: no interface description block")
        }
        onProgress(completion.progress)

        // Obtain one final common fold — sessions, connections and datagram evidence
        // together — so neither owned table is snapshotted twice, then wrap it in one
        // immutable ``InvestigationSnapshot``. The wrapper assesses the connection and
        // datagram analyses exactly once each, off-main, from the fold's own
        // projections; this loader never calls an assessor directly. The returned
        // `connections`/`datagramEvidence`/analyses are exactly this one read's values.
        let fold = accumulator.foldSnapshot()
        let investigation = InvestigationSnapshot(fold: fold)
        var sessions = investigation.sessions
        // Final saved summaries preserve decoded layers/metadata but hold no raw
        // representative bytes — those reload on demand through `evidence`.
        for index in sessions.indices {
            sessions[index].representativeBytes = []
        }

        let completeness: CaptureLoadCompleteness = switch completion.reason {
        case .cleanEndOfFile: .complete
        case .partialHeader,
             .partialBody: .incompleteTruncatedTail(completion.reason)
        }

        return SavedCaptureLoadResult(
            format: reader.format,
            identity: reader.identity,
            defaultLinkType: defaultLinkType,
            sessions: sessions,
            connections: investigation.connections,
            datagramEvidence: fold.datagramEvidence,
            tlsEvidence: fold.tlsEvidence,
            connectionAnalysis: investigation.connectionAnalysis,
            datagramAnalysis: investigation.datagramAnalysis,
            evidence: evidence,
            retainedTail: tail,
            activity: activity.activity(),
            completeness: completeness,
            totalFrames: totalFrames,
            finalProgress: completion.progress
        )
    }

    // MARK: Private

    private let configuration: Configuration
    private let reader: CaptureStreamReader

    /// A deterministic, opaque source token derived only from the opened file's
    /// identity. Two loads of the same unchanged file yield the same token; a
    /// replaced or resized file yields a different one. It carries no path and no
    /// bytes — it only lets a consumer holding the same capture-local identity
    /// correlate an evidence locator's offset back to this file.
    private static func sourceToken(for identity: PcapFileIdentity) -> UUID {
        SessionBuilder.stableID(
            "savedsource|\(identity.size)|\(identity.device)|\(identity.inode)"
                + "|\(identity.modifiedAt?.timeIntervalSince1970 ?? -1)"
        )
    }

    /// Drive the reader to its terminal, folding each frame exactly once. Kept
    /// separate so `load` reads as open → walk → finalize.
    private func walk(
        onProgress: (PcapStreamProgress) -> Void,
        sourceToken: UUID,
        accumulator: inout SessionAccumulator,
        evidence: inout [UUID: CaptureEvidenceReference],
        tail: inout RetainedFrameBuffer,
        activity: inout CaptureActivityAccumulator,
        totalFrames: inout Int
    )
        throws -> CaptureStreamCompletion
    {
        while true {
            switch try reader.next() {
            case let .frame(event):
                fold(
                    event,
                    sourceToken: sourceToken,
                    accumulator: &accumulator,
                    evidence: &evidence,
                    tail: &tail,
                    activity: &activity
                )
                totalFrames += 1
                if totalFrames % configuration.progressStride == 0 {
                    onProgress(event.progress)
                }
            case let .end(completion):
                return completion
            }
        }
    }

    /// Fold one frame: build its `CapturedFrame`, decode it once, accumulate the
    /// session, map the representative selection to an evidence reference, and
    /// stage the raw frame into the bounded tail and activity.
    private func fold(
        _ event: CaptureFrameEvent,
        sourceToken: UUID,
        accumulator: inout SessionAccumulator,
        evidence: inout [UUID: CaptureEvidenceReference],
        tail: inout RetainedFrameBuffer,
        activity: inout CaptureActivityAccumulator
    ) {
        let frame = CapturedFrame(
            bytes: event.bytes,
            timestamp: event.reference.timestamp,
            originalLength: event.reference.originalLength,
            capturedLength: event.reference.capturedLength,
            linkType: event.reference.linkType
        )
        // The frame carries its own link type, so `decodePacket` uses it directly;
        // the default is only a fallback and is never reached here.
        let packet = SessionBuilder.decodePacket(
            frame, linkType: reader.defaultLinkType ?? event.reference.linkType
        )

        // The connection fold's provenance carries an opaque locator: the per-file
        // source token plus this frame's payload offset. That is the *only* place
        // the offset lives — no ordinal-to-offset map or raw bytes are retained in
        // connection events, and the token exposes no path.
        let context = SessionFrameContext(
            capturedLength: event.reference.capturedLength,
            linkType: event.reference.linkType,
            locator: SessionEvidenceLocator(
                sourceToken: sourceToken, offset: event.reference.payloadOffset
            ),
            loss: .unknown
        )

        // A returned id means this frame became its session's representative, so
        // the session's evidence pointer moves to this exact frame. Mapping the id
        // straight to the current reference means no per-frame index is retained.
        if let sessionID = accumulator.add(packet, context: context) {
            evidence[sessionID] = CaptureEvidenceReference(
                identity: reader.identity,
                payloadOffset: event.reference.payloadOffset,
                capturedLength: event.reference.capturedLength,
                originalLength: event.reference.originalLength,
                timestamp: event.reference.timestamp,
                linkType: event.reference.linkType
            )
        }

        tail.append(contentsOf: [frame])
        activity.add(timestamp: event.reference.timestamp, originalLength: event.reference.originalLength)
    }
}
