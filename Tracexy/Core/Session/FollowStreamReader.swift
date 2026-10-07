import Foundation

// MARK: - FollowStreamReader

/// A pure, synchronous, on-demand reader that reconstructs one TCP conversation's
/// application byte stream from a *stable* saved / stopped-live capture file. It is
/// the backend: the coordinator owns the detached task, the source
/// lifetime and every generation guard; the inspector UI owns presentation.
///
/// It deliberately does **not** touch `LiveCaptureSpool`, an actor, the
/// `@MainActor`, persistence, the network, or any export path — it opens one
/// ``CaptureStreamReader``, refuses a source-identity mismatch before scanning,
/// decodes each scanned frame exactly once through the shared pure decode seam
/// (`SessionBuilder.decodePacket`), and folds only frames whose decoded tuple
/// *exactly* equals the requested canonical TCP tuple. No endpoint-role guessing.
///
/// Memory stays bounded by the per-direction byte/run bounds and the byte-free
/// ``TCPSequenceTracker`` pending bound — never by file size: raw frame bytes are
/// dropped once folded and only first-observed unique application bytes are held.
///
/// One instance performs one read; construct a fresh instance to read again. A
/// repeated read of the same unchanged file with the same tuple/bounds is
/// deterministic. ``readEach(contentsOf:expectedIdentity:tuples:sourceToken:configuration:tuplesPerPass:_:)``
/// follows many conversations with one file pass per group, each conversation
/// folded exactly as a single read would fold it.
nonisolated final class FollowStreamReader {
    // MARK: Lifecycle

    /// Open `url`, reject a non-TCP tuple and an identity mismatch, and prepare to
    /// scan.
    ///
    /// - Parameters:
    ///   - url: a stable saved / stopped-live capture file.
    ///   - expectedIdentity: the identity the caller recorded when it chose the
    ///     source; the opened file must still match it.
    ///   - tuple: the canonical TCP tuple to follow (`proto` must be `.tcp`).
    ///   - sourceToken: the source's opaque locator token; when given, each run
    ///     carries a navigable provenance for the frame that established it.
    ///   - configuration: hard byte/run bounds plus cancellation/progress tunables.
    /// - Throws: ``FollowStreamError/tupleNotTCP`` for a non-TCP tuple;
    ///   ``FollowStreamError/identityMismatch`` when the opened file no longer
    ///   matches `expectedIdentity`; rethrows the stream reader's construction error
    ///   (bad magic / short header).
    convenience init(
        contentsOf url: URL,
        expectedIdentity: PcapFileIdentity,
        tuple: FiveTuple,
        sourceToken: UUID? = nil,
        configuration: Configuration = Configuration()
    )
        throws
    {
        try self.init(
            contentsOf: url, expectedIdentity: expectedIdentity, tuples: [tuple],
            sourceToken: sourceToken, configuration: configuration
        )
    }

    /// Prepare one pass over `url` that folds every tuple in `tuples` (duplicates
    /// fold once). Callers go through ``readEach``, which bounds the group size.
    private init(
        contentsOf url: URL,
        expectedIdentity: PcapFileIdentity,
        tuples: [FiveTuple],
        sourceToken: UUID?,
        configuration: Configuration
    )
        throws
    {
        guard tuples.allSatisfy({ $0.proto == .tcp }) else {
            throw FollowStreamError.tupleNotTCP
        }
        var order: [FiveTuple] = []
        var conversations: [FiveTuple: Conversation] = [:]
        for tuple in tuples where conversations[tuple] == nil {
            order.append(tuple)
            conversations[tuple] = Conversation(trackerConfiguration: configuration.trackerConfiguration)
        }
        sourceURL = url
        self.order = order
        self.conversations = conversations
        self.sourceToken = sourceToken
        self.configuration = configuration
        let reader = try CaptureStreamReader(
            contentsOf: url,
            configuration: .init(
                maxCapturedLength: configuration.maxCapturedLength,
                isCancelled: configuration.isCancelled
            )
        )
        // Compare the opened identity to the caller's expected identity *before*
        // scanning: a replaced, truncated or grown file can never feed a mismatched
        // read.
        guard reader.identity.matches(expectedIdentity) else {
            throw FollowStreamError.identityMismatch
        }
        self.reader = reader
    }

    // MARK: Internal

    /// Hard bounds and cancellation/progress tunables for one read.
    nonisolated struct Configuration: Sendable {
        // MARK: Lifecycle

        init(
            maxCapturedLength: Int = CapturedFrame.maxReasonableLength,
            maxRetainedBytesPerDirection: Int = 1 << 20,
            maxRunsPerDirection: Int = 256,
            trackerConfiguration: TCPSequenceTracker.Configuration = TCPSequenceTracker.Configuration(),
            progressStride: Int = 256,
            isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }
        ) {
            self.maxCapturedLength = min(max(0, maxCapturedLength), CapturedFrame.maxReasonableLength)
            self.maxRetainedBytesPerDirection = min(
                max(0, maxRetainedBytesPerDirection), Self.maximumRetainedBytesPerDirection
            )
            self.maxRunsPerDirection = min(max(1, maxRunsPerDirection), Self.maximumRunsPerDirection)
            self.trackerConfiguration = trackerConfiguration
            self.progressStride = max(1, progressStride)
            self.isCancelled = isCancelled
        }

        // MARK: Internal

        /// A second, non-configurable ceiling prevents an internal caller from
        /// turning the on-demand presentation buffer into an effectively unbounded
        /// allocation by passing `Int.max`.
        static let maximumRetainedBytesPerDirection = 16 << 20
        static let maximumRunsPerDirection = 4_096

        let maxCapturedLength: Int
        /// Hard cap on unique retained application bytes *per direction*.
        let maxRetainedBytesPerDirection: Int
        /// Hard cap on distinct retained runs *per direction*.
        let maxRunsPerDirection: Int
        /// Bounds for each direction's byte-free ordering tracker.
        let trackerConfiguration: TCPSequenceTracker.Configuration
        /// Emit a coalesced progress callback at most once per this many scanned
        /// frames (plus one final callback at the terminal).
        let progressStride: Int
        let isCancelled: @Sendable () -> Bool
    }

    /// The most conversations one pass folds together. Memory for a pass is at most
    /// this many conversations times both directions' retained-byte bound.
    static let maximumTuplesPerPass = 64

    /// Follow every tuple in `tuples` with one scan of `url` per group of
    /// `tuplesPerPass`, handing each conversation's result to `body` in the order
    /// given (a repeated tuple is read once) as soon as its group's pass ends. Each
    /// result is the one a single read of that tuple would return; only the scan is
    /// shared.
    ///
    /// - Parameter tuplesPerPass: clamped to `1...maximumTuplesPerPass`. A group's
    ///   results are released before the next group is scanned.
    /// - Throws: ``FollowStreamError/tupleNotTCP`` before any scan when a tuple is
    ///   not TCP; otherwise whatever a single read throws, or what `body` throws.
    ///   A throw ends the whole call; results already handed over stay valid.
    static func readEach(
        contentsOf url: URL,
        expectedIdentity: PcapFileIdentity,
        tuples: [FiveTuple],
        sourceToken: UUID? = nil,
        configuration: Configuration = Configuration(),
        tuplesPerPass: Int = 16,
        _ body: (FollowStreamResult) throws -> Void
    )
        throws
    {
        guard tuples.allSatisfy({ $0.proto == .tcp }) else {
            throw FollowStreamError.tupleNotTCP
        }
        var seen = Set<FiveTuple>()
        let unique = tuples.filter { seen.insert($0).inserted }
        let group = min(max(1, tuplesPerPass), maximumTuplesPerPass)
        var start = 0
        while start < unique.count {
            if configuration.isCancelled() {
                throw CancellationError()
            }
            let end = min(start + group, unique.count)
            let results = try FollowStreamReader(
                contentsOf: url, expectedIdentity: expectedIdentity, tuples: Array(unique[start ..< end]),
                sourceToken: sourceToken, configuration: configuration
            ).readAll()
            for result in results {
                try body(result)
            }
            start = end
        }
    }

    /// Scan the file to its terminal and fold the requested conversation into one
    /// immutable ``FollowStreamResult``.
    ///
    /// - Parameter onProgress: coalesced, monotonic byte-progress callbacks on the
    ///   calling executor; never carries a partial result.
    /// - Throws: `CancellationError` on cancellation and `PacketError.malformed` on
    ///   corrupt metadata. Either throws before returning, so the caller adopts no
    ///   partial follow-stream state.
    func read(onProgress: (PcapStreamProgress) -> Void = { _ in }) throws -> FollowStreamResult {
        guard let result = try readAll(onProgress: onProgress).first else {
            // The public initializer always asks for exactly one tuple.
            preconditionFailure("A follow read has one requested conversation.")
        }
        return result
    }

    // MARK: Private

    private let sourceURL: URL
    /// Requested tuples, first-asked order, each once.
    private let order: [FiveTuple]
    private let sourceToken: UUID?
    private let configuration: Configuration
    private let reader: CaptureStreamReader

    private var conversations: [FiveTuple: Conversation]
    /// Rebuilds fragmented IP datagrams across this one pass over the capture.
    private var sequential = SequentialFrameDecoder()

    /// Scan once and return every requested conversation in `order`.
    private func readAll(onProgress: (PcapStreamProgress) -> Void = { _ in }) throws -> [FollowStreamResult] {
        var scanned = 0
        let completion = try walk(onProgress: onProgress, scanned: &scanned)
        try revalidateSourceIdentity()
        onProgress(completion.progress)

        let completeness: FollowStreamCompleteness = switch completion.reason {
        case .cleanEndOfFile: .complete
        case .partialHeader,
             .partialBody: .incompleteTruncatedTail(completion.reason)
        }

        return order.compactMap { tuple in
            guard var conversation = conversations.removeValue(forKey: tuple) else {
                return nil
            }
            // Finalize each direction's gap observation from its byte-free tracker: a
            // hole that was never bridged (still pending, or dropped by the pending
            // bound) is a genuine sequence gap, independent of byte retention.
            conversation.aToB.finalizeGap()
            conversation.bToA.finalizeGap()
            return FollowStreamResult(
                identity: reader.identity,
                format: reader.format,
                tuple: tuple,
                aToB: conversation.aToB.snapshot(navigable: sourceToken != nil),
                bToA: conversation.bToA.snapshot(navigable: sourceToken != nil),
                matchedFrameCount: conversation.aToB.matchedFrames + conversation.bToA.matchedFrames,
                scannedFrameCount: scanned,
                limitations: conversation.limitations(completeness: completeness),
                completeness: completeness,
                finalProgress: completion.progress
            )
        }
    }

    /// Drive the reader to its terminal, folding each frame exactly once.
    private func walk(
        onProgress: (PcapStreamProgress) -> Void,
        scanned: inout Int
    )
        throws -> CaptureStreamCompletion
    {
        while true {
            switch try reader.next() {
            case let .frame(event):
                scanned += 1
                fold(event, ordinal: scanned)
                if scanned % configuration.progressStride == 0 {
                    onProgress(event.progress)
                }
            case let .end(completion):
                return completion
            }
        }
    }

    /// Decode one frame once and, only if it matches the requested tuple, fold its
    /// direction: feed the byte-free ordering tracker and place its typed TCP
    /// payload bytes into the correct direction's runs.
    private func fold(_ event: CaptureFrameEvent, ordinal: Int) {
        let frame = CapturedFrame(
            bytes: event.bytes,
            timestamp: event.reference.timestamp,
            originalLength: event.reference.originalLength,
            capturedLength: event.reference.capturedLength,
            linkType: event.reference.linkType
        )
        // The frame carries its own link type, so `decodePacket` uses it directly;
        // the default is only a fallback and is never reached for a real frame.
        let locator = sourceToken.map {
            SessionEvidenceLocator(sourceToken: $0, offset: event.reference.payloadOffset)
        }
        let packet = sequential.decode(
            frame,
            linkType: reader.defaultLinkType ?? event.reference.linkType,
            ordinal: UInt64(ordinal),
            locator: locator
        )

        guard packet.transport == .tcp,
              let tuple = packet.fiveTuple, conversations[tuple] != nil,
              let facts = packet.tcpFacts,
              let source = packet.sourceEndpoint,
              let destination = packet.destinationEndpoint else
        {
            return
        }

        let direction: ConnectionDirection
        if source == tuple.a, destination == tuple.b {
            direction = .aToB
        } else if source == tuple.b, destination == tuple.a {
            direction = .bToA
        } else {
            // A canonical tuple equality guarantees the endpoints are {a, b}; this
            // is unreachable defensive code and folds nothing.
            return
        }

        // A short capture proves only that this matched frame was truncated. It
        // does not prove that the omitted tail was TCP application payload.
        if event.reference.capturedLength < event.reference.originalLength {
            conversations[tuple]?.capturedFrameTruncated = true
        }

        let provenance = SessionFrameProvenance(
            ordinal: FrameOrdinal(UInt64(ordinal)),
            timestamp: event.reference.timestamp,
            capturedLength: event.reference.capturedLength,
            originalLength: event.reference.originalLength,
            linkType: event.reference.linkType,
            locator: locator,
            reassembledFrom: sequential.lastReassembledFrom
        )
        // Mutated in place through the dictionary: a conversation's runs are never
        // copied per frame.
        conversations[tuple]?.ingest(
            direction: direction,
            facts: facts,
            payloadSequence: packet.tcpPayloadSequence,
            payloadBytes: packet.tcpPayloadBytes,
            provenance: provenance,
            maxRetainedBytes: configuration.maxRetainedBytesPerDirection,
            maxRuns: configuration.maxRunsPerDirection
        )
    }

    /// Reopen the selected path after the terminal and require it still to name
    /// the exact file snapshot this reader opened. The stream reader owns a stable
    /// descriptor, but without this second check a path replaced, grown or
    /// truncated during a long scan could still publish a result under a stale
    /// caller identity.
    private func revalidateSourceIdentity() throws {
        guard let handle = try? FileHandle(forReadingFrom: sourceURL) else {
            throw FollowStreamError.identityMismatch
        }
        defer { try? handle.close() }
        let current = PcapFileIdentity.snapshot(of: handle)
        guard current.matches(reader.identity) else {
            throw FollowStreamError.identityMismatch
        }
    }
}

// MARK: FollowStreamReader.Conversation

private extension FollowStreamReader {
    /// Both directions of one requested conversation, plus its captured-frame
    /// observation.
    nonisolated struct Conversation {
        // MARK: Lifecycle

        init(trackerConfiguration: TCPSequenceTracker.Configuration) {
            aToB = DirectionState(trackerConfiguration: trackerConfiguration)
            bToA = DirectionState(trackerConfiguration: trackerConfiguration)
        }

        // MARK: Internal

        var aToB: DirectionState
        var bToA: DirectionState
        /// Set when any matched frame's captured length was below its original length.
        var capturedFrameTruncated = false
        /// A second SYN in either direction may be a retransmission or a reused
        /// tuple. Keep it ambiguous instead of combining two connection instances.
        var openingSYNSeen: Set<ConnectionDirection> = []
        var connectionIncarnationAmbiguous = false

        /// Fold one matched segment into its direction state.
        mutating func ingest(
            direction: ConnectionDirection,
            facts: TCPSegmentFacts,
            payloadSequence: UInt32?,
            payloadBytes: [UInt8],
            provenance: SessionFrameProvenance,
            maxRetainedBytes: Int,
            maxRuns: Int
        ) {
            if facts.flags.contains(.syn) {
                if !openingSYNSeen.insert(direction).inserted {
                    connectionIncarnationAmbiguous = true
                }
            }
            switch direction {
            case .aToB:
                aToB.ingest(
                    facts: facts, payloadSequence: payloadSequence, payloadBytes: payloadBytes,
                    provenance: provenance, maxRetainedBytes: maxRetainedBytes, maxRuns: maxRuns
                )
            case .bToA:
                bToA.ingest(
                    facts: facts, payloadSequence: payloadSequence, payloadBytes: payloadBytes,
                    provenance: provenance, maxRetainedBytes: maxRetainedBytes, maxRuns: maxRuns
                )
            }
        }

        /// Combine both directions' independently-set flags with the captured-frame
        /// and source-tail observations into one limitation set.
        func limitations(completeness: FollowStreamCompleteness) -> FollowStreamLimitations {
            var flags: FollowStreamLimitations = []
            for direction in [aToB, bToA] {
                if direction.sequenceGap {
                    flags.insert(.sequenceGap)
                }
                if direction.outOfOrder {
                    flags.insert(.outOfOrder)
                }
                if direction.overlapConflict {
                    flags.insert(.overlapConflict)
                }
                if direction.serialAmbiguous {
                    flags.insert(.serialAmbiguous)
                }
                if direction.runRetentionTruncated {
                    flags.insert(.runRetentionTruncated)
                }
                if direction.byteRetentionTruncated {
                    flags.insert(.byteRetentionTruncated)
                }
            }
            if capturedFrameTruncated {
                flags.insert(.capturedFrameTruncated)
            }
            if connectionIncarnationAmbiguous {
                flags.insert(.connectionIncarnationAmbiguous)
            }
            if case .incompleteTruncatedTail = completeness {
                flags.insert(.sourceTailTruncated)
            }
            return flags
        }
    }
}

// MARK: FollowStreamReader.DirectionState

private extension FollowStreamReader {
    /// The bounded, first-observed byte reconstruction plus byte-free ordering
    /// observation for one direction. All ordering state comes from a single
    /// ``TCPSequenceTracker``; all byte state comes from the run set. Both are hard
    /// bounded and mutate only through `ingest`, so replaying the same matched
    /// segments in capture order is deterministic.
    nonisolated struct DirectionState {
        // MARK: Lifecycle

        init(trackerConfiguration: TCPSequenceTracker.Configuration) {
            tracker = TCPSequenceTracker(configuration: trackerConfiguration)
        }

        // MARK: Internal

        private(set) var matchedFrames = 0
        private(set) var outOfOrder = false
        private(set) var sequenceGap = false
        private(set) var serialAmbiguous = false
        private(set) var overlapConflict = false
        private(set) var byteRetentionTruncated = false
        private(set) var runRetentionTruncated = false

        /// Fold one matched segment: advance the ordering tracker with its typed
        /// facts, then place its typed payload bytes (if any) into the runs.
        mutating func ingest(
            facts: TCPSegmentFacts,
            payloadSequence: UInt32?,
            payloadBytes: [UInt8],
            provenance: SessionFrameProvenance,
            maxRetainedBytes: Int,
            maxRuns: Int
        ) {
            matchedFrames += 1

            // Ordering observation is byte-free and independent of retention. A
            // bridged reorder is out-of-order; an exact half-space distance is
            // ambiguous. Genuine gaps are finalized from the tracker's pending set.
            switch tracker.ingest(facts).disposition {
            case .pendingDrained: outOfOrder = true
            case .serialAmbiguous: serialAmbiguous = true
            default: break
            }

            guard let sequence = payloadSequence, !payloadBytes.isEmpty else {
                return
            }
            place(
                sequence: sequence,
                bytes: payloadBytes,
                provenance: provenance,
                maxRetainedBytes: maxRetainedBytes,
                maxRuns: maxRuns
            )
        }

        /// Finalize the sequence-gap observation: an unbridged hole (still pending,
        /// or dropped by the pending bound) is a genuine gap, distinct from any
        /// byte/run retention truncation.
        mutating func finalizeGap() {
            if tracker.pendingCount > 0 || tracker.droppedPendingCount > 0 {
                sequenceGap = true
            }
        }

        /// - Parameter navigable: publish each run's first-frame provenance. Only a
        ///   reader given the source token can produce a locator worth publishing.
        func snapshot(navigable: Bool) -> FollowStreamDirectionSnapshot {
            let anchor = byteAnchor
            let outRuns = runs.map { run in
                FollowStreamRun(
                    sequenceAnchor: (anchor ?? 0) &+ UInt32(truncatingIfNeeded: run.startOffset),
                    firstCaptureOrdinal: Int(run.firstProvenance.ordinal.rawValue),
                    bytes: run.bytes,
                    firstProvenance: navigable ? run.firstProvenance : nil
                )
            }
            var snapshot = FollowStreamDirectionSnapshot(
                anchorSequence: anchor,
                runs: outRuns,
                retainedByteCount: retainedBytes,
                observedOmittedByteCount: observedOmitted,
                matchedFrameCount: matchedFrames
            )
            // Without a source token the provenance carries no locator, so a mark
            // times a byte but never claims it can be opened.
            snapshot.segmentMarks = marks.map { FollowStreamSegmentMark(offset: $0.offset, provenance: $0.provenance) }
            snapshot.segmentMarksDroppedFrom = marksDroppedFrom
            return snapshot
        }

        // MARK: Private

        /// A retained run of contiguous bytes at `startOffset` (a signed serial
        /// offset from `byteAnchor`), carrying the ordinal of the frame that first
        /// established its leading byte.
        nonisolated private struct Run {
            var startOffset: Int64
            var firstProvenance: SessionFrameProvenance
            var bytes: [UInt8]
        }

        private static let serialHalfSpace: UInt32 = 0x80000000
        /// Bound on first-delivery marks per direction. One per payload-bearing
        /// frame, so this covers the frames of a long keep-alive conversation.
        private static let maximumMarks = 16_384

        /// Ascending by offset, one per offset.
        private var marks: [(offset: Int64, provenance: SessionFrameProvenance)] = []
        /// The lowest offset whose mark the bound dropped, if any.
        private var marksDroppedFrom: Int64?

        private var tracker: TCPSequenceTracker
        /// The direction anchor: the first observed payload sequence number.
        private var byteAnchor: UInt32?
        /// Runs sorted ascending by `startOffset`, disjoint, touching-merged.
        private var runs: [Run] = []
        private var retainedBytes = 0
        private var observedOmitted: UInt64 = 0

        private static func saturatingAdd(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
            lhs > UInt64.max - rhs ? .max : lhs + rhs
        }

        /// Place one segment's payload bytes, honoring first-observed overlaps,
        /// bridging, and the hard byte/run bounds enforced before any growth.
        private mutating func place(
            sequence: UInt32,
            bytes: [UInt8],
            provenance: SessionFrameProvenance,
            maxRetainedBytes: Int,
            maxRuns: Int
        ) {
            if byteAnchor == nil {
                byteAnchor = sequence
            }
            guard let anchor = byteAnchor else {
                return
            }

            // Serial arithmetic relative to the one direction anchor. An exact
            // half-space distance cannot be resolved as ahead/behind, so the bytes
            // are not placed and the ambiguity is recorded.
            let raw = sequence &- anchor
            if raw == Self.serialHalfSpace {
                serialAmbiguous = true
                return
            }
            let start = raw >= Self.serialHalfSpace
                ? Int64(raw) - (Int64(1) << 32)
                : Int64(raw)
            let length = Int64(bytes.count)
            let end = start + length
            // Marks are taken against the runs as they were before this segment, and
            // withdrawn below if the segment's bytes are not retained, so a mark
            // never credits bytes that were never kept.
            let retainedBefore = retainedBytes
            let droppedBefore = marksDroppedFrom
            let recorded = recordMark(start: start, end: end, provenance: provenance)
            defer {
                if retainedBytes == retainedBefore, !recorded.isEmpty {
                    marks.removeAll { mark in recorded.contains(mark.offset) }
                    marksDroppedFrom = droppedBefore
                }
            }

            var mergeIndices: [Int] = []
            for index in runs.indices {
                let runStart = runs[index].startOffset
                let runEnd = runStart + Int64(runs[index].bytes.count)
                if runStart <= end, runEnd >= start {
                    mergeIndices.append(index)
                }
            }

            if mergeIndices.isEmpty {
                insertIsolated(
                    start: start, bytes: bytes, provenance: provenance,
                    maxRetainedBytes: maxRetainedBytes, maxRuns: maxRuns
                )
                return
            }

            merge(
                mergeIndices: mergeIndices, start: start, end: end, bytes: bytes,
                provenance: provenance, maxRetainedBytes: maxRetainedBytes
            )
        }

        /// Record where this segment first delivered bytes: the start of every part
        /// of `[start, end)` no earlier run already holds. A segment that bridges a
        /// hole and runs past a later run marks each uncovered piece, so no byte is
        /// credited to a frame that did not deliver it first.
        @discardableResult
        private mutating func recordMark(start: Int64, end: Int64, provenance: SessionFrameProvenance) -> [Int64] {
            var recorded: [Int64] = []
            var cursor = start
            for run in runs {
                let runStart = run.startOffset
                let runEnd = runStart + Int64(run.bytes.count)
                guard runEnd > cursor else {
                    continue
                }
                guard runStart < end else {
                    break
                }
                if runStart > cursor, insertMark(at: cursor, provenance: provenance) {
                    recorded.append(cursor)
                }
                cursor = max(cursor, runEnd)
                if cursor >= end {
                    return recorded
                }
            }
            if cursor < end, insertMark(at: cursor, provenance: provenance) {
                recorded.append(cursor)
            }
            return recorded
        }

        /// Returns whether a mark was inserted. At the bound the offset is remembered
        /// as the lowest one without a mark, so no later byte is attributed to an
        /// earlier frame.
        private mutating func insertMark(at offset: Int64, provenance: SessionFrameProvenance) -> Bool {
            var low = 0
            var high = marks.count
            while low < high {
                let mid = (low + high) / 2
                if marks[mid].offset < offset {
                    low = mid + 1
                } else {
                    high = mid
                }
            }
            if low < marks.count, marks[low].offset == offset {
                return false
            }
            guard marks.count < Self.maximumMarks else {
                marksDroppedFrom = min(marksDroppedFrom ?? offset, offset)
                return false
            }
            marks.insert((offset, provenance), at: low)
            return true
        }

        /// Insert a brand-new run that touches no existing run. Enforces the run
        /// and byte bounds before allocating; a rejected run's bytes are counted as
        /// observed-but-not-retained.
        private mutating func insertIsolated(
            start: Int64,
            bytes: [UInt8],
            provenance: SessionFrameProvenance,
            maxRetainedBytes: Int,
            maxRuns: Int
        ) {
            let count = bytes.count
            if runs.count >= maxRuns {
                runRetentionTruncated = true
                observedOmitted = Self.saturatingAdd(observedOmitted, UInt64(count))
                return
            }
            let (newTotal, overflow) = retainedBytes.addingReportingOverflow(count)
            if overflow || newTotal > maxRetainedBytes {
                byteRetentionTruncated = true
                observedOmitted = Self.saturatingAdd(observedOmitted, UInt64(count))
                return
            }
            let run = Run(startOffset: start, firstProvenance: provenance, bytes: bytes)
            let position = runs.firstIndex { $0.startOffset > start } ?? runs.count
            runs.insert(run, at: position)
            retainedBytes += count
        }

        /// Merge a segment overlapping/touching one or more existing runs into a
        /// single contiguous run. First-observed bytes win every overlap; a
        /// byte-value disagreement is a neutral overlap conflict. Only the new
        /// (uncovered) bytes count against the byte bound, enforced before growth.
        private mutating func merge(
            mergeIndices: [Int],
            start: Int64,
            end: Int64,
            bytes: [UInt8],
            provenance: SessionFrameProvenance,
            maxRetainedBytes: Int
        ) {
            var mergedStart = start
            var mergedEnd = end
            var overlapWithExisting = 0
            for index in mergeIndices {
                let runStart = runs[index].startOffset
                let runEnd = runStart + Int64(runs[index].bytes.count)
                mergedStart = min(mergedStart, runStart)
                mergedEnd = max(mergedEnd, runEnd)
                let overlapStart = max(start, runStart)
                let overlapEnd = min(end, runEnd)
                if overlapEnd > overlapStart {
                    overlapWithExisting += Int(overlapEnd - overlapStart)
                }
            }
            let newCount = bytes.count - overlapWithExisting

            // A merge never increases the run count (it only combines runs), so
            // only the byte bound can reject it. Enforce it before allocating the
            // merged buffer; a rejected merge still reports byte disagreement.
            let (newTotal, overflow) = retainedBytes.addingReportingOverflow(newCount)
            if overflow || newTotal > maxRetainedBytes {
                detectConflict(mergeIndices: mergeIndices, start: start, end: end, bytes: bytes)
                byteRetentionTruncated = true
                observedOmitted = Self.saturatingAdd(observedOmitted, UInt64(newCount))
                return
            }

            let spanLength = Int(mergedEnd - mergedStart)
            var merged = [UInt8](repeating: 0, count: spanLength)
            var filled = [Bool](repeating: false, count: spanLength)
            // First-observed existing bytes take precedence.
            for index in mergeIndices {
                let base = Int(runs[index].startOffset - mergedStart)
                for (offset, byte) in runs[index].bytes.enumerated() {
                    merged[base + offset] = byte
                    filled[base + offset] = true
                }
            }
            // The segment fills only positions not already observed; a filled
            // position that disagrees is a neutral overlap conflict.
            let segmentBase = Int(start - mergedStart)
            for (offset, byte) in bytes.enumerated() {
                let index = segmentBase + offset
                if filled[index] {
                    if merged[index] != byte {
                        overlapConflict = true
                    }
                } else {
                    merged[index] = byte
                    filled[index] = true
                }
            }

            // The leading byte's origin: an existing run starting at the merged
            // start wins (first-observed); otherwise the segment established it.
            let firstProvenance: SessionFrameProvenance = if let leftmost = mergeIndices
                .first(where: { runs[$0].startOffset == mergedStart })
            {
                runs[leftmost].firstProvenance
            } else {
                provenance
            }

            for index in mergeIndices.sorted(by: >) {
                runs.remove(at: index)
            }
            let mergedRun = Run(startOffset: mergedStart, firstProvenance: firstProvenance, bytes: merged)
            let position = runs.firstIndex { $0.startOffset > mergedStart } ?? runs.count
            runs.insert(mergedRun, at: position)
            retainedBytes += newCount
        }

        /// Record an overlap conflict when a rejected (bound-limited) segment
        /// disagrees with already-retained bytes, without retaining anything.
        private mutating func detectConflict(
            mergeIndices: [Int],
            start: Int64,
            end: Int64,
            bytes: [UInt8]
        ) {
            for index in mergeIndices {
                let runStart = runs[index].startOffset
                let runEnd = runStart + Int64(runs[index].bytes.count)
                let overlapStart = max(start, runStart)
                let overlapEnd = min(end, runEnd)
                var position = overlapStart
                while position < overlapEnd {
                    let segmentIndex = Int(position - start)
                    let runIndex = Int(position - runStart)
                    if bytes[segmentIndex] != runs[index].bytes[runIndex] {
                        overlapConflict = true
                        break
                    }
                    position += 1
                }
            }
        }
    }
}
