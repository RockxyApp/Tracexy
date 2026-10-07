import Foundation

// MARK: - IPReassemblyConfiguration

/// The bounds of IP fragment reassembly.
nonisolated struct IPReassemblyConfiguration: Sendable {
    /// The largest datagram rebuilt: an IPv4 datagram's own ceiling, and an IPv6 one
    /// without a jumbo payload. Bytes kept per datagram never exceed it, since a
    /// fragment that overlaps keeps only what is new.
    var maximumDatagramBytes = 65_535
    var maximumFragmentsPerDatagram = 64
    var maximumPendingDatagrams = 256
    /// How long a datagram may wait for its remaining fragments, on the capture's
    /// own clock.
    var timeout: TimeInterval = 30
    /// How many frames a datagram may wait, which also bounds captures without
    /// capture times.
    var maximumFrameSpan: UInt64 = 100_000
    /// A datagram that could not be rebuilt absorbs its own later fragments; one
    /// that hears nothing for this many frames gives its key back, so a later
    /// datagram reusing the identification is rebuilt.
    var failedEntryQuietFrames: UInt64 = 256
}

// MARK: - IPReassemblyDiscards

/// Datagrams that could not be rebuilt, by reason, for diagnostics.
nonisolated struct IPReassemblyDiscards: Equatable, Sendable {
    var conflicting = 0
    var truncated = 0
    var oversized = 0
    var expired = 0
    var evicted = 0
}

// MARK: - IPFragmentReassembler

/// Rebuilds IPv4 and IPv6 datagrams from their fragments, in the order frames
/// arrive. Deterministic and bounded: the same frames in the same order always
/// complete the same datagrams on the same frames, whichever path reads them.
///
/// A datagram is rebuilt only when every byte from offset 0 to the end the last
/// fragment declares is present. Fragments that overlap must agree byte for byte;
/// a disagreement, a fragment cut short by the snapshot length, a datagram past
/// the size or fragment bounds, or one left waiting past the timeout or frame span
/// is never rebuilt — its fragments stay plain IP fragments.
///
/// Each fragment carries a caller `Tag` (a frame's provenance, say), kept with the
/// bytes it added and handed back with the datagram, so nothing outlives its
/// datagram.
nonisolated struct IPFragmentReassembler<Tag: Sendable>: Sendable {
    // MARK: Lifecycle

    init(configuration: IPReassemblyConfiguration = IPReassemblyConfiguration()) {
        self.configuration = configuration
    }

    // MARK: Internal

    /// One fragment's place in the capture.
    struct Source: Sendable {
        let ordinal: UInt64
        let timestamp: Date?
        let tag: Tag
    }

    /// A rebuilt datagram: its bytes (transport header first) and the sources whose
    /// fragments made it, in datagram-offset order.
    struct Datagram: Sendable {
        let bytes: [UInt8]
        let sources: [Source]
    }

    private(set) var discards = IPReassemblyDiscards()

    var pendingCount: Int {
        pending.count
    }

    /// Bytes held for all waiting datagrams.
    var retainedByteCount: Int {
        pending.values.reduce(0) { $0 + $1.retainedBytes }
    }

    /// Adds one fragment. Returns the datagram when this fragment completes it.
    mutating func add(_ fragment: IPFragmentFacts, payload: ArraySlice<UInt8>, source: Source) -> Datagram? {
        let key = Key(fragment)
        expire(at: source)
        if let entry = pending[key], entry.isFailed,
           source.ordinal &- entry.lastOrdinal > configuration.failedEntryQuietFrames
        {
            pending[key] = nil
        }
        if var entry = pending[key] {
            if entry.isFailed {
                pending[key]?.lastOrdinal = source.ordinal
                return nil
            }
            entry.add(fragment, payload: payload, source: source, configuration: configuration)
            return settle(entry, key: key)
        }
        if pending.count >= configuration.maximumPendingDatagrams {
            evictOldest()
        }
        var entry = Entry(first: source)
        entry.add(fragment, payload: payload, source: source, configuration: configuration)
        return settle(entry, key: key)
    }

    // MARK: Private

    private struct Key: Hashable {
        // MARK: Lifecycle

        init(_ fragment: IPFragmentFacts) {
            version = fragment.version
            source = fragment.source
            destination = fragment.destination
            protocolNumber = fragment.protocolNumber
            identification = fragment.identification
        }

        // MARK: Internal

        let version: IPFragmentFacts.Version
        let source: String
        let destination: String
        let protocolNumber: UInt8
        let identification: UInt32
    }

    /// Bytes one fragment added; pieces never overlap.
    private struct Piece {
        let offset: Int
        let bytes: [UInt8]
        /// Index into the entry's sources.
        let sourceIndex: Int

        var end: Int {
            offset + bytes.count
        }
    }

    private enum Failure {
        case conflicting
        case truncated
        case oversized
    }

    private struct Entry {
        // MARK: Lifecycle

        init(first: Source) {
            firstOrdinal = first.ordinal
            firstTimestamp = first.timestamp
            lastOrdinal = first.ordinal
        }

        // MARK: Internal

        let firstOrdinal: UInt64
        let firstTimestamp: Date?
        var lastOrdinal: UInt64
        /// Sorted by offset, disjoint.
        var pieces: [Piece] = []
        var sources: [Source] = []
        /// The datagram's length, known once the fragment without "more" arrives.
        var totalLength: Int?
        var failure: Failure?

        var isFailed: Bool {
            failure != nil
        }

        var retainedBytes: Int {
            pieces.reduce(0) { $0 + $1.bytes.count }
        }

        var isComplete: Bool {
            guard let totalLength, failure == nil else {
                return false
            }
            var covered = 0
            for piece in pieces {
                guard piece.offset <= covered else {
                    return false
                }
                covered = max(covered, piece.end)
            }
            return covered >= totalLength
        }

        mutating func add(
            _ fragment: IPFragmentFacts,
            payload: ArraySlice<UInt8>,
            source: Source,
            configuration: IPReassemblyConfiguration
        ) {
            lastOrdinal = source.ordinal
            guard fragment.isPayloadComplete else {
                fail(.truncated)
                return
            }
            let start = fragment.offset
            let end = start + payload.count
            guard start >= 0, end <= configuration.maximumDatagramBytes else {
                fail(.oversized)
                return
            }
            if !fragment.moreFragments {
                // Two "last" fragments that disagree on the end, or bytes already
                // received past the end it declares, describe no datagram.
                if let totalLength, totalLength != end {
                    fail(.conflicting)
                    return
                }
                if pieces.contains(where: { $0.end > end }) {
                    fail(.conflicting)
                    return
                }
                totalLength = end
            }
            if let totalLength, end > totalLength {
                fail(.conflicting)
                return
            }
            let bytes = Array(payload)
            // Overlap must agree; only what is not yet held is kept.
            var gaps: [Range<Int>] = []
            var cursor = start
            for piece in pieces where piece.offset < end && start < piece.end {
                let from = max(piece.offset, start)
                let to = min(piece.end, end)
                guard piece.bytes[(from - piece.offset) ..< (to - piece.offset)]
                    == bytes[(from - start) ..< (to - start)] else
                {
                    fail(.conflicting)
                    return
                }
                if cursor < from {
                    gaps.append(cursor ..< from)
                }
                cursor = max(cursor, to)
            }
            if cursor < end {
                gaps.append(cursor ..< end)
            }
            guard !gaps.isEmpty else {
                // Nothing new: a repeat contributes no bytes and is not a source.
                return
            }
            guard sources.count < configuration.maximumFragmentsPerDatagram else {
                fail(.oversized)
                return
            }
            sources.append(source)
            for gap in gaps {
                pieces.append(Piece(
                    offset: gap.lowerBound,
                    bytes: Array(bytes[(gap.lowerBound - start) ..< (gap.upperBound - start)]),
                    sourceIndex: sources.count - 1
                ))
            }
            pieces.sort { $0.offset < $1.offset }
        }

        func datagram() -> Datagram? {
            guard let totalLength, isComplete else {
                return nil
            }
            var bytes = [UInt8](repeating: 0, count: totalLength)
            var order: [Int] = []
            for piece in pieces {
                bytes.replaceSubrange(piece.offset ..< piece.end, with: piece.bytes)
                if !order.contains(piece.sourceIndex) {
                    order.append(piece.sourceIndex)
                }
            }
            return Datagram(bytes: bytes, sources: order.map { sources[$0] })
        }

        // MARK: Private

        private mutating func fail(_ reason: Failure) {
            failure = reason
            pieces = []
            sources = []
        }
    }

    private let configuration: IPReassemblyConfiguration
    private var pending: [Key: Entry] = [:]

    private mutating func settle(_ entry: Entry, key: Key) -> Datagram? {
        if let failure = entry.failure {
            switch failure {
            case .conflicting: discards.conflicting += 1
            case .truncated: discards.truncated += 1
            case .oversized: discards.oversized += 1
            }
            // Kept, failed and empty, so its remaining fragments do not start a
            // second, partial datagram.
            pending[key] = entry
            return nil
        }
        if let datagram = entry.datagram() {
            pending[key] = nil
            return datagram
        }
        pending[key] = entry
        return nil
    }

    /// Drops datagrams that have waited past the timeout (on the capture clock) or
    /// the frame span, judged at `source`.
    private mutating func expire(at source: Source) {
        let limit = configuration.timeout
        let span = configuration.maximumFrameSpan
        let expired = pending.filter { _, entry in
            if source.ordinal &- entry.firstOrdinal > span {
                return true
            }
            guard let now = source.timestamp, let first = entry.firstTimestamp else {
                return false
            }
            return now.timeIntervalSince(first) > limit
        }
        for (key, entry) in expired {
            if !entry.isFailed {
                discards.expired += 1
            }
            pending[key] = nil
        }
    }

    /// Makes room by dropping the datagram whose first fragment arrived earliest.
    private mutating func evictOldest() {
        guard let oldest = pending.min(by: { $0.value.firstOrdinal < $1.value.firstOrdinal }) else {
            return
        }
        if !oldest.value.isFailed {
            discards.evicted += 1
        }
        pending[oldest.key] = nil
    }
}
