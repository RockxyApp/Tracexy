import Foundation

// MARK: - TCPSequenceTracker

/// A pure, bounded ordering tracker for one canonical direction of one TCP
/// connection. It folds typed `TCPSegmentFacts` into an "expected next sequence"
/// and a small set of buffered *sequence intervals* — it never stores raw bytes,
/// reassembles a stream, reads a wall clock, or reaches the `@MainActor`. The
/// only source of state change is `ingest`, applied in capture order, so
/// replaying the same facts through the same configuration always yields the
/// same state and the same `Output`.
///
/// Sequence-space length is the captured payload length plus one for a SYN and
/// one for a FIN (RFC 793). A segment with zero sequence space (a pure ACK, or a
/// header-only frame) reports `noSequenceSpace` and never anchors or advances the
/// expected sequence.
///
/// All comparisons use RFC serial arithmetic (`Int32(bitPattern: value &- ref)`)
/// and are only trusted while the distance is unambiguous. An exact half-space
/// distance (`0x8000_0000`) is reported as `serialAmbiguous` and mutates nothing,
/// because it cannot be resolved as "ahead" or "behind". Every conversion is
/// checked or wrap-safe: a hand-built fact with a negative or larger-than-`UInt32`
/// payload length is classified as `serialAmbiguous` rather than trapping.
nonisolated struct TCPSequenceTracker: Equatable, Sendable {
    // MARK: Lifecycle

    init(configuration: Configuration = Configuration()) {
        self.configuration = configuration
    }

    // MARK: Internal

    // MARK: Configuration

    /// Injectable bounds. `maxPendingSegments` is clamped to at least one so no
    /// configuration can disable buffering entirely; test configurations may be
    /// tiny.
    nonisolated struct Configuration: Hashable, Sendable {
        // MARK: Lifecycle

        init(maxPendingSegments: Int = 32) {
            self.maxPendingSegments = max(1, maxPendingSegments)
        }

        // MARK: Internal

        let maxPendingSegments: Int
    }

    // MARK: Disposition

    /// How the tracker classified a single ingested segment. Every case is a
    /// pure observation about the segment's sequence space relative to the
    /// current expected sequence; none carries bytes.
    enum Disposition: Equatable, Sendable {
        /// The first sequence-bearing segment set the anchor.
        case initialized
        /// The segment began exactly at the expected sequence and advanced it,
        /// draining no buffered interval.
        case advanced
        /// The segment carried no new sequence space (it lay entirely at or
        /// behind the expected sequence): a retransmission or pure duplicate.
        case duplicate
        /// The segment straddled the expected sequence: `overlapBytes` were
        /// already seen and `newBytes` advanced the expected sequence.
        case overlap(overlapBytes: UInt32, newBytes: UInt32)
        /// The segment began ahead of the expected sequence, leaving a `gap`; its
        /// interval was buffered as pending.
        case outOfOrderBuffered(gap: UInt32)
        /// An advance connected one or more buffered intervals, moving the
        /// expected sequence past them.
        case pendingDrained
        /// Buffering this segment exceeded the pending bound; the farthest
        /// interval was deterministically discarded and the dropped count grew.
        case pendingOverflow
        /// The distance could not be resolved (exact half-space, or a payload
        /// length outside `UInt32`); ordering state was left unchanged.
        case serialAmbiguous
        /// The segment occupied zero sequence space; the expected sequence was
        /// neither anchored nor changed.
        case noSequenceSpace
    }

    // MARK: Output

    /// The result of one `ingest`: the classification plus the metrics a later
    /// analysis layer needs. `expectedSequence` is `nil` until the first
    /// sequence-bearing segment anchors the direction.
    nonisolated struct Output: Equatable, Sendable {
        let disposition: Disposition
        let expectedSequence: UInt32?
        let pendingCount: Int
        let droppedPendingCount: UInt64
    }

    /// The next sequence number expected in this direction, or `nil` before the
    /// first sequence-bearing segment.
    private(set) var expectedSequence: UInt32?
    /// The cumulative number of buffered intervals discarded to honor the
    /// pending bound. Saturates at `UInt64.max`.
    private(set) var droppedPendingCount: UInt64 = 0

    let configuration: Configuration

    /// The number of currently-buffered pending intervals. Never exceeds
    /// `configuration.maxPendingSegments`.
    var pendingCount: Int {
        pending.count
    }

    mutating func ingest(_ facts: TCPSegmentFacts) -> Output {
        guard let sequenceLength = sequenceSpaceLength(of: facts) else {
            return output(.serialAmbiguous)
        }
        guard sequenceLength > 0 else {
            return output(.noSequenceSpace)
        }

        let start = facts.sequenceNumber

        guard let expected = expectedSequence else {
            expectedSequence = start &+ sequenceLength
            return output(.initialized)
        }

        guard let distance = serialDistance(from: expected, to: start) else {
            return output(.serialAmbiguous)
        }

        if distance == 0 {
            expectedSequence = start &+ sequenceLength
            return output(drainPending() ? .pendingDrained : .advanced)
        }

        if distance < 0 {
            let overlapBytes = UInt32(-Int64(distance))
            guard overlapBytes < sequenceLength else {
                return output(.duplicate)
            }
            let newBytes = sequenceLength - overlapBytes
            expectedSequence = start &+ sequenceLength
            _ = drainPending()
            return output(.overlap(overlapBytes: overlapBytes, newBytes: newBytes))
        }

        // distance > 0: the segment begins ahead of the expected sequence.
        let horizon = UInt64(UInt32(distance)) + UInt64(sequenceLength)
        guard horizon < Self.serialHalfSpace else {
            return output(.serialAmbiguous)
        }
        pending.append(Interval(start: start, length: sequenceLength))
        normalizePending(relativeTo: expected)
        if enforcePendingCap(relativeTo: expected) {
            return output(.pendingOverflow)
        }
        return output(.outOfOrderBuffered(gap: UInt32(distance)))
    }

    // MARK: Private

    /// A buffered sequence interval `[start, start + length)`. It stores only
    /// sequence coordinates — never bytes.
    private struct Interval: Equatable, Sendable {
        var start: UInt32
        var length: UInt32
    }

    private static let serialHalfSpace = UInt64(1) << 31

    private var pending: [Interval] = []

    /// A signed offset of `start` from `reference`, mapping the upper half of the
    /// modular ring to negative values. Used purely for deterministic ordering
    /// and merging; it is wrap-safe and never traps.
    private static func signedOffset(from reference: UInt32, to start: UInt32) -> Int64 {
        let raw = UInt64(start &- reference)
        return raw >= 0x80000000 ? Int64(raw) - (Int64(1) << 32) : Int64(raw)
    }

    private func output(_ disposition: Disposition) -> Output {
        Output(
            disposition: disposition,
            expectedSequence: expectedSequence,
            pendingCount: pending.count,
            droppedPendingCount: droppedPendingCount
        )
    }

    /// The sequence-space length: captured payload plus one for SYN and one for
    /// FIN. Returns `nil` (never traps) when the payload length is negative or
    /// beyond `UInt32`, or when the SYN/FIN addition would overflow — the caller
    /// treats that as `serialAmbiguous`.
    private func sequenceSpaceLength(of facts: TCPSegmentFacts) -> UInt32? {
        guard facts.payloadLength >= 0, facts.payloadLength <= Int(UInt32.max) else {
            return nil
        }
        let payload = UInt32(facts.payloadLength)
        let control = UInt32((facts.flags.contains(.syn) ? 1 : 0) + (facts.flags.contains(.fin) ? 1 : 0))
        let (sum, overflow) = payload.addingReportingOverflow(control)
        guard !overflow, UInt64(sum) < Self.serialHalfSpace else {
            return nil
        }
        return sum
    }

    /// RFC serial distance from `reference` to `value`, trusted only while the
    /// magnitude is unambiguous. The exact half-space (`0x8000_0000`) is
    /// irreducible and returns `nil`.
    private func serialDistance(from reference: UInt32, to value: UInt32) -> Int32? {
        let raw = value &- reference
        guard raw != 0x80000000 else {
            return nil
        }
        return Int32(bitPattern: raw)
    }

    /// Sort pending ascending by signed offset from `expected`, tie-breaking on
    /// the raw start so the order is total and deterministic.
    private mutating func sortPending(relativeTo expected: UInt32) {
        pending.sort { lhs, rhs in
            let lo = Self.signedOffset(from: expected, to: lhs.start)
            let ro = Self.signedOffset(from: expected, to: rhs.start)
            if lo != ro {
                return lo < ro
            }
            return lhs.start < rhs.start
        }
    }

    /// Merge touching/overlapping and same-start intervals into a disjoint,
    /// ascending set. A merged span that would exceed `UInt32` saturates rather
    /// than wraps, keeping the result controlled for pathological facts.
    private mutating func normalizePending(relativeTo expected: UInt32) {
        guard pending.count > 1 else {
            return
        }
        sortPending(relativeTo: expected)

        var merged: [Interval] = []
        merged.reserveCapacity(pending.count)
        for interval in pending {
            guard var last = merged.last else {
                merged.append(interval)
                continue
            }
            let lastStart = Self.signedOffset(from: expected, to: last.start)
            let lastEnd = lastStart + Int64(last.length)
            let intervalStart = Self.signedOffset(from: expected, to: interval.start)
            let intervalEnd = intervalStart + Int64(interval.length)
            if intervalStart <= lastEnd {
                if intervalEnd > lastEnd {
                    let span = intervalEnd - lastStart
                    last.length = span > Int64(UInt32.max) ? UInt32.max : UInt32(span)
                    merged[merged.count - 1] = last
                }
                // Otherwise `interval` is fully covered and is dropped.
            } else {
                merged.append(interval)
            }
        }
        pending = merged
    }

    /// Drop the farthest interval(s) — greatest serial distance from `expected`,
    /// raw start as tie-break — until the pending bound holds. Each drop grows
    /// the cumulative dropped count. Returns whether any interval was discarded.
    private mutating func enforcePendingCap(relativeTo expected: UInt32) -> Bool {
        var overflowed = false
        while pending.count > configuration.maxPendingSegments {
            var farthest = 0
            for index in pending.indices where isFarther(pending[index], than: pending[farthest], from: expected) {
                farthest = index
            }
            pending.remove(at: farthest)
            droppedPendingCount = droppedPendingCount == .max ? .max : droppedPendingCount + 1
            overflowed = true
        }
        return overflowed
    }

    private func isFarther(_ lhs: Interval, than rhs: Interval, from expected: UInt32) -> Bool {
        let lo = Self.signedOffset(from: expected, to: lhs.start)
        let ro = Self.signedOffset(from: expected, to: rhs.start)
        if lo != ro {
            return lo > ro
        }
        return lhs.start > rhs.start
    }

    /// Advance the expected sequence across every buffered interval that touches
    /// or covers it, dropping any interval left fully behind. Wrap-safe; returns
    /// whether the expected sequence moved.
    private mutating func drainPending() -> Bool {
        guard let expected = expectedSequence else {
            return false
        }
        sortPending(relativeTo: expected)

        var drainedAny = false
        while let expected = expectedSequence, let first = pending.first {
            let startOffset = Self.signedOffset(from: expected, to: first.start)
            let endOffset = startOffset + Int64(first.length)
            if endOffset <= 0 {
                // Fully behind the expected sequence — already covered, discard.
                pending.removeFirst()
                continue
            }
            if startOffset <= 0 {
                // Touches or covers the expected sequence — advance past it.
                expectedSequence = first.start &+ first.length
                pending.removeFirst()
                drainedAny = true
                continue
            }
            // A gap remains ahead; nothing further connects.
            break
        }
        return drainedAny
    }
}
