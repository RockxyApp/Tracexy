import Foundation

/// A small, bounded TCP byte-stream prefix reassembler for one direction of one
/// five-tuple. It exists only to recover application metadata split across nearby
/// segments; it is not a connection table and never retains an unbounded stream.
nonisolated struct TCPStreamReassembler: Sendable {
    // MARK: Lifecycle

    init(maxBufferedBytes: Int = 16_384, maxPendingSegments: Int = 32) {
        self.maxBufferedBytes = max(5, maxBufferedBytes)
        self.maxPendingSegments = max(1, maxPendingSegments)
    }

    // MARK: Internal

    enum Disposition: Equatable, Sendable {
        case advanced
        case buffered
        case duplicate
        case reset
    }

    struct Output: Equatable, Sendable {
        let contiguous: [UInt8]
        let disposition: Disposition
    }

    private(set) var contiguous: [UInt8] = []
    private(set) var pendingByteCount = 0
    private(set) var didOverflow = false

    mutating func ingest(sequence: UInt32, payload: [UInt8]) -> Output {
        guard !payload.isEmpty else {
            return Output(contiguous: contiguous, disposition: .duplicate)
        }

        guard let expected = nextSequence else {
            return restart(at: sequence, payload: payload, disposition: .advanced)
        }

        let distance = serialDistance(from: expected, to: sequence)
        if distance <= 0 {
            let overlap = Int(-Int64(distance))
            guard overlap < payload.count else {
                return Output(contiguous: contiguous, disposition: .duplicate)
            }
            let suffix = Array(payload.dropFirst(overlap))
            guard contiguous.count + suffix.count <= maxBufferedBytes else {
                return restart(at: sequence, payload: payload, disposition: .reset)
            }
            contiguous.append(contentsOf: suffix)
            nextSequence = expected &+ UInt32(suffix.count)
            drainPending()
            return Output(contiguous: contiguous, disposition: .advanced)
        }

        insertPending(sequence: sequence, payload: payload)
        if pending.count > maxPendingSegments || pendingByteCount + contiguous.count > maxBufferedBytes {
            return restart(at: sequence, payload: payload, disposition: .reset)
        }
        return Output(contiguous: contiguous, disposition: .buffered)
    }

    mutating func reset() {
        nextSequence = nil
        contiguous.removeAll(keepingCapacity: false)
        pending.removeAll(keepingCapacity: false)
        pendingByteCount = 0
        didOverflow = false
    }

    // MARK: Private

    private struct Segment: Sendable {
        let sequence: UInt32
        let bytes: [UInt8]
    }

    private let maxBufferedBytes: Int
    private let maxPendingSegments: Int
    private var nextSequence: UInt32?
    private var pending: [Segment] = []

    private mutating func restart(
        at sequence: UInt32,
        payload: [UInt8],
        disposition: Disposition
    )
        -> Output
    {
        let kept = Array(payload.prefix(maxBufferedBytes))
        contiguous = kept
        nextSequence = sequence &+ UInt32(kept.count)
        pending.removeAll(keepingCapacity: false)
        pendingByteCount = 0
        didOverflow = disposition == .reset || payload.count > maxBufferedBytes
        return Output(contiguous: contiguous, disposition: disposition)
    }

    private mutating func insertPending(sequence: UInt32, payload: [UInt8]) {
        if let index = pending.firstIndex(where: { $0.sequence == sequence }) {
            let existing = pending[index].bytes
            if payload.count > existing.count, payload.starts(with: existing) {
                pendingByteCount += payload.count - existing.count
                pending[index] = Segment(sequence: sequence, bytes: payload)
            }
            return
        }
        pending.append(Segment(sequence: sequence, bytes: payload))
        pendingByteCount += payload.count
    }

    private mutating func drainPending() {
        while let expected = nextSequence {
            let candidates = pending.enumerated().filter {
                serialDistance(from: expected, to: $0.element.sequence) <= 0
            }
            guard let candidate = candidates.min(by: {
                serialDistance(from: expected, to: $0.element.sequence)
                    < serialDistance(from: expected, to: $1.element.sequence)
            }) else {
                return
            }

            let segment = pending.remove(at: candidate.offset)
            pendingByteCount -= segment.bytes.count
            let distance = serialDistance(from: expected, to: segment.sequence)
            let overlap = Int(-Int64(distance))
            guard overlap < segment.bytes.count else {
                continue
            }
            let suffix = Array(segment.bytes.dropFirst(overlap))
            guard contiguous.count + suffix.count <= maxBufferedBytes else {
                didOverflow = true
                pending.removeAll(keepingCapacity: false)
                pendingByteCount = 0
                return
            }
            contiguous.append(contentsOf: suffix)
            nextSequence = expected &+ UInt32(suffix.count)
        }
    }

    /// RFC-style serial-number comparison, valid while observed distances remain
    /// below 2^31 bytes — far above this metadata window.
    private func serialDistance(from reference: UInt32, to value: UInt32) -> Int32 {
        Int32(bitPattern: value &- reference)
    }
}
