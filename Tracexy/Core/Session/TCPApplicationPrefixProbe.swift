import Foundation

// MARK: - TCPApplicationPrefixProbe

/// A private, bounded first-record application probe for one canonical direction
/// of one connection. It reassembles only enough of the direction's TCP byte
/// stream to classify its first TLS/HTTP/DNS record, then releases the bytes.
///
/// It is owned *inside* a connection's per-direction working value, alongside the
/// byte-free `TCPSequenceTracker`. The two are deliberately separate coordinate
/// projections of the same segment: the tracker orders raw sequence space
/// (including SYN/FIN control positions) and never stores bytes; this probe stores
/// raw payload bytes keyed by `payloadSequence` and never touches control space.
/// The probe can never open, close, split or otherwise mutate connection lifecycle
/// — it only observes and hands off application metadata.
///
/// Bounds are hard: buffering more than `maxFragments` discrete fragments, or
/// retaining more than `maxBufferedBytes` contiguous-plus-pending bytes (including
/// a single oversized segment), drops every application byte, reports a one-shot
/// truncation and permanently disables recovery for the direction. Sequence
/// observation is unaffected. A complete first record likewise releases the bytes
/// and stops further probing. An incomplete but recognized record stays bounded and
/// may yield progressively richer handoffs until it completes.
nonisolated struct TCPApplicationPrefixProbe: Sendable {
    // MARK: Lifecycle

    init(maxBufferedBytes: Int = 16_384, maxFragments: Int = 32) {
        self.maxBufferedBytes = max(5, maxBufferedBytes)
        self.maxFragments = max(1, maxFragments)
    }

    // MARK: Internal

    /// The result of folding one segment's payload through the probe.
    struct Outcome: Sendable {
        static let none = Outcome(application: nil, truncated: false)

        /// Application metadata classified from the bounded prefix so far, or `nil`
        /// when this segment recognized nothing new. Progressive handoffs return an
        /// incomplete value that later segments may enrich.
        let application: PacketDecoder.ReassembledTCPApplication?
        /// `true` exactly on the segment whose buffering overflowed a bound and
        /// permanently disabled recovery. Sticky truncation is the caller's job.
        let truncated: Bool
    }

    /// Whether an overflow permanently disabled first-record recovery for this
    /// direction. Sequence observation continues regardless.
    private(set) var isDisabled = false

    /// Fold one segment's captured payload. `payloadSequence` is the sequence of the
    /// first payload byte (a SYN's control position is already excluded upstream, so
    /// SYN+data anchors exactly once). `packetIsClassified` is whether the frame was
    /// independently application-classified at its own boundary — used only to allow
    /// a midstream re-anchor away from an opaque retained prefix.
    mutating func ingest(
        payloadSequence: UInt32,
        payload: [UInt8],
        sourcePort: UInt16,
        destinationPort: UInt16,
        packetIsClassified: Bool
    )
        -> Outcome
    {
        guard !stopped, !payload.isEmpty else {
            return .none
        }

        if append(sequence: payloadSequence, payload: payload) == .overflow {
            // Drop everything and permanently disable; the byte-free sequence
            // tracker keeps ordering in its own coordinate space.
            releaseBytes()
            isDisabled = true
            stopped = true
            return Outcome(application: nil, truncated: true)
        }

        var metadata = decode(sourcePort: sourcePort, destinationPort: destinationPort)

        // Midstream re-anchor: a capture may begin inside an existing byte stream.
        // If the retained prefix is opaque but this packet is independently
        // classified at its own boundary, discard only the stale application bytes,
        // re-anchor here and retry. Lifecycle ordering is never touched.
        if metadata == nil, packetIsClassified, contiguous.count != payload.count {
            releaseBytes()
            _ = append(sequence: payloadSequence, payload: payload)
            metadata = decode(sourcePort: sourcePort, destinationPort: destinationPort)
        }

        guard let metadata else {
            return .none
        }

        if metadata.isComplete {
            // The complete first record is classified; release its bytes and stop.
            releaseBytes()
            stopped = true
        }
        return Outcome(application: metadata, truncated: false)
    }

    // MARK: Private

    private enum AppendResult {
        case ok
        case overflow
    }

    /// One buffered payload fragment `[sequence, sequence + bytes.count)` in
    /// `payloadSequence` coordinates. Unlike the tracker's byte-free intervals, this
    /// deliberately retains the raw bytes so the first record can be reconstructed.
    private struct Fragment: Sendable {
        let sequence: UInt32
        let bytes: [UInt8]
    }

    private let maxBufferedBytes: Int
    private let maxFragments: Int
    /// Set once a complete record classifies or an overflow disables the probe; no
    /// further payload is buffered afterward.
    private var stopped = false
    private var contiguous: [UInt8] = []
    private var nextSequence: UInt32?
    private var pending: [Fragment] = []
    private var pendingByteCount = 0

    private mutating func releaseBytes() {
        contiguous.removeAll(keepingCapacity: false)
        pending.removeAll(keepingCapacity: false)
        pendingByteCount = 0
        nextSequence = nil
    }

    private func decode(sourcePort: UInt16, destinationPort: UInt16) -> PacketDecoder.ReassembledTCPApplication? {
        PacketDecoder.decodeReassembledTCPPayload(
            contiguous, sourcePort: sourcePort, destinationPort: destinationPort
        )
    }

    /// Fold one fragment into the contiguous prefix / pending set. A conflicting
    /// overlap keeps the first-observed bytes (a retransmission adds nothing); a
    /// fragment ahead of the expected sequence is buffered discretely. Returns
    /// `.overflow` when a bound would be exceeded.
    private mutating func append(sequence: UInt32, payload: [UInt8]) -> AppendResult {
        guard let expected = nextSequence else {
            return anchor(at: sequence, payload: payload)
        }

        guard let distance = serialDistance(from: expected, to: sequence) else {
            // An exact half-space distance has no well-defined serial ordering.
            // Fail closed for this bounded application probe only; its caller marks
            // truncation while the independent sequence tracker keeps observing.
            return .overflow
        }
        if distance <= 0 {
            let overlap = Int(-distance)
            guard overlap < payload.count else {
                // Fully at or behind the expected sequence: a pure retransmission.
                return .ok
            }
            let suffix = Array(payload.dropFirst(overlap))
            guard contiguous.count + suffix.count <= maxBufferedBytes else {
                return .overflow
            }
            contiguous.append(contentsOf: suffix)
            nextSequence = expected &+ UInt32(suffix.count)
            return drainPending() ? .overflow : .ok
        }

        insertPending(sequence: sequence, payload: payload)
        if pending.count > maxFragments || pendingByteCount + contiguous.count > maxBufferedBytes {
            return .overflow
        }
        return .ok
    }

    /// Anchor the first payload byte. A single segment larger than the byte bound
    /// overflows rather than silently keeping a partial prefix.
    private mutating func anchor(at sequence: UInt32, payload: [UInt8]) -> AppendResult {
        guard payload.count <= maxBufferedBytes else {
            return .overflow
        }
        contiguous = payload
        nextSequence = sequence &+ UInt32(payload.count)
        pending.removeAll(keepingCapacity: false)
        pendingByteCount = 0
        return .ok
    }

    private mutating func insertPending(sequence: UInt32, payload: [UInt8]) {
        if let index = pending.firstIndex(where: { $0.sequence == sequence }) {
            let existing = pending[index].bytes
            // A longer retransmission of the same start extends the fragment; a
            // shorter or equal one is already covered (first-observed wins).
            if payload.count > existing.count, payload.starts(with: existing) {
                pendingByteCount += payload.count - existing.count
                pending[index] = Fragment(sequence: sequence, bytes: payload)
            }
            return
        }
        pending.append(Fragment(sequence: sequence, bytes: payload))
        pendingByteCount += payload.count
    }

    /// Advance the contiguous prefix across every buffered fragment that touches or
    /// covers the expected sequence. Returns whether the byte bound was exceeded
    /// while connecting fragments.
    private mutating func drainPending() -> Bool {
        while let expected = nextSequence {
            let ranked = pending.enumerated().compactMap { index, fragment
                -> (offset: Int, fragment: Fragment, distance: Int64)? in
                guard let distance = serialDistance(from: expected, to: fragment.sequence) else {
                    return nil
                }
                return (index, fragment, distance)
            }
            guard ranked.count == pending.count else {
                return true
            }
            guard let candidate = ranked.filter({ $0.distance <= 0 }).min(by: {
                $0.distance < $1.distance
            }) else {
                return false
            }

            let fragment = pending.remove(at: candidate.offset)
            pendingByteCount -= fragment.bytes.count
            let overlap = Int(-candidate.distance)
            guard overlap < fragment.bytes.count else {
                continue
            }
            let suffix = Array(fragment.bytes.dropFirst(overlap))
            guard contiguous.count + suffix.count <= maxBufferedBytes else {
                return true
            }
            contiguous.append(contentsOf: suffix)
            nextSequence = expected &+ UInt32(suffix.count)
        }
        return false
    }

    /// RFC-style serial-number comparison. An exact 2^31 distance is ambiguous and
    /// returns `nil`; all other values fit safely in `Int64` without turning the
    /// half-space sentinel into a giant overlap.
    private func serialDistance(from reference: UInt32, to value: UInt32) -> Int64? {
        let raw = value &- reference
        guard raw != 0x80000000 else {
            return nil
        }
        return Int64(Int32(bitPattern: raw))
    }
}
