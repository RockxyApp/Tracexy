import Foundation

// MARK: - TCPFlowControlTracker

/// A pure, bounded acknowledgement-and-window tracker for one TCP connection
/// (TCP health). It folds typed `TCPSegmentFacts` from both
/// canonical directions into a handful of per-direction scalars — the last
/// acknowledgement number, the last advertised window, the end of the last
/// sequence-bearing segment, and the window-scale shift each side offered on its
/// SYN — and reports which flow-control shapes the current segment matches. It
/// never stores raw bytes, reassembles a stream, reads a wall clock, or reaches
/// the `@MainActor`; the only source of state change is `ingest`, applied in
/// capture order, so replaying the same facts always yields the same
/// observations.
///
/// The shapes are the same passive signatures a packet analyst reads off a
/// trace (and that Wireshark labels `tcp.analysis.*`), stated only as what the
/// segments showed:
///   - **duplicate acknowledgement** — a pure ACK (no payload, no SYN/FIN/RST)
///     repeating this direction's previous acknowledgement number with the same
///     advertised window and the same sequence number. An ACK that answers the
///     peer's keep-alive probe is excluded, because it repeats by design, and so
///     is a repeated zero-window advertisement, which the zero-window observation
///     already explains.
///   - **zero window** — an ACK-bearing, control-free segment advertising a
///     receive window of zero: the sender of that segment has no buffer space.
///   - **zero-window probe** — a one-byte segment sent at this direction's edge
///     while the peer's last advertised window was zero. The probe is sent to be
///     rejected, so it never advances this tracker's edge; a retransmitted probe
///     therefore matches again.
///   - **window full** — a data segment whose end lands exactly on the peer's
///     acknowledged edge plus its scaled advertised window. Reported only when
///     both SYNs were observed, because the scale shift is otherwise unknown and
///     a guessed edge would be a fabricated observation.
///   - **fast retransmission** — a data segment beginning exactly at the
///     acknowledgement number the peer has repeated in at least two duplicate
///     acknowledgements (RFC 5681 §3.2 names this sender behaviour). It is the
///     mechanism the segments show, not a cause: whether the original segment
///     was lost or only delayed is not claimed. Reported once per repeated edge.
///     Unlike Wireshark there is no 20 ms window, because the tracker never
///     reads time.
///   - **ACKed unseen segment** — an acknowledgement beyond the farthest sequence
///     the peer was seen to send: the peer sent bytes this capture never saw.
///     Wireshark labels it "ACKed segment that wasn't captured (common at capture
///     start)". It points at the capture, not the network, so it is only reported
///     once the peer's own sequence edge is known (it sent a sequence-bearing
///     segment, a SYN included).
///   - **spurious retransmission** — a segment the sequence tracker already
///     classified as a retransmission whose whole sequence range was at or
///     behind the peer's last acknowledgement: the receiver had acknowledged
///     those bytes before they were sent again.
///
/// Serial comparisons use RFC 1982 arithmetic through wrapping operators; a
/// segment whose payload length cannot be expressed as sequence space is
/// ignored rather than trapped. A reset changes nothing and matches nothing —
/// its window and acknowledgement fields describe a torn-down socket.
nonisolated struct TCPFlowControlTracker: Equatable, Sendable {
    // MARK: Internal

    // MARK: Observations

    /// The flow-control shapes one ingested segment matched. Several can hold at
    /// once (a repeated zero-window ACK is both `zeroWindow` and
    /// `duplicateAcknowledgement`); the empty set means the segment was ordinary.
    nonisolated struct Observations: OptionSet, Hashable, Sendable {
        static let duplicateAcknowledgement = Observations(rawValue: 1 << 0)
        static let zeroWindow = Observations(rawValue: 1 << 1)
        static let zeroWindowProbe = Observations(rawValue: 1 << 2)
        static let windowFull = Observations(rawValue: 1 << 3)
        static let fastRetransmission = Observations(rawValue: 1 << 4)
        static let spuriousRetransmission = Observations(rawValue: 1 << 5)
        static let ackedUnseenSegment = Observations(rawValue: 1 << 6)

        let rawValue: UInt8
    }

    /// Fold one segment travelling in `direction`. `keepAlive` is the direction's
    /// sequence tracker verdict for the same segment (`TCPSequenceTracker
    /// .Disposition.keepAlive`), passed in so the peer's answering ACK can be told
    /// apart from a duplicate acknowledgement. `retransmission` is the same
    /// tracker's `duplicate` verdict, the only segments that can be spurious.
    /// Returns the matched shapes.
    mutating func ingest(
        direction: ConnectionDirection,
        facts: TCPSegmentFacts,
        keepAlive: Bool,
        retransmission: Bool = false
    )
        -> Observations
    {
        guard let sequenceLength = Self.sequenceSpaceLength(of: facts) else {
            return []
        }
        let flags = facts.flags
        var forward = self[direction]
        var reverse = self[direction.opposite]

        // A SYN (with or without ACK) is where a side declares its window-scale
        // shift; RFC 7323 §2.2 says the SYN's own window is never scaled.
        if flags.contains(.syn) {
            forward.synObserved = true
            forward.offeredWindowShift = facts.options.windowScale
        }
        guard !flags.contains(.rst) else {
            return []
        }

        let controlFree = !flags.contains(.syn) && !flags.contains(.fin)
        let acknowledging = flags.contains(.ack)
        var observations: Observations = []

        if controlFree, acknowledging, facts.payloadLength == 1,
           reverse.lastWindow == 0, forward.nextSequence == facts.sequenceNumber
        {
            observations.insert(.zeroWindowProbe)
        } else if controlFree, acknowledging, facts.payloadLength > 0,
                  let edge = Self.receiveWindowEdge(of: reverse, peer: forward),
                  facts.sequenceNumber &+ sequenceLength == edge
        {
            observations.insert(.windowFull)
        }

        if controlFree, acknowledging, facts.windowSize == 0 {
            observations.insert(.zeroWindow)
        }

        let carriesData = facts.payloadLength > 0 && !flags.contains(.syn)
            && !observations.contains(.zeroWindowProbe)
        if carriesData, reverse.duplicateAcknowledgementRun >= 2, !reverse.fastRetransmissionAnswered,
           reverse.lastAcknowledgement == facts.sequenceNumber
        {
            observations.insert(.fastRetransmission)
            reverse.fastRetransmissionAnswered = true
            self[direction.opposite] = reverse
        }
        if carriesData, retransmission, !keepAlive, let acknowledged = reverse.lastAcknowledgement,
           Int32(bitPattern: (facts.sequenceNumber &+ sequenceLength) &- acknowledged) <= 0
        {
            observations.insert(.spuriousRetransmission)
        }

        if acknowledging, let peerEdge = reverse.nextSequence,
           Int32(bitPattern: facts.acknowledgementNumber &- peerEdge) > 0
        {
            observations.insert(.ackedUnseenSegment)
        }

        let pureAcknowledgement = controlFree && acknowledging && facts.payloadLength == 0
        // A keep-alive is answered exactly once: the ACK that answers it consumes
        // the marker, so an identical ACK with no probe in between is a genuine
        // duplicate acknowledgement again.
        let answersKeepAlive = reverse.lastWasKeepAlive
            && reverse.nextSequence == facts.acknowledgementNumber
        if answersKeepAlive {
            reverse.lastWasKeepAlive = false
            self[direction.opposite] = reverse
        }
        // A repeated zero-window advertisement is a window statement, not the
        // "a segment is missing" signal a duplicate acknowledgement carries, so the
        // zero window supersedes it and the frame is reported once.
        if pureAcknowledgement, !keepAlive, !answersKeepAlive, !observations.contains(.zeroWindow),
           let lastAcknowledgement = forward.lastAcknowledgement,
           lastAcknowledgement == facts.acknowledgementNumber,
           forward.lastWindow == facts.windowSize,
           forward.nextSequence == facts.sequenceNumber
        {
            observations.insert(.duplicateAcknowledgement)
        }

        // Record this segment as the direction's latest, except that a probe never
        // moves the edge (the byte was sent to be refused). A duplicate
        // acknowledgement lengthens the run on the same edge; any other
        // acknowledgement number starts a new edge with no run.
        if observations.contains(.duplicateAcknowledgement) {
            forward.duplicateAcknowledgementRun += 1
        } else if acknowledging, forward.lastAcknowledgement != facts.acknowledgementNumber {
            forward.duplicateAcknowledgementRun = 0
            forward.fastRetransmissionAnswered = false
        }
        if acknowledging {
            forward.lastAcknowledgement = facts.acknowledgementNumber
        }
        forward.lastWindow = facts.windowSize
        forward.lastWindowIsFromSYN = flags.contains(.syn)
        if sequenceLength > 0, !observations.contains(.zeroWindowProbe) {
            let end = facts.sequenceNumber &+ sequenceLength
            if let next = forward.nextSequence {
                if Int32(bitPattern: end &- next) > 0 {
                    forward.nextSequence = end
                }
            } else {
                forward.nextSequence = end
            }
        }
        // A resent probe byte sits one behind the sequence tracker's edge and so
        // looks like a keep-alive to it; the probe verdict wins here too.
        forward.lastWasKeepAlive = keepAlive && !observations.contains(.zeroWindowProbe)
        self[direction] = forward
        return observations
    }

    // MARK: Private

    /// The per-direction scalars. Nothing here is a byte, a name or a claim about
    /// the peer's socket — only what this direction's segments last advertised.
    private struct DirectionState: Equatable, Sendable {
        var lastAcknowledgement: UInt32?
        var lastWindow: UInt16?
        var lastWindowIsFromSYN = false
        /// The end of the farthest sequence-bearing segment seen in this direction
        /// (RFC serial order), or `nil` before any. A pure ACK repeats it exactly.
        var nextSequence: UInt32?
        var synObserved = false
        /// The effective window-scale shift this side offered on its SYN, or `nil`
        /// when its SYN carried no Window Scale option (or was not observed).
        var offeredWindowShift: UInt8?
        var lastWasKeepAlive = false
        /// How many duplicate acknowledgements have repeated `lastAcknowledgement`,
        /// and whether a fast retransmission already answered that edge.
        var duplicateAcknowledgementRun = 0
        var fastRetransmissionAnswered = false
    }

    private var aToB = DirectionState()
    private var bToA = DirectionState()

    /// The sequence-space length of a segment (payload plus one per SYN/FIN), or
    /// `nil` when the payload length cannot be expressed in `UInt32` — mirroring
    /// `TCPSequenceTracker`, which treats such a fact as unclassifiable.
    private static func sequenceSpaceLength(of facts: TCPSegmentFacts) -> UInt32? {
        guard facts.payloadLength >= 0, facts.payloadLength <= Int(UInt32.max) else {
            return nil
        }
        let control = UInt32((facts.flags.contains(.syn) ? 1 : 0) + (facts.flags.contains(.fin) ? 1 : 0))
        let (sum, overflow) = UInt32(facts.payloadLength).addingReportingOverflow(control)
        return overflow ? nil : sum
    }

    /// The sequence number one past the last byte `receiver` is currently willing
    /// to accept from `peer`: its last acknowledgement plus its last advertised
    /// window, scaled by the shift it offered. RFC 7323 §2.2: scaling is in effect
    /// only when *both* SYNs carried the option, and a SYN's own window is never
    /// scaled. Returns `nil` — and so reports nothing — unless both SYNs and a
    /// prior acknowledgement from `receiver` were observed.
    private static func receiveWindowEdge(of receiver: DirectionState, peer: DirectionState) -> UInt32? {
        guard receiver.synObserved, peer.synObserved,
              let acknowledgement = receiver.lastAcknowledgement,
              let window = receiver.lastWindow else
        {
            return nil
        }
        var scaled = UInt32(window)
        if !receiver.lastWindowIsFromSYN,
           let shift = receiver.offeredWindowShift, peer.offeredWindowShift != nil
        {
            scaled <<= UInt32(min(shift, 14))
        }
        return acknowledgement &+ scaled
    }

    private subscript(direction: ConnectionDirection) -> DirectionState {
        get {
            switch direction {
            case .aToB: aToB
            case .bToA: bToA
            }
        }
        set {
            switch direction {
            case .aToB: aToB = newValue
            case .bToA: bToA = newValue
            }
        }
    }
}
