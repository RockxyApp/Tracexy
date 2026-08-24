import Testing
@testable import Tracexy

@Suite("Bounded per-direction TCP sequence tracking")
struct TCPSequenceTrackerTests {
    // MARK: Internal

    // MARK: Anchoring and sequence space

    @Test("A pure ACK before any anchor claims no sequence space")
    func ackBeforeAnchor() {
        var tracker = TCPSequenceTracker()
        let output = tracker.ingest(facts(seq: 5_000, payload: 0, flags: .ack))
        #expect(output.disposition == .noSequenceSpace)
        #expect(tracker.expectedSequence == nil)
        #expect(tracker.pendingCount == 0)
    }

    @Test("A pure ACK after an anchor leaves the expected sequence unchanged")
    func ackAfterAnchor() {
        var tracker = TCPSequenceTracker()
        _ = tracker.ingest(facts(seq: 100, payload: 4))
        let output = tracker.ingest(facts(seq: 999, payload: 0, flags: .ack))
        #expect(output.disposition == .noSequenceSpace)
        #expect(tracker.expectedSequence == 104)
    }

    @Test("SYN and FIN each consume exactly one sequence number")
    func synAndFinConsumption() {
        var tracker = TCPSequenceTracker()
        #expect(tracker.ingest(facts(seq: 100, payload: 0, flags: .syn)).disposition == .initialized)
        #expect(tracker.expectedSequence == 101)
        #expect(tracker.ingest(facts(seq: 101, payload: 3)).disposition == .advanced)
        #expect(tracker.expectedSequence == 104)
        #expect(tracker.ingest(facts(seq: 104, payload: 0, flags: .fin)).disposition == .advanced)
        #expect(tracker.expectedSequence == 105)
    }

    // MARK: Ordering

    @Test("Contiguous segments advance the expected sequence")
    func contiguousAdvance() {
        var tracker = TCPSequenceTracker()
        #expect(tracker.ingest(facts(seq: 100, payload: 10)).disposition == .initialized)
        let advanced = tracker.ingest(facts(seq: 110, payload: 5))
        #expect(advanced.disposition == .advanced)
        #expect(tracker.expectedSequence == 115)
    }

    @Test("An exact retransmission is a duplicate and moves nothing")
    func exactDuplicate() {
        var tracker = TCPSequenceTracker()
        _ = tracker.ingest(facts(seq: 100, payload: 10))
        let duplicate = tracker.ingest(facts(seq: 100, payload: 10))
        #expect(duplicate.disposition == .duplicate)
        #expect(tracker.expectedSequence == 110)
    }

    @Test("A partial overlap reports overlap and new bytes and advances")
    func partialOverlapSuffix() {
        var tracker = TCPSequenceTracker()
        _ = tracker.ingest(facts(seq: 100, payload: 10)) // expected 110
        let overlap = tracker.ingest(facts(seq: 105, payload: 10)) // covers 105..<115
        #expect(overlap.disposition == .overlap(overlapBytes: 5, newBytes: 5))
        #expect(tracker.expectedSequence == 115)
    }

    @Test("An out-of-order gap buffers, then the filler drains it")
    func outOfOrderThenDrain() {
        var tracker = TCPSequenceTracker()
        _ = tracker.ingest(facts(seq: 100, payload: 5)) // expected 105
        let gap = tracker.ingest(facts(seq: 110, payload: 5)) // 110..<115 ahead by 5
        #expect(gap.disposition == .outOfOrderBuffered(gap: 5))
        #expect(tracker.pendingCount == 1)
        let drained = tracker.ingest(facts(seq: 105, payload: 5)) // fills 105..<110
        #expect(drained.disposition == .pendingDrained)
        #expect(tracker.expectedSequence == 115)
        #expect(tracker.pendingCount == 0)
    }

    // MARK: Pending normalization and bounds

    @Test("Overlapping and same-start pending intervals normalize to one")
    func overlappingPendingNormalization() {
        var tracker = TCPSequenceTracker()
        _ = tracker.ingest(facts(seq: 0, payload: 1)) // expected 1
        _ = tracker.ingest(facts(seq: 10, payload: 5)) // 10..<15
        _ = tracker.ingest(facts(seq: 12, payload: 5)) // 12..<17 overlaps -> merge
        #expect(tracker.pendingCount == 1)
        _ = tracker.ingest(facts(seq: 10, payload: 3)) // same start, fully covered
        #expect(tracker.pendingCount == 1)
    }

    @Test("Exceeding the pending cap evicts the farthest interval and counts it")
    func pendingCapEvictsFarthest() {
        var tracker = TCPSequenceTracker(configuration: .init(maxPendingSegments: 2))
        _ = tracker.ingest(facts(seq: 0, payload: 1)) // expected 1
        _ = tracker.ingest(facts(seq: 10, payload: 1))
        _ = tracker.ingest(facts(seq: 20, payload: 1))
        let overflow = tracker.ingest(facts(seq: 30, payload: 1)) // farthest -> evicted
        #expect(overflow.disposition == .pendingOverflow)
        #expect(tracker.pendingCount == 2)
        #expect(tracker.droppedPendingCount == 1)

        // Prove the farthest (30) was the victim: filling to 10 and then 20 drains
        // both retained near intervals and stops at 21.
        #expect(tracker.ingest(facts(seq: 1, payload: 9)).disposition == .pendingDrained)
        #expect(tracker.ingest(facts(seq: 11, payload: 9)).disposition == .pendingDrained)
        #expect(tracker.expectedSequence == 21)
        #expect(tracker.pendingCount == 0)
    }

    @Test("Pending count never exceeds the configured cap")
    func pendingNeverExceedsCap() {
        var tracker = TCPSequenceTracker(configuration: .init(maxPendingSegments: 3))
        _ = tracker.ingest(facts(seq: 0, payload: 1)) // expected 1
        for index in 1 ... 10 {
            let seq = UInt32(index) &* 100
            _ = tracker.ingest(facts(seq: seq, payload: 1))
            #expect(tracker.pendingCount <= 3)
        }
        #expect(tracker.droppedPendingCount > 0)
    }

    @Test("A zero cap request clamps to one")
    func capClampsToOne() {
        let tracker = TCPSequenceTracker(configuration: .init(maxPendingSegments: 0))
        #expect(tracker.configuration.maxPendingSegments == 1)
    }

    // MARK: Serial edge cases

    @Test("The expected sequence wraps across the UInt32 boundary")
    func sequenceWrap() {
        var tracker = TCPSequenceTracker()
        _ = tracker.ingest(facts(seq: UInt32.max - 1, payload: 2)) // expected 0
        #expect(tracker.expectedSequence == 0)
        let advanced = tracker.ingest(facts(seq: 0, payload: 4))
        #expect(advanced.disposition == .advanced)
        #expect(tracker.expectedSequence == 4)
    }

    @Test("An exact half-space distance is ambiguous and mutates nothing")
    func exactHalfSpaceAmbiguity() {
        var tracker = TCPSequenceTracker()
        _ = tracker.ingest(facts(seq: 0, payload: 4)) // expected 4
        let ambiguous = tracker.ingest(facts(seq: 4 &+ 0x80000000, payload: 1))
        #expect(ambiguous.disposition == .serialAmbiguous)
        #expect(tracker.expectedSequence == 4)
        #expect(tracker.pendingCount == 0)
    }

    @Test("A negative payload length is controlled, never a trap")
    func negativePayloadCannotTrap() {
        var tracker = TCPSequenceTracker()
        let output = tracker.ingest(facts(seq: 100, payload: -5))
        #expect(output.disposition == .serialAmbiguous)
        #expect(tracker.expectedSequence == nil)
    }

    @Test("A payload length beyond UInt32 is controlled, never a trap")
    func oversizePayloadCannotTrap() {
        var tracker = TCPSequenceTracker()
        let output = tracker.ingest(facts(seq: 100, payload: Int(UInt32.max) + 10))
        #expect(output.disposition == .serialAmbiguous)
        #expect(tracker.expectedSequence == nil)
    }

    @Test("A sequence-space length at the half-space horizon is ambiguous")
    func halfSpaceLengthIsAmbiguous() {
        var tracker = TCPSequenceTracker()
        let output = tracker.ingest(facts(seq: 100, payload: 1 << 31))
        #expect(output.disposition == .serialAmbiguous)
        #expect(tracker.expectedSequence == nil)
    }

    @Test("An ahead interval crossing the half-space horizon is not buffered")
    func pendingIntervalCannotCrossSerialHorizon() {
        var tracker = TCPSequenceTracker()
        _ = tracker.ingest(facts(seq: 0, payload: 1)) // expected 1
        let output = tracker.ingest(
            facts(seq: 1 &+ 0x7FFFFFF0, payload: 32)
        )
        #expect(output.disposition == .serialAmbiguous)
        #expect(tracker.expectedSequence == 1)
        #expect(tracker.pendingCount == 0)
    }

    // MARK: Determinism

    @Test("The same ordered facts fold to equal state and outputs")
    func deterministicEqualFolds() {
        let script: [TCPSegmentFacts] = [
            facts(seq: 100, payload: 0, flags: .syn),
            facts(seq: 101, payload: 10),
            facts(seq: 121, payload: 5), // gap -> buffered
            facts(seq: 111, payload: 10), // fills + connects
            facts(seq: 105, payload: 4), // overlap
            facts(seq: 999, payload: 0, flags: .ack),
        ]
        var left = TCPSequenceTracker()
        var right = TCPSequenceTracker()
        for segment in script {
            #expect(left.ingest(segment) == right.ingest(segment))
        }
        #expect(left == right)
    }

    // MARK: Private

    // MARK: Fact construction

    /// Build header-derived segment facts. `payloadSequence` mirrors the SYN
    /// offset the real decoder applies, though the tracker derives its own
    /// sequence-space length from `sequenceNumber`, `payloadLength`, and flags.
    private func facts(
        seq: UInt32,
        payload: Int,
        flags: TCPFlags = []
    )
        -> TCPSegmentFacts
    {
        let synOffset: UInt32 = flags.contains(.syn) ? 1 : 0
        return TCPSegmentFacts(
            sequenceNumber: seq,
            acknowledgementNumber: 0,
            flags: flags,
            windowSize: 0,
            headerLength: 20,
            payloadSequence: seq &+ synOffset,
            payloadLength: payload,
            options: TCPOptionFacts()
        )
    }
}
