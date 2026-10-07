import Foundation
import Testing
@testable import Tracexy

/// The pure acknowledgement/window tracker. Every case feeds typed facts in
/// capture order and pins exactly which flow-control shapes each segment matches;
/// nothing here touches the connection fold.
@Suite("TCPFlowControlTracker")
struct TCPFlowControlTrackerTests {
    // MARK: Internal

    // MARK: Duplicate acknowledgements

    @Test("A pure ACK repeating the previous ack, window and sequence is a duplicate acknowledgement")
    func duplicateAcknowledgement() {
        var tracker = TCPFlowControlTracker()
        handshake(&tracker)
        // Server sends two segments; the client acknowledges the first, then
        // re-acknowledges it twice (the second segment was not received in order).
        #expect(tracker
            .ingest(direction: .bToA, facts: facts(seq: 5_001, ack: 1_001, payload: 100), keepAlive: false).isEmpty)
        #expect(tracker
            .ingest(direction: .bToA, facts: facts(seq: 5_101, ack: 1_001, payload: 100), keepAlive: false).isEmpty)
        #expect(tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_101), keepAlive: false).isEmpty)
        #expect(tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_101), keepAlive: false)
            == [.duplicateAcknowledgement])
        #expect(tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_101), keepAlive: false)
            == [.duplicateAcknowledgement])
        // A new acknowledgement edge ends the run.
        #expect(tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_201), keepAlive: false).isEmpty)
    }

    @Test("A repeated ack with a different window is a window update, not a duplicate")
    func windowUpdateIsNotDuplicate() {
        var tracker = TCPFlowControlTracker()
        handshake(&tracker)
        _ = tracker.ingest(direction: .bToA, facts: facts(seq: 5_001, ack: 1_001, payload: 100), keepAlive: false)
        _ = tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_101, window: 4_096), keepAlive: false)
        #expect(tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_101, window: 8_192), keepAlive: false)
            .isEmpty)
    }

    @Test("Data segments, FINs and the first ACK are never duplicate acknowledgements")
    func nonPureSegmentsAreNotDuplicates() {
        var tracker = TCPFlowControlTracker()
        handshake(&tracker)
        // The very first pure ACK in a direction has nothing to repeat.
        _ = tracker.ingest(direction: .bToA, facts: facts(seq: 5_001, ack: 1_001, payload: 10), keepAlive: false)
        #expect(tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_011), keepAlive: false).isEmpty)
        // Two data segments carrying the same ack are data, not duplicate ACKs.
        #expect(tracker
            .ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_011, payload: 10), keepAlive: false).isEmpty)
        #expect(tracker
            .ingest(direction: .aToB, facts: facts(seq: 1_011, ack: 5_011, payload: 10), keepAlive: false).isEmpty)
        // A FIN repeating the ack consumes sequence space and carries control.
        #expect(tracker.ingest(
            direction: .aToB,
            facts: facts(seq: 1_021, ack: 5_011, flags: [.fin, .ack]),
            keepAlive: false
        ).isEmpty)
    }

    @Test("The ACK answering a keep-alive probe is not a duplicate acknowledgement")
    func keepAliveAnswerIsNotDuplicate() {
        var tracker = TCPFlowControlTracker()
        handshake(&tracker)
        _ = tracker.ingest(direction: .bToA, facts: facts(seq: 5_001, ack: 1_001, payload: 100), keepAlive: false)
        _ = tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_101), keepAlive: false)
        // Server keep-alive: one garbage byte one behind its edge (the sequence
        // tracker's verdict is passed in).
        _ = tracker.ingest(direction: .bToA, facts: facts(seq: 5_100, ack: 1_001, payload: 1), keepAlive: true)
        // The client's answer repeats ack 5_101 with the same window and sequence,
        // exactly like a duplicate ACK would — but it answers the probe.
        #expect(tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_101), keepAlive: false).isEmpty)
        // A further identical ACK with no probe in between is a duplicate again.
        #expect(tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_101), keepAlive: false)
            == [.duplicateAcknowledgement])
    }

    // MARK: Zero window and probes

    @Test("A control-free ACK advertising window zero is a zero window; SYN, FIN and RST are not")
    func zeroWindow() {
        var tracker = TCPFlowControlTracker()
        #expect(tracker
            .ingest(direction: .aToB, facts: facts(seq: 1_000, flags: [.syn], window: 0), keepAlive: false).isEmpty)
        #expect(tracker.ingest(
            direction: .bToA,
            facts: facts(seq: 5_000, ack: 1_001, flags: [.syn, .ack], window: 0),
            keepAlive: false
        ).isEmpty)
        #expect(tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_001, window: 0), keepAlive: false)
            == [.zeroWindow])
        #expect(tracker.ingest(
            direction: .aToB,
            facts: facts(seq: 1_001, ack: 5_001, flags: [.fin, .ack], window: 0),
            keepAlive: false
        ).isEmpty)
        #expect(tracker.ingest(
            direction: .aToB,
            facts: facts(seq: 1_002, ack: 5_001, flags: [.rst, .ack], window: 0),
            keepAlive: false
        ).isEmpty)
    }

    @Test("A repeated zero-window ACK is only a zero window — the window statement supersedes the duplicate")
    func repeatedZeroWindowIsNotAlsoDuplicate() {
        var tracker = TCPFlowControlTracker()
        handshake(&tracker)
        _ = tracker.ingest(direction: .bToA, facts: facts(seq: 5_001, ack: 1_001, payload: 100), keepAlive: false)
        #expect(tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_101, window: 0), keepAlive: false)
            == [.zeroWindow])
        #expect(tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_101, window: 0), keepAlive: false)
            == [.zeroWindow])
    }

    @Test("A one-byte segment at the edge while the peer advertises zero is a probe, and a resent probe matches again")
    func zeroWindowProbe() {
        var tracker = TCPFlowControlTracker()
        handshake(&tracker)
        _ = tracker.ingest(direction: .bToA, facts: facts(seq: 5_001, ack: 1_001, payload: 100), keepAlive: false)
        _ = tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_101, window: 0), keepAlive: false)
        #expect(tracker.ingest(direction: .bToA, facts: facts(seq: 5_101, ack: 1_001, payload: 1), keepAlive: false)
            == [.zeroWindowProbe])
        // The probe never moved the edge, so the retransmitted probe is a probe too.
        #expect(tracker.ingest(direction: .bToA, facts: facts(seq: 5_101, ack: 1_001, payload: 1), keepAlive: false)
            == [.zeroWindowProbe])
        // The window opens; the next full segment from the edge is ordinary data.
        _ = tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_101, window: 65_535), keepAlive: false)
        #expect(tracker.ingest(direction: .bToA, facts: facts(seq: 5_101, ack: 1_001, payload: 100), keepAlive: false)
            .isEmpty)
    }

    @Test("A one-byte segment is not a probe when the peer's window is open or it is off the edge")
    func oneByteSegmentsThatAreNotProbes() {
        var tracker = TCPFlowControlTracker()
        handshake(&tracker)
        _ = tracker.ingest(direction: .bToA, facts: facts(seq: 5_001, ack: 1_001, payload: 100), keepAlive: false)
        _ = tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_101, window: 1_024), keepAlive: false)
        #expect(tracker
            .ingest(direction: .bToA, facts: facts(seq: 5_101, ack: 1_001, payload: 1), keepAlive: false).isEmpty)
        _ = tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_102, window: 0), keepAlive: false)
        // Off the edge (behind it): a retransmitted byte, not a probe.
        #expect(tracker
            .ingest(direction: .bToA, facts: facts(seq: 5_050, ack: 1_001, payload: 1), keepAlive: false).isEmpty)
    }

    // MARK: Window full

    @Test("A data segment ending exactly at the peer's acknowledged edge plus its window is window full")
    func windowFullUnscaled() {
        var tracker = TCPFlowControlTracker()
        handshake(&tracker)
        // Client acknowledges 5_001 with a 1_000-byte window; the server may send
        // up to sequence 6_001.
        _ = tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_001, window: 1_000), keepAlive: false)
        #expect(tracker
            .ingest(direction: .bToA, facts: facts(seq: 5_001, ack: 1_001, payload: 500), keepAlive: false).isEmpty)
        #expect(tracker.ingest(direction: .bToA, facts: facts(seq: 5_501, ack: 1_001, payload: 500), keepAlive: false)
            == [.windowFull])
        // Short of the edge, or past a freshly moved edge, is ordinary data.
        _ = tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 6_001, window: 1_000), keepAlive: false)
        #expect(tracker
            .ingest(direction: .bToA, facts: facts(seq: 6_001, ack: 1_001, payload: 999), keepAlive: false).isEmpty)
    }

    @Test("Window full applies the receiver's scale shift only when both SYNs offered one")
    func windowFullScaled() {
        var tracker = TCPFlowControlTracker()
        // Both sides offer a shift of 2 (×4).
        _ = tracker.ingest(direction: .aToB, facts: facts(seq: 1_000, flags: [.syn], shift: 2), keepAlive: false)
        _ = tracker.ingest(
            direction: .bToA,
            facts: facts(seq: 5_000, ack: 1_001, flags: [.syn, .ack], shift: 2),
            keepAlive: false
        )
        _ = tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_001, window: 250), keepAlive: false)
        // The edge is 5_001 + 250 × 4 = 6_001, not 5_251.
        #expect(tracker
            .ingest(direction: .bToA, facts: facts(seq: 5_001, ack: 1_001, payload: 250), keepAlive: false).isEmpty)
        #expect(tracker.ingest(direction: .bToA, facts: facts(seq: 5_251, ack: 1_001, payload: 750), keepAlive: false)
            == [.windowFull])

        // Only one side offered a shift: RFC 7323 says no scaling is in effect.
        var unscaled = TCPFlowControlTracker()
        _ = unscaled.ingest(direction: .aToB, facts: facts(seq: 1_000, flags: [.syn], shift: 2), keepAlive: false)
        _ = unscaled.ingest(
            direction: .bToA,
            facts: facts(seq: 5_000, ack: 1_001, flags: [.syn, .ack]),
            keepAlive: false
        )
        _ = unscaled.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_001, window: 250), keepAlive: false)
        #expect(unscaled.ingest(direction: .bToA, facts: facts(seq: 5_001, ack: 1_001, payload: 250), keepAlive: false)
            == [.windowFull])
    }

    @Test("Window full is never reported without both observed SYNs, because the scale is unknown")
    func windowFullFailsClosedMidstream() {
        var tracker = TCPFlowControlTracker()
        _ = tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_001, window: 1_000), keepAlive: false)
        #expect(tracker.ingest(direction: .bToA, facts: facts(seq: 5_001, ack: 1_001, payload: 1_000), keepAlive: false)
            .isEmpty)
    }

    @Test("The SYN's own window is never scaled when it is the latest advertisement")
    func synWindowIsUnscaled() {
        var tracker = TCPFlowControlTracker()
        _ = tracker.ingest(
            direction: .aToB,
            facts: facts(seq: 1_000, flags: [.syn], window: 100, shift: 3),
            keepAlive: false
        )
        _ = tracker.ingest(
            direction: .bToA,
            facts: facts(seq: 5_000, ack: 1_001, flags: [.syn, .ack], window: 100, shift: 3),
            keepAlive: false
        )
        // The server's latest advertisement is its SYN+ACK window (100), which is
        // unscaled despite the shift both sides offered: the edge for client data
        // is 1_001 + 100 = 1_101, not 1_001 + 800.
        #expect(tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_001, payload: 100), keepAlive: false)
            == [.windowFull])
    }

    // MARK: Resets and malformed facts

    @Test("A reset matches nothing and leaves the tracker unchanged")
    func resetIsInert() {
        var tracker = TCPFlowControlTracker()
        handshake(&tracker)
        let before = tracker
        #expect(tracker.ingest(
            direction: .bToA,
            facts: facts(seq: 5_001, ack: 1_001, flags: [.rst, .ack], window: 0),
            keepAlive: false
        ).isEmpty)
        #expect(tracker == before)
    }

    @Test("A payload length outside sequence space is ignored rather than trapped")
    func malformedLengthIsIgnored() {
        var tracker = TCPFlowControlTracker()
        handshake(&tracker)
        let before = tracker
        let bogus = TCPSegmentFacts(
            sequenceNumber: 5_001, acknowledgementNumber: 1_001, flags: [.ack], windowSize: 0,
            headerLength: 20, payloadSequence: 5_001, payloadLength: -1, options: TCPOptionFacts()
        )
        #expect(tracker.ingest(direction: .bToA, facts: bogus, keepAlive: false).isEmpty)
        #expect(tracker == before)
    }

    @Test("Replaying the same facts yields the same tracker and the same observations")
    func deterministicReplay() {
        func run() -> (TCPFlowControlTracker, [TCPFlowControlTracker.Observations]) {
            var tracker = TCPFlowControlTracker()
            var seen: [TCPFlowControlTracker.Observations] = []
            handshake(&tracker)
            seen.append(tracker.ingest(
                direction: .bToA,
                facts: facts(seq: 5_001, ack: 1_001, payload: 100),
                keepAlive: false
            ))
            seen.append(tracker.ingest(
                direction: .aToB,
                facts: facts(seq: 1_001, ack: 5_101, window: 0),
                keepAlive: false
            ))
            seen.append(tracker.ingest(
                direction: .aToB,
                facts: facts(seq: 1_001, ack: 5_101, window: 0),
                keepAlive: false
            ))
            seen.append(tracker.ingest(
                direction: .bToA,
                facts: facts(seq: 5_101, ack: 1_001, payload: 1),
                keepAlive: false
            ))
            return (tracker, seen)
        }
        let first = run()
        let second = run()
        #expect(first.0 == second.0)
        #expect(first.1 == second.1)
        #expect(first.1 == [[], [.zeroWindow], [.zeroWindow], [.zeroWindowProbe]])
    }

    // MARK: Private

    /// A validated three-way handshake with no window scaling: client ISN 1_000,
    /// server ISN 5_000, both windows 65_535.
    private func handshake(_ tracker: inout TCPFlowControlTracker) {
        _ = tracker.ingest(direction: .aToB, facts: facts(seq: 1_000, flags: [.syn]), keepAlive: false)
        _ = tracker.ingest(
            direction: .bToA,
            facts: facts(seq: 5_000, ack: 1_001, flags: [.syn, .ack]),
            keepAlive: false
        )
        _ = tracker.ingest(direction: .aToB, facts: facts(seq: 1_001, ack: 5_001), keepAlive: false)
    }

    private func facts(
        seq: UInt32,
        ack: UInt32 = 0,
        flags: TCPFlags = [.ack],
        payload: Int = 0,
        window: UInt16 = 65_535,
        shift: UInt8? = nil
    )
        -> TCPSegmentFacts
    {
        TCPSegmentFacts(
            sequenceNumber: seq,
            acknowledgementNumber: ack,
            flags: flags,
            windowSize: window,
            headerLength: 20,
            payloadSequence: flags.contains(.syn) ? seq &+ 1 : seq,
            payloadLength: payload,
            options: TCPOptionFacts(windowScaleRaw: shift, windowScale: shift)
        )
    }
}
