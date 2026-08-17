import Testing
@testable import Tracexy

@Suite("Bounded TCP stream reassembly")
struct TCPStreamReassemblerTests {
    @Test("In-order segments extend one contiguous prefix")
    func inOrder() {
        var stream = TCPStreamReassembler()
        #expect(stream.ingest(sequence: 100, payload: [1, 2]).contiguous == [1, 2])
        #expect(stream.ingest(sequence: 102, payload: [3, 4]).contiguous == [1, 2, 3, 4])
    }

    @Test("A gap buffers until the missing segment arrives")
    func outOfOrderGap() {
        var stream = TCPStreamReassembler()
        _ = stream.ingest(sequence: 100, payload: [1])
        let buffered = stream.ingest(sequence: 103, payload: [4])
        #expect(buffered.disposition == .buffered)
        #expect(buffered.contiguous == [1])
        #expect(stream.ingest(sequence: 101, payload: [2, 3]).contiguous == [1, 2, 3, 4])
    }

    @Test("Duplicate and overlapping retransmits emit no duplicate bytes")
    func retransmitsAndOverlap() {
        var stream = TCPStreamReassembler()
        _ = stream.ingest(sequence: 10, payload: [1, 2, 3])
        #expect(stream.ingest(sequence: 10, payload: [1, 2, 3]).disposition == .duplicate)
        #expect(stream.ingest(sequence: 12, payload: [3, 4, 5]).contiguous == [1, 2, 3, 4, 5])
    }

    @Test("Overlapping pending segments drain deterministically")
    func overlappingPending() {
        var stream = TCPStreamReassembler()
        _ = stream.ingest(sequence: 50, payload: [0])
        _ = stream.ingest(sequence: 54, payload: [4, 5])
        _ = stream.ingest(sequence: 53, payload: [3, 4])
        #expect(stream.ingest(sequence: 51, payload: [1, 2]).contiguous == [0, 1, 2, 3, 4, 5])
    }

    @Test("UInt32 sequence wrap preserves contiguous order")
    func sequenceWrap() {
        var stream = TCPStreamReassembler()
        _ = stream.ingest(sequence: UInt32.max - 1, payload: [1, 2])
        #expect(stream.ingest(sequence: 0, payload: [3, 4]).contiguous == [1, 2, 3, 4])
    }

    @Test("Buffered-byte overflow resets to a bounded new anchor")
    func byteCapacityReset() {
        var stream = TCPStreamReassembler(maxBufferedBytes: 8, maxPendingSegments: 8)
        _ = stream.ingest(sequence: 0, payload: [0, 1])
        let reset = stream.ingest(sequence: 100, payload: [2, 3, 4, 5, 6, 7, 8])
        #expect(reset.disposition == .reset)
        #expect(reset.contiguous.count <= 8)
        #expect(stream.didOverflow)
    }

    @Test("Pending segment count is bounded")
    func pendingCountReset() {
        var stream = TCPStreamReassembler(maxBufferedBytes: 64, maxPendingSegments: 2)
        _ = stream.ingest(sequence: 0, payload: [0])
        _ = stream.ingest(sequence: 10, payload: [1])
        _ = stream.ingest(sequence: 20, payload: [2])
        let reset = stream.ingest(sequence: 30, payload: [3])
        #expect(reset.disposition == .reset)
        #expect(reset.contiguous == [3])
    }

    @Test("Empty payload is a no-op")
    func emptyPayload() {
        var stream = TCPStreamReassembler()
        _ = stream.ingest(sequence: 42, payload: [1])
        let empty = stream.ingest(sequence: 43, payload: [])
        #expect(empty.disposition == .duplicate)
        #expect(empty.contiguous == [1])
    }
}
