import Foundation
import Testing
@testable import Tracexy

@Suite("BoundedFrameBuffer (helper staging buffer)")
struct BoundedFrameBufferTests {
    @Test("Eviction bounds the buffer and increments an observable drop count")
    func evictionIncrementsDropCount() {
        var buffer = BoundedFrameBuffer<Int>(capacity: 3)
        buffer.append(contentsOf: [1, 2, 3])
        #expect(buffer.frames == [1, 2, 3])
        #expect(buffer.droppedCount == 0)

        buffer.append(contentsOf: [4, 5]) // evicts the two oldest
        #expect(buffer.frames == [3, 4, 5])
        #expect(buffer.droppedCount == 2)
    }

    @Test("Drop count is cumulative across drains, not reset by a drain")
    func dropCountIsCumulativeAcrossDrains() {
        var buffer = BoundedFrameBuffer<Int>(capacity: 2)
        buffer.append(contentsOf: [1, 2, 3, 4]) // drops 1, 2
        #expect(buffer.droppedCount == 2)

        let drained = buffer.drain()
        #expect(drained == [3, 4])
        #expect(buffer.frames.isEmpty)
        // A drain hands off frames but the loss total spans the whole capture.
        #expect(buffer.droppedCount == 2)

        buffer.append(contentsOf: [5, 6, 7]) // drops one more
        #expect(buffer.droppedCount == 3)
    }

    @Test("Reset zeroes both the frames and the cumulative count")
    func resetZeroesFramesAndCount() {
        var buffer = BoundedFrameBuffer<Int>(capacity: 1)
        buffer.append(contentsOf: [1, 2, 3])
        #expect(buffer.droppedCount == 2)

        buffer.reset()
        #expect(buffer.frames.isEmpty)
        #expect(buffer.droppedCount == 0)
    }

    @Test("Capacity is clamped to at least one frame")
    func capacityIsAtLeastOne() {
        var buffer = BoundedFrameBuffer<Int>(capacity: 0)
        buffer.append(contentsOf: [1, 2])
        #expect(buffer.capacity == 1)
        #expect(buffer.frames == [2])
        #expect(buffer.droppedCount == 1)
    }
}
