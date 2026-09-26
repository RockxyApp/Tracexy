import Foundation
import Testing
@testable import Tracexy

@Suite("Statistics ▸ I/O Graph")
struct TrafficRateGraphTests {
    // MARK: Internal

    @Test("An empty capture has no axis and no columns")
    func emptyCapture() {
        let graph = TrafficRateGraph.compute(from: TrafficTimelineAccumulator().timeline(), requestedInterval: 1)
        #expect(graph.axis == nil)
        #expect(graph.columns.isEmpty)
        #expect(graph.csv() == "Interval start (s),Frames,Bytes,Packets per second,Bytes per second")
    }

    @Test("One-second intervals carry each second's frames and bytes, gaps as zero")
    func oneSecondColumns() throws {
        var accumulator = TrafficTimelineAccumulator()
        accumulator.add(timestamp: at(0.1), originalLength: 100, direction: .sent)
        accumulator.add(timestamp: at(0.8), originalLength: 60, direction: .received)
        accumulator.add(timestamp: at(3.5), originalLength: 40, direction: .sent)
        let graph = TrafficRateGraph.compute(from: accumulator.timeline(), requestedInterval: 1)
        let axis = try #require(graph.axis)

        #expect(axis.interval == 1)
        #expect(axis.resolution == 1)
        #expect(graph.columns.map(\.frames) == [2, 0, 0, 1])
        #expect(graph.columns.map(\.bytes) == [160, 0, 0, 40])
        #expect(graph.columns.map(\.packetsPerSecond) == [2, 0, 0, 1])
        #expect(graph.columns.map(\.bytesPerSecond) == [160, 0, 0, 40])
        #expect(graph.totalFrames == 3)
        #expect(graph.totalBytes == 200)
    }

    @Test("A wider interval sums whole slices and divides by its width")
    func widerInterval() throws {
        var accumulator = TrafficTimelineAccumulator()
        for second in 0 ..< 10 {
            accumulator.add(timestamp: at(Double(second) + 0.5), originalLength: 10, direction: .sent)
        }
        let graph = TrafficRateGraph.compute(from: accumulator.timeline(), requestedInterval: 5)
        let axis = try #require(graph.axis)

        #expect(axis.interval == 5)
        #expect(axis.availableIntervals.contains(1))
        #expect(axis.availableIntervals.contains(5))
        #expect(!axis.availableIntervals.contains(30))
        #expect(graph.columns.map(\.frames) == [5, 5])
        #expect(graph.columns.map(\.packetsPerSecond) == [1, 1])
        #expect(graph.columns.map(\.bytesPerSecond) == [10, 10])
    }

    @Test("A request finer than the kept slices snaps to the finest interval offered")
    func requestSnapsToResolution() throws {
        var accumulator = TrafficTimelineAccumulator(maxBuckets: 4)
        for second in 0 ..< 16 {
            accumulator.add(timestamp: at(Double(second)), originalLength: 1, direction: .sent)
        }
        let timeline = accumulator.timeline()
        let axis = try #require(TrafficIntervalAxis.plan(for: timeline, requested: 1))
        #expect(axis.resolution == timeline.bucketWidth)
        #expect(axis.interval == timeline.bucketWidth)
        #expect(axis.availableIntervals.allSatisfy { TrafficIntervalAxis.isWholeMultiple($0, of: axis.resolution) })
        let graph = TrafficRateGraph.compute(from: timeline, requestedInterval: 1)
        #expect(graph.totalFrames == 16)
    }

    @Test("Untimed frames are counted but plotted in no interval")
    func untimedFrames() {
        var accumulator = TrafficTimelineAccumulator()
        accumulator.add(timestamp: at(0.5), originalLength: 10, direction: .sent)
        accumulator.add(timestamp: nil, originalLength: 10, direction: .sent)
        let graph = TrafficRateGraph.compute(from: accumulator.timeline(), requestedInterval: 1)
        #expect(graph.totalFrames == 1)
        #expect(graph.untimedFrameCount == 1)
    }

    @Test("A long capture never plots more columns than the bound")
    func columnBound() throws {
        var accumulator = TrafficTimelineAccumulator()
        accumulator.add(timestamp: at(0), originalLength: 1, direction: .sent)
        accumulator.add(timestamp: at(100_000), originalLength: 1, direction: .sent)
        let axis = try #require(TrafficIntervalAxis.plan(for: accumulator.timeline(), requested: 1))
        #expect(axis.columnCount <= TrafficIntervalAxis.maximumColumns)
    }

    @Test("CSV has one row per interval with offsets from the first interval")
    func csvRows() {
        var accumulator = TrafficTimelineAccumulator()
        accumulator.add(timestamp: at(0.5), originalLength: 100, direction: .sent)
        accumulator.add(timestamp: at(1.5), originalLength: 50, direction: .sent)
        let lines = TrafficRateGraph.compute(from: accumulator.timeline(), requestedInterval: 1).csv()
            .split(separator: "\n")
        #expect(lines.count == 3)
        #expect(lines[1] == "0.000,1,100,1.0000,100.0000")
        #expect(lines[2] == "1.000,1,50,1.0000,50.0000")
    }

    @Test("Interval titles read as seconds, minutes and hours")
    func intervalTitles() {
        #expect(TrafficIntervalAxis.intervalTitle(1) == "1 s")
        #expect(TrafficIntervalAxis.intervalTitle(120) == "2 min")
        #expect(TrafficIntervalAxis.intervalTitle(3_600) == "1 h")
    }

    // MARK: Private

    private func at(_ seconds: Double) -> Date {
        Date(timeIntervalSince1970: 1_700_000_000 + seconds)
    }
}
