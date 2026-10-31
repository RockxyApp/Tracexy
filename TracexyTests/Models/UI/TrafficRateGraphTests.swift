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

    @Test("Filtered traffic distinguishes matches, nonmatches, unknowns and untimed frames")
    func filteredCoverageAndOriginalByteLengths() throws {
        var parser = FrameExpressionParser()
        var accumulator = try FilteredTrafficTimelineAccumulator(expression: parser.parse("frame.len >= 100"))
        accumulator.record(row(1, time: at(0), length: 50))
        accumulator.record(row(2, time: at(5), length: 200))
        accumulator.record(row(3, time: at(10), length: 300, known: false))
        accumulator.record(row(4, time: nil, length: 400))
        accumulator.record(row(5, time: nil, length: 10))
        let result = accumulator.result()
        let graph = TrafficRateGraph.compute(from: result.timeline, requestedInterval: 1)
        #expect(result.scannedFrames == 5)
        #expect(result.matchedFrames == 2)
        #expect(result.unknownFrames == 1)
        #expect(result.untimedCaptureFrames == 2)
        #expect(graph.untimedFrameCount == 1)
        #expect(graph.totalFrames == 1)
        #expect(graph.totalBytes == 200, "Use on-wire length, not the retained 20-byte prefix")
        #expect(graph.columns.count == 11)
        #expect(graph.columns[5].frames == 1)
        let csv = result.csv(graph: graph, expression: "frame.len >= 100")
        #expect(csv.contains("Frame Expression,Scanned frames,Matched frames,Unknown frames"))
        #expect(csv.contains("\"frame.len >= 100\",5,2,1,2,1\r\n"))
    }

    @Test("Zero matches still draw zero intervals across the original capture extent")
    func zeroMatchesPreserveAxis() throws {
        var parser = FrameExpressionParser()
        var accumulator = try FilteredTrafficTimelineAccumulator(expression: parser.parse("frame.len > 1000"))
        accumulator.record(row(1, time: at(10), length: 50))
        accumulator.record(row(2, time: at(-3), length: 50))
        let result = accumulator.result()
        let graph = TrafficRateGraph.compute(from: result.timeline, requestedInterval: 1)
        #expect(result.timeline.captureStartFrame == at(10))
        #expect(graph.axis?.origin == at(-3))
        #expect(graph.columns.count == 14)
        #expect(graph.columns.allSatisfy { $0.frames == 0 && $0.bytes == 0 })
        #expect(result.matchedFrames == 0)
    }

    @Test("An untimed-only filtered capture exports honest coverage without inventing an axis")
    func untimedFilteredCapture() throws {
        var parser = FrameExpressionParser()
        var accumulator = try FilteredTrafficTimelineAccumulator(expression: parser.parse("frame.len == 100"))
        accumulator.record(row(1, time: nil, length: 100))
        let result = accumulator.result()
        let graph = TrafficRateGraph.compute(from: result.timeline, requestedInterval: 1)
        #expect(graph.axis == nil)
        #expect(result.matchedFrames == 1)
        #expect(graph.untimedFrameCount == 1)
        #expect(result.csv(graph: graph, expression: "frame.len == 100")
            .contains(",,,,,\"frame.len == 100\",1,1,0,1,1\r\n"))
    }

    @Test("Filtered scans see beyond the retained page and apply the capture time correction")
    func scannerStreamsAllFramesWithCorrection() throws {
        let query = PacketBuilder.dnsQueryFrame(name: "example.test", src: "192.0.2.1", dst: "192.0.2.2")
        let reply = PacketBuilder.dnsResponseFrame(
            name: "example.test", answers: ["198.51.100.1"], src: "192.0.2.2", dst: "192.0.2.1"
        )
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("filtered-traffic-\(UUID()).pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        try PcapWriter.write(linkType: LinkType.ethernet, frames: [query, reply, query, reply].enumerated().map {
            CapturedFrame(bytes: $0.element, timestamp: at(Double($0.offset * 10)), originalLength: $0.element.count)
        }, to: url)
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let scanner = try CaptureFrameListScanner(
            contentsOf: url, expectedIdentity: identity, sourceToken: UUID(),
            configuration: .init(maxRetainedFrames: 1, timeCorrection: CaptureTimeCorrection(shiftBy: 1_000))
        )
        var parser = FrameExpressionParser()
        var accumulator = try FilteredTrafficTimelineAccumulator(expression: parser.parse("dns.response"))
        let list = try scanner.scan(onRow: { accumulator.record($0) })
        let result = accumulator.result()
        let graph = TrafficRateGraph.compute(from: result.timeline, requestedInterval: 10)
        #expect(list.rows.count == 1)
        #expect(list.completeness == .complete)
        #expect(result.scannedFrames == 4)
        #expect(result.matchedFrames == 2)
        #expect(result.unknownFrames == 0)
        #expect(result.timeline.captureStartFrame == at(1_000))
        #expect(graph.axis?.origin == at(1_000))
        #expect(graph.columns.map(\.frames) == [0, 1, 0, 1])
        #expect(graph.totalBytes == reply.count * 2)
    }

    // MARK: Private

    private func row(_ ordinal: UInt64, time: Date?, length: Int, known: Bool = true) -> CaptureFrameRow {
        var row = CaptureFrameRow(
            provenance: SessionFrameProvenance(
                ordinal: FrameOrdinal(rawValue: ordinal), timestamp: time,
                capturedLength: min(20, length), originalLength: length, linkType: LinkType.ethernet
            ),
            source: "", destination: "", protocolName: "", info: "frame.len >= 100", sessionID: nil,
            interfaceID: 0, hasComment: false
        )
        if known {
            row.filterFacts = FrameFilterFacts(
                packet: DecodedPacket(timestamp: time, originalLength: length), capturedLength: min(20, length)
            )
        }
        return row
    }

    private func at(_ seconds: Double) -> Date {
        Date(timeIntervalSince1970: 1_700_000_000 + seconds)
    }
}
