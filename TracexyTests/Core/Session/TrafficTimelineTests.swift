import Foundation
import SwiftUI
import Testing
@testable import Tracexy

// MARK: - TrafficTimelineTests

@Suite("Traffic timeline aggregation")
struct TrafficTimelineTests {
    // MARK: Internal

    @Test("An empty timeline renders nothing and reports nothing without trapping")
    func emptyTimeline() {
        let timeline = TrafficTimelineAccumulator().timeline()
        #expect(timeline.isEmpty)
        #expect(timeline.points().isEmpty)
        #expect(timeline.timedSpan == 0)
        #expect(timeline.bucketCount == 0)
        #expect(timeline.firstTimedFrame == nil)
        #expect(timeline == .empty)
    }

    @Test("Frames fold into one-second slices keyed by absolute time, split by direction")
    func directionalSlices() {
        var accumulator = TrafficTimelineAccumulator()
        accumulator.add(timestamp: at(0.2), originalLength: 100, direction: .sent)
        accumulator.add(timestamp: at(0.9), originalLength: 50, direction: .received)
        accumulator.add(timestamp: at(2.1), originalLength: 7, direction: .unattributed)
        let timeline = accumulator.timeline()

        #expect(timeline.totals.frames == 3)
        #expect(timeline.totals.bytes == 157)
        #expect(timeline.totals.sentBytes == 100)
        #expect(timeline.totals.receivedBytes == 50)
        #expect(timeline.totals.unattributedBytes == 7)
        #expect(timeline.bucketWidth == 1)
        #expect(timeline.bucketCount == 2)
        #expect(timeline.timedSpan == at(2.1).timeIntervalSince(at(0.2)))

        // The gap second is rendered as an explicit zero column, never skipped.
        let points = timeline.points()
        #expect(points.count == 3)
        #expect(points[0].date == at(0))
        #expect(points[0].totals.sentBytes == 100)
        #expect(points[0].totals.receivedBytes == 50)
        #expect(points[1].totals.isEmpty)
        #expect(points[2].date == at(2))
        #expect(points[2].totals.unattributedBytes == 7)
    }

    @Test("Untimed frames count toward the totals but never a slice or the span")
    func untimedFrames() {
        var accumulator = TrafficTimelineAccumulator()
        accumulator.add(timestamp: nil, originalLength: 60, direction: .sent)
        accumulator.add(timestamp: at(5), originalLength: 40, direction: .received)
        let timeline = accumulator.timeline()

        #expect(timeline.totals.frames == 2)
        #expect(timeline.totals.bytes == 100)
        #expect(timeline.untimedFrameCount == 1)
        #expect(timeline.timedSpan == 0)
        #expect(timeline.points().count == 1)
        #expect(timeline.points().first?.totals.bytes == 40)

        var untimedOnly = TrafficTimelineAccumulator()
        untimedOnly.add(timestamp: nil, originalLength: 1, direction: .sent)
        #expect(untimedOnly.timeline().points().isEmpty)
        #expect(!untimedOnly.timeline().isEmpty)
    }

    @Test("Out-of-order timestamps land in the right slice without shifting the axis")
    func outOfOrder() {
        var accumulator = TrafficTimelineAccumulator()
        accumulator.add(timestamp: at(10), originalLength: 1, direction: .sent)
        accumulator.add(timestamp: at(3), originalLength: 2, direction: .sent)
        let timeline = accumulator.timeline()

        #expect(timeline.firstTimedFrame == at(3))
        #expect(timeline.lastTimedFrame == at(10))
        let points = timeline.points()
        #expect(points.first?.date == at(3))
        #expect(points.first?.totals.bytes == 2)
        #expect(points.last?.date == at(10))
        #expect(points.last?.totals.bytes == 1)
        #expect(points.count == 8)
    }

    @Test("The bucket cap is honoured by doubling the width, conserving every byte")
    func boundedByDoubling() {
        var accumulator = TrafficTimelineAccumulator(maxBuckets: 4)
        for second in 0 ..< 40 {
            accumulator.add(timestamp: at(Double(second)), originalLength: 10, direction: .received)
        }
        let timeline = accumulator.timeline()

        #expect(timeline.bucketCount <= 4)
        #expect(timeline.bucketWidth == 16)
        #expect(timeline.totals.bytes == 400)
        #expect(timeline.points().reduce(0) { $0 + $1.totals.bytes } == 400)
        #expect(timeline.timedSpan == 39)
    }

    @Test("Rendering coalesces to the requested point count and keeps every byte")
    func renderedPointCap() {
        var accumulator = TrafficTimelineAccumulator()
        for second in 0 ..< 100 {
            accumulator.add(timestamp: at(Double(second)), originalLength: second, direction: .sent)
        }
        let timeline = accumulator.timeline()
        #expect(timeline.bucketCount == 100)

        let points = timeline.points(maxCount: 30)
        #expect(points.count <= 30)
        #expect(!points.isEmpty)
        #expect(points.reduce(0) { $0 + $1.totals.bytes } == (0 ..< 100).reduce(0, +))
        // Columns are evenly spaced at a power-of-two multiple of the bucket width.
        let widths = Set(zip(points, points.dropFirst()).map { $1.date.timeIntervalSince($0.date) })
        #expect(widths == [4])
    }

    @Test("The same frame sequence always yields the same timeline")
    func deterministic() {
        func build() -> TrafficTimeline {
            var accumulator = TrafficTimelineAccumulator(maxBuckets: 8)
            for index in 0 ..< 200 {
                accumulator.add(
                    timestamp: at(Double(index) * 1.7),
                    originalLength: (index * 37) % 101,
                    direction: index.isMultiple(of: 2) ? .sent : .received
                )
            }
            return accumulator.timeline()
        }
        let first = build()
        let second = build()
        #expect(first == second)
    }

    @Test("Reset drops every slice and total together")
    func reset() {
        var accumulator = TrafficTimelineAccumulator()
        accumulator.add(timestamp: at(1), originalLength: 5, direction: .sent)
        accumulator.reset()
        #expect(accumulator.timeline() == .empty)
    }

    @Test("Nearest-column hover resolves ties to the earlier column")
    func nearestDate() {
        let points = [at(0), at(2), at(4)].map { TrafficTimelinePoint(date: $0, totals: TrafficTotals()) }
        #expect(OverviewTrafficTimelineChart.nearestDate(to: at(0.9), in: points) == at(0))
        #expect(OverviewTrafficTimelineChart.nearestDate(to: at(1), in: points) == at(0))
        #expect(OverviewTrafficTimelineChart.nearestDate(to: at(3.2), in: points) == at(4))
        #expect(OverviewTrafficTimelineChart.nearestDate(to: at(9), in: points) == at(4))
        #expect(OverviewTrafficTimelineChart.nearestDate(to: at(1), in: []) == nil)
    }

    @Test("Finding markers are matched to the column that contains their evidence instant")
    func findingMarkersInColumn() {
        let markers = [
            OverviewFindingMarker(id: UUID(), date: at(3.5), severity: .warning, title: "A"),
            OverviewFindingMarker(id: UUID(), date: at(4), severity: .error, title: "B"),
            OverviewFindingMarker(id: UUID(), date: at(1), severity: .note, title: "C"),
        ]
        let inThree = OverviewTrafficTimelineChart.markers(markers, in: at(3), width: 1)
        #expect(inThree.map(\.title) == ["A"])
        let inFourWide = OverviewTrafficTimelineChart.markers(markers, in: at(2), width: 4)
        #expect(Set(inFourWide.map(\.title)) == ["A", "B"])
        // A single-instant capture has a zero-width column that still owns its instant.
        let instant = OverviewTrafficTimelineChart.markers(markers, in: at(1), width: 0)
        #expect(instant.map(\.title) == ["C"])
    }

    @Test("Finding markers past the cap are sampled across the whole list, deterministically")
    func findingMarkerSampling() throws {
        let all = Array(0 ..< 200)
        let sampled = OverviewView.sampled(all, limit: 64)
        #expect(sampled.count == 64)
        #expect(sampled.first == 0)
        #expect(try #require(sampled.last) >= 190)
        #expect(sampled == sampled.sorted())
        #expect(OverviewView.sampled(all, limit: 64) == sampled)
        #expect(OverviewView.sampled([1, 2, 3], limit: 64) == [1, 2, 3])
        #expect(OverviewView.sampled(all, limit: 0).isEmpty)
    }

    // MARK: Fold integration

    @Test("The common fold attributes every accepted frame once, by session client, batch and live alike")
    func foldAttributesFrames() async {
        let frames = ReplayCorpus.conversationCapturedFrames()
        let batch = SessionBuilder.buildDetailed(from: frames, linkType: LinkType.ethernet)
        let timeline = batch.trafficTimeline

        // Every frame is counted exactly once with its wire length.
        #expect(timeline.totals.frames == frames.count)
        #expect(timeline.totals.bytes == frames.reduce(0) { $0 + $1.originalLength })
        #expect(timeline.untimedFrameCount == 0)

        // Direction agrees with the per-session client/server split the summaries
        // publish; the corpus is fully timed, so the two must match byte for byte.
        let sentBySessions = batch.sessions.reduce(0) { $0 + $1.bytesUp }
        let receivedBySessions = batch.sessions.reduce(0) { $0 + $1.bytesDown }
        #expect(timeline.totals.sentBytes == sentBySessions)
        #expect(timeline.totals.receivedBytes == receivedBySessions)
        #expect(timeline.totals.unattributedBytes
            == timeline.totals.bytes - sentBySessions - receivedBySessions)
        #expect(timeline.totals.hasDirectionalBytes)

        // The live engine folds through the same accumulator and must agree.
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        await engine.ingest(Array(frames.prefix(5)), linkType: LinkType.ethernet, epoch: 1)
        await engine.ingest(Array(frames.dropFirst(5)), linkType: LinkType.ethernet, epoch: 1)
        let live = await engine.investigationSnapshot(epoch: 1)
        #expect(live?.trafficTimeline == timeline)
    }

    @Test("A server-first capture puts service bytes in the received timeline series")
    func serverFirstDirectionAgreesWithSession() throws {
        let server = PacketBuilder.ethernetIPv4(
            proto: 6, src: "93.184.216.34", dst: "10.0.0.5",
            payload: PacketBuilder.tcp(srcPort: 443, dstPort: 50_000, flags: 0x18, payload: [1, 2, 3, 4])
        )
        let client = PacketBuilder.ethernetIPv4(
            proto: 6, src: "10.0.0.5", dst: "93.184.216.34",
            payload: PacketBuilder.tcp(srcPort: 50_000, dstPort: 443, flags: 0x18, payload: [5])
        )
        let frames = [
            CapturedFrame(bytes: server, timestamp: at(1), originalLength: server.count),
            CapturedFrame(bytes: client, timestamp: at(2), originalLength: client.count),
        ]
        let result = SessionBuilder.buildDetailed(from: frames, linkType: LinkType.ethernet)
        let session = try #require(result.sessions.first)
        #expect(session.bytesDown == server.count)
        #expect(session.bytesUp == client.count)
        #expect(result.trafficTimeline.totals.receivedBytes == session.bytesDown)
        #expect(result.trafficTimeline.totals.sentBytes == session.bytesUp)
        #expect(result.trafficTimeline.points().first?.totals.receivedBytes == server.count)
    }

    @Test("A later SYN that changes orientation keeps exact totals without a false directional chart")
    func changedOrientationUsesTotalSeries() throws {
        let data = PacketBuilder.ethernetIPv4(
            proto: 6, src: "10.0.0.5", dst: "10.0.0.9",
            payload: PacketBuilder.tcp(srcPort: 8_080, dstPort: 40_000, flags: 0x18, payload: [1, 2])
        )
        let syn = PacketBuilder.ethernetIPv4(
            proto: 6, src: "10.0.0.5", dst: "10.0.0.9",
            payload: PacketBuilder.tcp(srcPort: 8_080, dstPort: 40_000, flags: 0x02, payload: [], sequence: 7)
        )
        let frames = [
            CapturedFrame(bytes: data, timestamp: at(1), originalLength: data.count),
            CapturedFrame(bytes: syn, timestamp: at(2), originalLength: syn.count),
        ]
        let result = SessionBuilder.buildDetailed(from: frames, linkType: LinkType.ethernet)
        let session = try #require(result.sessions.first)
        #expect(session.bytesUp == data.count + syn.count)
        #expect(result.trafficTimeline.totals.bytes == session.totalBytes)
        #expect(result.trafficTimeline.directionMayHaveChanged)
        #expect(!result.trafficTimeline.hasStableDirectionalBytes)
        #expect(result.trafficTimeline.points().reduce(0) { $0 + $1.totals.bytes } == session.totalBytes)
    }

    @Test("Resetting the accumulator empties the timeline with the tables")
    func accumulatorResetClearsTimeline() {
        var accumulator = SessionAccumulator()
        for frame in ReplayCorpus.conversationCapturedFrames() {
            let packet = SessionBuilder.decodePacket(frame, linkType: LinkType.ethernet)
            accumulator.add(
                packet,
                context: SessionFrameContext(capturedLength: frame.capturedLength, linkType: LinkType.ethernet)
            )
        }
        #expect(!accumulator.foldSnapshot().trafficTimeline.isEmpty)
        accumulator.reset()
        #expect(accumulator.foldSnapshot().trafficTimeline == .empty)
    }

    @Test("A scoped series lands on the same columns and sums to the scope's session bytes")
    func scopedSeriesMatchesSessions() throws {
        func frame(_ src: String, _ dst: String, _ sport: UInt16, _ dport: UInt16, _ size: Int, at seconds: Double)
            -> CapturedFrame
        {
            let bytes = PacketBuilder.ethernetIPv4(
                proto: 6, src: src, dst: dst,
                payload: PacketBuilder.tcp(
                    srcPort: sport, dstPort: dport, flags: 0x18, payload: [UInt8](repeating: 1, count: size)
                )
            )
            return CapturedFrame(bytes: bytes, timestamp: at(seconds), originalLength: bytes.count)
        }
        let frames = [
            frame("10.0.0.5", "192.0.2.1", 50_000, 443, 10, at: 0.1),
            frame("10.0.0.5", "192.0.2.2", 50_001, 443, 20, at: 0.5),
            frame("192.0.2.1", "10.0.0.5", 443, 50_000, 30, at: 3.2),
            frame("10.0.0.5", "192.0.2.2", 50_001, 443, 40, at: 5.9),
        ]
        let result = SessionBuilder.buildDetailed(from: frames, linkType: LinkType.ethernet)
        let first = try #require(result.sessions.first { $0.destinationEndpoint.hasPrefix("192.0.2.1") })
        let timeline = result.trafficTimeline
        #expect(timeline.sessionSeriesComplete)

        let all = timeline.points()
        let scoped = timeline.points(scope: [first.id])
        #expect(scoped.map(\.date) == all.map(\.date))
        #expect(scoped.reduce(0) { $0 + $1.totals.bytes } == first.totalBytes)
        // The scope never exceeds the capture-wide column it sits on.
        #expect(zip(scoped, all).allSatisfy { $0.totals.bytes <= $1.totals.bytes })
        // Both sessions together are every attributed byte.
        let both = timeline.points(scope: Set(result.sessions.map(\.id)))
        #expect(both.map(\.totals.bytes) == all.map(\.totals.bytes))
        #expect(timeline.points(scope: []).allSatisfy { $0.totals.bytes == 0 })
    }

    @Test("Widening the slices merges each session's buckets without losing bytes")
    func scopedSeriesSurvivesDoubling() {
        var accumulator = TrafficTimelineAccumulator(maxBuckets: 4)
        let session = UUID()
        for second in 0 ..< 20 {
            accumulator.add(
                timestamp: at(Double(second)), originalLength: 10, direction: .sent,
                sessionID: second.isMultiple(of: 2) ? session : nil
            )
        }
        let timeline = accumulator.timeline()
        #expect(timeline.bucketWidth > 1)
        #expect(timeline.points(scope: [session]).reduce(0) { $0 + $1.totals.bytes } == 100)
        #expect(timeline.points().reduce(0) { $0 + $1.totals.bytes } == 200)
    }

    @Test("The per-session bound is stated, and the capture-wide series stays exact")
    func scopedSeriesBound() {
        var accumulator = TrafficTimelineAccumulator(maxSessionEntries: 3)
        for second in 0 ..< 5 {
            accumulator.add(timestamp: at(Double(second)), originalLength: 10, direction: .sent, sessionID: UUID())
        }
        let timeline = accumulator.timeline()
        #expect(!timeline.sessionSeriesComplete)
        #expect(timeline.totals.bytes == 50)
        accumulator.reset()
        #expect(accumulator.timeline().sessionSeriesComplete)
        #expect(accumulator.timeline() == .empty)
    }

    @Test("Every measure reads the same totals: bytes, packets per direction, and bits per second per column")
    func measuresReadTheSameTotals() {
        var accumulator = TrafficTimelineAccumulator()
        accumulator.add(timestamp: at(0), originalLength: 1_000, direction: .sent)
        accumulator.add(timestamp: at(0.5), originalLength: 500, direction: .received)
        accumulator.add(timestamp: at(0.7), originalLength: 250, direction: .received)
        accumulator.add(timestamp: at(0.8), originalLength: 60, direction: .unattributed)
        let point = accumulator.timeline().points()[0]
        #expect(point.totals.sentFrames == 1)
        #expect(point.totals.receivedFrames == 2)
        #expect(TrafficMeasure.bytes.value(of: point.totals, columnWidth: 1) == 1_810)
        #expect(TrafficMeasure.packets.value(of: point.totals, columnWidth: 1) == 4)
        #expect(TrafficMeasure.packets.value(of: point.totals, part: .received, columnWidth: 1) == 2)
        #expect(TrafficMeasure.bitsPerSecond.value(of: point.totals, part: .sent, columnWidth: 2) == 4_000)
        #expect(TrafficMeasure.bitsPerSecond.value(of: point.totals, columnWidth: 0) == 0)
        // One decimal below 100 in the user's locale (4.0 or 4,0).
        #expect(TrafficMeasure.bitRate(4_000) == "\(4.0.formatted(.number.precision(.fractionLength(1)))) kb/s")
        #expect(TrafficMeasure.bitRate(950) == "950 b/s")
        #expect(TrafficMeasure.bitRate(123_456_789) == "123 Mb/s")
    }

    @Test("A scoped series carries each session's packets as well as its bytes, through a width doubling")
    func scopedSeriesCarriesPackets() {
        var accumulator = TrafficTimelineAccumulator(maxBuckets: 4)
        let session = UUID()
        for second in 0 ..< 20 {
            accumulator.add(
                timestamp: at(Double(second)), originalLength: 10, direction: .sent,
                sessionID: second.isMultiple(of: 2) ? session : nil
            )
        }
        let scoped = accumulator.timeline().points(scope: [session])
        #expect(scoped.reduce(0) { $0 + $1.totals.frames } == 10)
        #expect(scoped.reduce(0) { $0 + $1.totals.bytes } == 100)
    }

    // MARK: Private

    private func at(_ seconds: TimeInterval) -> Date {
        Date(timeIntervalSince1970: 1_700_000_000 + seconds)
    }
}
