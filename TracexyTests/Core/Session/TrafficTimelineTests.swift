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

    // MARK: Private

    private func at(_ seconds: TimeInterval) -> Date {
        Date(timeIntervalSince1970: 1_700_000_000 + seconds)
    }
}
