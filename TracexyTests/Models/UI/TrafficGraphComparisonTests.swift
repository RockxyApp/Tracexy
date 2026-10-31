import Foundation
import Testing
@testable import Tracexy

@Suite("I/O Graph comparison core")
struct TrafficGraphComparisonTests {
    // MARK: Internal

    @Test("Disjoint and overlapping expressions count independently on the same axis")
    func independentSeries() throws {
        let configuration = try configuration([
            ("Large", "frame.len >= 100"), ("Small", "frame.len < 100"), ("All", "frame.len >= 0"),
        ])
        var accumulator = TrafficGraphComparisonAccumulator(configuration: configuration)
        accumulator.record(row(1, time: at(0.1), length: 100))
        accumulator.record(row(2, time: at(1.1), length: 50))
        accumulator.record(row(3, time: at(3.1), length: 200))
        let result = accumulator.result()
        let axis = try #require(result.axis)

        #expect(axis.columnCount == 4)
        #expect(result.scannedFrames == 3)
        #expect(result.series.map(\.graph.axis) == Array(repeating: Optional(axis), count: 3))
        #expect(result.series[0].graph.columns.map(\.frames) == [1, 0, 0, 1])
        #expect(result.series[1].graph.columns.map(\.frames) == [0, 1, 0, 0])
        #expect(result.series[2].graph.columns.map(\.frames) == [1, 1, 0, 1])
        #expect(result.series.map { $0.coverage?.matchedFrames } == [2, 1, 3])
        #expect(result.series.map { $0.coverage?.nonmatchingFrames } == [1, 2, 0])
        #expect(result.series.map { $0.coverage?.matchedBytes } == [300, 50, 350])
        #expect(result.series[0].representativeFrameOrdinals == [1, nil, nil, 3])
        #expect(result.series[1].representativeFrameOrdinals == [nil, 2, nil, nil])
        #expect(result.series[2].representativeFrameOrdinals == [1, 2, nil, 3])
    }

    @Test("Interval changes reproject the bounded snapshot without rescanning")
    func intervalReprojection() throws {
        var accumulator = try TrafficGraphComparisonAccumulator(configuration: configuration([
            ("Large", "frame.len >= 100"), ("All", "frame.len >= 0"),
        ]))
        accumulator.record(row(1, time: at(0.1), length: 100))
        accumulator.record(row(2, time: at(1.1), length: 50))
        accumulator.record(row(3, time: at(3.1), length: 200))
        let original = accumulator.result(requestedInterval: 1)
        let wider = original.usingInterval(2)

        #expect(wider.scannedFrames == original.scannedFrames)
        #expect(wider.axis?.interval == 2)
        #expect(wider.series.allSatisfy { $0.graph.axis == wider.axis })
        #expect(wider.series.map(\.graph.totalFrames) == [2, 3])
        #expect(wider.series.map { $0.coverage?.matchedFrames } == [2, 3])
        #expect(original.axis?.interval == 1)
        #expect(wider.series[0].representativeFrameOrdinals == [1, 3])
        #expect(wider.series[1].representativeFrameOrdinals == [2, 3])
        #expect(wider.usingInterval(1).series.map(\.representativeFrameOrdinals)
            == original.series.map(\.representativeFrameOrdinals))
    }

    @Test("Unknown evaluations and untimed matches stay separate from no-match zero columns")
    func unknownAndUntimedCoverage() throws {
        var accumulator = try TrafficGraphComparisonAccumulator(configuration: configuration([
            ("Exact", "frame.len == 100"), ("No match", "frame.len == 999"),
        ]))
        accumulator.record(row(1, time: at(0.1), length: 100))
        accumulator.record(row(2, time: at(3.1), length: 200, known: false))
        accumulator.record(row(3, time: nil, length: 100))
        accumulator.record(row(4, time: nil, length: 200, known: false))
        let result = accumulator.result()
        let exact = try #require(result.series[0].coverage)
        let none = try #require(result.series[1].coverage)

        #expect(result.scannedFrames == 4)
        #expect(result.untimedCaptureFrames == 2)
        #expect(exact.matchedFrames == 2)
        #expect(exact.nonmatchingFrames == 0)
        #expect(exact.unknownFrames == 2)
        #expect(exact.untimedMatchingFrames == 1)
        #expect(exact.matchedBytes == 200)
        #expect(result.series[0].graph.totalFrames == 1)
        #expect(result.series[0].graph.totalBytes == 100)
        #expect(none.matchedFrames == 0)
        #expect(none.nonmatchingFrames == 2)
        #expect(none.unknownFrames == 2)
        #expect(result.series[1].graph.columns.map(\.frames) == [0, 0, 0, 0])
        #expect(result.series[1].graph.axis == result.axis)
        #expect(result.series[0].representativeFrameOrdinals == [1, nil, nil, nil])
        #expect(result.series[1].representativeFrameOrdinals == [nil, nil, nil, nil])
    }

    @Test("Disabled series remain unevaluated while all capture timestamps establish the axis")
    func disabledSeriesPreserveExtent() throws {
        let draft = TrafficGraphSeriesDraft(name: "Hidden", expressionText: "frame.len >= 0", isEnabled: false)
        var accumulator = try TrafficGraphComparisonAccumulator(configuration: .init(validating: [draft]))
        accumulator.record(row(1, time: at(0.1), length: 100, known: false))
        accumulator.record(row(2, time: at(3.1), length: 100))
        accumulator.record(row(3, time: nil, length: 100))
        let result = accumulator.result()

        #expect(result.axis?.columnCount == 4)
        #expect(result.scannedFrames == 3)
        #expect(result.untimedCaptureFrames == 1)
        #expect(result.series[0].coverage == nil)
        #expect(result.series[0].graph.columns.allSatisfy { $0.frames == 0 && $0.bytes == 0 })
        #expect(result.enabledSeries.isEmpty)
        #expect(result.series[0].representativeFrameOrdinals == [nil, nil, nil, nil])
        #expect(result.series[0].retainedRepresentativeBucketCount == result.series[0].retainedBucketCount)
        #expect(result.csv().components(separatedBy: "\r\n").count == 2)
    }

    @Test("Explicit Apply preserves the previous snapshot for any invalid draft")
    func invalidDraftPreservesAcceptedConfiguration() throws {
        let draft = TrafficGraphSeriesDraft(name: "Accepted", expressionText: "frame.len == 100")
        var selection = TrafficGraphComparisonSelection()
        let initialApply = selection.apply([draft])
        #expect(initialApply)
        let original = try #require(selection.accepted)
        var changed = draft
        changed.expressionText = "tcp.port =="
        #expect(selection.accepted == original)
        let invalidExpressionApply = selection.apply([changed])
        #expect(!invalidExpressionApply)
        #expect(selection.accepted == original)
        #expect(selection.error?.rowID == draft.id)
        #expect(selection.error?.position != nil)

        changed.expressionText = "frame.len == 200"
        changed.name = "  "
        let invalidNameApply = selection.apply([changed])
        #expect(!invalidNameApply)
        #expect(selection.accepted == original)
        let emptyApply = selection.apply([])
        #expect(!emptyApply)
        let tooManyApply = selection.apply((0 ..< 5).map {
            TrafficGraphSeriesDraft(name: "Series \($0)", expressionText: "frame.len == 100")
        })
        #expect(!tooManyApply)
        #expect(selection.accepted == original)
        changed.name = "Replacement"
        let replacementApply = selection.apply([changed])
        #expect(replacementApply)
        #expect(selection.error == nil)
        #expect(selection.accepted?.series.first?.expressionText == "frame.len == 200")
        selection.clear()
        #expect(selection.accepted == nil)
        #expect(selection.error == nil)
    }

    @Test("Names, identities and expressions are bounded, including disabled rows")
    func validatesEveryDraft() {
        let valid = TrafficGraphSeriesDraft(name: "First", expressionText: "frame.len == 100")
        let invalid = [
            TrafficGraphSeriesDraft(name: "first", expressionText: "frame.len == 200"),
            TrafficGraphSeriesDraft(name: "A\nB", expressionText: "frame.len == 100"),
            TrafficGraphSeriesDraft(name: String(repeating: "a", count: 81), expressionText: "frame.len == 100"),
            TrafficGraphSeriesDraft(
                name: "a" + String(repeating: "\u{301}", count: 200),
                expressionText: "frame.len == 100"
            ),
            TrafficGraphSeriesDraft(
                name: "Too long",
                expressionText: String(repeating: "not ", count: 130) + "tcp.syn"
            ),
            TrafficGraphSeriesDraft(name: "Invalid disabled", expressionText: "unsupported.field", isEnabled: false),
            TrafficGraphSeriesDraft(id: valid.id, name: "Duplicate ID", expressionText: "frame.len == 200"),
        ]
        for candidate in invalid {
            #expect(throws: TrafficGraphComparisonConfiguration.ValidationError.self) {
                _ = try TrafficGraphComparisonConfiguration(validating: [valid, candidate])
            }
        }
    }

    @Test("Four series get distinct color and non-color identities")
    func distinctPaletteTokens() throws {
        let configuration = try configuration((0 ..< 4).map { ("Series \($0)", "frame.len == \($0)") })
        #expect(Set(configuration.series.map(\.palette.rawValue)).count == 4)
        #expect(Set(configuration.series.map(\.palette.symbolName)).count == 4)
        #expect(Set(configuration.series.map(\.palette.lightRGB)).count == 4)
        #expect(Set(configuration.series.map(\.palette.darkRGB)).count == 4)
        #expect(Set(configuration.series.map(\.palette.dashPattern)).count == 4)
    }

    @Test("Adaptive coarsening preserves counts and one common resolution for sparse matches")
    func commonResolution() throws {
        var accumulator = try TrafficGraphComparisonAccumulator(
            configuration: configuration([("One", "frame.len == 1"), ("Two", "frame.len == 2")]),
            maxBuckets: 4
        )
        for index in (0 ..< 100).reversed() {
            accumulator.record(row(UInt64(index + 1), time: at(Double(index)), length: index.isMultiple(of: 2) ? 1 : 2))
        }
        let result = accumulator.result(requestedInterval: 1)
        let axis = try #require(result.axis)

        #expect(axis.resolution > 1)
        #expect(axis.interval >= axis.resolution)
        #expect(result.series.allSatisfy { $0.retainedBucketCount <= 4 && $0.graph.axis == axis })
        #expect(result.series.map(\.graph.totalFrames) == [50, 50])
        #expect(result.series.map(\.graph.totalBytes) == [50, 100])
        #expect(result.series[0].graph.columns.map(\.start) == result.series[1].graph.columns.map(\.start))
    }

    @Test("Caller overrides cannot exceed the retained or rendered 2,000 bucket bounds")
    func hardBucketBound() throws {
        var accumulator = try TrafficGraphComparisonAccumulator(
            configuration: configuration([("All", "frame.len >= 0"), ("None", "frame.len < 1")]),
            maxBuckets: Int.max
        )
        for index in 0 ..< 5_000 {
            accumulator.record(row(UInt64(index + 1), time: at(Double(index)), length: 10))
        }
        let result = accumulator.result()
        #expect(result.series.allSatisfy { $0.retainedBucketCount <= 2_000 && $0.graph.columns.count <= 2_000 })
        #expect(result.series.allSatisfy {
            $0.retainedRepresentativeBucketCount <= 2_000
                && $0.retainedRepresentativeBucketCount == $0.retainedBucketCount
                && $0.representativeFrameOrdinals.count == $0.graph.columns.count
        })
        #expect(result.series[1].representativeFrameOrdinals.allSatisfy { $0 == nil })
        #expect(result.series[0].representativeFrameOrdinals.compactMap { $0 }.max() == 5_000)
        #expect(result.series[0].graph.totalFrames == 5_000)
        #expect(result.series[0].graph.totalBytes == 50_000)
        #expect(result.series[1].graph.totalFrames == 0)
        #expect(result.series[0].graph.axis == result.series[1].graph.axis)
    }

    @Test("One comparison series agrees with the existing filtered graph fold")
    func singleSeriesCompatibility() throws {
        let configuration = try configuration([("Selected", "frame.len >= 100")])
        var comparison = TrafficGraphComparisonAccumulator(configuration: configuration)
        var existing = FilteredTrafficTimelineAccumulator(
            expression: configuration.series[0].expression,
            maxBuckets: 2_000
        )
        let rows = [
            row(1, time: at(0.1), length: 100), row(2, time: at(7.1), length: 20),
            row(3, time: nil, length: 200), row(4, time: at(12.1), length: 300, known: false),
        ]
        for row in rows {
            comparison.record(row)
            existing.record(row)
        }
        let expected = existing.result()
        let result = comparison.result(requestedInterval: 5)
        #expect(result.series[0].graph == TrafficRateGraph.compute(from: expected.timeline, requestedInterval: 5))
        #expect(result.series[0].coverage?.matchedFrames == expected.matchedFrames)
        #expect(result.series[0].coverage?.unknownFrames == expected.unknownFrames)
    }

    @Test("CSV quotes and formula-guards labels while retaining expressions and untimed coverage")
    func csvLabelsAndUntimedCoverage() throws {
        let labels = [" =SUM(1,2) \"peak\" ", "+plus", "-minus", "@at"]
        var accumulator = try TrafficGraphComparisonAccumulator(configuration: configuration(labels.map {
            ($0, "frame.len == 100")
        }))
        accumulator.record(row(1, time: nil, length: 100))
        let result = accumulator.result()
        let csv = result.csv()

        #expect(result.axis == nil)
        let hasNoRepresentativeFrames = result.series.allSatisfy(\.representativeFrameOrdinals.isEmpty)
        #expect(hasNoRepresentativeFrames)
        #expect(result.series.allSatisfy { $0.graph.columns.isEmpty && $0.coverage?.untimedMatchingFrames == 1 })
        #expect(csv.contains("\"'=SUM(1,2) \"\"peak\"\"\",frame.len == 100,"))
        for label in labels.dropFirst() {
            #expect(csv.contains("'\(label),frame.len == 100,"))
        }
        #expect(csv.components(separatedBy: "\r\n").count == 6)
        #expect(csv.contains(",1,1,0,0,1,1,100\r\n"))
    }

    @Test("An empty scan has no invented time axis and retains zero evaluated coverage")
    func emptyScan() throws {
        let accumulator = try TrafficGraphComparisonAccumulator(configuration: configuration([(
            "Empty",
            "frame.len >= 0"
        )]))
        let result = accumulator.result()
        #expect(result.axis == nil)
        #expect(result.scannedFrames == 0)
        #expect(result.series[0].coverage?.matchedFrames == 0)
        #expect(result.series[0].graph.columns.isEmpty)
        #expect(result.series[0].representativeFrameOrdinals.isEmpty)
        #expect(result.series[0].retainedRepresentativeBucketCount == 0)
        #expect(result.csv().components(separatedBy: "\r\n").count == 3)
    }

    @Test("Representatives use capture ordinal, not latest time or last evaluation order")
    func representativeCaptureOrder() throws {
        var accumulator = try TrafficGraphComparisonAccumulator(configuration: configuration([
            ("All", "frame.len >= 0"),
        ]))
        accumulator.record(row(2, time: at(0.9), length: 100))
        accumulator.record(row(9, time: at(0.1), length: 100))
        accumulator.record(row(4, time: at(0.8), length: 100))
        let result = accumulator.result()

        #expect(result.series[0].representativeFrameOrdinals == [9])
        #expect(result.series[0].graph.totalFrames == 3)
    }

    @Test("Stable source identity survives interval reprojection")
    func sourceTokenReprojection() throws {
        var accumulator = try TrafficGraphComparisonAccumulator(configuration: configuration([
            ("All", "frame.len >= 0"),
        ]))
        accumulator.record(row(1, time: at(0.5), length: 100))
        let sourceToken = UUID()
        let sourced = accumulator.result().usingSourceToken(sourceToken)

        #expect(sourced.sourceToken == sourceToken)
        #expect(sourced.usingInterval(2).sourceToken == sourceToken)
    }

    @Test("Boundary frames belong to exactly one half-open interval, including negative times")
    func representativeIntervalBoundaries() throws {
        var accumulator = try TrafficGraphComparisonAccumulator(configuration: configuration([
            ("All", "frame.len >= 0"),
        ]))
        for (index, time) in [-1.0, -0.25, 0.0, 0.75, 1.0, 2.0].enumerated() {
            accumulator.record(row(UInt64(index + 1), time: Date(timeIntervalSince1970: time), length: 10))
        }
        let result = accumulator.result()
        #expect(result.axis?.origin == Date(timeIntervalSince1970: -1))
        #expect(result.series[0].representativeFrameOrdinals == [2, 4, 5, 6])
        let wider = result.usingInterval(2)
        #expect(wider.axis?.origin == Date(timeIntervalSince1970: -2))
        #expect(wider.series[0].representativeFrameOrdinals == [2, 5, 6])
    }

    @Test("Repeated coarsening and reprojection retain the last matching ordinal in every column")
    func representativeCoarsening() throws {
        var accumulator = try TrafficGraphComparisonAccumulator(
            configuration: configuration([
                ("Odd", "frame.len == 1"), ("Even", "frame.len == 2"), ("All", "frame.len >= 0"),
            ]),
            maxBuckets: 4
        )
        // Capture ordinals increase while timestamps decrease across the Unix epoch.
        let rows = (0 ..< 257).map { index in
            row(
                UInt64(index + 1), time: Date(timeIntervalSince1970: Double(128 - index)),
                length: index.isMultiple(of: 2) ? 1 : 2
            )
        }
        for row in rows {
            accumulator.record(row)
        }
        let original = accumulator.result()
        #expect(try #require(original.axis).resolution >= 64)
        for result in [original, original.usingInterval(128), original.usingInterval(256)] {
            let axis = try #require(result.axis)
            for item in result.series {
                #expect(item.retainedRepresentativeBucketCount <= 4)
                #expect(item.retainedRepresentativeBucketCount == item.retainedBucketCount)
                #expect(item.representativeFrameOrdinals.count == item.graph.columns.count)
                var expected = [UInt64?](repeating: nil, count: axis.columnCount)
                for row in rows where item.definition.expression.evaluate(row.filterFacts) == .yes {
                    let timestamp = try #require(row.provenance.timestamp)
                    let column = try #require(axis.column(containing: timestamp))
                    expected[column] = max(expected[column] ?? row.ordinal, row.ordinal)
                }
                #expect(item.representativeFrameOrdinals == expected)
            }
        }
        #expect(original.usingInterval(256).usingInterval(1).series.map(\.representativeFrameOrdinals)
            == original.series.map(\.representativeFrameOrdinals))
    }

    // MARK: Private

    private func configuration(_ entries: [(String, String)]) throws -> TrafficGraphComparisonConfiguration {
        try TrafficGraphComparisonConfiguration(validating: entries.map {
            TrafficGraphSeriesDraft(name: $0.0, expressionText: $0.1)
        })
    }

    private func row(_ ordinal: UInt64, time: Date?, length: Int, known: Bool = true) -> CaptureFrameRow {
        var row = CaptureFrameRow(
            provenance: SessionFrameProvenance(
                ordinal: FrameOrdinal(rawValue: ordinal), timestamp: time,
                capturedLength: min(20, length), originalLength: length, linkType: LinkType.ethernet
            ),
            source: "", destination: "", protocolName: "", info: "", sessionID: nil,
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
