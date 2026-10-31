import Foundation

// MARK: - TrafficGraphPaletteToken

/// Fixed color, symbol and dash identities keep series distinguishable without
/// relying on color alone. The view supplies the matching native chart styles.
nonisolated enum TrafficGraphPaletteToken: String, CaseIterable, Equatable, Sendable {
    case blue
    case vermillion
    case green
    case purple

    // MARK: Internal

    var lightRGB: UInt32 {
        switch self {
        case .blue: 0x0072B2
        case .vermillion: 0xC44E00
        case .green: 0x007A5A
        case .purple: 0x9D4E8A
        }
    }

    var darkRGB: UInt32 {
        switch self {
        case .blue: 0x56B4E9
        case .vermillion: 0xE69F00
        case .green: 0x66CCAA
        case .purple: 0xCC79A7
        }
    }

    var symbolName: String {
        switch self {
        case .blue: "circle.fill"
        case .vermillion: "square.fill"
        case .green: "diamond.fill"
        case .purple: "triangle.fill"
        }
    }

    var dashPattern: [Double] {
        switch self {
        case .blue: []
        case .vermillion: [6, 3]
        case .green: [2, 3]
        case .purple: [8, 3, 2, 3]
        }
    }
}

// MARK: - TrafficGraphSeriesDraft

/// Capture-local editable input. Editing a draft never changes an accepted scan.
nonisolated struct TrafficGraphSeriesDraft: Identifiable, Equatable, Sendable {
    // MARK: Lifecycle

    init(id: UUID = UUID(), name: String, expressionText: String, isEnabled: Bool = true) {
        self.id = id
        self.name = name
        self.expressionText = expressionText
        self.isEnabled = isEnabled
    }

    // MARK: Internal

    let id: UUID
    var name: String
    var expressionText: String
    var isEnabled: Bool
}

// MARK: - TrafficGraphComparisonConfiguration

/// An atomic, validated snapshot of one to four independently parsed expressions.
/// Disabled rows are validated too, but are not evaluated by the accumulator.
nonisolated struct TrafficGraphComparisonConfiguration: Equatable, Sendable {
    // MARK: Lifecycle

    init(validating drafts: [TrafficGraphSeriesDraft]) throws {
        guard (1 ... Self.maximumSeries).contains(drafts.count) else {
            throw ValidationError(rowID: nil, reason: "Use between one and four graph series.")
        }
        guard Set(drafts.map(\.id)).count == drafts.count else {
            throw ValidationError(rowID: nil, reason: "Each graph series must have a unique identity.")
        }
        var names: Set<String> = []
        var parsed: [Series] = []
        for (index, draft) in drafts.enumerated() {
            guard draft.name.utf8.count <= Self.maximumNameBytes else {
                throw ValidationError(rowID: draft.id, reason: "Keep the graph name within 320 UTF-8 bytes.")
            }
            guard draft.expressionText.utf8.count <= Self.maximumExpressionBytes else {
                throw ValidationError(rowID: draft.id, reason: "Enter a Frame Expression within 512 bytes.")
            }
            let name = draft.name.trimmingCharacters(in: .whitespacesAndNewlines)
            let text = draft.expressionText.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !name.isEmpty, name.count <= Self.maximumNameCharacters,
                  !name.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) else
            {
                throw ValidationError(
                    rowID: draft.id,
                    reason: "Use a name of 1–80 characters without control characters."
                )
            }
            guard names.insert(name.lowercased()).inserted else {
                throw ValidationError(rowID: draft.id, reason: "Use a different name for each graph series.")
            }
            guard !text.isEmpty, text.utf8.count <= Self.maximumExpressionBytes else {
                throw ValidationError(rowID: draft.id, reason: "Enter a Frame Expression within 512 bytes.")
            }
            var parser = FrameExpressionParser()
            let expression: FrameExpression
            do {
                expression = try parser.parse(text)
            } catch let error as FrameExpressionError {
                throw ValidationError(rowID: draft.id, reason: error.reason, position: error.position)
            }
            parsed.append(Series(
                id: draft.id, name: name, expressionText: text, isEnabled: draft.isEnabled,
                palette: TrafficGraphPaletteToken.allCases[index], expression: expression
            ))
        }
        series = parsed
    }

    // MARK: Internal

    struct Series: Identifiable, Equatable, Sendable {
        let id: UUID
        let name: String
        let expressionText: String
        let isEnabled: Bool
        let palette: TrafficGraphPaletteToken
        let expression: FrameExpression
    }

    struct ValidationError: Error, LocalizedError, Equatable, Sendable {
        // MARK: Lifecycle

        init(rowID: UUID?, reason: String, position: Int? = nil) {
            self.rowID = rowID
            self.reason = reason
            self.position = position
        }

        // MARK: Internal

        let rowID: UUID?
        let reason: String
        let position: Int?

        var errorDescription: String? {
            position.map { "\(reason) at character \($0)." } ?? reason
        }
    }

    static let maximumSeries = 4
    static let maximumNameCharacters = 80
    static let maximumNameBytes = 320
    static let maximumExpressionBytes = 512

    let series: [Series]
}

// MARK: - TrafficGraphComparisonSelection

/// Explicit Apply replaces the whole accepted configuration only after every row
/// validates. Source identity and scan publication guards belong to the caller.
nonisolated struct TrafficGraphComparisonSelection: Equatable, Sendable {
    private(set) var accepted: TrafficGraphComparisonConfiguration?
    private(set) var error: TrafficGraphComparisonConfiguration.ValidationError?

    @discardableResult
    mutating func apply(_ drafts: [TrafficGraphSeriesDraft]) -> Bool {
        do {
            let replacement = try TrafficGraphComparisonConfiguration(validating: drafts)
            accepted = replacement
            error = nil
            return true
        } catch let validation as TrafficGraphComparisonConfiguration.ValidationError {
            error = validation
        } catch {
            self.error = .init(rowID: nil, reason: "The graph expressions could not be parsed.")
        }
        return false
    }

    mutating func clear() {
        accepted = nil
        error = nil
    }
}

// MARK: - TrafficGraphSeriesCoverage

nonisolated struct TrafficGraphSeriesCoverage: Equatable, Sendable {
    let matchedFrames: Int
    let nonmatchingFrames: Int
    let unknownFrames: Int
    let untimedMatchingFrames: Int
    /// Original wire lengths, including untimed matches. Graph bytes contain only
    /// timed matches, so neither total silently stands in for the other.
    let matchedBytes: Int
}

// MARK: - TrafficGraphComparison

/// One immutable complete-scan snapshot. Overlapping series count independently;
/// totals across series must not be added as if they partitioned the capture.
nonisolated struct TrafficGraphComparison: Equatable, Sendable {
    struct Series: Identifiable, Equatable, Sendable {
        // MARK: Internal

        let definition: TrafficGraphComparisonConfiguration.Series
        /// The bounded aggregate supports changing interval without rescanning the source.
        let timeline: TrafficTimeline
        let graph: TrafficRateGraph
        /// Highest capture ordinal among timed matches in each rendered column.
        /// Nil means that column has no matching frame, not an unknown ordinal.
        let representativeFrameOrdinals: [UInt64?]
        /// Nil means disabled and unevaluated, never zero observed matches.
        let coverage: TrafficGraphSeriesCoverage?
        let retainedBucketCount: Int

        var retainedRepresentativeBucketCount: Int {
            representativeBuckets.count
        }

        var id: UUID {
            definition.id
        }

        // MARK: Fileprivate

        fileprivate let representativeBuckets: TrafficGraphRepresentativeBuckets
    }

    let axis: TrafficIntervalAxis?
    let series: [Series]
    let scannedFrames: Int
    let untimedCaptureFrames: Int
    /// Opaque identity of the stable saved/spooled source used for this scan.
    let sourceToken: UUID?

    var enabledSeries: [Series] {
        series.filter(\.definition.isEnabled)
    }

    /// Reproject retained aggregate buckets onto a different common interval.
    /// This is an in-memory operation; it never reopens the capture.
    func usingInterval(_ requestedInterval: TimeInterval) -> TrafficGraphComparison {
        let axis = series.first.flatMap { TrafficIntervalAxis.plan(for: $0.timeline, requested: requestedInterval) }
        let projected = series.map { item in
            TrafficGraphComparison.Series(
                definition: item.definition,
                timeline: item.timeline,
                graph: TrafficGraphComparisonAccumulator.graph(item.timeline, axis: axis),
                representativeFrameOrdinals: item.representativeBuckets.projected(on: axis),
                coverage: item.coverage,
                retainedBucketCount: item.retainedBucketCount,
                representativeBuckets: item.representativeBuckets
            )
        }
        return TrafficGraphComparison(
            axis: axis, series: projected, scannedFrames: scannedFrames, untimedCaptureFrames: untimedCaptureFrames,
            sourceToken: sourceToken
        )
    }

    func usingSourceToken(_ sourceToken: UUID) -> TrafficGraphComparison {
        TrafficGraphComparison(
            axis: axis, series: series, scannedFrames: scannedFrames, untimedCaptureFrames: untimedCaptureFrames,
            sourceToken: sourceToken
        )
    }

    /// Long-form rectangular CSV: one row per enabled series and interval. A
    /// wholly untimed capture still exports one coverage row per enabled series.
    func csv() -> String {
        let header = [
            "Series", "Frame Expression", "Interval start (s)", "Interval width (s)",
            "Frames", "Bytes", "Packets per second", "Bytes per second", "Scanned frames",
            "Matched frames", "Nonmatching frames", "Unknown frames", "Untimed capture frames",
            "Untimed matching frames", "Matched bytes including untimed",
        ]
        var rows = [AutomationExport.encodeRow(header)]
        for item in enabledSeries {
            guard let coverage = item.coverage else {
                continue
            }
            let prefix = [AutomationExport.spreadsheetSafe(item.definition.name), item.definition.expressionText]
            let suffix = [
                String(scannedFrames), String(coverage.matchedFrames), String(coverage.nonmatchingFrames),
                String(coverage.unknownFrames), String(untimedCaptureFrames),
                String(coverage.untimedMatchingFrames), String(coverage.matchedBytes),
            ]
            if let axis {
                for column in item.graph.columns {
                    let values = [
                        String(axis.offset(ofColumn: column.index)), String(axis.interval),
                        String(column.frames), String(column.bytes),
                        String(column.packetsPerSecond), String(column.bytesPerSecond),
                    ]
                    rows.append(AutomationExport.encodeRow(prefix + values + suffix))
                }
            } else {
                rows.append(AutomationExport.encodeRow(prefix + Array(repeating: "", count: 6) + suffix))
            }
        }
        return rows.joined(separator: "\r\n") + "\r\n"
    }
}

// MARK: - TrafficGraphComparisonAccumulator

/// A bounded fold consumed by one complete-source scanner. Every series observes
/// every timestamp, including disabled rows and false/unknown matches, so retained
/// resolutions and the final axis are identical. No rows or payloads are retained.
nonisolated struct TrafficGraphComparisonAccumulator: Sendable {
    // MARK: Lifecycle

    init(configuration: TrafficGraphComparisonConfiguration, maxBuckets: Int = Self.maximumBuckets) {
        self.configuration = configuration
        let bound = min(Self.maximumBuckets, max(2, maxBuckets))
        states = configuration.series.map { _ in
            State(
                accumulator: TrafficTimelineAccumulator(maxBuckets: bound, maxSessionEntries: 0),
                representatives: TrafficGraphRepresentativeBuckets(maxBuckets: bound)
            )
        }
    }

    // MARK: Internal

    static let maximumBuckets = 2_000

    mutating func record(_ row: CaptureFrameRow) {
        scannedFrames += 1
        if row.provenance.timestamp == nil {
            untimedCaptureFrames += 1
        }
        for index in states.indices {
            let definition = configuration.series[index]
            let truth = definition.isEnabled ? definition.expression.evaluate(row.filterFacts) : nil
            if truth == .yes {
                states[index].matchedFrames += 1
            }
            if truth == .no {
                states[index].nonmatchingFrames += 1
            }
            if truth == .unknown {
                states[index].unknownFrames += 1
            }
            states[index].representatives.record(
                timestamp: row.provenance.timestamp, ordinal: truth == .yes ? row.ordinal : nil
            )
            states[index].accumulator.add(
                timestamp: row.provenance.timestamp, originalLength: row.provenance.originalLength,
                direction: .unattributed, includesTraffic: truth == .yes
            )
        }
    }

    func result(requestedInterval: TimeInterval = 1) -> TrafficGraphComparison {
        let timelines = states.map { $0.accumulator.timeline() }
        let axis = timelines.first.flatMap { TrafficIntervalAxis.plan(for: $0, requested: requestedInterval) }
        let series = zip(configuration.series.indices, timelines).map { index, timeline in
            let definition = configuration.series[index]
            let state = states[index]
            return TrafficGraphComparison.Series(
                definition: definition, timeline: timeline, graph: Self.graph(timeline, axis: axis),
                representativeFrameOrdinals: state.representatives.projected(on: axis),
                coverage: definition.isEnabled ? TrafficGraphSeriesCoverage(
                    matchedFrames: state.matchedFrames, nonmatchingFrames: state.nonmatchingFrames,
                    unknownFrames: state.unknownFrames, untimedMatchingFrames: timeline.untimedFrameCount,
                    matchedBytes: timeline.totals.bytes
                ) : nil,
                retainedBucketCount: timeline.bucketCount,
                representativeBuckets: state.representatives
            )
        }
        return TrafficGraphComparison(
            axis: axis, series: series, scannedFrames: scannedFrames, untimedCaptureFrames: untimedCaptureFrames,
            sourceToken: nil
        )
    }

    // MARK: Fileprivate

    fileprivate static func graph(_ timeline: TrafficTimeline, axis: TrafficIntervalAxis?) -> TrafficRateGraph {
        guard let axis else {
            return TrafficRateGraph(axis: nil, columns: [], untimedFrameCount: timeline.untimedFrameCount)
        }
        var frames = [Int](repeating: 0, count: axis.columnCount)
        var bytes = [Int](repeating: 0, count: axis.columnCount)
        for point in timeline.points(maxCount: TrafficIntervalAxis.maximumBaseColumns) {
            guard let index = axis.column(containing: point.date) else {
                continue
            }
            frames[index] += point.totals.frames
            bytes[index] += point.totals.bytes
        }
        let columns = (0 ..< axis.columnCount).map { index in
            TrafficRateGraph.Column(
                index: index, start: axis.columnStart(index), frames: frames[index], bytes: bytes[index],
                packetsPerSecond: Double(frames[index]) / axis.interval,
                bytesPerSecond: Double(bytes[index]) / axis.interval
            )
        }
        return TrafficRateGraph(axis: axis, columns: columns, untimedFrameCount: timeline.untimedFrameCount)
    }

    // MARK: Private

    private struct State: Sendable {
        var accumulator: TrafficTimelineAccumulator
        var representatives: TrafficGraphRepresentativeBuckets
        var matchedFrames = 0
        var nonmatchingFrames = 0
        var unknownFrames = 0
    }

    private let configuration: TrafficGraphComparisonConfiguration
    private var states: [State]
    private var scannedFrames = 0
    private var untimedCaptureFrames = 0
}

// MARK: - TrafficGraphRepresentativeBuckets

/// Follows the traffic fold's absolute, power-of-two bucket alignment and observes
/// every timestamp, even when it has no representative. Retains one optional ordinal
/// per bucket, never a frame row, source locator, or payload. Merging by maximum
/// capture ordinal preserves capture order even when timestamps arrive out of order.
nonisolated private struct TrafficGraphRepresentativeBuckets: Equatable, Sendable {
    // MARK: Lifecycle

    init(maxBuckets: Int) {
        cap = min(TrafficGraphComparisonAccumulator.maximumBuckets, max(2, maxBuckets))
    }

    // MARK: Internal

    var count: Int {
        buckets.count
    }

    mutating func record(timestamp: Date?, ordinal: UInt64?) {
        guard let timestamp, timestamp.timeIntervalSince1970.isFinite else {
            return
        }
        var key = Self.key(for: timestamp, width: width)
        while buckets[key] == nil, buckets.count >= cap {
            width *= 2
            var merged: [Int64: Bucket] = [:]
            for (existingKey, bucket) in buckets {
                merged[existingKey >> 1, default: Bucket()].include(bucket.ordinal)
            }
            buckets = merged
            key = Self.key(for: timestamp, width: width)
        }
        buckets[key, default: Bucket()].include(ordinal)
    }

    func projected(on axis: TrafficIntervalAxis?) -> [UInt64?] {
        guard let axis else {
            return []
        }
        var result = [UInt64?](repeating: nil, count: axis.columnCount)
        for (key, bucket) in buckets {
            guard let ordinal = bucket.ordinal,
                  let index = axis.column(containing: Date(timeIntervalSince1970: Double(key) * width)) else
            {
                continue
            }
            result[index] = max(result[index] ?? ordinal, ordinal)
        }
        return result
    }

    // MARK: Private

    private struct Bucket: Equatable, Sendable {
        var ordinal: UInt64?

        mutating func include(_ candidate: UInt64?) {
            guard let candidate, candidate > 0 else {
                return
            }
            ordinal = max(ordinal ?? candidate, candidate)
        }
    }

    private let cap: Int
    private var width: TimeInterval = 1
    private var buckets: [Int64: Bucket] = [:]

    private static func key(for timestamp: Date, width: TimeInterval) -> Int64 {
        let position = (timestamp.timeIntervalSince1970 / width).rounded(.down)
        if position >= Double(Int64.max) {
            return Int64.max
        }
        if position <= Double(Int64.min) {
            return Int64.min
        }
        return Int64(position)
    }
}
