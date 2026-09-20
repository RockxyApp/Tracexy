import Charts
import SwiftUI

// MARK: - OverviewFindingMarker

/// A typed finding pinned to the instant of its first cited frame, so "what
/// needs attention" sits on the same time axis as "what happened". Only findings
/// whose evidence carries a capture time can be placed; the rest stay in the
/// findings summary and are counted, never guessed onto the axis.
struct OverviewFindingMarker: Identifiable, Equatable {
    let id: UUID
    let date: Date
    let severity: Finding.Severity
    let title: String
}

// MARK: - OverviewTrafficTimelineChart

/// Wire bytes over real capture time, one series per session direction (or a
/// single total when nothing was attributed), with the scoped findings pinned
/// along the top of the plot. Hovering pins a rule to the nearest column and
/// reads its values exactly instead of estimating them against the axis.
struct OverviewTrafficTimelineChart: View {
    // MARK: Internal

    let timeline: TrafficTimeline
    /// The rendered columns, computed once by the caller and shared with the
    /// sibling charts on the same axis.
    let points: [TrafficTimelinePoint]
    var findingMarkers: [OverviewFindingMarker] = []

    var body: some View {
        let directional = timeline.hasStableDirectionalBytes
        let peak = Double(points.map(\.totals.bytes).max() ?? 0)
        Chart {
            ForEach(points) { point in
                if directional {
                    seriesMarks(at: point.date, bytes: point.totals.sentBytes, series: Self.sentSeries)
                    seriesMarks(at: point.date, bytes: point.totals.receivedBytes, series: Self.receivedSeries)
                } else {
                    seriesMarks(at: point.date, bytes: point.totals.bytes, series: Self.totalSeries)
                }
            }
            // Findings ride just above the traffic so they read as events on the
            // same clock; the y position is presentational, not a byte value.
            ForEach(findingMarkers) { marker in
                PointMark(x: .value("Finding time", marker.date), y: .value("Bytes", peak * 1.08))
                    .symbol(.diamond)
                    .symbolSize(34)
                    .foregroundStyle(marker.severity.tint)
            }
            if let hovered = hoveredPoint(in: points) {
                RuleMark(x: .value("Hovered time", hovered.date))
                    .foregroundStyle(.primary.opacity(0.25))
                    .lineStyle(StrokeStyle(lineWidth: 1, dash: [3, 3]))
                    .annotation(
                        position: .top,
                        overflowResolution: .init(x: .fit(to: .chart), y: .disabled)
                    ) {
                        OverviewChartCallout(
                            title: Self.timeFormat(hovered.date, width: renderedWidth(points)),
                            rows: calloutRows(for: hovered, directional: directional)
                                + findingCalloutRows(at: hovered.date, width: renderedWidth(points))
                        )
                    }
                ForEach(calloutRows(for: hovered, directional: directional)) { row in
                    PointMark(x: .value("Hovered time", hovered.date), y: .value("Hovered bytes", row.rawValue))
                        .foregroundStyle(row.color)
                        .symbolSize(44)
                }
            }
        }
        .chartForegroundStyleScale([
            Self.sentSeries: Theme.Traffic.sent,
            Self.receivedSeries: Theme.Traffic.received,
            Self.totalSeries: Color.accentColor,
        ])
        .chartLegend(.hidden)
        .chartXAxis {
            AxisMarks(values: .automatic(desiredCount: 5)) { value in
                AxisGridLine().foregroundStyle(.quaternary)
                AxisValueLabel {
                    if let date = value.as(Date.self) {
                        Text(Self.timeFormat(date, width: renderedWidth(points)))
                            .font(Theme.Typography.micro)
                    }
                }
                .foregroundStyle(.tertiary)
            }
        }
        .chartYAxis {
            AxisMarks(position: .leading, values: .automatic(desiredCount: 4)) { value in
                AxisGridLine().foregroundStyle(.quaternary)
                AxisValueLabel {
                    if let bytes = value.as(Double.self) {
                        Text(Self.byteString(bytes)).font(Theme.Typography.micro)
                    }
                }
                .foregroundStyle(.tertiary)
            }
        }
        .chartPlotStyle { plot in
            plot.background(.primary.opacity(0.02))
        }
        .chartOverlay { proxy in
            GeometryReader { geometry in
                Rectangle()
                    .fill(.clear)
                    .contentShape(Rectangle())
                    .onContinuousHover { phase in
                        switch phase {
                        case let .active(location):
                            guard let plotFrame = proxy.plotFrame else {
                                hoveredDate = nil
                                return
                            }
                            let plot = geometry[plotFrame]
                            guard plot.contains(location),
                                  let date = proxy.value(atX: location.x - plot.minX, as: Date.self) else
                            {
                                hoveredDate = nil
                                return
                            }
                            hoveredDate = Self.nearestDate(to: date, in: points)
                        case .ended:
                            hoveredDate = nil
                        }
                    }
            }
        }
        .accessibilityLabel(directional ? "Sent and received bytes over capture time" : "Bytes over capture time")
        .accessibilityValue(accessibilitySummary(points: points))
    }

    /// The column whose start is closest to `date`; ties resolve to the earlier
    /// column so a hover never flickers between two equally near neighbours.
    nonisolated static func nearestDate(to date: Date, in points: [TrafficTimelinePoint]) -> Date? {
        points.reduce(nil) { nearest, point -> Date? in
            guard let nearest else {
                return point.date
            }
            let current = abs(nearest.timeIntervalSince(date))
            let candidate = abs(point.date.timeIntervalSince(date))
            if candidate == current {
                return min(nearest, point.date)
            }
            return candidate < current ? point.date : nearest
        }
    }

    /// Findings whose first cited frame falls inside the column starting at
    /// `start`; the hover readout names them beside the bytes.
    nonisolated static func markers(
        _ markers: [OverviewFindingMarker],
        in start: Date,
        width: TimeInterval
    )
        -> [OverviewFindingMarker]
    {
        guard width > 0 else {
            return markers.filter { $0.date == start }
        }
        let end = start.addingTimeInterval(width)
        return markers.filter { $0.date >= start && $0.date < end }
    }

    // MARK: Private

    private static let sentSeries = "Sent"
    private static let receivedSeries = "Received"
    private static let totalSeries = "Total"

    @State private var hoveredDate: Date?

    private static func timeFormat(_ date: Date, width: TimeInterval) -> String {
        if width >= 60 {
            return date.formatted(.dateTime.hour().minute())
        }
        return date.formatted(.dateTime.hour().minute().second())
    }

    private static func byteString(_ bytes: Double) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(max(0, bytes)), countStyle: .binary)
    }

    @ChartContentBuilder
    private func seriesMarks(at date: Date, bytes: Int, series: String) -> some ChartContent {
        AreaMark(x: .value("Time", date), y: .value("Bytes", bytes), stacking: .unstacked)
            .foregroundStyle(by: .value("Direction", series))
            .interpolationMethod(.monotone)
            .opacity(0.12)
        LineMark(x: .value("Time", date), y: .value("Bytes", bytes))
            .foregroundStyle(by: .value("Direction", series))
            .interpolationMethod(.monotone)
            .lineStyle(StrokeStyle(lineWidth: 2.25, lineCap: .round, lineJoin: .round))
    }

    private func hoveredPoint(in points: [TrafficTimelinePoint]) -> TrafficTimelinePoint? {
        guard let hoveredDate else {
            return nil
        }
        return points.first { $0.date == hoveredDate }
    }

    private func calloutRows(for point: TrafficTimelinePoint, directional: Bool) -> [OverviewChartCalloutRow] {
        if directional {
            return [
                OverviewChartCalloutRow(
                    id: Self.sentSeries, title: Self.sentSeries,
                    value: Self.byteString(Double(point.totals.sentBytes)),
                    rawValue: point.totals.sentBytes, color: Theme.Traffic.sent
                ),
                OverviewChartCalloutRow(
                    id: Self.receivedSeries, title: Self.receivedSeries,
                    value: Self.byteString(Double(point.totals.receivedBytes)),
                    rawValue: point.totals.receivedBytes, color: Theme.Traffic.received
                ),
            ]
        }
        return [
            OverviewChartCalloutRow(
                id: Self.totalSeries, title: Self.totalSeries,
                value: Self.byteString(Double(point.totals.bytes)),
                rawValue: point.totals.bytes, color: .accentColor
            ),
        ]
    }

    private func findingCalloutRows(at start: Date, width: TimeInterval) -> [OverviewChartCalloutRow] {
        Self.markers(findingMarkers, in: start, width: width).prefix(3).map { marker in
            OverviewChartCalloutRow(
                id: marker.id.uuidString, title: marker.title, value: "",
                rawValue: 0, color: marker.severity.tint
            )
        }
    }

    /// Width of one rendered column; chooses whether the axis needs seconds.
    private func renderedWidth(_ points: [TrafficTimelinePoint]) -> TimeInterval {
        guard points.count >= 2 else {
            return timeline.bucketWidth
        }
        return points[1].date.timeIntervalSince(points[0].date)
    }

    private func accessibilitySummary(points: [TrafficTimelinePoint]) -> String {
        guard let peak = points.max(by: { $0.totals.bytes < $1.totals.bytes }) else {
            return "No timed traffic"
        }
        let peakText = "\(Self.byteString(Double(peak.totals.bytes))) at "
            + Self.timeFormat(peak.date, width: renderedWidth(points))
        let findings = findingMarkers.isEmpty ? "" : ", \(findingMarkers.count) findings marked"
        return "\(points.count) columns, peak \(peakText)\(findings)"
    }
}

// MARK: - OverviewProportionBar

/// A thin proportional fill over a track. Bounded to `0...1`; a zero fraction
/// shows the bare track rather than trapping.
struct OverviewProportionBar: View {
    let fraction: Double
    let tint: Color

    var body: some View {
        let clamped = min(max(fraction, 0), 1)
        GeometryReader { proxy in
            ZStack(alignment: .leading) {
                Capsule().fill(.quaternary.opacity(0.5))
                Capsule().fill(tint.gradient)
                    .frame(width: max(0, proxy.size.width * clamped))
            }
        }
        .frame(height: 6)
        .frame(maxWidth: .infinity)
        .accessibilityHidden(true)
    }
}

// MARK: - OverviewDirectionBar

/// Sent and received bytes laid end to end in one track, each scaled against
/// the same reference so rows compare to each other and the split within a row
/// shows its client/server balance.
struct OverviewDirectionBar: View {
    let sentFraction: Double
    let receivedFraction: Double

    var body: some View {
        GeometryReader { proxy in
            ZStack(alignment: .leading) {
                Capsule().fill(.quaternary.opacity(0.5))
                HStack(spacing: 0) {
                    Rectangle().fill(Theme.Traffic.sent)
                        .frame(width: max(0, proxy.size.width * min(max(sentFraction, 0), 1)))
                    Rectangle().fill(Theme.Traffic.received)
                        .frame(width: max(0, proxy.size.width * min(max(receivedFraction, 0), 1)))
                }
                .clipShape(Capsule())
            }
        }
        .frame(height: 6)
        .frame(maxWidth: .infinity)
        .accessibilityHidden(true)
    }
}

// MARK: - OverviewChartCalloutRow

struct OverviewChartCalloutRow: Identifiable {
    let id: String
    let title: String
    let value: String
    let rawValue: Int
    let color: Color
}

// MARK: - OverviewChartCallout

/// The small floating readout shown while hovering the activity chart.
struct OverviewChartCallout: View {
    let title: String
    let rows: [OverviewChartCalloutRow]

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            Text(title)
                .font(Theme.Typography.microEmphasis)
                .monospacedDigit()
            ForEach(rows) { row in
                HStack(spacing: Theme.Metrics.spacingS) {
                    StatusDot(row.color, size: 6)
                    Text(row.title).foregroundStyle(.secondary)
                    if !row.value.isEmpty {
                        Text(row.value).fontWeight(.semibold).monospacedDigit()
                    }
                }
                .font(Theme.Typography.micro)
            }
        }
        .padding(.horizontal, Theme.Metrics.spacingM)
        .padding(.vertical, Theme.Metrics.controlSpacing)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 7, style: .continuous)
                .stroke(.primary.opacity(Theme.Glass.neutralStrokeOpacity), lineWidth: 1)
        }
        .shadow(color: .black.opacity(0.12), radius: 4, y: 2)
        .fixedSize()
        .accessibilityHidden(true)
    }
}
