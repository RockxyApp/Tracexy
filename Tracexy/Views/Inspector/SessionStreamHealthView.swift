import Charts
import SwiftUI

// MARK: - SessionStreamHealthView

/// The TCP health charts for the selected session: sequence progress, throughput,
/// round trip and receive window, one at a time behind a segmented picker.
///
/// It sits under the measured response times, because "how long did that take"
/// answers one exchange while these answer the whole conversation. Every word, unit
/// and caveat comes from ``SessionStreamHealth`` so the claims are testable without a
/// window; this view draws marks, axes and the route into a frame only.
///
/// Every point is a frame. Hovering reads the nearest one exactly rather than against
/// the axis, and clicking the plot opens that frame in the evidence inspector — the
/// same `inspectCitation` route the response times use.
struct SessionStreamHealthView: View {
    // MARK: Internal

    let health: SessionStreamHealth
    let inspectFrame: (SessionFrameProvenance) -> Void

    var body: some View {
        if let chart = health.chart(for: selectedKind) {
            ContextInspectorTable(title: "TCP Health") {
                if health.charts.count > 1 {
                    ContextInspectorFullRow {
                        picker
                    }
                    Divider()
                }
                ContextInspectorFullRow {
                    VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
                        plot(chart)
                            .frame(height: 150)
                        legend(chart)
                        Text(chart.axisCaption)
                            .font(Theme.Typography.micro)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                if let caveat = chart.caveat {
                    Divider()
                    ContextInspectorFullRow {
                        note(caveat)
                    }
                }
                ForEach(Array(health.caveats.enumerated()), id: \.offset) { _, caveat in
                    Divider()
                    ContextInspectorFullRow {
                        note(caveat)
                    }
                }
            }
        }
    }

    // MARK: Private

    @State private var selectedKind: TCPStreamSeriesKind?
    @State private var hoveredDate: Date?

    /// The picker never holds a kind the current session cannot draw: reading falls
    /// back to the first available chart, exactly as ``SessionStreamHealth/chart(for:)``
    /// does, so switching sessions can never leave the panel blank.
    private var pickerSelection: Binding<TCPStreamSeriesKind> {
        Binding(
            get: { health.chart(for: selectedKind)?.kind ?? .sequence },
            set: { kind in
                selectedKind = kind
                hoveredDate = nil
            }
        )
    }

    /// Segments when the dock is wide enough for all of them; a pop-up menu
    /// otherwise, so the control never forces the dock wider than its column.
    private var picker: some View {
        ViewThatFits(in: .horizontal) {
            chartPicker.pickerStyle(.segmented)
            chartPicker.pickerStyle(.menu).fixedSize()
        }
        .labelsHidden()
        .controlSize(.small)
    }

    private var chartPicker: some View {
        Picker("Chart", selection: pickerSelection) {
            ForEach(health.charts) { chart in
                Text(chart.title).tag(chart.kind)
            }
        }
    }

    /// A caveat line. Never coloured as a severity: it states coverage, not a verdict.
    private func note(_ text: String) -> some View {
        Label(text, systemImage: "info.circle")
            .font(Theme.Typography.micro)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func plot(_ chart: SessionStreamChart) -> some View {
        Chart {
            ForEach(chart.lines) { line in
                marks(for: line, kind: chart.kind)
            }
            if let hovered = hoveredPoint(in: chart) {
                RuleMark(x: .value("Hovered time", hovered.date))
                    .foregroundStyle(.primary.opacity(0.25))
                    .lineStyle(StrokeStyle(lineWidth: 1, dash: [3, 3]))
                    .annotation(
                        position: .top,
                        overflowResolution: .init(x: .fit(to: .chart), y: .disabled)
                    ) {
                        OverviewChartCallout(
                            title: Self.timeLabel(hovered.date),
                            rows: calloutRows(for: chart, at: hovered.date)
                        )
                    }
            }
        }
        .chartLegend(.hidden)
        .chartXAxis {
            AxisMarks(values: .automatic(desiredCount: 4)) { value in
                AxisGridLine().foregroundStyle(.quaternary)
                AxisValueLabel {
                    if let date = value.as(Date.self) {
                        Text(Self.timeLabel(date)).font(Theme.Typography.micro)
                    }
                }
                .foregroundStyle(.tertiary)
            }
        }
        .chartYAxis {
            AxisMarks(position: .leading, values: .automatic(desiredCount: 4)) { value in
                AxisGridLine().foregroundStyle(.quaternary)
                AxisValueLabel {
                    if let number = value.as(Double.self), let role = chart.lines.first?.role {
                        Text(SessionStreamHealth.valueLabel(number, role: role))
                            .font(Theme.Typography.micro)
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
                            hoveredDate = date(at: location, proxy: proxy, geometry: geometry)
                        case .ended:
                            hoveredDate = nil
                        }
                    }
                    .onTapGesture { location in
                        guard let date = date(at: location, proxy: proxy, geometry: geometry),
                              let point = nearestPoint(in: chart, to: date),
                              let provenance = point.provenance else
                        {
                            return
                        }
                        inspectFrame(provenance)
                    }
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(chart.title) chart. \(chart.axisCaption)")
        .accessibilityValue(Self.accessibilityValue(for: chart))
    }

    /// A compact legend: the inspector column is too narrow for Swift Charts' own, and
    /// each line's phrase already names its direction by endpoint.
    @ViewBuilder
    private func legend(_ chart: SessionStreamChart) -> some View {
        if chart.lines.count > 1 {
            VStack(alignment: .leading, spacing: 2) {
                ForEach(chart.lines) { line in
                    HStack(spacing: Theme.Metrics.spacingS) {
                        StatusDot(Self.color(for: line), size: 6)
                        Text(line.label)
                            .font(Theme.Typography.micro)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
            }
        }
    }

    @ChartContentBuilder
    private func marks(for line: SessionStreamChartLine, kind: TCPStreamSeriesKind) -> some ChartContent {
        ForEach(line.points) { point in
            if kind == .roundTrip {
                PointMark(
                    x: .value("Time", point.date),
                    y: .value(line.label, point.value)
                )
                .symbolSize(24)
                .foregroundStyle(Self.color(for: line))
            } else {
                LineMark(
                    x: .value("Time", point.date),
                    y: .value(line.label, point.value),
                    series: .value("Series", line.id)
                )
                .interpolationMethod(.monotone)
                .lineStyle(Self.strokeStyle(for: line))
                .foregroundStyle(Self.color(for: line))
            }
        }
    }

    private func date(at location: CGPoint, proxy: ChartProxy, geometry: GeometryProxy) -> Date? {
        guard let plotFrame = proxy.plotFrame else {
            return nil
        }
        let plot = geometry[plotFrame]
        guard plot.contains(location) else {
            return nil
        }
        return proxy.value(atX: location.x - plot.minX, as: Date.self)
    }

    /// The point nearest the hovered instant across every line on this chart, so the
    /// readout names a frame that exists rather than a value read off the axis.
    private func nearestPoint(in chart: SessionStreamChart, to date: Date) -> TCPStreamPoint? {
        chart.lines
            .flatMap(\.points)
            .min { lhs, rhs in
                abs(lhs.date.timeIntervalSince(date)) < abs(rhs.date.timeIntervalSince(date))
            }
    }

    private func hoveredPoint(in chart: SessionStreamChart) -> TCPStreamPoint? {
        guard let hoveredDate else {
            return nil
        }
        return nearestPoint(in: chart, to: hoveredDate)
    }

    /// One readout row per line, each showing that line's own nearest point, so two
    /// lines are compared at the same instant instead of at one shared value.
    private func calloutRows(for chart: SessionStreamChart, at date: Date) -> [OverviewChartCalloutRow] {
        chart.lines.compactMap { line in
            guard let point = line.points.min(by: { lhs, rhs in
                abs(lhs.date.timeIntervalSince(date)) < abs(rhs.date.timeIntervalSince(date))
            }) else {
                return nil
            }
            return OverviewChartCalloutRow(
                id: "\(line.id)",
                title: line.label,
                value: SessionStreamHealth.valueLabel(point.value, role: line.role),
                rawValue: point.value,
                color: Self.color(for: line)
            )
        }
    }
}

// MARK: - Presentation constants

private extension SessionStreamHealthView {
    /// Colour carries the direction; the dash carries the role. Two adjacent cool hues
    /// keep the pair readable against each other and away from the protocol accents,
    /// and neither ever means "bad" — this panel grades nothing.
    static func color(for line: SessionStreamChartLine) -> Color {
        let base = line.direction == .aToB ? Theme.Traffic.sent : Theme.Traffic.received
        switch line.role {
        case .sequenceAcknowledged,
             .bytesInFlight:
            return base.opacity(0.55)
        default:
            return base
        }
    }

    static func strokeStyle(for line: SessionStreamChartLine) -> StrokeStyle {
        switch line.role {
        case .sequenceAcknowledged,
             .bytesInFlight:
            StrokeStyle(lineWidth: 1.5, dash: [3, 3])
        default:
            StrokeStyle(lineWidth: 1.5)
        }
    }

    static func timeLabel(_ date: Date) -> String {
        date.formatted(.dateTime.hour().minute().second())
    }

    /// What a screen reader is told instead of the marks: every line, its point count
    /// and the range it spans. A chart whose values cannot be read is not accessible
    /// just because its title is.
    static func accessibilityValue(for chart: SessionStreamChart) -> String {
        chart.lines.map { line in
            let values = line.points.map(\.value)
            guard let low = values.min(), let high = values.max() else {
                return "\(line.label), no points"
            }
            return "\(line.label), \(values.count.formatted()) points, "
                + "\(SessionStreamHealth.valueLabel(low, role: line.role)) to "
                + "\(SessionStreamHealth.valueLabel(high, role: line.role))"
        }
        .joined(separator: ". ")
    }
}
