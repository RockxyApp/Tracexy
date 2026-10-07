import AppKit
import Charts
import SwiftUI

// MARK: - TrafficRateGraphWindow

/// Statistics ▸ I/O Graph: the open capture's packets per second and bytes per
/// second over time, one interval per point, as Wireshark's I/O Graph opens with.
/// The interval can be widened to whole multiples of the slices the capture keeps;
/// pointing at the graph reads out one interval.
struct TrafficRateGraphWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let graph = TrafficRateGraph.compute(from: coordinator.trafficTimeline, requestedInterval: requestedInterval)
        Group {
            if let axis = graph.axis, graph.totalFrames > 0 {
                VStack(spacing: 0) {
                    charts(graph, axis: axis)
                        .padding(Theme.Metrics.spacingL)
                }
            } else {
                ContentUnavailableView(
                    "No Traffic to Graph",
                    systemImage: "chart.xyaxis.line",
                    description: Text("Open a capture or start capturing to see its traffic over time.")
                )
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                intervalPicker(graph.axis)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) { footer(graph) }
        .frame(minWidth: 620, minHeight: 380)
    }

    // MARK: Private

    /// Binary units, and "0 bytes" rather than "Zero KB" at the axis origin.
    private static let byteFormatter: ByteCountFormatter = {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        formatter.allowsNonnumericFormatting = false
        return formatter
    }()

    @State private var requestedInterval: TimeInterval = 1
    @State private var hoveredColumn: Int?
    @State private var notice: String?

    private func intervalPicker(_ axis: TrafficIntervalAxis?) -> some View {
        let options = axis?.availableIntervals ?? [requestedInterval]
        return Picker("Interval", selection: Binding(
            get: { axis?.interval ?? requestedInterval },
            set: { requestedInterval = $0 }
        )) {
            ForEach(options, id: \.self) { interval in
                Text(verbatim: TrafficIntervalAxis.intervalTitle(interval)).tag(interval)
            }
        }
        .pickerStyle(.menu)
        .fixedSize()
        .disabled(axis == nil)
        .help(intervalHelp(axis))
    }

    private func charts(_ graph: TrafficRateGraph, axis: TrafficIntervalAxis) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            rateChart(
                graph, axis: axis, title: "Packets/s", color: .blue,
                value: \.packetsPerSecond, format: Self.packetRate
            )
            rateChart(
                graph, axis: axis, title: "Bytes/s", color: .orange,
                value: \.bytesPerSecond, format: Self.byteRate
            )
        }
    }

    private func rateChart(
        _ graph: TrafficRateGraph,
        axis: TrafficIntervalAxis,
        title: LocalizedStringKey,
        color: Color,
        value: KeyPath<TrafficRateGraph.Column, Double>,
        format: @escaping (Double) -> String
    )
        -> some View
    {
        Chart {
            ForEach(graph.columns) { column in
                LineMark(
                    x: .value("Seconds", axis.offset(ofColumn: column.index)),
                    y: .value(title, column[keyPath: value])
                )
                .foregroundStyle(color)
                .interpolationMethod(.stepEnd)
            }
            if let hoveredColumn, graph.columns.indices.contains(hoveredColumn) {
                RuleMark(x: .value("Seconds", axis.offset(ofColumn: hoveredColumn)))
                    .foregroundStyle(.secondary)
            }
        }
        .chartXAxisLabel("Seconds since start")
        .chartYAxisLabel(title)
        .chartYAxis {
            AxisMarks { mark in
                AxisGridLine()
                AxisValueLabel {
                    if let number = mark.as(Double.self) {
                        Text(verbatim: format(number))
                    }
                }
            }
        }
        .chartOverlay { proxy in
            GeometryReader { geometry in
                Rectangle().fill(.clear).contentShape(Rectangle())
                    .onContinuousHover { phase in
                        switch phase {
                        case let .active(location):
                            guard let plot = proxy.plotFrame else {
                                hoveredColumn = nil
                                return
                            }
                            let origin = geometry[plot].origin
                            let seconds: Double? = proxy.value(atX: location.x - origin.x)
                            hoveredColumn = seconds.flatMap { axis.column(containing: axis.origin + $0) }
                        case .ended:
                            hoveredColumn = nil
                        }
                    }
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(title))
        .accessibilityValue(accessibilitySummary(graph, value: value, format: format))
    }

    private func footer(_ graph: TrafficRateGraph) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Text(summary(graph))
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            Spacer()
            if let notice {
                Text(notice).font(Theme.Typography.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Menu("Save Chart As") {
                ForEach(StatisticsImageFormat.allCases) { format in
                    Button(format.menuTitle) {
                        guard let axis = graph.axis else {
                            return
                        }
                        notice = StatisticsExport.saveImage(
                            exportedCharts(graph, axis: axis), size: CGSize(width: 860, height: 520), format: format,
                            suggestedName: "I/O Graph.\(format.fileExtension)"
                        )
                    }
                }
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .disabled(graph.axis == nil)
            .help("Save both graphs as an image")
            Button("Save as CSV…") {
                notice = StatisticsExport.saveText(graph.csv(), suggestedName: "I/O Graph.csv")
            }
            .disabled(graph.axis == nil)
            .help("Save every interval's frames, bytes and rates as comma-separated values")
        }
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    /// Both graphs as a saved image, titled.
    private func exportedCharts(_ graph: TrafficRateGraph, axis: TrafficIntervalAxis) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            Text("I/O Graph").font(Theme.Typography.surfaceTitle)
            charts(graph, axis: axis)
        }
        .padding(24)
    }

    private static func packetRate(_ value: Double) -> String {
        value.formatted(.number.precision(.fractionLength(0 ... 1)))
    }

    private static func byteRate(_ value: Double) -> String {
        byteFormatter.string(fromByteCount: Int64(max(0, value).rounded()))
    }

    private func intervalHelp(_ axis: TrafficIntervalAxis?) -> String {
        guard let axis else {
            return String(localized: "The interval each point covers")
        }
        let finest = TrafficIntervalAxis.intervalTitle(axis.resolution)
        return String(
            localized: "The interval each point covers. This capture keeps traffic in \(finest) slices, the finest interval."
        )
    }

    private func accessibilitySummary(
        _ graph: TrafficRateGraph,
        value: KeyPath<TrafficRateGraph.Column, Double>,
        format: (Double) -> String
    )
        -> String
    {
        let values = graph.columns.map { $0[keyPath: value] }
        let peak = values.max() ?? 0
        let average = values.isEmpty ? 0 : values.reduce(0, +) / Double(values.count)
        return String(localized: "\(graph.columns.count) intervals, peak \(format(peak)), average \(format(average))")
    }

    /// Where the pointer is, or else what the graph covers.
    private func summary(_ graph: TrafficRateGraph) -> String {
        guard let axis = graph.axis else {
            return String(localized: "No timed frames yet")
        }
        if let hoveredColumn, graph.columns.indices.contains(hoveredColumn) {
            let column = graph.columns[hoveredColumn]
            let start = axis.offset(ofColumn: hoveredColumn).formatted(.number.precision(.fractionLength(0 ... 3)))
            return String(localized: """
            At \(start) s: \(Self.packetRate(column.packetsPerSecond)) packets/s, \
            \(Self.byteRate(column.bytesPerSecond))/s
            """)
        }
        let interval = TrafficIntervalAxis.intervalTitle(axis.interval)
        if graph.untimedFrameCount > 0 {
            return String(localized: """
            \(graph.totalFrames.formatted()) frames in \(graph.columns.count.formatted()) intervals of \(interval); \
            \(graph.untimedFrameCount.formatted()) frames carry no capture time
            """)
        }
        return String(
            localized: "\(graph.totalFrames.formatted()) frames in \(graph.columns.count.formatted()) intervals of \(interval)"
        )
    }
}
