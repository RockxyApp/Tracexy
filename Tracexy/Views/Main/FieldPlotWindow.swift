import AppKit
import Charts
import SwiftUI

// MARK: - FieldPlotWindow

/// Statistics ▸ Plot: a decode-tree field's numeric values over time, as Wireshark's
/// Plots window — dots or a line, a linear or logarithmic value axis, time from the
/// capture's start or from the first point. Pointing at the plot names the frame;
/// clicking goes to it.
struct FieldPlotWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        @Bindable var controller = controller
        content
            .toolbar {
                ToolbarItem(placement: .navigation) {
                    Toggle("Limit to Sessions in View", isOn: $controller.limitToSessionsInView)
                        .toggleStyle(.checkbox)
                        .help("Plot only the frames of the sessions the main window shows")
                }
                ToolbarItemGroup(placement: .primaryAction) {
                    Picker("Style", selection: $style) {
                        Text("Dots").tag(Style.dots)
                        Text("Line").tag(Style.line)
                    }
                    .pickerStyle(.segmented)
                    .help("Draw each value as a dot, or join them with a line")
                    fieldMenu
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            // The plot is fixed content rather than a scroll view, so it gains no
            // safe-area inset of its own and would sit under the footer's glass.
            .tracexyChromeContentClearance(
                edge: .bottom,
                length: Theme.Metrics.footerBarHeight + Theme.Glass.functionalBarVerticalInset * 2
            )
            .tracexySafeAreaBar(edge: .bottom) { footer }
            .frame(minWidth: 620, minHeight: 360)
            .task(id: RunKey(
                field: controller.field,
                limited: controller.limitToSessionsInView,
                project: coordinator.projectStore.activeProjectID,
                generation: coordinator.startGeneration
            )) {
                controller.run(from: coordinator)
            }
            .onDisappear { controller.cancel() }
    }

    /// The points drawn: on a logarithmic axis only positive values can be placed.
    static func drawable(_ points: [FieldPlot.Point], logarithmic: Bool) -> [FieldPlot.Point] {
        logarithmic ? points.filter { $0.value > 0 } : points
    }

    /// The point nearest `time`, for pointing and clicking.
    static func nearest(to time: Double, in points: [FieldPlot.Point]) -> FieldPlot.Point? {
        points.min { abs($0.time - time) < abs($1.time - time) }
    }

    // MARK: Private

    private enum Style: Hashable {
        case dots
        case line
    }

    /// Carries the Project and capture generation so switching either reloads
    /// this window instead of leaving it on the previous capture's figures.
    private struct RunKey: Hashable {
        let field: FieldKey?
        let limited: Bool
        let project: UUID
        let generation: Int
    }

    @State private var style = Style.dots
    @State private var isLogarithmic = false
    @State private var startsAtFirstPoint = false
    @State private var hovered: FieldPlot.Point?
    @State private var notice: String?
    /// The point the keyboard route is on, so going to a frame needs no pointer.
    @State private var navigationIndex = 0

    private var controller: FieldPlotController {
        FieldPlotController.shared
    }

    /// Where the pointer is, or else how many points there are and what was left out.
    private var summary: String {
        if let hovered {
            return String(localized: """
            Frame \(hovered.frame.formatted()): \(hovered.value.formatted()) at \(hovered.time
                .formatted(.number.precision(.fractionLength(3)))) s
            """)
        }
        guard let plot = controller.result else {
            return ""
        }
        var text = plot.points.count == 1 ? String(localized: "1 point")
            : String(localized: "\(plot.points.count.formatted()) points")
        if plot.isThinned {
            text =
                String(localized: "\(plot.points.count.formatted()) of \(plot.numericCount.formatted()) points shown")
        }
        if plot.nonNumericCount > 0 {
            text = String(localized: "\(text), \(plot.nonNumericCount.formatted()) not numeric")
        }
        return text
    }

    /// The points as the chart draws them, so the keyboard route and the plot agree
    /// on what point an index means.
    private var navigablePoints: [FieldPlot.Point] {
        Self.drawable(controller.result?.points ?? [], logarithmic: isLogarithmic)
    }

    /// Clamped on both sides: the result can shrink under a stored index.
    private var navigationBinding: Binding<Int> {
        Binding {
            min(max(0, navigationIndex), max(0, navigablePoints.count - 1))
        } set: { requested in
            let points = navigablePoints
            guard !points.isEmpty else {
                return
            }
            let index = min(max(0, requested), points.count - 1)
            navigationIndex = index
            hovered = points[index]
        }
    }

    private var navigationLabel: String {
        let position = (navigationBinding.wrappedValue + 1).formatted()
        return String(localized: "Point \(position) of \(navigablePoints.count.formatted())")
    }

    private var navigatedPoint: FieldPlot.Point? {
        let points = navigablePoints
        let index = min(max(0, navigationIndex), points.count - 1)
        return points.indices.contains(index) ? points[index] : nil
    }

    /// What VoiceOver reads for the plot as a whole, rather than one mark's coordinate.
    private var chartAccessibilityValue: String {
        guard let plot = controller.result, !plot.points.isEmpty else {
            return String(localized: "No points")
        }
        let points = navigablePoints
        guard let first = points.first, let last = points.last,
              let lowest = points.min(by: { $0.value < $1.value }),
              let highest = points.max(by: { $0.value < $1.value }) else
        {
            return String(localized: "No points")
        }
        return String(
            localized: """
            \(points.count.formatted()) points, \
            \(lowest.value.formatted()) to \(highest.value.formatted()), \
            over \((last.time - first.time).formatted(.number.precision(.fractionLength(3)))) seconds
            """
        )
    }

    private var csv: String {
        let lines = (controller.result?.points ?? [])
            .map { "\($0.frame),\(String(format: "%.6f", $0.time)),\($0.value)" }
        return (["Frame,Time (s),Value"] + lines).joined(separator: "\r\n") + "\r\n"
    }

    @ViewBuilder private var content: some View {
        if controller.field == nil {
            ContentUnavailableView(
                "Choose a Field",
                systemImage: "chart.xyaxis.line",
                description: Text(
                    "Right-click a numeric field in Layers and choose Plot Over Time, or pick one from the Field menu."
                )
            )
        } else if controller.isLoading {
            ProgressView("Reading values…")
                .controlSize(.small)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let error = controller.error {
            ContentUnavailableView("Plot Unavailable", systemImage: "chart.xyaxis.line", description: Text(error))
        } else if let plot = controller.result, !plot.points.isEmpty {
            chart(plot)
                .padding(Theme.Metrics.spacingL)
        } else if let field = controller.field {
            ContentUnavailableView(
                "Nothing to Plot",
                systemImage: "chart.xyaxis.line",
                description: Text("No frame in view carries a numeric \(field.title).")
            )
        }
    }

    private var fieldMenu: some View {
        let offered = ValueDistributionWindow.fields(in: coordinator.selectedSession?.decodedLayers ?? [])
        return Menu {
            if offered.isEmpty {
                Text("Select a session to choose among its fields")
            }
            ForEach(offered, id: \.self) { key in
                Button(key.title) { controller.field = key }
            }
            Divider()
            Toggle("Logarithmic Scale", isOn: $isLogarithmic)
            Toggle("Time From First Point", isOn: $startsAtFirstPoint)
        } label: {
            Label(controller.field?.title ?? String(localized: "Field"), systemImage: "list.bullet.rectangle")
                .labelStyle(.titleAndIcon)
        }
        .help("The field plotted, the value scale and where time starts")
    }

    private var footer: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Text(notice ?? summary)
                .lineLimit(1)
                .truncationMode(.tail)
            Spacer()
            if navigablePoints.count > 1 {
                Stepper(value: navigationBinding, in: 0 ... (navigablePoints.count - 1)) {
                    Text(navigationLabel).lineLimit(1)
                }
                .help("Choose a point with the keyboard or VoiceOver, then activate Show frame.")
            }
            if let navigatedPoint {
                Button("Show frame \(navigatedPoint.frame.formatted())") {
                    notice = coordinator.goToFrame(navigatedPoint.frame)
                }
                .help("Select frame \(navigatedPoint.frame.formatted()) in All Frames")
            }
            Button("Copy as CSV") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(csv, forType: .string)
            }
            .keyboardShortcut(.defaultAction)
            .disabled(controller.result?.points.isEmpty ?? true)
            Button("Save as CSV…") {
                notice = StatisticsExport.saveText(csv, suggestedName: "Plot.csv")
            }
            .disabled(controller.result?.points.isEmpty ?? true)
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    private func chart(_ plot: FieldPlot) -> some View {
        let points = Self.drawable(plot.points, logarithmic: isLogarithmic)
        let offset = startsAtFirstPoint ? points.first?.time ?? 0 : 0
        return Chart {
            ForEach(points) { point in
                switch style {
                case .dots:
                    PointMark(x: .value("Time", point.time - offset), y: .value(plot.key.name, point.value))
                        .symbolSize(18)
                case .line:
                    LineMark(x: .value("Time", point.time - offset), y: .value(plot.key.name, point.value))
                        .interpolationMethod(.linear)
                }
            }
            if let hovered {
                RuleMark(x: .value("Time", hovered.time - offset))
                    .foregroundStyle(.secondary)
                    .lineStyle(StrokeStyle(lineWidth: 1, dash: [3, 3]))
            }
        }
        .chartYScale(type: isLogarithmic ? .log : .linear)
        .chartXAxisLabel(startsAtFirstPoint ? "Seconds since the first point" : "Seconds since the capture began")
        .chartYAxisLabel(plot.key.title)
        .chartOverlay { proxy in
            GeometryReader { geometry in
                Rectangle().fill(.clear).contentShape(Rectangle())
                    .onContinuousHover { phase in
                        switch phase {
                        case let .active(location):
                            hovered = point(at: location, proxy: proxy, geometry: geometry, in: points, offset: offset)
                        case .ended:
                            hovered = nil
                        }
                    }
                    .onTapGesture { location in
                        if let point = point(
                            at: location,
                            proxy: proxy,
                            geometry: geometry,
                            in: points,
                            offset: offset
                        ) {
                            notice = coordinator.goToFrame(point.frame)
                        }
                    }
            }
        }
        // One element for the whole plot: each mark would otherwise be announced
        // on its own as a bare coordinate pair.
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("Plot of \(plot.key.title) over time"))
        .accessibilityValue(Text(chartAccessibilityValue))
    }

    private func point(
        at location: CGPoint,
        proxy: ChartProxy,
        geometry: GeometryProxy,
        in points: [FieldPlot.Point],
        offset: Double
    )
        -> FieldPlot.Point?
    {
        guard let frame = proxy.plotFrame.map({ geometry[$0] }) else {
            return nil
        }
        let x = location.x - frame.origin.x
        guard let time: Double = proxy.value(atX: x) else {
            return nil
        }
        return Self.nearest(to: time + offset, in: points)
    }
}
