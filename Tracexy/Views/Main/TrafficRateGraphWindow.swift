import AppKit
import Charts
import SwiftUI

// MARK: - TrafficRateGraphWindow

/// Statistics ▸ I/O Graph keeps the unfiltered live graph available and compares
/// up to four independently filtered series from one stable capture scan.
struct TrafficRateGraphWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let key = scanKey
        let scannedComparison = resultKey == key ? comparisonResult : nil
        let comparison = scannedComparison?.usingInterval(requestedInterval)
        let graph = TrafficRateGraph.compute(
            from: selection.accepted == nil ? coordinator.trafficTimeline : .empty,
            requestedInterval: requestedInterval
        )
        let axis = selection.accepted == nil ? graph.axis : comparison?.axis
        Group {
            if selection.accepted != nil {
                comparisonContent(comparison, key: key)
            } else if let axis = graph.axis, graph.totalFrames > 0 {
                charts(graph, axis: axis).padding(Theme.Metrics.spacingL)
            } else {
                ContentUnavailableView(
                    "No Traffic to Graph", systemImage: "chart.xyaxis.line",
                    description: Text("Open a capture or start capturing to see its traffic over time.")
                )
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) { intervalPicker(axis) }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .top) { comparisonControls }
        .tracexySafeAreaBar(edge: .bottom) { footer(graph, comparison: comparison) }
        .frame(minWidth: 740, minHeight: 560)
        .task(id: key) { await scanComparison(key) }
        .onChange(of: coordinator.projectStore.activeProjectID) { _, _ in
            clearComparison(resetDrafts: true)
        }
        .onDisappear { scanRequestID &+= 1 }
    }

    // MARK: Private

    private struct ScanKey: Equatable {
        let configuration: TrafficGraphComparisonConfiguration?
        let projectID: UUID
        let generation: Int
        let savedURL: URL?
        let savedIdentity: PcapFileIdentity?
        let correction: CaptureTimeCorrection?
        let unavailableReason: String?
        let revision: Int
    }

    private static let byteFormatter: ByteCountFormatter = {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        formatter.allowsNonnumericFormatting = false
        return formatter
    }()

    @Environment(\.openWindow) private var openWindow

    @Environment(\.colorScheme) private var colorScheme
    @State private var requestedInterval: TimeInterval = 1
    @State private var hoveredColumn: Int?
    @State private var notice: String?
    @State private var drafts = [TrafficGraphSeriesDraft(name: "All traffic", expressionText: "frame.len >= 0")]
    @State private var selection = TrafficGraphComparisonSelection()
    @State private var comparisonResult: TrafficGraphComparison?
    @State private var resultKey: ScanKey?
    @State private var errorKey: ScanKey?
    @State private var scanError: String?
    @State private var scanRevision = 0
    @State private var scanRequestID = 0
    @State private var frameNavigationSeriesID: UUID?
    @State private var frameNavigationColumnIndex = 0

    private var scanKey: ScanKey {
        ScanKey(
            configuration: selection.accepted,
            projectID: coordinator.projectStore.activeProjectID, generation: coordinator.startGeneration,
            savedURL: coordinator.isViewingSavedCapture ? coordinator.savedCaptureEvidenceURL : nil,
            savedIdentity: coordinator.adoptedSavedCaptureIdentity,
            correction: coordinator.activeSavedCapture?.timeCorrection,
            unavailableReason: coordinator.allFramesUnavailableReason, revision: scanRevision
        )
    }

    private var comparisonControls: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            ForEach($drafts) { $draft in
                draftRow($draft)
            }
            HStack(spacing: Theme.Metrics.spacingM) {
                Button("Add Series", systemImage: "plus") { addDraft() }
                    .disabled(drafts.count >= TrafficGraphComparisonConfiguration.maximumSeries)
                Spacer()
                Button("Show All Traffic") { clearComparison() }
                    .disabled(selection.accepted == nil && selection.error == nil)
                    .help("Return to the unfiltered graph, including live traffic. Keep the series drafts.")
                Button("Apply Comparison") { applyComparison() }
                    .disabled(coordinator.isCapturing || coordinator.isStarting)
            }
            if let comparison = comparisonResult, resultKey == scanKey, !comparison.enabledSeries.isEmpty {
                Picker("Frame navigation series", selection: $frameNavigationSeriesID) {
                    ForEach(comparison.enabledSeries) { series in
                        Text(series.definition.name).tag(Optional(series.id))
                    }
                }
                .frame(maxWidth: 260, alignment: .leading)
                .help("A chart click selects the matching frame from this series in the hovered interval.")
                if let axis = comparison.axis, axis.columnCount > 0 {
                    Stepper(value: frameNavigationColumn(axis.columnCount), in: 0 ... axis.columnCount - 1) {
                        Text(navigationIntervalLabel(axis: axis))
                    }
                    .help("Choose an interval with the keyboard or VoiceOver, then activate Show frame in its series.")
                }
            }
            if let error = selection.error {
                Text(error.errorDescription ?? error.reason)
                    .foregroundStyle(.red)
                    .accessibilityLabel("Invalid graph comparison: \(error.errorDescription ?? error.reason)")
            }
            Text(selection.accepted == nil
                ? "Showing all capture traffic. Apply the series to compare a saved or fully stopped capture."
                : "Showing the applied series. Draft changes take effect together when you apply them.")
            if coordinator.isCapturing || coordinator.isStarting {
                Text("Stop the live capture before applying a comparison.")
            }
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    private func draftRow(_ draft: Binding<TrafficGraphSeriesDraft>) -> some View {
        let value = draft.wrappedValue
        let index = drafts.firstIndex(where: { $0.id == value.id }) ?? 0
        let palette = TrafficGraphPaletteToken.allCases[min(index, TrafficGraphPaletteToken.allCases.count - 1)]
        return HStack(spacing: Theme.Metrics.spacingS) {
            Toggle("Enabled", isOn: draft.isEnabled)
                .labelsHidden()
                .toggleStyle(.checkbox)
                .accessibilityLabel("Enable graph series \(index + 1)")
            Image(systemName: palette.symbolName)
                .foregroundStyle(seriesColor(palette))
                .frame(width: 16)
                .accessibilityHidden(true)
            TextField("Series name", text: draft.name)
                .textFieldStyle(.roundedBorder)
                .frame(width: 145)
                .accessibilityLabel("Graph series \(index + 1) name")
            TextField("Frame Expression", text: draft.expressionText, prompt: Text("dns.response or tcp.flags.reset"))
                .textFieldStyle(.roundedBorder)
                .onSubmit { applyComparison() }
                .accessibilityLabel("Graph series \(index + 1) Frame Expression")
            Button {
                drafts.removeAll { $0.id == value.id }
            } label: {
                Image(systemName: "minus.circle")
            }
            .disabled(drafts.count <= 1)
            .accessibilityLabel("Remove graph series \(index + 1)")
            .help("Remove this draft series; apply to update the graph")
        }
    }

    @ViewBuilder
    private func comparisonContent(_ comparison: TrafficGraphComparison?, key: ScanKey) -> some View {
        if errorKey == key, let scanError {
            ContentUnavailableView(
                "Comparison Unavailable", systemImage: "chart.xyaxis.line", description: Text(scanError)
            )
        } else if let comparison {
            ScrollView {
                VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
                    comparisonLegend(comparison)
                    if comparison.enabledSeries.isEmpty {
                        ContentUnavailableView(
                            "All Series Disabled", systemImage: "chart.xyaxis.line",
                            description: Text("Enable a series in the draft and apply the comparison to draw it.")
                        )
                    } else if let axis = comparison.axis {
                        comparisonCharts(comparison, axis: axis)
                    } else {
                        ContentUnavailableView(
                            "No Timed Frames", systemImage: "clock",
                            description: Text("Matching untimed frames are counted above and included in CSV coverage.")
                        )
                    }
                }
                .padding(Theme.Metrics.spacingL)
            }
        } else {
            ProgressView("Scanning capture for graph series…")
                .controlSize(.small)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func intervalPicker(_ axis: TrafficIntervalAxis?) -> some View {
        let options = axis?.availableIntervals ?? [requestedInterval]
        return Picker("Interval", selection: Binding(
            get: { axis?.interval ?? requestedInterval },
            set: {
                hoveredColumn = nil
                requestedInterval = $0
            }
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

    private func charts(_ graph: TrafficRateGraph, axis: TrafficIntervalAxis, exported: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            rateChart(
                graph, axis: axis, title: "Packets/s", color: .blue,
                value: \.packetsPerSecond, format: Self.packetRate, exported: exported
            )
            rateChart(
                graph, axis: axis, title: "Bytes/s", color: .orange,
                value: \.bytesPerSecond, format: Self.byteRate, exported: exported
            )
        }
    }

    private func rateChart(
        _ graph: TrafficRateGraph,
        axis: TrafficIntervalAxis,
        title: LocalizedStringKey,
        color: Color,
        value: KeyPath<TrafficRateGraph.Column, Double>,
        format: @escaping (Double) -> String,
        exported: Bool
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
            hoverMark(axis, exported: exported)
        }
        .chartXAxisLabel("Seconds since start")
        .chartYAxisLabel(title)
        .chartYAxis { rateAxis(format: format) }
        .chartOverlay { proxy in hoverOverlay(proxy: proxy, axis: axis, exported: exported, comparison: nil) }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(title))
        .accessibilityValue(accessibilitySummary(graph, value: value, format: format))
    }

    private func comparisonCharts(
        _ comparison: TrafficGraphComparison, axis: TrafficIntervalAxis, exported: Bool = false
    )
        -> some View
    {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            comparisonChart(
                comparison, axis: axis, title: "Packets/s", value: \.packetsPerSecond,
                format: Self.packetRate, exported: exported
            )
            comparisonChart(
                comparison, axis: axis, title: "Bytes/s", value: \.bytesPerSecond,
                format: Self.byteRate, exported: exported
            )
        }
    }

    private func comparisonChart(
        _ comparison: TrafficGraphComparison,
        axis: TrafficIntervalAxis,
        title: LocalizedStringKey,
        value: KeyPath<TrafficRateGraph.Column, Double>,
        format: @escaping (Double) -> String,
        exported: Bool
    )
        -> some View
    {
        Chart {
            ForEach(comparison.enabledSeries) { series in
                comparisonMarks(series, axis: axis, title: title, value: value, exported: exported)
            }
            hoverMark(axis, exported: exported)
        }
        .chartXScale(domain: 0 ... axis.span)
        .chartXAxisLabel("Seconds since start")
        .chartYAxisLabel(title)
        .chartYAxis { rateAxis(format: format) }
        .chartOverlay { proxy in
            hoverOverlay(proxy: proxy, axis: axis, exported: exported, comparison: comparison)
        }
        .frame(height: exported ? 190 : 180)
        .overlay(alignment: .topLeading) {
            if !exported {
                comparisonHoverReadout(comparison, axis: axis, value: value, format: format)
                    .padding(8)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(title))
        .accessibilityValue(comparisonAccessibilitySummary(comparison, value: value, format: format))
    }

    private func hoverOverlay(
        proxy: ChartProxy, axis: TrafficIntervalAxis, exported: Bool,
        comparison: TrafficGraphComparison?
    )
        -> some View
    {
        GeometryReader { geometry in
            Rectangle().fill(.clear).contentShape(Rectangle())
                .allowsHitTesting(!exported)
                .gesture(SpatialTapGesture().onEnded { tap in
                    guard !exported, let comparison,
                          let column = graphColumn(at: tap.location, proxy: proxy, geometry: geometry, axis: axis) else
                    {
                        return
                    }
                    hoveredColumn = column
                    frameNavigationColumnIndex = column
                    showFrame(for: comparison, column: column)
                })
                .onContinuousHover { phase in
                    guard !exported else {
                        return
                    }
                    switch phase {
                    case let .active(location):
                        hoveredColumn = graphColumn(at: location, proxy: proxy, geometry: geometry, axis: axis)
                        if let hoveredColumn {
                            frameNavigationColumnIndex = hoveredColumn
                        }
                    case .ended:
                        if comparison == nil {
                            hoveredColumn = nil
                        }
                    }
                }
        }
    }

    private func comparisonLegend(_ comparison: TrafficGraphComparison, exported: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            Text(comparisonSummary(comparison))
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
            ForEach(comparison.series) { series in
                HStack(alignment: .top, spacing: Theme.Metrics.spacingS) {
                    Image(systemName: series.definition.palette.symbolName)
                        .foregroundStyle(seriesColor(series.definition.palette, exported: exported))
                        .frame(width: 18)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(series.definition.name).font(Theme.Typography.captionMedium)
                        Text(series.definition.expressionText)
                            .font(Theme.Typography.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(exported ? nil : 2)
                            .help(series.definition.expressionText)
                        Text(coverageText(series.coverage))
                            .font(Theme.Typography.caption)
                            .foregroundStyle(.secondary)
                        if !exported, let hoveredColumn, series.coverage != nil,
                           series.graph.columns.indices.contains(hoveredColumn)
                        {
                            Text(summary(series.graph))
                                .font(Theme.Typography.captionMedium)
                        }
                        if !exported, let column = navigationColumn(in: comparison),
                           series.representativeFrameOrdinals.indices.contains(column),
                           let ordinal = series.representativeFrameOrdinals[column]
                        {
                            Button("Show frame \(ordinal.formatted())") {
                                requestFrameNavigation(ordinal: ordinal, comparison: comparison)
                            }
                            .help("Select frame \(ordinal.formatted()) in All Frames")
                        } else if !exported, series.coverage != nil, navigationColumn(in: comparison) != nil {
                            Text("No matching timed frame in this interval")
                                .font(Theme.Typography.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .fixedSize(horizontal: false, vertical: true)
                }
                .accessibilityElement(children: .contain)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .textSelection(.enabled)
    }

    private func footer(_ graph: TrafficRateGraph, comparison: TrafficGraphComparison?) -> some View {
        let comparing = selection.accepted != nil
        let imageAvailable = comparing
            ? comparison?.axis != nil && comparison?.enabledSeries.isEmpty == false
            : graph.axis != nil
        let csvAvailable = comparing ? comparison?.enabledSeries.isEmpty == false : graph.axis != nil
        return HStack(spacing: Theme.Metrics.spacingM) {
            Text(comparison.map(comparisonSummary) ?? (comparing ? "Comparison pending" : summary(graph)))
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .help(comparison.map(comparisonSummary) ?? summary(graph))
            Spacer()
            if let notice {
                Text(notice).font(Theme.Typography.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Menu("Save Chart As") {
                ForEach(StatisticsImageFormat.allCases) { format in
                    Button(format.menuTitle) { saveImage(graph, comparison: comparison, format: format) }
                }
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .disabled(!imageAvailable)
            .help("Save both graphs, their applied series and coverage as an image")
            Button("Save as CSV…") {
                notice = StatisticsExport.saveText(comparison?.csv() ?? graph.csv(), suggestedName: "I/O Graph.csv")
            }
            .disabled(!csvAvailable)
            .help("Save enabled series with every interval's rates and observed coverage")
        }
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    private func exportedCharts(_ graph: TrafficRateGraph, axis: TrafficIntervalAxis) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            Text("I/O Graph").font(Theme.Typography.surfaceTitle)
            charts(graph, axis: axis, exported: true)
        }
        .padding(24)
    }

    private func exportedComparison(_ comparison: TrafficGraphComparison, axis: TrafficIntervalAxis) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            Text("I/O Graph Comparison").font(Theme.Typography.surfaceTitle)
            comparisonCharts(comparison, axis: axis, exported: true)
            comparisonLegend(comparison, exported: true)
        }
        .padding(24)
    }

    @ViewBuilder
    private func comparisonHoverReadout(
        _ comparison: TrafficGraphComparison, axis: TrafficIntervalAxis,
        value: KeyPath<TrafficRateGraph.Column, Double>, format: @escaping (Double) -> String
    )
        -> some View
    {
        if let hoveredColumn, (0 ..< axis.columnCount).contains(hoveredColumn) {
            VStack(alignment: .leading, spacing: 4) {
                let start = axis.offset(ofColumn: hoveredColumn)
                    .formatted(.number.precision(.fractionLength(0 ... 3)))
                Text("At \(start) s").font(Theme.Typography.captionMedium)
                ForEach(comparison.enabledSeries) { series in
                    if series.graph.columns.indices.contains(hoveredColumn) {
                        HStack(spacing: 5) {
                            Image(systemName: series.definition.palette.symbolName)
                                .foregroundStyle(seriesColor(series.definition.palette))
                                .accessibilityHidden(true)
                            Text(series.definition.name).lineLimit(1)
                            Spacer(minLength: 8)
                            Text(verbatim: format(series.graph.columns[hoveredColumn][keyPath: value]))
                        }
                    }
                }
            }
            .font(Theme.Typography.caption)
            .padding(8)
            .frame(maxWidth: 300)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
            .accessibilityElement(children: .combine)
        }
    }

    private static func chartSymbol(_ token: TrafficGraphPaletteToken) -> BasicChartSymbolShape {
        switch token {
        case .blue: .circle
        case .vermillion: .square
        case .green: .diamond
        case .purple: .triangle
        }
    }

    private static func packetRate(_ value: Double) -> String {
        value.formatted(.number.precision(.fractionLength(0 ... 1)))
    }

    private static func byteRate(_ value: Double) -> String {
        byteFormatter.string(fromByteCount: Int64(max(0, value).rounded()))
    }

    private func graphColumn(
        at location: CGPoint, proxy: ChartProxy, geometry: GeometryProxy, axis: TrafficIntervalAxis
    )
        -> Int?
    {
        guard let plot = proxy.plotFrame else {
            return nil
        }
        let origin = geometry[plot].origin
        let seconds: Double? = proxy.value(atX: location.x - origin.x)
        return seconds.flatMap { axis.column(containing: axis.origin + $0) }
    }

    private func showFrame(for comparison: TrafficGraphComparison, column: Int) {
        guard let series = comparison.enabledSeries.first(where: { $0.id == frameNavigationSeriesID })
            ?? comparison.enabledSeries.first,
            series.representativeFrameOrdinals.indices.contains(column),
            let ordinal = series.representativeFrameOrdinals[column] else
        {
            notice = String(localized: "No matching timed frame exists in this interval.")
            return
        }
        requestFrameNavigation(ordinal: ordinal, comparison: comparison)
    }

    private func frameNavigationColumn(_ columnCount: Int) -> Binding<Int> {
        Binding(
            get: { min(max(0, frameNavigationColumnIndex), max(0, columnCount - 1)) },
            set: {
                frameNavigationColumnIndex = $0
                hoveredColumn = $0
            }
        )
    }

    private func navigationIntervalLabel(axis: TrafficIntervalAxis) -> String {
        let column = min(max(0, frameNavigationColumnIndex), axis.columnCount - 1)
        let offset = axis.offset(ofColumn: column).formatted(.number.precision(.fractionLength(0 ... 3)))
        let width = TrafficIntervalAxis.intervalTitle(axis.interval)
        return String(localized: "Frame interval at \(offset) seconds, width \(width)")
    }

    private func navigationColumn(in comparison: TrafficGraphComparison) -> Int? {
        guard let axis = comparison.axis, axis.columnCount > 0 else {
            return nil
        }
        return min(max(0, frameNavigationColumnIndex), axis.columnCount - 1)
    }

    private func requestFrameNavigation(ordinal: UInt64, comparison: TrafficGraphComparison) {
        guard let sourceToken = comparison.sourceToken else {
            notice = String(localized: "This graph has no current capture source.")
            return
        }
        Task { @MainActor in
            do {
                try await coordinator.requestAllFramesSelection(ordinal: ordinal, sourceToken: sourceToken)
                openWindow(id: TracexyApp.allFramesWindowID)
                notice = String(localized: "Opening frame \(ordinal.formatted()) in All Frames…")
            } catch {
                notice = String(localized: "The capture changed. Apply the comparison again before opening a frame.")
            }
        }
    }

    @ChartContentBuilder
    private func comparisonMarks(
        _ series: TrafficGraphComparison.Series, axis: TrafficIntervalAxis,
        title: LocalizedStringKey, value: KeyPath<TrafficRateGraph.Column, Double>, exported: Bool
    )
        -> some ChartContent
    {
        let palette = series.definition.palette
        let stride = max(1, series.graph.columns.count / 24)
        ForEach(series.graph.columns) { column in
            LineMark(
                x: .value("Seconds", axis.offset(ofColumn: column.index)),
                y: .value(title, column[keyPath: value]),
                series: .value("Series", series.id.uuidString)
            )
            .foregroundStyle(seriesColor(palette, exported: exported))
            .lineStyle(StrokeStyle(lineWidth: 2, dash: palette.dashPattern.map { CGFloat($0) }))
            .interpolationMethod(.stepEnd)
            if column.index.isMultiple(of: stride) || column.index == series.graph.columns.count - 1 {
                PointMark(
                    x: .value("Seconds", axis.offset(ofColumn: column.index)),
                    y: .value(title, column[keyPath: value])
                )
                .foregroundStyle(seriesColor(palette, exported: exported))
                .symbol(Self.chartSymbol(palette))
                .symbolSize(22)
            }
        }
        if let last = series.graph.columns.last {
            LineMark(
                x: .value("Seconds", axis.span), y: .value(title, last[keyPath: value]),
                series: .value("Series", series.id.uuidString)
            )
            .foregroundStyle(seriesColor(palette, exported: exported))
            .lineStyle(StrokeStyle(lineWidth: 2, dash: palette.dashPattern.map { CGFloat($0) }))
            .interpolationMethod(.stepEnd)
        }
    }

    @AxisContentBuilder
    private func rateAxis(format: @escaping (Double) -> String) -> some AxisContent {
        AxisMarks { mark in
            AxisGridLine()
            AxisValueLabel {
                if let number = mark.as(Double.self) {
                    Text(verbatim: format(number))
                }
            }
        }
    }

    @ChartContentBuilder
    private func hoverMark(_ axis: TrafficIntervalAxis, exported: Bool) -> some ChartContent {
        if !exported, let hoveredColumn, (0 ..< axis.columnCount).contains(hoveredColumn) {
            RuleMark(x: .value("Seconds", axis.offset(ofColumn: hoveredColumn)))
                .foregroundStyle(.secondary)
        }
    }

    private func saveImage(
        _ graph: TrafficRateGraph, comparison: TrafficGraphComparison?, format: StatisticsImageFormat
    ) {
        if let comparison, let axis = comparison.axis, !comparison.enabledSeries.isEmpty {
            let textHeight = comparison.series.reduce(0) { total, series in
                total + 72 + (series.definition.expressionText.count / 105 + 1) * 15
            }
            notice = StatisticsExport.saveImage(
                exportedComparison(comparison, axis: axis),
                size: CGSize(width: 1_040, height: CGFloat(540 + textHeight)), format: format,
                suggestedName: "I/O Graph Comparison.\(format.fileExtension)"
            )
        } else if selection.accepted == nil, let axis = graph.axis {
            notice = StatisticsExport.saveImage(
                exportedCharts(graph, axis: axis), size: CGSize(width: 860, height: 520), format: format,
                suggestedName: "I/O Graph.\(format.fileExtension)"
            )
        }
    }

    private func addDraft() {
        guard drafts.count < TrafficGraphComparisonConfiguration.maximumSeries else {
            return
        }
        let names = Set(drafts.map { $0.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() })
        let next = (1 ... TrafficGraphComparisonConfiguration.maximumSeries + 1)
            .first { !names.contains("series \($0)") } ?? drafts.count + 1
        drafts.append(TrafficGraphSeriesDraft(name: "Series \(next)", expressionText: ""))
    }

    private func applyComparison() {
        guard !coordinator.isCapturing, !coordinator.isStarting, selection.apply(drafts) else {
            return
        }
        notice = nil
        hoveredColumn = nil
        scanRevision &+= 1
    }

    private func clearComparison(resetDrafts: Bool = false) {
        scanRequestID &+= 1
        selection.clear()
        comparisonResult = nil
        resultKey = nil
        errorKey = nil
        scanError = nil
        notice = nil
        hoveredColumn = nil
        if resetDrafts {
            drafts = [TrafficGraphSeriesDraft(name: "All traffic", expressionText: "frame.len >= 0")]
        }
    }

    @MainActor
    private func scanComparison(_ key: ScanKey) async {
        guard !Task.isCancelled, key == scanKey else {
            return
        }
        scanRequestID &+= 1
        let requestID = scanRequestID
        guard let configuration = key.configuration else {
            return
        }
        comparisonResult = nil
        resultKey = nil
        errorKey = nil
        scanError = nil
        hoveredColumn = nil
        do {
            let result = try await coordinator.scanTrafficGraphComparison(
                configuration, requestedInterval: 1
            )
            guard !Task.isCancelled, requestID == scanRequestID, key == scanKey else {
                return
            }
            comparisonResult = result
            frameNavigationSeriesID = result.enabledSeries.first?.id
            frameNavigationColumnIndex = 0
            resultKey = key
        } catch {
            guard !Task.isCancelled, requestID == scanRequestID, key == scanKey else {
                return
            }
            scanError = error is CancellationError
                ? String(localized: "The capture changed during the scan. Apply the comparison again.")
                : error.localizedDescription
            errorKey = key
        }
    }

    private func seriesColor(_ token: TrafficGraphPaletteToken, exported: Bool = false) -> Color {
        let rgb = !exported && colorScheme == .dark ? token.darkRGB : token.lightRGB
        return Color(
            red: Double((rgb >> 16) & 0xFF) / 255,
            green: Double((rgb >> 8) & 0xFF) / 255,
            blue: Double(rgb & 0xFF) / 255
        )
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

    private func coverageText(_ coverage: TrafficGraphSeriesCoverage?) -> String {
        guard let coverage else {
            return String(localized: "Disabled; not evaluated.")
        }
        return String(
            localized: "\(coverage.matchedFrames.formatted()) match · \(coverage.nonmatchingFrames.formatted()) do not match · \(coverage.unknownFrames.formatted()) unknown · \(coverage.untimedMatchingFrames.formatted()) matching frames have no time"
        )
    }

    private func comparisonSummary(_ comparison: TrafficGraphComparison) -> String {
        let scope =
            String(
                localized: "\(comparison.scannedFrames.formatted()) capture frames · \(comparison.untimedCaptureFrames.formatted()) untimed · series count independently"
            )
        guard let axis = comparison.axis else {
            return scope
        }
        return scope + " · " +
            String(
                localized: "\(axis.columnCount.formatted()) intervals of \(TrafficIntervalAxis.intervalTitle(axis.interval))"
            )
    }

    private func accessibilitySummary(
        _ graph: TrafficRateGraph, value: KeyPath<TrafficRateGraph.Column, Double>, format: (Double) -> String
    )
        -> String
    {
        let values = graph.columns.map { $0[keyPath: value] }
        let peak = values.max() ?? 0
        let average = values.isEmpty ? 0 : values.reduce(0, +) / Double(values.count)
        return String(localized: "\(graph.columns.count) intervals, peak \(format(peak)), average \(format(average))")
    }

    private func comparisonAccessibilitySummary(
        _ comparison: TrafficGraphComparison,
        value: KeyPath<TrafficRateGraph.Column, Double>, format: (Double) -> String
    )
        -> String
    {
        comparison.enabledSeries.map { series in
            let overview = accessibilitySummary(series.graph, value: value, format: format)
            guard let hoveredColumn, series.graph.columns.indices.contains(hoveredColumn),
                  let axis = comparison.axis else
            {
                return "\(series.definition.name): \(overview)"
            }
            let start = axis.offset(ofColumn: hoveredColumn).formatted(.number.precision(.fractionLength(0 ... 3)))
            let observed = format(series.graph.columns[hoveredColumn][keyPath: value])
            return String(localized: "\(series.definition.name): at \(start) seconds, \(observed); \(overview)")
        }.joined(separator: "; ")
    }

    private func summary(_ graph: TrafficRateGraph) -> String {
        guard let axis = graph.axis else {
            return String(localized: "No timed frames yet")
        }
        if let hoveredColumn, graph.columns.indices.contains(hoveredColumn) {
            let column = graph.columns[hoveredColumn]
            let start = axis.offset(ofColumn: hoveredColumn).formatted(.number.precision(.fractionLength(0 ... 3)))
            return String(
                localized: "At \(start) s: \(Self.packetRate(column.packetsPerSecond)) packets/s, \(Self.byteRate(column.bytesPerSecond))/s"
            )
        }
        let interval = TrafficIntervalAxis.intervalTitle(axis.interval)
        if graph.untimedFrameCount > 0 {
            return String(
                localized: "\(graph.totalFrames.formatted()) frames in \(graph.columns.count.formatted()) intervals of \(interval); \(graph.untimedFrameCount.formatted()) frames carry no capture time"
            )
        }
        return String(
            localized: "\(graph.totalFrames.formatted()) frames in \(graph.columns.count.formatted()) intervals of \(interval)"
        )
    }
}
