import AppKit
import Charts
import SwiftUI

// MARK: - RTPStreamAnalysisSheet

/// RTP Stream Analysis for one direction, with an optional reversed-endpoint
/// stream overlaid in the same window for comparison.
struct RTPStreamAnalysisSheet: View {
    // MARK: Internal

    let analyses: [RTPStreamAnalysis]
    let onOpenFrame: (UInt64) -> Void

    var body: some View {
        VStack(spacing: 0) {
            summary
                .padding(Theme.Metrics.spacingL)
            Picker("Show", selection: $showsGraph) {
                Text("Packets").tag(false)
                Text("Graph").tag(true)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            .accessibilityIdentifier("rtp.analysis.display")
            .padding(.bottom, Theme.Metrics.spacingS)
            if !reverseAnalyses.isEmpty {
                reversePicker
                    .padding(.bottom, Theme.Metrics.spacingS)
                directionPicker
                    .padding(.bottom, Theme.Metrics.spacingS)
            }
            Divider()
            if showsGraph {
                graph
            } else {
                packetTable
            }
            Divider()
            footer
        }
        .frame(minWidth: 760, idealWidth: 820, minHeight: 440, idealHeight: 520)
    }

    // MARK: Private

    private struct GraphSeries: Identifiable {
        let name: String
        let key: String
        let value: KeyPath<RTPStreamAnalysis.Packet, Double>

        var id: String {
            key
        }
    }

    @Environment(\.dismiss) private var dismiss
    @State private var selection: RTPStreamAnalysis.Packet.ID?
    @State private var notice: String?
    @State private var showsGraph = false
    @State private var selectedDirectionID = ""
    @State private var selectedReverseID = ""
    @State private var visibleSeries: Set<String> = []
    /// Every series offered so far, so only new ones are switched on.
    @State private var knownSeries: Set<String> = []

    private var forwardAnalysis: RTPStreamAnalysis {
        analyses[0]
    }

    private var reverseAnalyses: [RTPStreamAnalysis] {
        Array(analyses.dropFirst())
    }

    private var comparedAnalyses: [RTPStreamAnalysis] {
        guard let reverse = reverseAnalyses.first(where: { $0.stream.id == selectedReverseID }) else {
            return [forwardAnalysis]
        }
        return [forwardAnalysis, reverse]
    }

    private var selectedAnalysis: RTPStreamAnalysis {
        comparedAnalyses.first { $0.stream.id == selectedDirectionID } ?? forwardAnalysis
    }

    private var combinedCSV: String {
        guard let first = analysesForCSV.first else {
            return ""
        }
        let rows = analysesForCSV.flatMap { analysis in
            analysis.csv.components(separatedBy: "\r\n").dropFirst().dropLast()
        }
        let header = first.csv.components(separatedBy: "\r\n")[0]
        return ([header] + rows).joined(separator: "\r\n") + "\r\n"
    }

    private var analysesForCSV: [RTPStreamAnalysis] {
        comparedAnalyses
    }

    private var reversePicker: some View {
        Picker("Reverse stream", selection: $selectedReverseID) {
            Text("No reverse stream").tag("")
            ForEach(reverseAnalyses, id: \.stream.id) { analysis in
                Text(
                    "\(analysis.stream.source.display) → \(analysis.stream.destination.display), \(analysis.stream.ssrcText)"
                )
                .tag(analysis.stream.id)
            }
        }
        .labelsHidden()
        .frame(maxWidth: 520)
        .accessibilityIdentifier("rtp.analysis.reverse-stream")
        .onAppear { selectDefaultReverseIfNeeded() }
        .onChange(of: selectedReverseID) { _, newValue in
            if selectedDirectionID != forwardAnalysis.stream.id, selectedDirectionID != newValue {
                selectedDirectionID = forwardAnalysis.stream.id
            }
        }
    }

    private var directionPicker: some View {
        Picker("Direction", selection: $selectedDirectionID) {
            ForEach(comparedAnalyses, id: \.stream.id) { analysis in
                Text(directionName(analysis)).tag(analysis.stream.id)
            }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .fixedSize()
        .accessibilityIdentifier("rtp.analysis.direction")
        .onAppear {
            if selectedDirectionID.isEmpty {
                selectedDirectionID = forwardAnalysis.stream.id
            }
        }
    }

    /// Jitter, delta and skew may be independently hidden for each selected direction.
    private var graph: some View {
        let series = [
            GraphSeries(name: String(localized: "Jitter"), key: "jitter", value: \.jitter),
            GraphSeries(name: String(localized: "Delta"), key: "delta", value: \.delta),
            GraphSeries(name: String(localized: "Skew"), key: "skew", value: \.skew),
        ]
        // One origin for every direction compared, so a reverse stream that began
        // later is drawn later rather than from zero.
        let origin = comparedAnalyses.map(\.start).min() ?? 0
        return VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            ScrollView(.horizontal) {
                seriesControls(series)
                    .fixedSize(horizontal: true, vertical: false)
            }
            .padding(.horizontal, Theme.Metrics.spacingL)
            Chart {
                ForEach(comparedAnalyses, id: \.stream.id) { analysis in
                    ForEach(series) { item in
                        if visibleSeries.contains(seriesID(analysis, key: item.key)) {
                            ForEach(analysis.packets) { packet in
                                graphLineMark(analysis: analysis, packet: packet, series: item, origin: origin)
                            }
                        }
                    }
                }
            }
            .chartXAxisLabel("Time (s)")
            .chartYAxisLabel("ms")
            .padding(Theme.Metrics.spacingL)
            .frame(maxHeight: .infinity)
        }
        .onAppear { synchronizeVisibleSeries() }
        .onChange(of: selectedReverseID) { _, _ in synchronizeVisibleSeries() }
    }

    private var packetTable: some View {
        Table(selectedAnalysis.packets, selection: $selection) {
            TableColumn("Packet") { Text($0.frame.formatted()).monospacedDigit() }
                .width(min: 60, ideal: 70)
            TableColumn("Sequence") { Text(String($0.sequence)).monospacedDigit() }
                .width(min: 60, ideal: 70)
            TableColumn("Delta (ms)") { Text(Self.decimal($0.delta, 3)).monospacedDigit() }
                .width(min: 64, ideal: 84)
            TableColumn("Jitter (ms)") { Text(Self.decimal($0.jitter, 3)).monospacedDigit() }
                .width(min: 64, ideal: 84)
            TableColumn("Skew") { Text(Self.decimal($0.skew, 3)).monospacedDigit() }
                .width(min: 64, ideal: 84)
            TableColumn("Bandwidth") { Text(Self.decimal($0.bandwidth, 1)).monospacedDigit() }
                .width(min: 64, ideal: 84)
            TableColumn("Marker") { packet in
                Text(packet.isMarker ? "SET" : "")
            }
            .width(min: 44, ideal: 52)
            TableColumn("Status") { packet in
                if let status = packet.status {
                    Text(status).foregroundStyle(.orange)
                } else {
                    Text("OK").foregroundStyle(.secondary)
                }
            }
            .width(min: 120, ideal: 200)
        }
        .accessibilityIdentifier("rtp.analysis.packets")
        .contextMenu(forSelectionType: RTPStreamAnalysis.Packet.ID.self) { _ in
        } primaryAction: { ids in
            if let frame = ids.first {
                onOpenFrame(frame)
            }
        }
    }

    private var footer: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Text(notice ?? String(localized: "Double-click a packet to open its frame.")).lineLimit(1)
            Spacer()
            Button("Save as CSV…") {
                notice = StatisticsExport.saveText(combinedCSV, suggestedName: "RTP Stream Analysis.csv")
            }
            Button("Done") { dismiss() }
                .keyboardShortcut(.defaultAction)
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    private var summary: some View {
        Grid(alignment: .leading, horizontalSpacing: Theme.Metrics.spacingL, verticalSpacing: 4) {
            GridRow {
                Text(String(localized: "Stream")).foregroundStyle(.secondary)
                ForEach(comparedAnalyses, id: \.stream.id) { analysis in
                    Text(
                        "\(directionName(analysis)): \(analysis.stream.source.display) → \(analysis.stream.destination.display), SSRC \(analysis.stream.ssrcText)"
                    )
                    .monospacedDigit().textSelection(.enabled)
                    .accessibilityIdentifier("rtp.analysis.summary.stream.\(seriesDirection(analysis))")
                }
            }
            summaryRow(String(localized: "Packets")) { analysis in
                String(
                    localized: "\(analysis.packets.count.formatted()) of \(analysis.expected.formatted()) expected, \(analysis.lost.formatted()) lost"
                )
            }
            summaryRow(String(localized: "Largest delta")) { analysis in
                analysis.maxDeltaFrame.map {
                    String(localized: "\(Self.decimal(analysis.maxDelta, 3)) ms at packet \($0.formatted())")
                } ?? "—"
            }
            summaryRow(String(localized: "Largest jitter / mean")) { analysis in
                "\(Self.decimal(analysis.maxJitter, 3)) / \(Self.decimal(analysis.meanJitter, 3)) ms"
            }
            summaryRow(String(localized: "Largest skew")) { analysis in
                "\(Self.decimal(analysis.maxSkew, 3)) ms"
            }
            summaryRow(String(localized: "Sequence errors")) { $0.sequenceErrors.formatted() }
            summaryRow(String(localized: "Clock / frequency drift")) { analysis in
                "\(Self.decimal(analysis.clockDrift, 0)) ms · \(Self.decimal(analysis.frequencyDrift, 0)) Hz (\(Self.decimal(analysis.frequencyDriftPercent, 2)) %)"
            }
        }
        .font(Theme.Typography.caption)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func seriesControls(
        _ series: [GraphSeries]
    )
        -> some View
    {
        HStack(spacing: Theme.Metrics.spacingM) {
            ForEach(comparedAnalyses, id: \.stream.id) { analysis in
                ForEach(series) { item in
                    let id = seriesID(analysis, key: item.key)
                    Toggle("\(directionName(analysis)) · \(item.name)", isOn: Binding(
                        get: { visibleSeries.contains(id) },
                        set: { isVisible in
                            if isVisible {
                                visibleSeries.insert(id)
                            } else {
                                visibleSeries.remove(id)
                            }
                        }
                    ))
                    .toggleStyle(.checkbox)
                    .font(Theme.Typography.caption)
                    .fixedSize()
                    .accessibilityIdentifier("rtp.analysis.series.\(seriesDirection(analysis)).\(item.key)")
                }
            }
        }
    }

    private func summaryRow(
        _ title: String,
        value: @escaping (RTPStreamAnalysis) -> String
    )
        -> some View
    {
        GridRow {
            Text(title).foregroundStyle(.secondary)
            ForEach(comparedAnalyses, id: \.stream.id) { analysis in
                Text(value(analysis)).monospacedDigit().textSelection(.enabled)
            }
        }
    }

    private static func decimal(_ value: Double, _ digits: Int) -> String {
        String(format: "%.*f", digits, value)
    }

    private func graphLineMark(
        analysis: RTPStreamAnalysis,
        packet: RTPStreamAnalysis.Packet,
        series: GraphSeries,
        origin: Double
    )
        -> some ChartContent
    {
        let time = (analysis.start + packet.time - origin) / 1_000
        let value = packet[keyPath: series.value]
        let label = "\(directionName(analysis)) · \(series.name)"
        return LineMark(x: .value("Time (s)", time), y: .value("ms", value))
            .foregroundStyle(by: .value("Series", label))
    }

    private func synchronizeVisibleSeries() {
        let validIDs = Set(comparedAnalyses.flatMap { analysis in
            ["jitter", "delta", "skew"].map { seriesID(analysis, key: $0) }
        })
        // Series seen for the first time start visible; one the user hid stays
        // hidden when its direction is chosen again or the Graph is reopened.
        visibleSeries.formUnion(validIDs.subtracting(knownSeries))
        knownSeries.formUnion(validIDs)
        if selectedDirectionID.isEmpty {
            selectedDirectionID = forwardAnalysis.stream.id
        }
    }

    private func selectDefaultReverseIfNeeded() {
        if selectedReverseID.isEmpty, let first = reverseAnalyses.first {
            selectedReverseID = first.stream.id
        }
    }

    private func directionName(_ analysis: RTPStreamAnalysis) -> String {
        analysis.stream.id == forwardAnalysis.stream.id
            ? String(localized: "Forward") : String(localized: "Reverse")
    }

    private func seriesID(_ analysis: RTPStreamAnalysis, key: String) -> String {
        "\(analysis.stream.id):\(key)"
    }

    private func seriesDirection(_ analysis: RTPStreamAnalysis) -> String {
        analysis.stream.id == forwardAnalysis.stream.id ? "forward" : "reverse"
    }
}
