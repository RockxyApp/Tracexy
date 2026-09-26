import AppKit
import Charts
import SwiftUI

// MARK: - RTPStreamAnalysisSheet

/// Telephony ▸ RTP ▸ Stream Analysis for one stream: each packet's delta, jitter,
/// skew, bandwidth, marker and status, under the stream's largest delta and jitter,
/// mean jitter, largest skew and loss — Wireshark's RTP Stream Analysis.
struct RTPStreamAnalysisSheet: View {
    // MARK: Internal

    let stream: RTPStreamRow
    let analysis: RTPStreamAnalysis
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
            .padding(.bottom, Theme.Metrics.spacingS)
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

    @Environment(\.dismiss) private var dismiss
    @State private var selection: RTPStreamAnalysis.Packet.ID?
    @State private var notice: String?
    @State private var showsGraph = false

    /// Jitter, delta and skew over the stream, as Wireshark's analysis graph draws them.
    private var graph: some View {
        let series: [(String, KeyPath<RTPStreamAnalysis.Packet, Double>)] = [
            (String(localized: "Jitter"), \.jitter), (String(localized: "Delta"), \.delta),
            (String(localized: "Skew"), \.skew),
        ]
        return Chart {
            ForEach(series, id: \.0) { name, value in
                ForEach(analysis.packets) { packet in
                    LineMark(x: .value("Time (s)", packet.time / 1_000), y: .value("ms", packet[keyPath: value]))
                        .foregroundStyle(by: .value("Series", name))
                }
            }
        }
        .chartXAxisLabel("Time (s)")
        .chartYAxisLabel("ms")
        .padding(Theme.Metrics.spacingL)
        .frame(maxHeight: .infinity)
    }

    private var packetTable: some View {
        Table(analysis.packets, selection: $selection) {
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
                notice = StatisticsExport.saveText(analysis.csv, suggestedName: "RTP Stream Analysis.csv")
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
        let items: [(String, String)] = [
            (
                String(localized: "Stream"),
                "\(stream.source.display) → \(stream.destination.display), SSRC \(stream.ssrcText)"
            ),
            (String(localized: "Largest delta"), analysis.maxDeltaFrame.map {
                String(localized: "\(Self.decimal(analysis.maxDelta, 3)) ms at packet \($0.formatted())")
            } ?? "—"),
            (String(localized: "Largest jitter"), "\(Self.decimal(analysis.maxJitter, 3)) ms"),
            (String(localized: "Mean jitter"), "\(Self.decimal(analysis.meanJitter, 3)) ms"),
            (String(localized: "Largest skew"), "\(Self.decimal(analysis.maxSkew, 3)) ms"),
            (
                String(localized: "Packets"),
                String(
                    localized: "\(analysis.packets.count.formatted()) of \(analysis.expected.formatted()) expected, \(analysis.lost.formatted()) lost"
                )
            ),
            (String(localized: "Sequence errors"), analysis.sequenceErrors.formatted()),
            (String(localized: "Clock drift"), "\(Self.decimal(analysis.clockDrift, 0)) ms"),
            (String(localized: "Frequency drift"), String(
                localized: "\(Self.decimal(analysis.frequencyDrift, 0)) Hz (\(Self.decimal(analysis.frequencyDriftPercent, 2)) %)"
            )),
        ]
        return Grid(alignment: .leading, horizontalSpacing: Theme.Metrics.spacingL, verticalSpacing: 4) {
            ForEach(items, id: \.0) { label, value in
                GridRow {
                    Text(label).foregroundStyle(.secondary)
                    Text(value).monospacedDigit().textSelection(.enabled)
                }
            }
        }
        .font(Theme.Typography.caption)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private static func decimal(_ value: Double, _ digits: Int) -> String {
        String(format: "%.\(digits)f", value)
    }
}
