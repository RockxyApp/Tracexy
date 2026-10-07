import AppKit
import Charts
import SwiftUI

// MARK: - PacketLengthRow

/// One row of Statistics ▸ Packet Lengths: a Wireshark length range with its count,
/// average, extremes, rate and share of the frames in view.
struct PacketLengthRow: Identifiable, Hashable {
    // MARK: Internal

    let id: Int
    let range: String
    let bucket: FrameLengthHistogram.Bucket
    let share: Double
    let perSecond: Double?

    /// Every row, the range rows first and the total last, from the sessions in view.
    static func rows(of sessions: [SessionSummary]) -> (ranges: [PacketLengthRow], total: PacketLengthRow) {
        var histogram = FrameLengthHistogram()
        for session in sessions {
            histogram.add(session.frameLengths)
        }
        let total = histogram.total
        let span = Self.span(of: sessions)
        func rate(_ count: Int) -> Double? {
            guard let span, span > 0 else {
                return nil
            }
            return Double(count) / span
        }
        let ranges = histogram.buckets.enumerated().map { index, bucket in
            PacketLengthRow(
                id: index,
                range: FrameLengthHistogram.label(ofBucket: index),
                bucket: bucket,
                share: total.isEmpty ? 0 : Double(bucket.count) / Double(total.count),
                perSecond: rate(bucket.count)
            )
        }
        let totalRow = PacketLengthRow(
            id: -1, range: String(localized: "All frames"), bucket: total, share: total.isEmpty ? 0 : 1,
            perSecond: rate(total.count)
        )
        return (ranges, totalRow)
    }

    // MARK: Private

    /// Seconds from the earliest session start to the latest session end in view.
    private static func span(of sessions: [SessionSummary]) -> TimeInterval? {
        let starts = sessions.compactMap(\.startTime)
        let ends = sessions.compactMap { session in session.startTime.map { $0 + (session.duration ?? 0) } }
        guard let first = starts.min(), let last = ends.max() else {
            return nil
        }
        return last.timeIntervalSince(first)
    }
}

// MARK: - PacketLengthsWindow

/// Statistics ▸ Packet Lengths: the frames of the sessions in view counted into
/// Wireshark's length ranges, as a chart and a table with count, average, minimum,
/// maximum, rate and percent.
struct PacketLengthsWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let sessions = coordinator.visibleSessions
        let (ranges, total) = PacketLengthRow.rows(of: sessions)
        Group {
            if total.bucket.isEmpty {
                ContentUnavailableView(
                    "No Frames in View",
                    systemImage: "chart.bar",
                    description: Text("The sessions in view carry no frames to count.")
                )
            } else {
                VStack(spacing: 0) {
                    chart(ranges)
                        .frame(height: 150)
                        .padding(Theme.Metrics.spacingL)
                    Divider()
                    table(ranges + [total])
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) {
            footer(rows: ranges + [total], sessions: sessions.count)
        }
        .frame(minWidth: 620, minHeight: 380)
    }

    // MARK: Private

    @State private var selection: PacketLengthRow.ID?
    @State private var notice: String?

    /// The chart as a saved image: titled, the ranges only (not the total row).
    private func exportedChart(_ rows: [PacketLengthRow]) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            Text("Packet Lengths").font(Theme.Typography.surfaceTitle)
            chart(rows.filter { $0.id >= 0 })
        }
        .padding(24)
    }

    private func chart(_ rows: [PacketLengthRow]) -> some View {
        Chart(rows) { row in
            BarMark(
                x: .value("Length", row.range),
                y: .value("Frames", row.bucket.count)
            )
            .foregroundStyle(Color.accentColor)
            .accessibilityLabel(row.range)
            .accessibilityValue("\(row.bucket.count) frames")
        }
        .chartXAxisLabel("Frame length (bytes)")
        .chartYAxisLabel("Frames")
    }

    private func table(_ rows: [PacketLengthRow]) -> some View {
        Table(rows, selection: $selection) {
            TableColumn("Length") { row in
                Text(row.range)
                    .fontWeight(row.id < 0 ? .semibold : .regular)
                    .monospacedDigit()
            }
            .width(min: 110, ideal: 130)
            TableColumn("Count") { row in
                Text(row.bucket.count.formatted()).monospacedDigit()
            }
            .width(min: 60, ideal: 72)
            TableColumn("Average") { row in
                Text(row.bucket.average.map { $0.formatted(.number.precision(.fractionLength(2))) } ?? "—")
                    .monospacedDigit().foregroundStyle(.secondary)
            }
            .width(min: 60, ideal: 76)
            TableColumn("Min") { row in
                Text(row.bucket.isEmpty ? "—" : row.bucket.minimum.formatted()).monospacedDigit()
                    .foregroundStyle(.secondary)
            }
            .width(min: 44, ideal: 56)
            TableColumn("Max") { row in
                Text(row.bucket.isEmpty ? "—" : row.bucket.maximum.formatted()).monospacedDigit()
                    .foregroundStyle(.secondary)
            }
            .width(min: 44, ideal: 56)
            TableColumn("Rate (/s)") { row in
                Text(row.perSecond.map { $0.formatted(.number.precision(.fractionLength(1))) } ?? "—")
                    .monospacedDigit().foregroundStyle(.secondary)
            }
            .width(min: 60, ideal: 72)
            TableColumn("Percent") { row in
                Text(row.share.formatted(.percent.precision(.fractionLength(2)))).monospacedDigit()
            }
            .width(min: 60, ideal: 72)
        }
        .contextMenu(forSelectionType: PacketLengthRow.ID.self) { _ in
            Button("Copy All as CSV") {
                copy(csv(rows))
            }
        }
    }

    private func footer(rows: [PacketLengthRow], sessions: Int) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Text("Frames of the \(sessions.formatted()) sessions in view; frames outside any session are not counted")
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
                        notice = StatisticsExport.saveImage(
                            exportedChart(rows), size: CGSize(width: 720, height: 360), format: format,
                            suggestedName: "Packet Lengths.\(format.fileExtension)"
                        )
                    }
                }
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .help("Save the chart as an image")
            Button("Copy as CSV") {
                copy(csv(rows))
            }
            .help("Copy every range as comma-separated values")
            Button("Save as CSV…") {
                notice = StatisticsExport.saveText(csv(rows), suggestedName: "Packet Lengths.csv")
            }
        }
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    private func csv(_ rows: [PacketLengthRow]) -> String {
        let header = "Range,Count,Average,Min,Max,Rate per second,Percent"
        let lines = rows.map { row in
            [
                row.range.replacingOccurrences(of: "–", with: "-"),
                String(row.bucket.count),
                row.bucket.average.map { String(format: "%.2f", $0) } ?? "",
                row.bucket.isEmpty ? "" : String(row.bucket.minimum),
                row.bucket.isEmpty ? "" : String(row.bucket.maximum),
                row.perSecond.map { String(format: "%.4f", $0) } ?? "",
                String(format: "%.4f", row.share * 100),
            ].joined(separator: ",")
        }
        return ([header] + lines).joined(separator: "\n")
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
