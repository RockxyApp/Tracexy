import AppKit
import SwiftUI

// MARK: - RTPStreamsWindow

/// Statistics ▸ RTP Streams: the RTP streams in the frames in view, with the loss,
/// packet spacing and jitter that decide how a call sounded, as Wireshark's
/// Telephony ▸ RTP ▸ RTP Streams. A stream's frames stay UDP everywhere else.
struct RTPStreamsWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        @Bindable var frames = coordinator.allFrames
        let inView = Set(coordinator.visibleSessions.map(\.id))
        let rows = frames.visibleRows(sessionsInView: inView)
        let streams = RTPStreams.streams(rows: rows)
        Group {
            if frames.isLoading {
                ProgressView("Listing frames…")
                    .controlSize(.small)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let error = frames.error {
                ContentUnavailableView("RTP Streams Unavailable", systemImage: "waveform", description: Text(error))
            } else if streams.isEmpty {
                ContentUnavailableView(
                    "No RTP Streams",
                    systemImage: "waveform",
                    description: Text("No UDP datagram in the frames in view carries an RTP header.")
                )
            } else {
                table(streams, rows: rows)
            }
        }
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Toggle("Limit to Sessions in View", isOn: $frames.limitToSessionsInView)
                    .toggleStyle(.checkbox)
                    .help("Count only the frames of the sessions the main window shows")
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) {
            footer(streams)
        }
        .frame(minWidth: 760, minHeight: 320)
        .onAppear { coordinator.loadAllFrames() }
        .sheet(item: $analyzed) { stream in
            let reverseStreams = RTPStreams.reverseStreams(for: stream, in: streams)
            let analyses = ([stream] + reverseStreams).map { RTPStreamAnalysis(stream: $0, rows: rows) }
            RTPStreamAnalysisSheet(analyses: analyses) { frame in
                if let row = rows.first(where: { $0.ordinal == frame }) {
                    notice = coordinator.revealFrame(row)
                        ? nil : String(localized: "That frame's session is not in the main window's list.")
                }
            }
        }
    }

    // MARK: Private

    @State private var selection: RTPStreamRow.ID?
    /// The stream Stream Analysis shows.
    @State private var analyzed: RTPStreamRow?
    @State private var notice: String?

    private func table(_ streams: [RTPStreamRow], rows: [CaptureFrameRow]) -> some View {
        Table(streams, selection: $selection) {
            TableColumn("Source") { row in
                Text(row.source.display).font(Theme.Typography.mono).lineLimit(1).truncationMode(.middle)
            }
            .width(min: 110, ideal: 124)
            TableColumn("Destination") { row in
                Text(row.destination.display).font(Theme.Typography.mono).lineLimit(1).truncationMode(.middle)
            }
            .width(min: 110, ideal: 124)
            TableColumn("SSRC") { row in
                Text(row.ssrcText).font(Theme.Typography.mono)
            }
            .width(min: 80, ideal: 86)
            TableColumn("Payload") { row in
                Text(row.payloads).lineLimit(1)
            }
            .width(min: 50, ideal: 64)
            TableColumn("Packets") { row in
                number(row.packets.formatted())
            }
            .width(min: 50, ideal: 60)
            TableColumn("Lost") { row in
                number(row
                    .lost == 0 ? "0" :
                    "\(row.lost) (\(row.lostPercent.formatted(.number.precision(.fractionLength(1))))%)")
                    .foregroundStyle(row.lost > 0 ? Color.orange : Color.primary)
            }
            .width(min: 60, ideal: 80)
            TableColumn("Max Delta") { row in
                number(milliseconds(row.maxDelta))
            }
            .width(min: 70, ideal: 84)
            TableColumn("Mean Jitter") { row in
                number(row.jitter.map { milliseconds($0.mean) } ?? "—")
            }
            .width(min: 70, ideal: 84)
            TableColumn("Max Jitter") { row in
                number(row.jitter.map { milliseconds($0.max) } ?? "—")
                    .help(row
                        .jitter == nil ? "The payload type's clock rate is not known, so jitter cannot be measured" :
                        "")
            }
            .width(min: 70, ideal: 84)
            TableColumn("") { row in
                if row.hasProblem {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .help("Sequence numbers or timestamps arrived out of order or skipped")
                        .accessibilityLabel("Sequence problem")
                }
            }
            .width(22)
        }
        .contextMenu(forSelectionType: RTPStreamRow.ID.self) { ids in
            if let row = streams.first(where: { ids.contains($0.id) }) {
                Button("Show Sessions") { coordinator.showSessions(narrowingWith: row.term) }
                Button("Stream Analysis…") { analyzed = row }
                Button("Open First Frame") {
                    if let frame = rows.first(where: { $0.ordinal == row.firstFrame }) {
                        notice = coordinator.revealFrame(frame)
                            ? nil : String(localized: "That frame's session is not in the main window's list.")
                    }
                }
            }
        } primaryAction: { ids in
            if let row = streams.first(where: { ids.contains($0.id) }) {
                coordinator.showSessions(narrowingWith: row.term)
            }
        }
    }

    private func footer(_ streams: [RTPStreamRow]) -> some View {
        let selected = streams.first { $0.id == selection }
        return HStack(spacing: Theme.Metrics.spacingM) {
            Text(notice ??
                (streams
                    .count == 1 ? String(localized: "1 stream") :
                    String(localized: "\(streams.count.formatted()) streams")))
                .lineLimit(1)
            Spacer()
            Button("Copy as CSV") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(RTPStreams.csv(streams), forType: .string)
            }
            .disabled(streams.isEmpty)
            Button("Save as CSV…") {
                notice = StatisticsExport.saveText(RTPStreams.csv(streams), suggestedName: "RTP Streams.csv")
            }
            .disabled(streams.isEmpty)
            Button("Stream Analysis…") { analyzed = selected }
                .disabled(selected == nil)
            Button("Show Sessions") {
                if let selected {
                    coordinator.showSessions(narrowingWith: selected.term)
                }
            }
            .disabled(selected == nil)
            .keyboardShortcut(.defaultAction)
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    private func number(_ text: String) -> Text {
        Text(text).monospacedDigit()
    }

    private func milliseconds(_ value: Double) -> String {
        "\(value.formatted(.number.precision(.fractionLength(1)))) ms"
    }
}
