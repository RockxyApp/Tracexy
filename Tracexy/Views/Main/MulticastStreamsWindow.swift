import AppKit
import SwiftUI

// MARK: - MulticastStreamsWindow

/// Statistics ▸ UDP Multicast Streams: each source's datagrams to a multicast group,
/// with the bursts and receive-buffer growth that explain dropped video or market
/// data, as Wireshark's dialog of the same name. Parameters are Wireshark's.
struct MulticastStreamsWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        @Bindable var frames = coordinator.allFrames
        let inView = Set(coordinator.visibleSessions.map(\.id))
        let rows = frames.visibleRows(sessionsInView: inView)
        let result = MulticastStreams.streams(rows: rows, parameters: parameters)
        Group {
            if frames.isLoading {
                ProgressView("Listing frames…")
                    .controlSize(.small)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let error = frames.error {
                ContentUnavailableView(
                    "Multicast Streams Unavailable",
                    systemImage: "dot.radiowaves.left.and.right",
                    description: Text(error)
                )
            } else if result.streams.isEmpty {
                ContentUnavailableView(
                    "No Multicast Streams",
                    systemImage: "dot.radiowaves.left.and.right",
                    description: Text("No UDP datagram in the frames in view was sent to a multicast group.")
                )
            } else {
                table(result.streams, rows: rows)
            }
        }
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Toggle("Limit to Sessions in View", isOn: $frames.limitToSessionsInView)
                    .toggleStyle(.checkbox)
                    .help("Count only the frames of the sessions the main window shows")
            }
            ToolbarItem(placement: .primaryAction) {
                Button("Parameters", systemImage: "slider.horizontal.3") { isEditingParameters = true }
                    .help("Burst interval, alarm thresholds and buffer empty speeds")
                    .popover(isPresented: $isEditingParameters, arrowEdge: .bottom) {
                        MulticastParametersForm(parameters: $parameters)
                    }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) {
            footer(result)
        }
        .frame(minWidth: 820, minHeight: 320)
        .onAppear { coordinator.loadAllFrames() }
    }

    // MARK: Private

    @State private var selection: MulticastStreamRow.ID?
    @State private var notice: String?
    @State private var parameters = MulticastStreams.Parameters()
    @State private var isEditingParameters = false

    private func table(_ streams: [MulticastStreamRow], rows: [CaptureFrameRow]) -> some View {
        Table(streams, selection: $selection) {
            TableColumn("Source") { row in
                Text(row.sourceText).font(Theme.Typography.mono).lineLimit(1).truncationMode(.middle)
            }
            .width(min: 96, ideal: 128)
            TableColumn("Group") { row in
                Text(row.groupText).font(Theme.Typography.mono).lineLimit(1).truncationMode(.middle)
            }
            .width(min: 96, ideal: 128)
            TableColumn("Packets") { row in
                number(row.packets.formatted())
            }
            .width(min: 50, ideal: 60)
            TableColumn("Packets/s") { row in
                number(row.packetsPerSecond.formatted(.number.precision(.fractionLength(2))))
            }
            .width(min: 60, ideal: 70)
            TableColumn("Average Rate") { row in
                number(TrafficCells.rate(row.averageBitsPerSecond))
            }
            .width(min: 70, ideal: 84)
            TableColumn("Peak Rate") { row in
                number(TrafficCells.rate(row.maxBitsPerSecond))
                    .help("The largest burst's rate over one burst interval")
            }
            .width(min: 70, ideal: 84)
            TableColumn("Max Burst") { row in
                number(String(localized: "\(row.maxBurst) in \(parameters.burstInterval) ms"))
            }
            .width(min: 70, ideal: 84)
            TableColumn("Burst Alarms") { row in
                number(row.burstAlarms.formatted())
                    .foregroundStyle(row.burstAlarms > 0 ? Color.orange : Color.primary)
            }
            .width(min: 56, ideal: 76)
            TableColumn("Max Buffer") { row in
                number(ByteUnits.string(Int64(row.maxBufferBytes)))
            }
            .width(min: 56, ideal: 72)
            TableColumn("Buffer Alarms") { row in
                number(row.bufferAlarms.formatted())
                    .foregroundStyle(row.bufferAlarms > 0 ? Color.orange : Color.primary)
            }
            .width(min: 56, ideal: 80)
        }
        .contextMenu(forSelectionType: MulticastStreamRow.ID.self) { ids in
            if let row = streams.first(where: { ids.contains($0.id) }) {
                Button("Show Sessions") { coordinator.showSessions(narrowingWith: row.term) }
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

    private func footer(_ result: MulticastStreams.Result) -> some View {
        let streams = result.streams
        let selected = streams.first { $0.id == selection }
        return HStack(spacing: Theme.Metrics.spacingM) {
            Text(notice ?? summary(result))
                .lineLimit(1)
                .truncationMode(.tail)
            Spacer()
            Button("Copy as CSV") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(MulticastStreams.csv(streams), forType: .string)
            }
            .disabled(streams.isEmpty)
            Button("Save as CSV…") {
                notice = StatisticsExport.saveText(
                    MulticastStreams.csv(streams),
                    suggestedName: "UDP Multicast Streams.csv"
                )
            }
            .disabled(streams.isEmpty)
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

    /// The count, then what all streams together reached — Wireshark's summary line.
    private func summary(_ result: MulticastStreams.Result) -> String {
        let count = result.streams.count == 1 ? String(localized: "1 stream")
            : String(localized: "\(result.streams.count.formatted()) streams")
        guard let totals = result.totals else {
            return count
        }
        let peak = TrafficCells.rate(totals.maxBitsPerSecond)
        let buffer = ByteUnits.string(Int64(totals.maxBufferBytes))
        return String(localized: "\(count), peaking at \(peak) with up to \(buffer) buffered")
    }

    private func number(_ text: String) -> Text {
        Text(text).monospacedDigit()
    }
}

// MARK: - MulticastParametersForm

/// Wireshark's five multicast parameters, each kept only while it is in range.
private struct MulticastParametersForm: View {
    // MARK: Internal

    @Binding var parameters: MulticastStreams.Parameters

    var body: some View {
        Form {
            field("Burst interval", unit: "ms", value: \.burstInterval, range: 1 ... 1_000)
            field("Burst alarm", unit: "packets", value: \.burstAlarmThreshold, range: 1 ... 1_000_000)
            field("Buffer alarm", unit: "bytes", value: \.bufferAlarmThreshold, range: 1 ... 100_000_000)
            field("Stream empty speed", unit: "kbit/s", value: \.streamEmptySpeed, range: 1 ... 10_000_000)
            field("Total empty speed", unit: "kbit/s", value: \.totalEmptySpeed, range: 1 ... 10_000_000)
            Button("Restore Defaults") { parameters = MulticastStreams.Parameters() }
                .disabled(parameters == MulticastStreams.Parameters())
        }
        .formStyle(.grouped)
        .frame(width: 320)
    }

    // MARK: Private

    private func field(
        _ title: LocalizedStringKey,
        unit: LocalizedStringKey,
        value: WritableKeyPath<MulticastStreams.Parameters, Int>,
        range: ClosedRange<Int>
    )
        -> some View
    {
        LabeledContent(title) {
            HStack(spacing: Theme.Metrics.spacingS) {
                TextField(title, value: Binding(
                    get: { parameters[keyPath: value] },
                    set: { parameters[keyPath: value] = min(max($0, range.lowerBound), range.upperBound) }
                ), format: .number.grouping(.never))
                    .labelsHidden()
                    .multilineTextAlignment(.trailing)
                    .frame(width: 90)
                Text(unit).foregroundStyle(.secondary)
            }
        }
    }
}
