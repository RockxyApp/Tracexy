import AppKit
import SwiftUI

// MARK: - TrafficKindPicker

/// The address-family chooser shared by Conversations and Endpoints: one segment per
/// family, each labelled with its row count the way Wireshark labels its tabs.
struct TrafficKindPicker: View {
    @Binding var kind: TrafficAddressKind

    let counts: [TrafficAddressKind: Int]

    var body: some View {
        Picker("Address Type", selection: $kind) {
            ForEach(TrafficAddressKind.allCases) { kind in
                Text("\(kind.title) (\(counts[kind, default: 0].formatted()))").tag(kind)
            }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .fixedSize()
        .help("Network addresses (IPv4, IPv6) or addresses with their port (TCP, UDP)")
    }
}

// MARK: - ConversationsWindow

/// View ▸ Conversations: traffic between pairs of addresses (or address:port pairs)
/// across the sessions in view, with frames and bytes in each direction, span and
/// rate. Each row leads back to its sessions through a Session Expression.
struct ConversationsWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let sessions = coordinator.visibleSessions
        let all = TrafficStatistics.conversations(of: sessions, kind: kind)
        let rows = all.filter(matches).sorted(using: sortOrder)
        let origin = coordinator.trafficTimeline.firstTimedFrame
        Group {
            if all.isEmpty {
                ContentUnavailableView(
                    "No \(kind.title) Conversations in View",
                    systemImage: "arrow.left.arrow.right",
                    description: Text("None of the sessions in view is carried over \(kind.title).")
                )
            } else {
                table(rows, origin: origin)
            }
        }
        .searchable(text: $filter, placement: .toolbar, prompt: "Address or port")
        .toolbar {
            ToolbarItem(placement: .navigation) {
                TrafficKindPicker(kind: $kind, counts: TrafficStatistics.conversationCounts(of: sessions))
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) {
            footer(rows: rows, total: all.count, sessions: sessions.count)
        }
        .frame(minWidth: 720, minHeight: 320)
    }

    // MARK: Private

    @State private var kind: TrafficAddressKind = .ipv4
    @State private var filter = ""
    @State private var notice: String?
    @State private var selection: TrafficConversationRow.ID?
    @State private var sortOrder = [KeyPathComparator(\TrafficConversationRow.bytes, order: .reverse)]

    private func table(_ rows: [TrafficConversationRow], origin: Date?) -> some View {
        Table(rows, selection: $selection, sortOrder: $sortOrder) {
            TableColumn("Address A", value: \TrafficConversationRow.labelA) { (row: TrafficConversationRow) in
                Text(row.labelA).font(Theme.Typography.mono).lineLimit(1).truncationMode(.middle).help(row.labelA)
            }
            .width(min: 120, ideal: 170)
            TableColumn("Address B", value: \TrafficConversationRow.labelB) { (row: TrafficConversationRow) in
                Text(row.labelB).font(Theme.Typography.mono).lineLimit(1).truncationMode(.middle).help(row.labelB)
            }
            .width(min: 120, ideal: 170)
            TableColumn("Sessions", value: \TrafficConversationRow.sessionCount) { (row: TrafficConversationRow) in
                TrafficCells.number(row.sessionCount)
            }
            .width(min: 52, ideal: 60)
            TableColumn("Packets", value: \TrafficConversationRow.packets) { (row: TrafficConversationRow) in
                TrafficCells.number(row.packets)
            }
            .width(min: 52, ideal: 64)
            TableColumn("Bytes", value: \TrafficConversationRow.bytes) { (row: TrafficConversationRow) in
                TrafficCells.bytes(row.bytes)
            }
            .width(min: 60, ideal: 72)
            // A table takes ten columns per builder block; the directional ones are grouped.
            Group {
                TableColumn(
                    "Packets A → B",
                    value: \TrafficConversationRow.packetsAToB
                ) { (row: TrafficConversationRow) in
                    TrafficCells.number(row.packetsAToB)
                }
                .width(min: 60, ideal: 80)
                TableColumn("Bytes A → B", value: \TrafficConversationRow.bytesAToB) { (row: TrafficConversationRow) in
                    TrafficCells.bytes(row.bytesAToB)
                }
                .width(min: 60, ideal: 80)
                TableColumn(
                    "Packets B → A",
                    value: \TrafficConversationRow.packetsBToA
                ) { (row: TrafficConversationRow) in
                    TrafficCells.number(row.packetsBToA)
                }
                .width(min: 60, ideal: 80)
                TableColumn("Bytes B → A", value: \TrafficConversationRow.bytesBToA) { (row: TrafficConversationRow) in
                    TrafficCells.bytes(row.bytesBToA)
                }
                .width(min: 60, ideal: 80)
            }
            Group {
                TableColumn("Rel Start") { (row: TrafficConversationRow) in
                    Text(TrafficCells.relativeStart(row.start, origin: origin)).monospacedDigit()
                        .foregroundStyle(.secondary)
                }
                .width(min: 64, ideal: 76)
                TableColumn("Duration") { (row: TrafficConversationRow) in
                    Text(row.duration.map { SessionResponseTimes.durationLabel($0) } ?? "—")
                        .monospacedDigit().foregroundStyle(.secondary)
                }
                .width(min: 60, ideal: 72)
                TableColumn("Bits/s A → B") { (row: TrafficConversationRow) in
                    Text(TrafficCells.rate(row.bitsPerSecondAToB)).monospacedDigit().foregroundStyle(.secondary)
                }
                .width(min: 64, ideal: 84)
                TableColumn("Bits/s B → A") { (row: TrafficConversationRow) in
                    Text(TrafficCells.rate(row.bitsPerSecondBToA)).monospacedDigit().foregroundStyle(.secondary)
                }
                .width(min: 64, ideal: 84)
            }
        }
        .contextMenu(forSelectionType: TrafficConversationRow.ID.self) { ids in
            if let row = rows.first(where: { $0.id == ids.first }) {
                Button("Show Sessions (\(row.term))") {
                    coordinator.showSessions(narrowingWith: row.term)
                }
                Button("Copy as Session Expression") {
                    copy(row.term)
                }
                Divider()
                Button("Copy Row as CSV") {
                    copy(TrafficStatistics.csv([row]))
                }
            }
            Button("Copy All as CSV") {
                copy(TrafficStatistics.csv(rows))
            }
        } primaryAction: { ids in
            if let row = rows.first(where: { $0.id == ids.first }) {
                coordinator.showSessions(narrowingWith: row.term)
            }
        }
    }

    private func footer(rows: [TrafficConversationRow], total: Int, sessions: Int) -> some View {
        let selected = rows.first { $0.id == selection }
        return HStack(spacing: Theme.Metrics.spacingM) {
            Text(rows.count == total
                ? "\(total.formatted()) conversations from \(sessions.formatted()) sessions in view"
                : "Showing \(rows.count.formatted()) of \(total.formatted()) conversations")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            Spacer()
            if let notice {
                Text(notice).font(Theme.Typography.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Button("Save as CSV…") {
                notice = StatisticsExport.saveText(TrafficStatistics.csv(rows), suggestedName: "Conversations.csv")
            }
            .disabled(rows.isEmpty)
            .help("Save the rows shown as comma-separated values")
            Button("Show Sessions") {
                if let selected {
                    coordinator.showSessions(narrowingWith: selected.term)
                }
            }
            .disabled(selected == nil)
            .keyboardShortcut(.defaultAction)
            .help("Narrow the Session Expression in the main window to the selected conversation")
        }
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    private func matches(_ row: TrafficConversationRow) -> Bool {
        filter.isEmpty || row.labelA.localizedCaseInsensitiveContains(filter)
            || row.labelB.localizedCaseInsensitiveContains(filter)
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

// MARK: - TrafficCells

/// Cell formatting shared by Conversations and Endpoints.
enum TrafficCells {
    static func number(_ value: Int) -> some View {
        Text(value.formatted()).monospacedDigit()
    }

    static func bytes(_ value: Int) -> some View {
        Text(ByteUnits.string(Int64(value))).monospacedDigit()
    }

    /// Seconds since the capture's first timed frame, as Wireshark's "Rel Start".
    static func relativeStart(_ date: Date?, origin: Date?) -> String {
        guard let date, let origin else {
            return "—"
        }
        return String(format: "%.3f s", date.timeIntervalSince(origin))
    }

    /// A bit rate with SI units, or an em dash when the span gives no rate.
    static func rate(_ bitsPerSecond: Double?) -> String {
        guard let bitsPerSecond else {
            return "—"
        }
        let units = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s"]
        var value = bitsPerSecond
        var index = 0
        while value >= 1_000, index < units.count - 1 {
            value /= 1_000
            index += 1
        }
        return index == 0 ? "\(Int(value.rounded())) \(units[index])" : String(format: "%.1f ", value) + units[index]
    }
}
