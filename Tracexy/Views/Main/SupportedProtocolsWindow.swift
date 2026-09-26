import SwiftUI

// MARK: - SupportedProtocolsWindow

/// Help ▸ Supported Protocols: what Tracexy recognizes, what it reads from each, the
/// Session Expression keyword for it and how many sessions of the open capture carry
/// it — Wireshark's View ▸ Internals ▸ Supported Protocols, ending in Show Sessions.
struct SupportedProtocolsWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let rows = SupportedProtocols.rows
        let counts = Self.sessionCounts(coordinator.presentedSessions)
        Table(rows, selection: $selection) {
            TableColumn("Protocol") { row in
                Text(row.kind.label)
                    .font(Theme.Typography.badge)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .tracexyChipStyle(tint: Theme.color(for: row.kind), isActive: true)
            }
            .width(min: 60, ideal: 70)
            TableColumn("Name") { row in
                Text(row.name).lineLimit(1).help(row.name)
            }
            .width(min: 160, ideal: 230)
            TableColumn("Read") { row in
                Text(row.reads).foregroundStyle(.secondary).lineLimit(1).help(row.reads)
            }
            .width(min: 200, ideal: 340)
            TableColumn("Expression") { row in
                Text(row.keywords.joined(separator: ", ")).font(Theme.Typography.mono)
            }
            .width(min: 70, ideal: 90)
            TableColumn("Sessions") { row in
                Text((counts[row.kind] ?? 0).formatted()).monospacedDigit()
                    .foregroundStyle(counts[row.kind] == nil ? .tertiary : .primary)
                    .frame(maxWidth: .infinity, alignment: .trailing)
            }
            .width(min: 56, ideal: 70)
        }
        .contextMenu(forSelectionType: SupportedProtocolRow.ID.self) { ids in
            if let row = rows.first(where: { ids.contains($0.id) }), let keyword = row.keywords.first {
                Button("Show Sessions") { coordinator.showSessions(narrowingWith: keyword) }
                    .disabled(counts[row.kind] == nil)
            }
        } primaryAction: { ids in
            if let row = rows.first(where: { ids.contains($0.id) }), let keyword = row.keywords.first,
               counts[row.kind] != nil
            {
                coordinator.showSessions(narrowingWith: keyword)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) { footer(rows: rows, counts: counts) }
        .frame(minWidth: 640, minHeight: 360)
    }

    /// Sessions of each protocol in `sessions`, counting a session once per protocol
    /// in its stack.
    static func sessionCounts(_ sessions: [SessionSummary]) -> [ProtocolKind: Int] {
        var counts: [ProtocolKind: Int] = [:]
        for session in sessions {
            for kind in Set(session.protocolStack) {
                counts[kind, default: 0] += 1
            }
        }
        return counts
    }

    // MARK: Private

    @State private var selection: SupportedProtocolRow.ID?

    private func footer(rows: [SupportedProtocolRow], counts: [ProtocolKind: Int]) -> some View {
        let selected = rows.first { $0.id == selection }
        return HStack(spacing: Theme.Metrics.spacingM) {
            Text("\(rows.count) protocols, \(counts.count) in this capture")
            Spacer()
            Button("Show Sessions") {
                if let keyword = selected?.keywords.first {
                    coordinator.showSessions(narrowingWith: keyword)
                }
            }
            .disabled(selected?.keywords.first == nil || selected.map { counts[$0.kind] == nil } ?? true)
            .keyboardShortcut(.defaultAction)
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }
}
