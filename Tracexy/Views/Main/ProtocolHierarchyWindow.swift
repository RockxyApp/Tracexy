import AppKit
import SwiftUI

// MARK: - ProtocolHierarchyWindow

/// Statistics ▸ Protocol Hierarchy: the sessions in view grouped by protocol path, with
/// their share of sessions and bytes; every row leads back to its sessions.
struct ProtocolHierarchyWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let sessions = coordinator.visibleSessions
        let roots = ProtocolHierarchy.roots(of: sessions)
        let totalSessions = max(1, sessions.count)
        let totalBytes = max(1, sessions.reduce(0) { $0 + $1.totalBytes })
        Group {
            if roots.isEmpty {
                ContentUnavailableView(
                    "No Sessions in View",
                    systemImage: "square.stack.3d.up",
                    description: Text("Open or capture traffic, or widen the scope, to see its protocols.")
                )
            } else {
                Table(roots, children: \.children, selection: $selection) {
                    TableColumn("Protocol") { node in
                        Text(node.protocolKind.label)
                            .foregroundStyle(Theme.color(for: node.protocolKind))
                            .help(node.path.map(\.label).joined(separator: " › "))
                    }
                    .width(min: 130, ideal: 170)
                    TableColumn("Sessions") { node in
                        Text(node.sessionCount.formatted()).monospacedDigit()
                    }
                    .width(min: 56, ideal: 72)
                    TableColumn("% Sessions") { node in
                        Text(Self.percent(node.sessionCount, of: totalSessions)).monospacedDigit()
                            .foregroundStyle(.secondary)
                    }
                    .width(min: 64, ideal: 82)
                    TableColumn("Bytes") { node in
                        Text(ByteUnits.string(Int64(node.byteCount))).monospacedDigit()
                    }
                    .width(min: 64, ideal: 82)
                    TableColumn("% Bytes") { node in
                        Text(Self.percent(node.byteCount, of: totalBytes)).monospacedDigit()
                            .foregroundStyle(.secondary)
                    }
                    .width(min: 56, ideal: 72)
                }
                .contextMenu(forSelectionType: ProtocolHierarchyNode.ID.self) { ids in
                    if let node = find(ids.first, in: roots) {
                        Button("Show Sessions with \(node.path.map(\.label).joined(separator: " and "))") {
                            coordinator.showSessionsForProtocolPath(node.path)
                        }
                    }
                } primaryAction: { ids in
                    if let node = find(ids.first, in: roots) {
                        coordinator.showSessionsForProtocolPath(node.path)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) {
            footer(roots: roots, sessionCount: sessions.count, csv: ProtocolHierarchyNode.csv(
                roots, totalSessions: sessions.count, totalBytes: sessions.reduce(0) { $0 + $1.totalBytes }
            ))
        }
        .frame(minWidth: 520, minHeight: 320)
    }

    // MARK: Private

    @State private var selection: ProtocolHierarchyNode.ID?
    @State private var notice: String?

    private func footer(roots: [ProtocolHierarchyNode], sessionCount: Int, csv: String) -> some View {
        let selected = find(selection, in: roots)
        return HStack(spacing: Theme.Metrics.spacingM) {
            Text(sessionCount == coordinator.presentedSessions.count
                ? "\(sessionCount.formatted()) sessions"
                : "\(sessionCount.formatted()) of \(coordinator.presentedSessions.count.formatted()) sessions in view")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
            Spacer()
            if let notice {
                Text(notice).font(Theme.Typography.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Button("Copy as CSV") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(csv, forType: .string)
            }
            .disabled(roots.isEmpty)
            Button("Save as CSV…") {
                notice = StatisticsExport.saveText(csv, suggestedName: "Protocol Hierarchy.csv")
            }
            .disabled(roots.isEmpty)
            Button("Show Sessions") {
                if let selected {
                    coordinator.showSessionsForProtocolPath(selected.path)
                }
            }
            .disabled(selected == nil)
            .keyboardShortcut(.defaultAction)
            .help("Show the sessions that carry every protocol on the selected row")
        }
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    private static func percent(_ part: Int, of whole: Int) -> String {
        (Double(part) / Double(whole)).formatted(.percent.precision(.fractionLength(1)))
    }

    private func find(_ id: ProtocolHierarchyNode.ID?, in nodes: [ProtocolHierarchyNode]) -> ProtocolHierarchyNode? {
        guard let id else {
            return nil
        }
        for node in nodes {
            if node.id == id {
                return node
            }
            if let match = find(id, in: node.children ?? []) {
                return match
            }
        }
        return nil
    }
}
