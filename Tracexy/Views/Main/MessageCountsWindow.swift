import SwiftUI

// MARK: - MessageCountsWindow

/// Statistics ▸ Message Counts: the HTTP requests by method, HTTP responses by status and
/// DHCP messages by type counted in the sessions in view; every leaf leads back to
/// its sessions through a Session Expression term.
struct MessageCountsWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let sessions = coordinator.visibleSessions
        let roots = ApplicationMessageCounts.roots(of: sessions)
        Group {
            if roots.isEmpty {
                ContentUnavailableView(
                    "No HTTP or DHCP Messages in View",
                    systemImage: "list.number",
                    description: Text("Plain HTTP/1 requests and responses and DHCP messages are counted here.")
                )
            } else {
                Table(roots, children: \.children, selection: $selection) {
                    TableColumn("Message") { node in
                        Text(node.title)
                            .fontWeight(node.children != nil && node.term == nil ? .semibold : .regular)
                            .help(node.term.map { "Session Expression: \($0)" } ?? node.title)
                    }
                    .width(min: 160, ideal: 220)
                    TableColumn("Count") { node in
                        Text(node.messageCount.formatted()).monospacedDigit()
                    }
                    .width(min: 52, ideal: 64)
                    TableColumn("Sessions") { node in
                        Text(node.sessionCount.formatted()).monospacedDigit().foregroundStyle(.secondary)
                    }
                    .width(min: 56, ideal: 72)
                }
                .contextMenu(forSelectionType: ApplicationMessageNode.ID.self) { ids in
                    if let node = find(ids.first, in: roots), let term = node.term {
                        Button("Show Sessions (\(term))") {
                            coordinator.showSessions(narrowingWith: term)
                        }
                        Button("Copy as Session Expression") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(term, forType: .string)
                        }
                    }
                } primaryAction: { ids in
                    if let term = find(ids.first, in: roots)?.term {
                        coordinator.showSessions(narrowingWith: term)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) {
            footer(roots: roots, omitted: ApplicationMessageCounts.omittedCount(of: sessions))
        }
        .frame(minWidth: 420, minHeight: 300)
    }

    // MARK: Private

    @State private var selection: ApplicationMessageNode.ID?

    private func footer(roots: [ApplicationMessageNode], omitted: Int) -> some View {
        let selected = find(selection, in: roots)
        return HStack(spacing: Theme.Metrics.spacingM) {
            Text(omitted == 0
                ? "Counted from each frame's first 512 bytes"
                : "\(omitted.formatted()) more messages had kinds past the per-session bound")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .help("A message whose first line did not begin a captured frame is not counted.")
            Spacer()
            Button("Show Sessions") {
                if let term = selected?.term {
                    coordinator.showSessions(narrowingWith: term)
                }
            }
            .disabled(selected?.term == nil)
            .keyboardShortcut(.defaultAction)
            .help("Narrow the Session Expression in the main window to the selected row's sessions")
        }
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    private func find(_ id: ApplicationMessageNode.ID?, in nodes: [ApplicationMessageNode]) -> ApplicationMessageNode? {
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
