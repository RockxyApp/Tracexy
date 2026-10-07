import AppKit
import SwiftUI

// MARK: - FindingsWindow

/// Statistics ▸ Findings: every typed finding in the sessions in view, grouped by kind
/// like Wireshark's Expert Information. A group leads to its sessions through a
/// `finding ==` term; an occurrence opens its session and first cited frame.
struct FindingsWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let visible = coordinator.visibleSessions
        let visibleIDs = Set(visible.map(\.id))
        let inView = coordinator.findings.filter { visibleIDs.contains($0.sessionID) }
        let hosts = Dictionary(visible.map { ($0.id, $0.host) }, uniquingKeysWith: { first, _ in first })
        let nodes = FindingsSummary.nodes(
            of: inView, hosts: hosts, floor: floor, search: search, grouped: isGrouped
        )
        Group {
            if inView.isEmpty {
                ContentUnavailableView(
                    "No Findings in View",
                    systemImage: "checkmark.seal",
                    description: Text("None of the sessions in view has a typed finding.")
                )
            } else if nodes.isEmpty {
                ContentUnavailableView.search(text: search)
            } else {
                table(nodes)
            }
        }
        .searchable(text: $search, placement: .toolbar, prompt: "Summary or host")
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Picker("Severity", selection: $floor) {
                    ForEach(FindingsSummary.SeverityFloor.allCases) { floor in
                        Text(floor.title).tag(floor)
                    }
                }
                .labelsHidden()
                .fixedSize()
                .help("Show every finding, or only warnings")
            }
            ToolbarItem(placement: .navigation) {
                Toggle("Group by Kind", isOn: $isGrouped)
                    .toggleStyle(.checkbox)
                    .help("One row per kind of finding, or one row per finding")
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) {
            footer(nodes: nodes, inView: inView)
        }
        .frame(minWidth: 620, minHeight: 320)
    }

    // MARK: Private

    @State private var selection: FindingsSummaryNode.ID?
    @State private var search = ""
    @State private var floor: FindingsSummary.SeverityFloor = .all
    @State private var isGrouped = true

    private func table(_ nodes: [FindingsSummaryNode]) -> some View {
        Table(nodes, children: \.children, selection: $selection) {
            TableColumn("Severity") { node in
                // An occurrence sits indented under its group, which already names the
                // severity; the icon alone keeps the column from truncating.
                if node.isGroup || !isGrouped {
                    Label(FindingsSummary.severityTitle(node.severity), systemImage: node.severity.systemImage)
                        .foregroundStyle(node.severity.tint)
                        .labelStyle(.titleAndIcon)
                } else {
                    Image(systemName: node.severity.systemImage)
                        .foregroundStyle(node.severity.tint)
                        .accessibilityLabel(FindingsSummary.severityTitle(node.severity))
                }
            }
            .width(min: 84, ideal: 96)
            TableColumn("Summary") { node in
                Text(node.title)
                    .fontWeight(node.isGroup ? .semibold : .regular)
                    .lineLimit(1)
                    .help(node.finding?.subtitle ?? node.title)
            }
            .width(min: 180, ideal: 260)
            TableColumn("Where") { node in
                Text(node.detail)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .foregroundStyle(.secondary)
                    .help(node.term.map { "Session Expression: \($0)" } ?? node.detail)
            }
            .width(min: 110, ideal: 150)
            TableColumn("Count") { node in
                Text(node.findingCount.formatted()).monospacedDigit()
            }
            .width(min: 44, ideal: 52)
            TableColumn("Sessions") { node in
                Text(node.sessionCount.formatted()).monospacedDigit().foregroundStyle(.secondary)
            }
            .width(min: 52, ideal: 64)
            TableColumn("Cited Frames") { node in
                Text(node.citedFrameCount.formatted()).monospacedDigit().foregroundStyle(.secondary)
            }
            .width(min: 60, ideal: 80)
        }
        .contextMenu(forSelectionType: FindingsSummaryNode.ID.self) { ids in
            if let node = find(ids.first, in: nodes) {
                menu(for: node)
            }
        } primaryAction: { ids in
            if let node = find(ids.first, in: nodes) {
                open(node)
            }
        }
    }

    @ViewBuilder
    private func menu(for node: FindingsSummaryNode) -> some View {
        if let finding = node.finding {
            Button("Open Session and Cited Frame") {
                coordinator.revealFinding(finding)
            }
        }
        if let term = node.term {
            Button("Show Sessions (\(term))") {
                coordinator.showSessions(narrowingWith: term)
            }
            Button("Copy as Session Expression") {
                copy(term)
            }
        }
        Divider()
        Button("Copy") {
            copy(FindingsSummary.copyText([node] + (node.children ?? [])))
        }
    }

    private func footer(nodes: [FindingsSummaryNode], inView: [Finding]) -> some View {
        let selected = find(selection, in: nodes)
        let counts = FindingsSummary.severityCounts(of: inView)
        let warnings = counts[.warning, default: 0] + counts[.error, default: 0]
        let notes = counts[.note, default: 0]
        return HStack(spacing: Theme.Metrics.spacingM) {
            Text(
                "\(warnings.formatted()) warnings, \(notes.formatted()) notes in \(coordinator.visibleSessions.count.formatted()) sessions in view"
            )
            .font(Theme.Typography.caption)
            .foregroundStyle(.secondary)
            .lineLimit(1)
            Spacer()
            Button(selected?.isGroup == false ? "Open Frame" : "Show Sessions") {
                if let selected {
                    open(selected)
                }
            }
            .disabled(selected == nil)
            .keyboardShortcut(.defaultAction)
            .help("Open the selected finding's session and first cited frame, or narrow to a kind's sessions")
        }
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    private func open(_ node: FindingsSummaryNode) {
        if let finding = node.finding {
            coordinator.revealFinding(finding)
        } else if let term = node.term {
            coordinator.showSessions(narrowingWith: term)
        }
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    private func find(_ id: FindingsSummaryNode.ID?, in nodes: [FindingsSummaryNode]) -> FindingsSummaryNode? {
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
