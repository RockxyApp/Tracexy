import AppKit
import SwiftUI
import UniformTypeIdentifiers

// MARK: - HTTPStatisticsWindow

/// Statistics ▸ HTTP: Wireshark's HTTP Requests, Load Distribution and Packet
/// Counter trees over the frames the All Frames list shows, as one outline table
/// per tree. Copy or save a tree as CSV.
struct HTTPStatisticsWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        @Bindable var frames = coordinator.allFrames
        let inView = Set(coordinator.visibleSessions.map(\.id))
        let statistics = HTTPStatistics(rows: frames.visibleRows(sessionsInView: inView))
        Group {
            if frames.isLoading {
                ProgressView("Listing frames…")
                    .controlSize(.small)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let error = frames.error {
                ContentUnavailableView(
                    "HTTP Statistics Unavailable",
                    systemImage: "globe",
                    description: Text(error)
                )
            } else if statistics.isEmpty {
                ContentUnavailableView(
                    "No HTTP Requests",
                    systemImage: "globe",
                    description: Text("No HTTP/1 request or response line was read in the frames in view.")
                )
            } else {
                VStack(spacing: 0) {
                    Picker("Statistics", selection: $tree) {
                        ForEach(HTTPStatistics.Tree.allCases) { tree in
                            Text(tree.title).tag(tree)
                        }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .fixedSize()
                    .padding(.vertical, Theme.Metrics.spacingM)
                    table(statistics.nodes(tree))
                }
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
            footer(statistics)
        }
        .frame(minWidth: 640, minHeight: 360)
        .onAppear { coordinator.loadAllFrames() }
    }

    // MARK: Private

    @State private var tree: HTTPStatistics.Tree = .requests
    @State private var notice: String?
    /// Collapsed rows; every row starts expanded, as Wireshark shows its trees.
    @State private var collapsed: Set<String> = []
    /// How many levels of Request Sequences are open so far (see ``revealLevels``).
    @State private var revealedDepth = 0

    @TableColumnBuilder<HTTPStatisticsNode, Never>
    private var columns: some TableColumnContent<HTTPStatisticsNode, Never> {
        TableColumn("Topic / Item") { node in
            Text(node.title)
                .lineLimit(1)
                .truncationMode(.middle)
                .help(node.title)
        }
        .width(min: 240, ideal: 420)
        TableColumn("Count") { node in
            Text(node.count.formatted())
                .monospacedDigit()
                .frame(maxWidth: .infinity, alignment: .trailing)
        }
        .width(min: 60, ideal: 80)
        TableColumn("Percent") { node in
            Text(node.share.map { $0.formatted(.percent.precision(.fractionLength(2))) } ?? "")
                .monospacedDigit()
                .frame(maxWidth: .infinity, alignment: .trailing)
        }
        .width(min: 60, ideal: 80)
    }

    /// The tree as an outline, up to four levels deep (Load Distribution's
    /// server ▸ address ▸ host).
    @ViewBuilder
    private func table(_ roots: [HTTPStatisticsNode]) -> some View {
        if tree == .sequences {
            if roots.isEmpty {
                ContentUnavailableView(
                    "No Request Sequences",
                    systemImage: "arrow.triangle.branch",
                    description: Text(
                        "No HTTP request in the frames in view named a Referer, and no response redirected one."
                    )
                )
            } else {
                // A referer chain has no fixed depth, so its rows nest recursively.
                Table(of: HTTPStatisticsNode.self) {
                    columns
                } rows: {
                    HTTPStatisticsTreeRows(nodes: roots, depth: 0) { node, depth in
                        expanded(node, depth: depth)
                    }
                }
                .task(id: roots) { await revealLevels(of: roots) }
                .onDisappear { revealedDepth = 0 }
            }
        } else {
            fixedDepthTable(roots)
        }
    }

    private func fixedDepthTable(_ roots: [HTTPStatisticsNode]) -> some View {
        Table(of: HTTPStatisticsNode.self) {
            columns
        } rows: {
            ForEach(roots) { root in
                DisclosureTableRow(root, isExpanded: expanded(root)) {
                    ForEach(root.children ?? []) { second in
                        if let thirds = second.children {
                            DisclosureTableRow(second, isExpanded: expanded(second)) {
                                ForEach(thirds) { third in
                                    if let fourths = third.children {
                                        DisclosureTableRow(third, isExpanded: expanded(third)) {
                                            ForEach(fourths) { TableRow($0) }
                                        }
                                    } else {
                                        TableRow(third)
                                    }
                                }
                            }
                        } else {
                            TableRow(second)
                        }
                    }
                }
            }
        }
    }

    private func footer(_ statistics: HTTPStatistics) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Text(notice ?? String(localized: """
            \(statistics.requestCount.formatted()) requests, \(statistics.responseCount.formatted()) responses
            """))
            Spacer()
            Button("Copy as CSV") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(statistics.csv(tree), forType: .string)
            }
            .disabled(statistics.isEmpty)
            Button("Save as CSV…") { save(statistics) }
                .disabled(statistics.isEmpty)
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    /// Opens a recursive outline one level per pass: the outline drops the expansion
    /// of a row under a parent it is expanding in the same pass (see
    /// `StatsTreeWindow.isTableSettled`), so deeper rows report expanded only after
    /// the level above them has.
    private func revealLevels(of roots: [HTTPStatisticsNode]) async {
        func depth(_ nodes: [HTTPStatisticsNode]) -> Int {
            nodes.map { 1 + depth($0.children ?? []) }.max() ?? 0
        }
        // Only new, deeper levels are stepped in, so a live refresh never re-folds
        // what is already open; switching trees starts again from the top.
        let target = depth(roots)
        while revealedDepth < target {
            try? await Task.sleep(for: .milliseconds(20))
            revealedDepth += 1
        }
    }

    private func expanded(_ node: HTTPStatisticsNode, depth: Int) -> Binding<Bool> {
        Binding(
            get: { depth <= revealedDepth && !collapsed.contains(node.id) },
            set: { isExpanded in
                if isExpanded {
                    collapsed.remove(node.id)
                } else {
                    collapsed.insert(node.id)
                }
            }
        )
    }

    private func expanded(_ node: HTTPStatisticsNode) -> Binding<Bool> {
        Binding(
            get: { !collapsed.contains(node.id) },
            set: { isExpanded in
                if isExpanded {
                    collapsed.remove(node.id)
                } else {
                    collapsed.insert(node.id)
                }
            }
        )
    }

    private func save(_ statistics: HTTPStatistics) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "HTTP \(tree.title).csv"
        panel.allowedContentTypes = [.commaSeparatedText]
        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }
        do {
            try Data(statistics.csv(tree).utf8).write(to: url, options: .atomic)
            notice = nil
        } catch {
            notice = String(localized: "Couldn’t save the statistics: \(error.localizedDescription)")
        }
    }
}

// MARK: - HTTPStatisticsTreeRows

/// Outline rows of any depth, every one starting expanded as Wireshark shows its
/// trees.
private struct HTTPStatisticsTreeRows: TableRowContent {
    let nodes: [HTTPStatisticsNode]
    let depth: Int
    let isExpanded: (HTTPStatisticsNode, Int) -> Binding<Bool>

    var tableRowBody: some TableRowContent<HTTPStatisticsNode> {
        ForEach(nodes) { node in
            if let children = node.children {
                DisclosureTableRow(node, isExpanded: isExpanded(node, depth)) {
                    HTTPStatisticsTreeRows(nodes: children, depth: depth + 1, isExpanded: isExpanded)
                }
            } else {
                TableRow(node)
            }
        }
    }
}
