import SwiftUI

// MARK: - StatsTreeTable

/// A Wireshark statistics tree as an outline of any depth — topic, count, average,
/// minimum and maximum — every row opening expanded as Wireshark shows its trees.
/// Levels open one pass at a time: the outline drops the expansion of a row under a
/// parent it is expanding in the same pass (found natively on Label Stats).
struct StatsTreeTable: View {
    // MARK: Internal

    let roots: [StatsTreeNode]

    var body: some View {
        Table(of: StatsTreeNode.self) {
            TableColumn("Topic / Item") { node in
                Text(node.title).lineLimit(1).truncationMode(.middle).help(node.title)
            }
            .width(min: 220, ideal: 300)
            TableColumn("Count") { node in
                Text(node.count.formatted()).monospacedDigit().frame(maxWidth: .infinity, alignment: .trailing)
            }
            .width(min: 50, ideal: 70)
            TableColumn("Average") { node in number(node.average) }
                .width(min: 60, ideal: 80)
            TableColumn("Min") { node in number(node.minimum) }
                .width(min: 50, ideal: 70)
            TableColumn("Max") { node in number(node.maximum) }
                .width(min: 50, ideal: 70)
        } rows: {
            StatsTreeRows(nodes: roots, depth: 0) { node, depth in expanded(node, depth: depth) }
        }
        .task(id: roots) { await revealLevels() }
        .onDisappear { revealedDepth = 0 }
    }

    /// Levels in `nodes` below and including them.
    static func depth(_ nodes: [StatsTreeNode]) -> Int {
        nodes.map { 1 + depth($0.children ?? []) }.max() ?? 0
    }

    // MARK: Private

    /// Collapsed rows; every row starts expanded, as Wireshark shows its trees.
    @State private var collapsed: Set<String> = []
    @State private var revealedDepth = 0

    private func number(_ value: Double?) -> some View {
        Text(value.map { $0.formatted(.number.precision(.fractionLength(2))) } ?? "")
            .monospacedDigit()
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .trailing)
    }

    /// Steps in only new, deeper levels, so a live refresh never re-folds what is open.
    private func revealLevels() async {
        let target = Self.depth(roots)
        while revealedDepth < target {
            try? await Task.sleep(for: .milliseconds(20))
            revealedDepth += 1
        }
    }

    private func expanded(_ node: StatsTreeNode, depth: Int) -> Binding<Bool> {
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
}

// MARK: - StatsTreeRows

private struct StatsTreeRows: TableRowContent {
    let nodes: [StatsTreeNode]
    let depth: Int
    let isExpanded: (StatsTreeNode, Int) -> Binding<Bool>

    var tableRowBody: some TableRowContent<StatsTreeNode> {
        ForEach(nodes) { node in
            if let children = node.children {
                DisclosureTableRow(node, isExpanded: isExpanded(node, depth)) {
                    StatsTreeRows(nodes: children, depth: depth + 1, isExpanded: isExpanded)
                }
            } else {
                TableRow(node)
            }
        }
    }
}
