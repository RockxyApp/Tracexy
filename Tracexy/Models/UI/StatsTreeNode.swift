import Foundation

// MARK: - StatsTreeNode

/// One row of a statistics tree (Statistics ▸ DNS, ▸ SIP): a topic with its count
/// and, for measured topics (sizes, counts, times), the average, minimum and maximum.
struct StatsTreeNode: Identifiable, Hashable {
    let id: String
    let title: String
    let count: Int
    var average: Double?
    var minimum: Double?
    var maximum: Double?
    /// `nil` for a leaf.
    var children: [StatsTreeNode]?

    /// No frame counted here (`count < 1`, which the formatter leaves alone).
    var isEmpty: Bool {
        count < 1
    }

    /// Stats-tree CSV: the topic indented by depth, count, average, minimum, maximum.
    static func csv(_ nodes: [Self]) -> String {
        var lines = ["Topic / Item,Count,Average,Min,Max"]
        func number(_ value: Double?) -> String {
            value.map { String(format: "%.2f", $0) } ?? ""
        }
        func walk(_ nodes: [Self], depth: Int) {
            for node in nodes {
                lines.append([
                    String(repeating: "  ", count: depth) + node.title, String(node.count),
                    number(node.average), number(node.minimum), number(node.maximum),
                ].joined(separator: ","))
                walk(node.children ?? [], depth: depth + 1)
            }
        }
        walk(nodes, depth: 0)
        return lines.joined(separator: "\r\n") + "\r\n"
    }
}

// MARK: - StatsTreeOrder

/// The order a Wireshark stats tree prints its children in (`stats_tree_sort_compare`
/// by count, descending): most counted first, and ties by name — also descending,
/// since descending order reverses the whole comparison — compared byte-wise as
/// `strcmp` does.
nonisolated enum StatsTreeOrder {
    static func precedes(count: Int, name: String, before otherCount: Int, _ otherName: String) -> Bool {
        count == otherCount ? Array(otherName.utf8).lexicographicallyPrecedes(name.utf8) : count > otherCount
    }
}
