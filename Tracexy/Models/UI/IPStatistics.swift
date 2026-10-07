import Foundation

// MARK: - IPStatistics

/// Statistics ▸ IPv4 and IPv6: Wireshark's five IP stats trees
/// (`plugins/epan/stats_tree/pinfo_stats_tree.c`), counted over the frames in view —
/// All Addresses, IP Protocol Types, Source and Destination Addresses, Destinations and
/// Ports, and Source TTLs (Source Hop Limits for IPv6).
nonisolated enum IPStatistics {
    // MARK: Internal

    enum Tree: String, CaseIterable, Identifiable, Sendable {
        case allAddresses
        case protocolTypes
        case sourcesAndDestinations
        case destinationsAndPorts
        case sourceHopLimits

        // MARK: Internal

        var id: String {
            rawValue
        }

        /// tshark's `-z` name for the IPv4 tree; IPv6 adds its own prefix.
        var tapName: String {
            switch self {
            case .allAddresses: "ip_hosts"
            case .protocolTypes: "ptype"
            case .sourcesAndDestinations: "ip_srcdst"
            case .destinationsAndPorts: "dests"
            case .sourceHopLimits: "ip_ttl"
            }
        }

        func title(ipv6: Bool) -> String {
            switch self {
            case .allAddresses: String(localized: "All Addresses")
            case .protocolTypes: String(localized: "IP Protocol Types")
            case .sourcesAndDestinations: String(localized: "Source and Destination Addresses")
            case .destinationsAndPorts: String(localized: "Destinations and Ports")
            case .sourceHopLimits:
                if ipv6 {
                    String(localized: "Source Hop Limits")
                } else {
                    String(localized: "Source TTLs")
                }
            }
        }
    }

    static func tree(_ tree: Tree, ipv6: Bool, rows: [CaptureFrameRow]) -> [StatsTreeNode] {
        let ticks = rows.compactMap(\.ip).flatMap { fact in
            fact.headers.filter { $0.isIPv6 == ipv6 }.map { (fact, $0.hopLimit) }
        }
        guard !ticks.isEmpty else {
            return []
        }
        var builder = Builder()
        let root = tree.title(ipv6: ipv6)
        let version = ipv6 ? "IPv6" : "IPv4"
        for (fact, hopLimit) in ticks {
            switch tree {
            case .allAddresses:
                builder.tick([root])
                builder.tick([root, fact.source])
                builder.tick([root, fact.destination])
            case .protocolTypes:
                builder.tick([root])
                builder.tick([root, fact.portType])
            case .sourcesAndDestinations:
                builder.tick(["Source \(version) Addresses"])
                builder.tick(["Source \(version) Addresses", fact.source])
                builder.tick(["Destination \(version) Addresses"])
                builder.tick(["Destination \(version) Addresses", fact.destination])
            case .destinationsAndPorts:
                builder.tickPath([root, fact.destination, fact.portType, String(fact.destinationPort)])
            case .sourceHopLimits:
                builder.tickPath([root, fact.source, String(hopLimit), fact.destination])
            }
        }
        // The source branch always leads (ST_FLG_SORT_TOP); other roots keep their order.
        return builder.nodes(sortingRoots: false)
    }

    // MARK: Private

    /// Wireshark's `tick_stat_node`: each tick counts one node, named under its parent.
    private struct Builder {
        // MARK: Internal

        mutating func tick(_ path: [String]) {
            counts[path, default: 0] += 1
            if counts[path] == 1 {
                let parent = Array(path.dropLast())
                children[parent, default: []].append(path)
            }
        }

        /// Ticks every level of `path`, as the nested trees do.
        mutating func tickPath(_ path: [String]) {
            for depth in 1 ... path.count {
                tick(Array(path.prefix(depth)))
            }
        }

        func nodes(sortingRoots: Bool) -> [StatsTreeNode] {
            node(children: children[[]] ?? [], sorted: sortingRoots)
        }

        // MARK: Private

        private var counts: [[String]: Int] = [:]
        private var children: [[String]: [[String]]] = [:]

        private func node(children paths: [[String]], sorted: Bool) -> [StatsTreeNode] {
            let ordered = sorted ? paths.sorted { lhs, rhs in
                StatsTreeOrder.precedes(
                    count: counts[lhs] ?? 0, name: lhs.last ?? "", before: counts[rhs] ?? 0, rhs.last ?? ""
                )
            } : paths
            return ordered.map { path in
                let below = children[path] ?? []
                return StatsTreeNode(
                    id: path.joined(separator: "\u{1F}"), title: path.last ?? "", count: counts[path] ?? 0,
                    children: below.isEmpty ? nil : node(children: below, sorted: true)
                )
            }
        }
    }
}
