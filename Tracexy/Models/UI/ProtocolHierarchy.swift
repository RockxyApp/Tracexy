import Foundation

// MARK: - ProtocolHierarchyNode

/// One protocol path in the hierarchy (`UDP › DNS`), with the sessions whose
/// protocol stack begins with it and their bytes.
nonisolated struct ProtocolHierarchyNode: Identifiable, Hashable, Sendable {
    /// The protocols from the outermost shown layer to this one.
    let path: [ProtocolKind]
    let sessionCount: Int
    let byteCount: Int
    /// Sessions whose stack ends at this layer (no deeper protocol was named).
    let endingSessionCount: Int
    /// `nil` for a leaf, so a hierarchical table draws no disclosure triangle.
    var children: [ProtocolHierarchyNode]?

    var id: String {
        path.map(\.rawValue).joined(separator: "/")
    }

    var protocolKind: ProtocolKind {
        path[path.count - 1]
    }
}

// MARK: - ProtocolHierarchy

/// Wireshark's Protocol Hierarchy, counted in sessions: each session contributes
/// once to every prefix of its protocol stack (as the Sessions table names it,
/// network layers omitted), so a parent's count is at least the sum of its
/// children's. Sessions without a stack are counted in the total only.
///
/// Tunnel layers (GRE, VXLAN) are left out of the paths and listed as rows of their
/// own, so a TCP session inside VXLAN counts under TCP like any other. That keeps
/// every row equal to what its Show Sessions route lists: the sessions carrying
/// every protocol on the row.
nonisolated enum ProtocolHierarchy {
    // MARK: Internal

    /// The deepest level built, far beyond any stack the decoder names today.
    static let maximumDepth = 8
    static let tunnelKinds: Set<ProtocolKind> = [.gre, .vxlan]

    static func roots(of sessions: [SessionSummary]) -> [ProtocolHierarchyNode] {
        let paths = sessions.map { session in
            (Array(session.protocolStack.filter { !tunnelKinds.contains($0) }.prefix(maximumDepth)), session.totalBytes)
        }
        var roots = build(paths, prefix: [])
        for tunnel in tunnelKinds.sorted(by: { $0.rawValue < $1.rawValue }) {
            let carried = sessions.filter { $0.protocolStack.contains(tunnel) }
            guard !carried.isEmpty else {
                continue
            }
            roots.append(ProtocolHierarchyNode(
                path: [tunnel],
                sessionCount: carried.count,
                byteCount: carried.reduce(0) { $0 + $1.totalBytes },
                endingSessionCount: 0,
                children: nil
            ))
        }
        return roots
    }

    // MARK: Private

    private static func build(_ entries: [([ProtocolKind], Int)], prefix: [ProtocolKind]) -> [ProtocolHierarchyNode] {
        let depth = prefix.count
        var groups: [ProtocolKind: [([ProtocolKind], Int)]] = [:]
        var order: [ProtocolKind] = []
        for entry in entries where entry.0.count > depth {
            let kind = entry.0[depth]
            if groups[kind] == nil {
                order.append(kind)
            }
            groups[kind, default: []].append(entry)
        }
        let nodes = order.map { kind -> ProtocolHierarchyNode in
            let members = groups[kind] ?? []
            let path = prefix + [kind]
            let children = build(members, prefix: path)
            return ProtocolHierarchyNode(
                path: path,
                sessionCount: members.count,
                byteCount: members.reduce(0) { $0 + $1.1 },
                endingSessionCount: members.filter { $0.0.count == path.count }.count,
                children: children.isEmpty ? nil : children
            )
        }
        return nodes.sorted { lhs, rhs in
            lhs.byteCount != rhs.byteCount ? lhs.byteCount > rhs.byteCount : lhs.protocolKind.label < rhs.protocolKind
                .label
        }
    }
}

// MARK: - CSV

extension ProtocolHierarchyNode {
    /// Wireshark's Protocol Hierarchy as CSV: each protocol indented by depth, its
    /// sessions and bytes, and their shares of the whole view.
    static func csv(_ roots: [ProtocolHierarchyNode], totalSessions: Int, totalBytes: Int) -> String {
        var lines = ["Protocol,Sessions,Percent Sessions,Bytes,Percent Bytes"]
        func percent(_ part: Int, _ whole: Int) -> String {
            whole > 0 ? String(format: "%.2f", Double(part) / Double(whole) * 100) : ""
        }
        func walk(_ nodes: [ProtocolHierarchyNode], depth: Int) {
            for node in nodes {
                lines.append([
                    String(repeating: "  ", count: depth) + node.protocolKind.label,
                    String(node.sessionCount), percent(node.sessionCount, totalSessions),
                    String(node.byteCount), percent(node.byteCount, totalBytes),
                ].joined(separator: ","))
                walk(node.children ?? [], depth: depth + 1)
            }
        }
        walk(roots, depth: 0)
        return lines.joined(separator: "\r\n") + "\r\n"
    }
}
