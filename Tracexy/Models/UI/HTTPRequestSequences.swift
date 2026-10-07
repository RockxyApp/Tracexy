import Foundation

// MARK: - HTTPRequestSequences

/// Statistics ▸ HTTP ▸ Request Sequences, as Wireshark's `http_seq` stats tree
/// (`tshark -z http_seq,tree`): each request filed under the page that referred to
/// it, and each redirect's target under the request it answered, so the tree reads
/// as the order a browser walked a site. Ported from `packet-http.c` with its
/// counting kept exactly: when a URI is seen again it is counted where it was last
/// placed, and every ancestor of a referer is counted once more per request.
nonisolated enum HTTPRequestSequences {
    // MARK: Internal

    static let rootTitle = "HTTP Request Sequences"

    static func tree(rows: [CaptureFrameRow]) -> [HTTPStatisticsNode] {
        var tree = Tree()
        // Per connection, the latest request: its full URI, and whether a final
        // response has already answered it (Wireshark's `req_res_tail`).
        var latest: [UUID: (fullURI: String?, isRequest: Bool, isAnswered: Bool)] = [:]
        for row in rows {
            switch row.http {
            case let .request(_, host, uri, referer):
                let full = fullURI(host: host, uri: uri)
                if let key = row.sessionID {
                    latest[key] = (full, true, false)
                }
                if let referer, let full {
                    tree.record(full, after: referer)
                }
            case let .response(status, location):
                guard let key = row.sessionID else {
                    continue
                }
                var tail = latest[key]
                if tail == nil || tail?.isAnswered == true {
                    tail = (nil, false, false)
                }
                if status >= 200 {
                    tail?.isAnswered = true
                }
                latest[key] = tail
                if let location, tail?.isRequest == true, let base = tail?.fullURI,
                   let target = locationTarget(base: base, location: location)
                {
                    tree.record(target, after: base)
                }
            case nil:
                break
            }
        }
        return tree.isEmpty ? [] : [tree.node(1, share: nil)]
    }

    /// `http://` + Host + URI, or the URI itself when it is already absolute or the
    /// method is CONNECT; `nil` without a Host, as Wireshark leaves `full_uri` unset.
    static func fullURI(host: String, uri: String) -> String? {
        let trimmed = host.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, trimmed != "—" else {
            return nil
        }
        let lower = uri.lowercased()
        if lower.hasPrefix("http://") || lower.hasPrefix("https://") {
            return uri
        }
        return "http://\(trimmed)\(uri)"
    }

    /// `determine_http_location_target`: Wireshark's shortcut resolution of a
    /// Location against the request's full URI; `nil` where it gives up.
    static func locationTarget(base: String, location: String) -> String? {
        guard let schemeEnd = base.range(of: "://") else {
            return nil
        }
        if location.isEmpty {
            return base
        }
        if location.hasPrefix("//") {
            return "\(base[..<schemeEnd.lowerBound]):\(location)"
        }
        if location.contains("://") {
            return location
        }
        let noFragment = base.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first
            .map(String.init) ?? base
        let noQuery = noFragment.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false).first
            .map(String.init) ?? noFragment
        if location.hasPrefix("?") {
            return noQuery + location
        }
        guard let authority = noQuery.range(of: "://") else {
            return nil
        }
        let afterScheme = noQuery[authority.upperBound...]
        if location.hasPrefix("/") {
            guard let netlocEnd = afterScheme.firstIndex(of: "/") else {
                return nil
            }
            return noQuery[..<netlocEnd] + location
        }
        if let lastSlash = afterScheme.lastIndex(of: "/") {
            return "\(noQuery[..<lastSlash])/\(location)"
        }
        return "\(noQuery)/\(location)"
    }

    // MARK: Private

    /// Wireshark's stats tree plus the three maps `packet-http.c` keeps beside it.
    private struct Tree {
        // MARK: Internal

        var isEmpty: Bool {
            nodes[1].hits == 0
        }

        /// One request (or redirect target) `uri` reached from `referer`.
        mutating func record(_ uri: String, after referer: String) {
            let refererNode = tickReferer(referer)
            tickRequest(uri, under: refererNode)
            var current = refererNode
            while let parent = parents[current] {
                tick(names[current] ?? "", under: parent)
                current = parent
            }
        }

        func node(_ index: Int, share: Double?) -> HTTPStatisticsNode {
            let item = nodes[index]
            // Wireshark's stats-tree order: most counted first, ties by name, descending.
            let ordered = item.children.enumerated().sorted { lhs, rhs in
                StatsTreeOrder.precedes(
                    count: nodes[lhs.element].hits, name: nodes[lhs.element].title,
                    before: nodes[rhs.element].hits, nodes[rhs.element].title
                )
            }
            let children = ordered.map { child in
                node(child.element, share: Double(nodes[child.element].hits) / Double(max(item.hits, 1)))
            }
            return HTTPStatisticsNode(
                id: "sequences/\(index)",
                title: item.title,
                count: item.hits,
                share: share,
                children: children.isEmpty ? nil : children
            )
        }

        // MARK: Private

        private struct Node {
            let title: String
            var hits = 0
            var children: [Int] = []
            var childByTitle: [String: Int] = [:]
        }

        /// Node 0 is the stats tree's own root; node 1 is "HTTP Request Sequences".
        private var nodes = [
            Node(title: "", children: [1], childByTitle: [HTTPRequestSequences.rootTitle: 1]),
            Node(title: HTTPRequestSequences.rootTitle),
        ]
        private var nodeByURI: [String: Int] = [HTTPRequestSequences.rootTitle: 1]
        private var names: [Int: String] = [1: HTTPRequestSequences.rootTitle]
        private var parents: [Int: Int] = [1: 0]

        /// `tick_stat_node`: count the child named `title` under `parent`, creating it.
        @discardableResult
        private mutating func tick(_ title: String, under parent: Int) -> Int {
            if let existing = nodes[parent].childByTitle[title] {
                nodes[existing].hits += 1
                return existing
            }
            nodes.append(Node(title: title, hits: 1))
            let index = nodes.count - 1
            nodes[parent].children.append(index)
            nodes[parent].childByTitle[title] = index
            return index
        }

        private mutating func tickReferer(_ referer: String) -> Int {
            if let known = nodeByURI[referer] {
                return tick(referer, under: parents[known] ?? 1)
            }
            let index = tick(referer, under: 1)
            nodeByURI[referer] = index
            names[index] = referer
            parents[index] = 1
            return index
        }

        private mutating func tickRequest(_ uri: String, under referer: Int) {
            let index = tick(uri, under: referer)
            if names[index] == nil {
                names[index] = uri
                parents[index] = referer
            }
            nodeByURI[uri] = index
        }
    }
}
