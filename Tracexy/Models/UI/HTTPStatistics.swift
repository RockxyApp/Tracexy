import Foundation

// MARK: - HTTPStatisticsNode

/// One row of an HTTP statistics tree: a topic or item, its count, and its share
/// of its parent's count.
struct HTTPStatisticsNode: Identifiable, Hashable {
    let id: String
    let title: String
    let count: Int
    /// This node's count as a fraction of its parent's; `nil` for a root.
    let share: Double?
    /// `nil` for a leaf, so a hierarchical `Table` shows no disclosure for it.
    let children: [HTTPStatisticsNode]?

    /// No frame counted here (`count < 1`, which the formatter leaves alone).
    var isEmpty: Bool {
        count < 1
    }
}

// MARK: - HTTPStatistics

/// Statistics ▸ HTTP: Wireshark's three HTTP stats trees over the frames the All
/// Frames scan read — Requests (by Host, then URI), Load Distribution (requests by
/// server address and Host, responses by server address) and Packet Counter
/// (requests by method, responses by status class and code). HTTP/1 only, from
/// each frame's first line and Host header.
struct HTTPStatistics: Equatable {
    // MARK: Lifecycle

    init(rows: [CaptureFrameRow]) {
        var requests: [(method: String, host: String, uri: String, server: String)] = []
        var responses: [(status: Int, server: String)] = []
        for row in rows {
            switch row.http {
            case let .request(method, host, uri, _):
                requests.append((method, host, uri, row.destination))
            case let .response(status, _):
                responses.append((status, row.source))
            case nil:
                break
            }
        }
        requestCount = requests.count
        responseCount = responses.count
        sequenceTree = HTTPRequestSequences.tree(rows: rows)

        requestTree = [Self.node(
            "requests", title: String(localized: "HTTP Requests by HTTP Host"), count: requests.count, share: nil,
            children: Self.group(requests, path: "requests", key: \.host) { path, items in
                Self.group(items, path: path, key: \.uri, leaf: true)
            }
        )]

        let byAddress = Self.group(requests, path: "load.address", key: \.server) { path, items in
            Self.group(items, path: path, key: \.host, leaf: true)
        }
        let byHost = Self.group(requests, path: "load.host", key: \.host) { path, items in
            Self.group(items, path: path, key: \.server, leaf: true)
        }
        loadTree = [
            Self.node(
                "load", title: String(localized: "HTTP Requests by Server"), count: requests.count, share: nil,
                children: [
                    Self.node(
                        "load.address", title: String(localized: "HTTP Requests by Server Address"),
                        count: requests.count, share: 1, children: byAddress
                    ),
                    Self.node(
                        "load.host", title: String(localized: "HTTP Requests by HTTP Host"),
                        count: requests.count, share: 1, children: byHost
                    ),
                ]
            ),
            Self.node(
                "responses", title: String(localized: "HTTP Responses by Server Address"),
                count: responses.count, share: nil,
                children: Self.group(responses, path: "responses", key: \.server) { path, items in
                    Self.group(items, path: path, key: { $0.status < 400 ? "OK" : "Error" }, leaf: true)
                }
            ),
        ]

        let total = requests.count + responses.count
        let byMethod = Self.group(requests, path: "counter.requests", key: \.method, leaf: true)
        let classOf: ((status: Int, server: String)) -> String = { Self.statusClass($0.status) }
        let byClass = Self.group(responses, path: "counter.responses", key: classOf) { path, items in
            Self.group(items, path: path, key: { Self.statusTitle($0.status) }, leaf: true)
        }
        counterTree = [Self.node(
            "counter", title: String(localized: "Total HTTP Packets"), count: total, share: nil,
            children: [
                Self.node(
                    "counter.requests", title: String(localized: "HTTP Request Packets"), count: requests.count,
                    share: Self.share(requests.count, of: total), children: byMethod
                ),
                Self.node(
                    "counter.responses", title: String(localized: "HTTP Response Packets"),
                    count: responses.count, share: Self.share(responses.count, of: total), children: byClass
                ),
            ]
        )]
    }

    // MARK: Internal

    enum Tree: String, CaseIterable, Identifiable {
        case requests
        case load
        case packetCounter
        case sequences

        // MARK: Internal

        var id: String {
            rawValue
        }

        var title: String {
            switch self {
            case .requests: String(localized: "Requests")
            case .load: String(localized: "Load Distribution")
            case .packetCounter: String(localized: "Packet Counter")
            case .sequences: String(localized: "Request Sequences")
            }
        }
    }

    /// Children beyond this many under one node are folded into one "Other" item.
    static let maxChildren = 1_000

    let requestTree: [HTTPStatisticsNode]
    let loadTree: [HTTPStatisticsNode]
    let counterTree: [HTTPStatisticsNode]
    /// Requests under their referers and redirects under their requests; empty when
    /// no request named a referer. Any depth.
    let sequenceTree: [HTTPStatisticsNode]
    let requestCount: Int
    let responseCount: Int

    var isEmpty: Bool {
        requestCount == 0 && responseCount == 0
    }

    func nodes(_ tree: Tree) -> [HTTPStatisticsNode] {
        switch tree {
        case .requests: requestTree
        case .load: loadTree
        case .packetCounter: counterTree
        case .sequences: sequenceTree
        }
    }

    /// Wireshark's stats-tree CSV: the topic indented by depth, the count and the
    /// percentage of the parent.
    func csv(_ tree: Tree) -> String {
        var lines = ["Topic / Item,Count,Percent"]
        func walk(_ nodes: [HTTPStatisticsNode], depth: Int) {
            for node in nodes {
                let title = String(repeating: "  ", count: depth) + node.title
                let percent = node.share.map { String(format: "%.2f%%", $0 * 100) } ?? ""
                lines.append("\(Self.csvField(title)),\(node.count),\(percent)")
                walk(node.children ?? [], depth: depth + 1)
            }
        }
        walk(nodes(tree), depth: 0)
        return lines.joined(separator: "\r\n") + "\r\n"
    }

    // MARK: Private

    private static let reasonPhrases: [Int: String] = [
        100: "Continue", 101: "Switching Protocols", 200: "OK", 201: "Created", 202: "Accepted",
        203: "Non-authoritative Information", 204: "No Content", 205: "Reset Content", 206: "Partial Content",
        300: "Multiple Choices", 301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified",
        305: "Use Proxy", 307: "Temporary Redirect", 308: "Permanent Redirect", 400: "Bad Request",
        401: "Unauthorized", 402: "Payment Required", 403: "Forbidden", 404: "Not Found",
        405: "Method Not Allowed", 406: "Not Acceptable", 407: "Proxy Authentication Required",
        408: "Request Time-out", 409: "Conflict", 410: "Gone", 411: "Length Required",
        412: "Precondition Failed", 413: "Request Entity Too Large", 414: "Request-URI Too Long",
        415: "Unsupported Media Type", 416: "Requested Range Not Satisfiable", 417: "Expectation Failed",
        418: "I'm a teapot", 421: "Misdirected Request", 422: "Unprocessable Entity", 423: "Locked",
        424: "Failed Dependency", 425: "Too Early", 426: "Upgrade Required", 428: "Precondition Required",
        429: "Too Many Requests", 431: "Request Header Fields Too Large", 451: "Unavailable For Legal Reasons",
        500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway", 503: "Service Unavailable",
        504: "Gateway Time-out", 505: "HTTP Version not supported", 506: "Variant Also Negotiates",
        507: "Insufficient Storage", 508: "Loop Detected", 510: "Not Extended",
        511: "Network Authentication Required",
    ]

    private static func node(
        _ id: String,
        title: String,
        count: Int,
        share: Double?,
        children: [HTTPStatisticsNode]?
    )
        -> HTTPStatisticsNode
    {
        HTTPStatisticsNode(id: id, title: title, count: count, share: share, children: children)
    }

    /// One child per distinct key, most frequent first, each with its share of
    /// `items`; `nested` builds a child's own children from its items.
    private static func group<Item>(
        _ items: [Item],
        path: String,
        key: (Item) -> String,
        leaf: Bool = false,
        nested: ((String, [Item]) -> [HTTPStatisticsNode]?)? = nil
    )
        -> [HTTPStatisticsNode]
    {
        let groups = Dictionary(grouping: items, by: key)
        let sorted = groups
            .sorted { StatsTreeOrder.precedes(count: $0.value.count, name: $0.key, before: $1.value.count, $1.key) }
        var children = sorted.prefix(maxChildren).map { title, members in
            let childPath = "\(path)/\(title)"
            return HTTPStatisticsNode(
                id: childPath, title: title, count: members.count, share: share(members.count, of: items.count),
                children: leaf ? nil : nested?(childPath, members)
            )
        }
        let rest = sorted.dropFirst(maxChildren).reduce(0) { $0 + $1.value.count }
        if rest > 0 {
            children.append(HTTPStatisticsNode(
                id: "\(path)/…other", title: String(localized: "Other"), count: rest,
                share: share(rest, of: items.count), children: nil
            ))
        }
        return children
    }

    private static func group<Item>(
        _ items: [Item],
        path: String,
        key: (Item) -> String,
        nested: @escaping (String, [Item]) -> [HTTPStatisticsNode]?
    )
        -> [HTTPStatisticsNode]
    {
        group(items, path: path, key: key, leaf: false, nested: nested)
    }

    private static func share(_ count: Int, of total: Int) -> Double {
        total > 0 ? Double(count) / Double(total) : 0
    }

    /// "404 Not Found", with the reason phrases Wireshark's HTTP counter prints.
    private static func statusTitle(_ status: Int) -> String {
        reasonPhrases[status].map { "\(status) \($0)" } ?? String(status)
    }

    private static func statusClass(_ status: Int) -> String {
        switch status {
        case 100 ..< 200: "1xx: Informational"
        case 200 ..< 300: "2xx: Success"
        case 300 ..< 400: "3xx: Redirection"
        case 400 ..< 500: "4xx: Client Error"
        default: "5xx: Server Error"
        }
    }

    private static func csvField(_ text: String) -> String {
        guard text.contains(where: { $0 == "," || $0 == "\"" || $0 == "\n" || $0 == "\r" }) else {
            return text
        }
        return "\"" + text.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }
}
