import Foundation

// MARK: - StatisticsTap

/// `tracexy stats <capture> --tap <name>`: the Statistics windows as text, CSV or
/// JSON — the counterparts of tshark's `-z` taps, computed by the same models the
/// windows use over the sessions an optional `--expression` keeps.
enum StatisticsTap: Equatable {
    case conversations(TrafficAddressKind)
    case endpoints(TrafficAddressKind)
    case packetLengths
    case protocolHierarchy
    case expert
    case dns
    case http
    /// `smb2,srt`, `ldap,srt`, `kerberos,srt`: Statistics ▸ Service Response Time.
    case serviceResponseTime(ServiceResponseTime.Service)
    /// `ip_hosts,tree` … `ipv6_hop,tree`: Statistics ▸ IP Statistics.
    case ipStatistics(IPStatistics.Tree, ipv6: Bool)
    /// `http_seq,tree`: Statistics ▸ HTTP ▸ Request Sequences.
    case httpSequences
    /// `sip,stat`: Statistics ▸ SIP.
    case sip
    /// `rtp,streams`: Statistics ▸ RTP Streams.
    case rtpStreams

    // MARK: Lifecycle

    /// tshark spellings are accepted too: `conv,ip`, `io,phs`, `plen,tree`, `dns,tree`, `http,tree`.
    init?(_ text: String) {
        let parts = text.lowercased().split(separator: ",").map(String.init)
        let kind: TrafficAddressKind? = switch parts.dropFirst().first {
        case "ip",
             "ipv4": .ipv4
        case "ipv6": .ipv6
        case "tcp": .tcp
        case "udp": .udp
        default: nil
        }
        if let tree = Self.ipTree(parts.first ?? "") {
            self = .ipStatistics(tree.tree, ipv6: tree.ipv6)
            return
        }
        switch parts.first {
        case "http_seq": self = .httpSequences
        case "sip" where parts.dropFirst().first == "stat": self = .sip
        case "rtp" where parts.dropFirst().first == "streams": self = .rtpStreams
        case "conv":
            guard let kind else {
                return nil
            }
            self = .conversations(kind)
        case "endpoints":
            guard let kind else {
                return nil
            }
            self = .endpoints(kind)
        case "plen": self = .packetLengths
        case "phs": self = .protocolHierarchy
        case "io" where parts.dropFirst().first == "phs": self = .protocolHierarchy
        case "expert": self = .expert
        case "dns": self = .dns
        case "http": self = .http
        case "smb2" where parts.dropFirst().first == "srt": self = .serviceResponseTime(.smb2)
        case "ldap" where parts.dropFirst().first == "srt": self = .serviceResponseTime(.ldap)
        case "kerberos" where parts.dropFirst().first == "srt": self = .serviceResponseTime(.kerberos)
        case "icmp" where parts.dropFirst().first == "srt": self = .serviceResponseTime(.icmp)
        case "icmpv6" where parts.dropFirst().first == "srt": self = .serviceResponseTime(.icmpv6)
        default: return nil
        }
    }

    // MARK: Internal

    static let names = "conv,ipv4|ipv6|tcp|udp, endpoints,ipv4|ipv6|tcp|udp, plen, phs, expert, dns, http, "
        + "smb2,srt, ldap,srt, kerberos,srt, icmp,srt, icmpv6,srt, ip_hosts|ptype|ip_srcdst|dests|ip_ttl (and "
        + "ipv6_hosts|ipv6_ptype|ipv6_srcdst|ipv6_dests|ipv6_hop), http_seq, sip,stat, rtp,streams"

    /// Every tap name `--tap` accepts, one each.
    static var allNames: [String] {
        let kinds = ["ipv4", "ipv6", "tcp", "udp"]
        let ip = IPStatistics.Tree.allCases.map(\.tapName)
            + ["ipv6_hosts", "ipv6_ptype", "ipv6_srcdst", "ipv6_dests", "ipv6_hop"]
        return kinds.map { "conv,\($0)" } + kinds.map { "endpoints,\($0)" }
            + ["plen", "phs", "expert", "dns", "http", "http_seq", "sip,stat", "rtp,streams"] + ip
            + ["smb2", "ldap", "kerberos", "icmp", "icmpv6"].map { "\($0),srt" }
    }

    var needsFrames: Bool {
        switch self {
        case .serviceResponseTime,
             .ipStatistics,
             .httpSequences,
             .sip,
             .rtpStreams: true
        default: false
        }
    }

    /// Rows as named columns, the shared shape of every output format.
    func table(
        sessions: [SessionSummary],
        findings: [Finding],
        snapshot: InvestigationSnapshot,
        frames: [CaptureFrameRow] = []
    )
        -> StatisticsTable
    {
        switch self {
        case let .ipStatistics(tree, ipv6):
            return Self.treeTable(
                "\(ipv6 ? "IPv6" : "IPv4") Statistics/\(tree.title(ipv6: ipv6))",
                IPStatistics.tree(tree, ipv6: ipv6, rows: frames).map { ($0.title, $0.count, $0.children ?? []) }
            )
        case .sip:
            return Self.treeTable("SIP Statistics", SIPStatistics.tree(rows: frames).map {
                ($0.title, $0.count, $0.children ?? [])
            })
        case .httpSequences:
            var rows: [[String]] = []
            func walk(_ nodes: [HTTPStatisticsNode], depth: Int) {
                for node in nodes {
                    rows.append([String(repeating: "  ", count: depth) + node.title, String(node.count)])
                    walk(node.children ?? [], depth: depth + 1)
                }
            }
            walk(HTTPRequestSequences.tree(rows: frames), depth: 0)
            return StatisticsTable(title: "HTTP Request Sequences", columns: ["topic", "count"], rows: rows)
        case .rtpStreams:
            let lines = RTPStreams.csv(RTPStreams.streams(rows: frames)).split(separator: "\r\n").map {
                $0.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
            }
            return StatisticsTable(
                title: "RTP Streams",
                columns: (lines.first ?? []).map {
                    $0.lowercased().replacingOccurrences(of: " (ms)", with: "_ms").replacingOccurrences(
                        of: " %",
                        with: "_percent"
                    )
                    .replacingOccurrences(of: " ", with: "_")
                },
                rows: Array(lines.dropFirst())
            )
        case let .serviceResponseTime(service) where service.isEcho:
            let echo = EchoResponseTime(rows: frames, ipv6: service == .icmpv6)
            return StatisticsTable(
                title: "\(service.title) Service Response Time (SRT) Statistics (all times in ms)",
                columns: EchoResponseTime.columns.map { $0.lowercased().replacingOccurrences(of: " ", with: "_") },
                rows: [echo.values]
            )
        case let .serviceResponseTime(service):
            let rows = ServiceResponseTime.table(service, rows: frames)
            return StatisticsTable(
                title: "\(service.title) SRT Statistics",
                columns: [
                    "index",
                    service == .smb2 ? "command" : "procedure",
                    "calls",
                    "min_srt_s",
                    "max_srt_s",
                    "avg_srt_s",
                    "sum_srt_s"
                ],
                rows: rows.map { row in
                    [
                        String(row.index), row.procedure, String(row.calls), ServiceResponseTime.seconds(row.minimum),
                        ServiceResponseTime.seconds(row.maximum), ServiceResponseTime.seconds(row.average),
                        ServiceResponseTime.seconds(row.sum),
                    ]
                }
            )
        case let .conversations(kind):
            let rows = TrafficStatistics.conversations(of: sessions, kind: kind)
            return StatisticsTable(
                title: "\(kind.title) Conversations",
                columns: [
                    "address_a",
                    "port_a",
                    "address_b",
                    "port_b",
                    "sessions",
                    "frames_a_to_b",
                    "bytes_a_to_b",
                    "frames_b_to_a",
                    "bytes_b_to_a",
                    "frames",
                    "bytes",
                    "duration_s"
                ],
                rows: rows.map { row in
                    [
                        row.addressA,
                        row.portA.map(String.init) ?? "",
                        row.addressB,
                        row.portB.map(String.init) ?? "",
                        String(row.sessionCount),
                        String(row.packetsAToB),
                        String(row.bytesAToB),
                        String(row.packetsBToA),
                        String(row.bytesBToA),
                        String(row.packets),
                        String(row.bytes),
                        row.duration.map { String(format: "%.6f", $0) } ?? ""
                    ]
                }
            )
        case let .endpoints(kind):
            let rows = TrafficStatistics.endpoints(of: sessions, kind: kind)
            return StatisticsTable(
                title: "\(kind.title) Endpoints",
                columns: [
                    "address",
                    "port",
                    "sessions",
                    "frames",
                    "bytes",
                    "tx_frames",
                    "tx_bytes",
                    "rx_frames",
                    "rx_bytes"
                ],
                rows: rows.map { row in
                    [
                        row.address,
                        row.port.map(String.init) ?? "",
                        String(row.sessionCount),
                        String(row.packets),
                        String(row.bytes),
                        String(row.txPackets),
                        String(row.txBytes),
                        String(row.rxPackets),
                        String(row.rxBytes)
                    ]
                }
            )
        case .packetLengths:
            var histogram = FrameLengthHistogram()
            sessions.forEach { histogram.add($0.frameLengths) }
            let total = histogram.total
            let rows = histogram.buckets.enumerated().map { index, bucket in
                Self.lengthRow(
                    FrameLengthHistogram.label(ofBucket: index).replacingOccurrences(of: "–", with: "-"),
                    bucket,
                    total: total.count
                )
            } + [Self.lengthRow("all", total, total: total.count)]
            return StatisticsTable(
                title: "Packet Lengths",
                columns: ["range", "count", "average", "min", "max", "percent"],
                rows: rows
            )
        case .protocolHierarchy,
             .expert,
             .dns,
             .http:
            return analysisTable(sessions: sessions, findings: findings, snapshot: snapshot)
        }
    }

    // MARK: Private

    private static func lengthRow(_ label: String, _ bucket: FrameLengthHistogram.Bucket, total: Int) -> [String] {
        [
            label,
            String(bucket.count),
            bucket.average.map { String(format: "%.2f", $0) } ?? "",
            bucket.isEmpty ? "" : String(bucket.minimum),
            bucket.isEmpty ? "" : String(bucket.maximum),
            total == 0 ? "0.00" : String(format: "%.2f", Double(bucket.count) * 100 / Double(total)),
        ]
    }

    /// tshark's stats-tree tap names for Statistics ▸ IP Statistics.
    private static func ipTree(_ name: String) -> (tree: IPStatistics.Tree, ipv6: Bool)? {
        for tree in IPStatistics.Tree.allCases {
            if name == tree.tapName {
                return (tree, false)
            }
            let v6 = tree == .sourceHopLimits ? "ipv6_hop" : "ipv6_" + tree.tapName.replacingOccurrences(
                of: "ip_",
                with: ""
            )
            if name == v6 {
                return (tree, true)
            }
        }
        return nil
    }

    /// A stats tree as indented topics and counts.
    private static func treeTable(_ title: String, _ roots: [(String, Int, [StatsTreeNode])]) -> StatisticsTable {
        var rows: [[String]] = []
        func walk(_ nodes: [StatsTreeNode], depth: Int) {
            for node in nodes {
                rows.append([String(repeating: "  ", count: depth) + node.title, String(node.count)])
                walk(node.children ?? [], depth: depth + 1)
            }
        }
        for (topic, count, children) in roots {
            rows.append([topic, String(count)])
            walk(children, depth: 1)
        }
        return StatisticsTable(title: title, columns: ["topic", "count"], rows: rows)
    }

    /// The report taps (hierarchy, findings, DNS, message counts), split from
    /// ``table(sessions:findings:snapshot:)`` to keep each function short.
    private func analysisTable(
        sessions: [SessionSummary],
        findings: [Finding],
        snapshot: InvestigationSnapshot
    )
        -> StatisticsTable
    {
        switch self {
        case .protocolHierarchy:
            var rows: [[String]] = []
            func walk(_ nodes: [ProtocolHierarchyNode]) {
                for node in nodes {
                    rows.append([
                        node.path.map(\.label).joined(separator: ":"),
                        String(node.sessionCount),
                        String(node.byteCount),
                        String(node.endingSessionCount)
                    ])
                    walk(node.children ?? [])
                }
            }
            walk(ProtocolHierarchy.roots(of: sessions))
            return StatisticsTable(
                title: "Protocol Hierarchy", columns: ["path", "sessions", "bytes", "ending_sessions"], rows: rows
            )
        case .expert:
            let hosts = Dictionary(sessions.map { ($0.id, $0.host) }, uniquingKeysWith: { first, _ in first })
            let nodes = FindingsSummary.nodes(of: findings, hosts: hosts)
            return StatisticsTable(
                title: "Findings",
                columns: ["severity", "summary", "expression", "count", "sessions", "cited_frames"],
                rows: nodes.map { node in
                    [
                        FindingsSummary.severityTitle(node.severity),
                        node.title,
                        node.term ?? "",
                        String(node.findingCount),
                        String(node.sessionCount),
                        String(node.citedFrameCount)
                    ]
                }
            )
        case .dns:
            let rows = DNSLookups.rows(
                sessions: sessions,
                findings: snapshot.datagramAnalysis.findings,
                responseTimes: snapshot.timing.measurements
            )
            return StatisticsTable(
                title: "DNS Lookups",
                columns: [
                    "name",
                    "lookups",
                    "answered",
                    "no_such_name",
                    "failed",
                    "unanswered",
                    "addresses",
                    "median_response_s"
                ],
                rows: rows.map { row in
                    [
                        row.name,
                        String(row.lookupCount),
                        String(row.answeredCount),
                        String(row.noSuchNameCount),
                        String(row.failedCount),
                        String(row.unansweredCount),
                        String(row.addressCount),
                        row.medianResponseTime.map { String(format: "%.6f", $0) } ?? ""
                    ]
                }
            )
        case .http:
            var rows: [[String]] = []
            func walk(_ nodes: [ApplicationMessageNode], depth: Int) {
                for node in nodes {
                    rows.append([
                        String(repeating: "  ", count: depth) + node.title,
                        String(node.messageCount),
                        String(node.sessionCount),
                        node.term ?? ""
                    ])
                    walk(node.children ?? [], depth: depth + 1)
                }
            }
            walk(ApplicationMessageCounts.roots(of: sessions), depth: 0)
            return StatisticsTable(
                title: "Message Counts", columns: ["message", "count", "sessions", "expression"], rows: rows
            )
        case .conversations,
             .endpoints,
             .packetLengths,
             .serviceResponseTime,
             .ipStatistics,
             .httpSequences,
             .sip,
             .rtpStreams:
            return table(sessions: sessions, findings: findings, snapshot: snapshot)
        }
    }
}

// MARK: - StatisticsTable

/// One statistic as named columns and string cells, rendered as an aligned text
/// table, RFC 4180 CSV (formula-guarded like the other exports) or JSON objects.
struct StatisticsTable: Equatable {
    // MARK: Internal

    let title: String
    let columns: [String]
    let rows: [[String]]

    var text: String {
        let widths = columns.indices.map { index in
            ([columns[index]] + rows.map { $0[index] }).map(\.count).max() ?? 0
        }
        func line(_ cells: [String]) -> String {
            cells.enumerated().map { index, cell in
                cell.padding(toLength: widths[index], withPad: " ", startingAt: 0)
            }.joined(separator: "  ").replacing(#/\s+$/#, with: "")
        }
        let rule = String(repeating: "=", count: max(title.count, widths.reduce(0, +) + 2 * (widths.count - 1)))
        return ([rule, title, line(columns), String(repeating: "-", count: rule.count)] + rows.map(line) + [rule])
            .joined(separator: "\n") + "\n"
    }

    var csv: String {
        ([columns] + rows).map { $0.map(Self.csvCell).joined(separator: ",") }.joined(separator: "\n") + "\n"
    }

    var jsonObject: [String: Any] {
        ["statistic": title, "rows": rows.map { Dictionary(uniqueKeysWithValues: zip(columns, $0)) }]
    }

    // MARK: Private

    private static func csvCell(_ value: String) -> String {
        // Guard spreadsheet formula injection as the investigation export does.
        let guarded = ["=", "+", "-", "@"]
            .contains(where: value.hasPrefix) && Double(value) == nil ? "'" + value : value
        guard guarded.contains(where: { $0 == "," || $0 == "\"" || $0 == "\n" }) else {
            return guarded
        }
        return "\"" + guarded.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }
}

// MARK: - Frames

extension TracexyCommandLine {
    /// `tracexy frames`: the All Frames list as a table — tshark's `-T fields` over the
    /// columns Tracexy lists — limited to the sessions an `--expression` keeps.
    static func framesTable(
        file original: URL,
        sessions: [SessionSummary],
        limited: Bool,
        columns: [FieldKey] = []
    )
        throws -> StatisticsTable
    {
        let rows = try frameRows(file: original, sessions: sessions, limited: limited, columns: columns)
        let origin = rows.first?.provenance.timestamp
        return StatisticsTable(
            title: "Frames",
            columns: ["number", "time_s", "source", "destination", "protocol", "length", "info", "session"]
                + columns.map { "\($0.proto.label):\($0.name)" },
            rows: rows.map { row in
                [
                    String(row.ordinal),
                    Self.elapsedText(row.provenance.timestamp, since: origin),
                    row.source, row.destination, row.protocolName, String(row.length), row.info,
                    row.sessionID?.uuidString ?? "",
                ] + row.columnValues
            }
        )
    }

    /// `Protocol:Field` — the protocol by its label or name, any case.
    static func fieldKey(_ text: String) -> FieldKey? {
        guard let colon = text.firstIndex(of: ":"), colon != text.startIndex,
              text.index(after: colon) != text.endIndex else
        {
            return nil
        }
        let name = text[..<colon].lowercased()
        guard let proto = ProtocolKind.allCases.first(where: { $0.label.lowercased() == name || $0.rawValue == name }) else {
            return nil
        }
        return FieldKey(proto: proto, name: String(text[text.index(after: colon)...]))
    }

    /// Every name a script can use: expression terms and protocols, finding kinds,
    /// statistics taps and Export Objects types.
    static func glossary(_ format: Format) -> String {
        let sections: [(String, [String])] = [
            ("terms", SessionExpressionCompletion.termNames),
            ("protocols", SessionQueryParser.protocolKeywords.keys.sorted()),
            ("findings", SessionQueryParser.findingNames.keys.sorted()),
            ("taps", StatisticsTap.allNames),
            ("objectTypes", CaptureObjectKind.allCases.map(\.rawValue)),
        ]
        if format == .json {
            let object = Dictionary(uniqueKeysWithValues: sections)
            let data = (try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]))
                ?? Data()
            return (String(bytes: data, encoding: .utf8) ?? "") + "\n"
        }
        return sections.map { title, names in "\(title):\n" + names.map { "  \($0)" }.joined(separator: "\n") }
            .joined(separator: "\n\n") + "\n"
    }

    /// Every frame of the capture, or only the kept sessions' frames when `limited`.
    static func frameRows(
        file original: URL,
        sessions: [SessionSummary],
        limited: Bool,
        columns: [FieldKey] = []
    )
        throws -> [CaptureFrameRow]
    {
        // A gzip or LZ4 container is expanded first, as `load` does for the fold.
        var file = original
        let header = try FileHandle(forReadingFrom: original)
        let magic = try [UInt8](header.read(upToCount: 8) ?? Data())
        try header.close()
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-cli-frames-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        if CaptureArchiveContainer(header: magic) != nil {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            file = try CaptureImporter.importCapture(from: original, intoDirectory: directory)
        }
        let handle = try FileHandle(forReadingFrom: file)
        let identity = PcapFileIdentity.snapshot(of: handle)
        try handle.close()
        let list = try CaptureFrameListScanner(
            contentsOf: file, expectedIdentity: identity, sourceToken: UUID(), configuration: .init(columns: columns)
        ).scan()
        let kept = Set(sessions.map(\.id))
        return list.rows.filter { row in
            !limited || row.sessionID.map(kept.contains) == true
        }
    }

    private static func elapsedText(_ stamp: Date?, since origin: Date?) -> String {
        guard let stamp, let origin else {
            return ""
        }
        return String(format: "%.6f", stamp.timeIntervalSince(origin))
    }
}
