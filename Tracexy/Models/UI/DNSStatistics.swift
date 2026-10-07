import Foundation

// MARK: - DNSStatistics

/// Wireshark's Statistics ▸ DNS (`tshark -z dns,tree`) over the frames the All
/// Frames scan read: packet types, query and answer types, classes, response
/// codes, opcodes, payload sizes, question-name statistics, section counts and
/// request/response times paired by session and transaction ID.
enum DNSStatistics {
    // MARK: Internal

    static func tree(rows: [CaptureFrameRow]) -> [StatsTreeNode] {
        let frames = rows.compactMap { row in row.dns.map { (row, $0) } }
        guard !frames.isEmpty else {
            return []
        }
        let facts = frames.map(\.1)
        let queries = facts.filter { !$0.isResponse }
        var nodes: [StatsTreeNode] = []
        nodes.append(node("total", "Total Packets", count: facts.count))
        let types: [StatsTreeNode] = counted("qr", facts) { $0.isResponse ? "Response" : "Query" }
        nodes.append(node("qr", "Response", count: facts.count, children: types))
        let queryTypes: [StatsTreeNode] = counted("qtype", facts) { $0.queryType.map(PacketDecoder.dnsTypeName) }
        nodes.append(node("qtype", "Query Type", count: facts.count { $0.queryType != nil }, children: queryTypes))
        let answerTypes: [StatsTreeNode] = countedMany("atype", facts) {
            $0.answerTypes.map(PacketDecoder.dnsTypeName)
        }
        let answerCount: Int = facts.reduce(0) { $0 + $1.answerTypes.count }
        nodes.append(node("atype", "Answer Type", count: answerCount, children: answerTypes))
        let classes: [StatsTreeNode] = counted("class", facts) { $0.queryClass.map(className) }
        nodes.append(node("class", "Class", count: facts.count { $0.queryClass != nil }, children: classes))
        let codes: [StatsTreeNode] = counted("rcode", facts) { responseCodeName($0.responseCode) }
        nodes.append(node("rcode", "rcode", count: facts.count, children: codes))
        let opcodes: [StatsTreeNode] = counted("opcode", facts) { opcodeName($0.opcode) }
        nodes.append(node("opcode", "opcodes", count: facts.count, children: opcodes))
        nodes.append(measured("payload", "Payload size", facts.map { Double($0.messageLength) }))
        nodes.append(node("query", "Query Stats", count: 0, children: [
            measured("query/len", "Qname Len", queries.compactMap { $0.queryNameLength.map(Double.init) }),
            node("query/labels", "Label Stats", count: 0, children: counted("query/labels", queries) { fact in
                fact.queryLabelCount.map(levelName)
            }),
        ]))
        // Section counts of every response, once each. (Wireshark 4.x adds each
        // answered response a second time — a double count Tracexy does not copy.)
        let service = serviceStats(frames)
        let counted = facts.filter(\.isResponse)
        nodes.append(node("response", "Response Stats", count: 0, children: [
            measured("response/qd", "no. of questions", counted.map { Double($0.questionCount) }),
            measured("response/ns", "no. of authorities", counted.map { Double($0.authorityCount) }),
            measured("response/an", "no. of answers", counted.map { Double($0.answerCount) }),
            measured("response/ar", "no. of additionals", counted.map { Double($0.additionalCount) }),
        ]))
        nodes.append(service.node)
        return nodes
    }

    // MARK: Private

    private static func node(
        _ id: String,
        _ title: String,
        count: Int,
        children: [StatsTreeNode]? = nil
    )
        -> StatsTreeNode
    {
        StatsTreeNode(id: id, title: title, count: count, children: children)
    }

    /// One child per distinct value, most frequent first.
    private static func counted(
        _ path: String,
        _ facts: [DNSFrameFact],
        key: (DNSFrameFact) -> String?
    )
        -> [StatsTreeNode]
    {
        countedMany(path, facts) { key($0).map { [$0] } ?? [] }
    }

    private static func countedMany(
        _ path: String,
        _ facts: [DNSFrameFact],
        keys: (DNSFrameFact) -> [String]
    )
        -> [StatsTreeNode]
    {
        var counts: [String: Int] = [:]
        for fact in facts {
            for key in keys(fact) {
                counts[key, default: 0] += 1
            }
        }
        return counts
            .sorted { StatsTreeOrder.precedes(count: $0.value, name: $0.key, before: $1.value, $1.key) }
            .map { StatsTreeNode(id: "\(path)/\($0.key)", title: $0.key, count: $0.value) }
    }

    private static func measured(_ id: String, _ title: String, _ values: [Double]) -> StatsTreeNode {
        StatsTreeNode(
            id: id, title: title, count: values.count,
            average: values.isEmpty ? nil : values.reduce(0, +) / Double(values.count),
            minimum: values.min(), maximum: values.max()
        )
    }

    /// Request/response times (ms) of each query answered in the same session with
    /// the same transaction ID (timed from its first query); responses no query asked
    /// for (by position in `frames`); and responses repeated for an answered query.
    private static func serviceStats(
        _ frames: [(CaptureFrameRow, DNSFrameFact)]
    )
        -> (node: StatsTreeNode, unsolicited: Set<Int>)
    {
        var pending: [String: Date?] = [:]
        var answered: Set<String> = []
        var times: [Double] = []
        var unsolicited: Set<Int> = []
        var retransmissions = 0
        for (index, (row, fact)) in frames.enumerated() {
            let key = "\(row.sessionID?.uuidString ?? "-")#\(fact.transactionID)"
            guard fact.isResponse else {
                if pending[key] == nil {
                    // `updateValue` keeps an untimed query (a `nil` value) in the map.
                    pending.updateValue(row.provenance.timestamp, forKey: key)
                    answered.remove(key)
                }
                continue
            }
            guard let sent = pending.removeValue(forKey: key) else {
                if answered.contains(key) {
                    retransmissions += 1
                } else {
                    unsolicited.insert(index)
                }
                continue
            }
            answered.insert(key)
            if let sent, let received = row.provenance.timestamp {
                times.append(received.timeIntervalSince(sent) * 1_000)
            }
        }
        let node = node("service", "Service Stats", count: 0, children: [
            measured("service/rrt", "request-response time (msec)", times),
            node("service/unsolicited", "no. of unsolicited responses", count: unsolicited.count),
            node("service/retransmissions", "no. of retransmissions", count: retransmissions),
        ])
        return (node, unsolicited)
    }

    private static func className(_ value: UInt16) -> String {
        switch value & 0x7FFF {
        case 1: "IN"
        case 3: "CH"
        case 4: "HS"
        case 254: "NONE"
        case 255: "ANY"
        default: "Unknown (\(value))"
        }
    }

    private static func responseCodeName(_ code: UInt8) -> String {
        switch code {
        case 0: "No error"
        case 1: "Format error"
        case 2: "Server failure"
        case 3: "No such name"
        case 4: "Not implemented"
        case 5: "Refused"
        case 6: "Name exists"
        case 7: "RRset exists"
        case 8: "RRset does not exist"
        case 9: "Not authoritative"
        case 10: "Name out of zone"
        default: "Unknown (\(code))"
        }
    }

    private static func opcodeName(_ opcode: UInt8) -> String {
        switch opcode {
        case 0: "Standard query"
        case 1: "Inverse query"
        case 2: "Server status request"
        case 4: "Zone change notification"
        case 5: "Dynamic update"
        default: "Unknown operation (\(opcode))"
        }
    }

    private static func levelName(_ labels: Int) -> String {
        switch labels {
        case ...1: "1st Level"
        case 2: "2nd Level"
        case 3: "3rd Level"
        default: "4th Level or more"
        }
    }
}
