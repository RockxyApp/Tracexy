import Foundation

// MARK: - TrafficAddressKind

/// The address families View ▸ Conversations and View ▸ Endpoints split traffic by,
/// as Wireshark's per-type tabs do: network addresses alone, or addresses with the
/// transport port.
enum TrafficAddressKind: String, CaseIterable, Identifiable, Sendable {
    case ethernet
    case ipv4
    case ipv6
    case tcp
    case udp

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .ethernet: "Ethernet"
        case .ipv4: "IPv4"
        case .ipv6: "IPv6"
        case .tcp: "TCP"
        case .udp: "UDP"
        }
    }

    /// Whether rows carry a port (TCP/UDP) or only an address (Ethernet/IPv4/IPv6).
    var usesPorts: Bool {
        self == .tcp || self == .udp
    }

    /// The Session Expression field its addresses are matched with.
    var addressField: String {
        self == .ethernet ? "mac" : "ip"
    }
}

// MARK: - TrafficEndpointRow

/// One row of View ▸ Endpoints: an address (or address and port) with what it sent
/// and received across the sessions in view. Tx is what this endpoint sent.
struct TrafficEndpointRow: Identifiable, Hashable, Sendable {
    let id: String
    let address: String
    let port: UInt16?
    /// `mac` for Ethernet rows, `ip` otherwise.
    var addressField = "ip"
    /// A named subnet's row: `address` is the block, and it sums its addresses.
    var isSubnet = false
    var sessionCount = 0
    var txPackets = 0
    var txBytes = 0
    var rxPackets = 0
    var rxBytes = 0
    var firstSeen: Date?
    var lastSeen: Date?

    var packets: Int {
        txPackets + rxPackets
    }

    var bytes: Int {
        txBytes + rxBytes
    }

    var label: String {
        port.map { TrafficStatistics.endpointLabel(address, port: $0) } ?? address
    }

    /// The Session Expression that finds this endpoint's sessions.
    var term: String {
        if isSubnet {
            return "ip in \(address)"
        }
        if let port {
            return "\(addressField) == \(address) and port == \(port)"
        }
        return "\(addressField) == \(address)"
    }
}

// MARK: - TrafficConversationRow

/// One row of View ▸ Conversations: traffic between two endpoints A and B, A being
/// the side that started the first session seen between them.
struct TrafficConversationRow: Identifiable, Hashable, Sendable {
    // MARK: Internal

    let id: String
    let addressA: String
    let portA: UInt16?
    let addressB: String
    let portB: UInt16?
    /// `mac` for Ethernet rows, `ip` otherwise.
    var addressField = "ip"
    var sessionCount = 0
    var packetsAToB = 0
    var bytesAToB = 0
    var packetsBToA = 0
    var bytesBToA = 0
    var start: Date?
    var end: Date?

    var packets: Int {
        packetsAToB + packetsBToA
    }

    var bytes: Int {
        bytesAToB + bytesBToA
    }

    var duration: TimeInterval? {
        guard let start, let end else {
            return nil
        }
        return max(0, end.timeIntervalSince(start))
    }

    /// Mean rate over the conversation's span, `nil` when the span is unknown or
    /// zero (a single instant has no rate).
    var bitsPerSecondAToB: Double? {
        rate(bytesAToB)
    }

    var bitsPerSecondBToA: Double? {
        rate(bytesBToA)
    }

    var labelA: String {
        portA.map { TrafficStatistics.endpointLabel(addressA, port: $0) } ?? addressA
    }

    var labelB: String {
        portB.map { TrafficStatistics.endpointLabel(addressB, port: $0) } ?? addressB
    }

    /// The Session Expression that finds the sessions of this conversation.
    var term: String {
        var parts = ["\(addressField) == \(addressA)", "\(addressField) == \(addressB)"]
        if let portA, let portB {
            parts += portA == portB ? ["port == \(portA)"] : ["port == \(portA)", "port == \(portB)"]
        }
        return parts.joined(separator: " and ")
    }

    // MARK: Private

    private func rate(_ bytes: Int) -> Double? {
        guard let duration, duration > 0 else {
            return nil
        }
        return Double(bytes) * 8 / duration
    }
}

// MARK: - TrafficStatistics

/// Folds the sessions in view into Wireshark's Conversations and Endpoints tables.
/// Every figure is a sum of the sessions' own per-direction frame and byte tallies,
/// so a row never claims more than the sessions it came from.
enum TrafficStatistics {
    // MARK: Internal

    /// Endpoint rows. With `subnets` (IPv4 only), an address in a named block adds to
    /// that block's row instead of its own; a session between two of its addresses
    /// counts once for it, and both sides' traffic adds up, as Wireshark aggregates.
    static func endpoints(
        of sessions: [SessionSummary],
        kind: TrafficAddressKind,
        subnets: [SubnetName] = []
    )
        -> [TrafficEndpointRow]
    {
        let groups = kind == .ipv4 ? subnets : []
        var rows: [String: TrafficEndpointRow] = [:]
        var order: [String] = []
        for session in sessions {
            guard let (client, server) = endpoints(of: session, kind: kind) else {
                continue
            }
            let sides = [
                EndpointSide(
                    endpoint: client,
                    sent: (session.packetsUp, session.bytesUp),
                    received: (session.packetsDown, session.bytesDown)
                ),
                EndpointSide(
                    endpoint: server,
                    sent: (session.packetsDown, session.bytesDown),
                    received: (session.packetsUp, session.bytesUp)
                ),
            ]
            var seen: Set<String> = []
            for side in sides {
                let port = kind.usesPorts ? side.endpoint.port : nil
                let subnet = groups.isEmpty ? nil : SubnetNames.lookup(side.endpoint.ip, in: groups)
                let key = subnet.map { "subnet|\($0.text)" } ?? key(side.endpoint.ip, port: port)
                var row = rows[key] ?? TrafficEndpointRow(
                    id: key, address: subnet?.text ?? side.endpoint.ip, port: port, addressField: kind.addressField,
                    isSubnet: subnet != nil
                )
                if rows[key] == nil {
                    order.append(key)
                }
                // A session between two ports of one address counts once for it.
                if seen.insert(key).inserted {
                    row.sessionCount += 1
                }
                row.txPackets += side.sent.packets
                row.txBytes += side.sent.bytes
                row.rxPackets += side.received.packets
                row.rxBytes += side.received.bytes
                row.firstSeen = earliest(row.firstSeen, session.startTime)
                row.lastSeen = latest(row.lastSeen, end(of: session))
                rows[key] = row
            }
        }
        return order.compactMap { rows[$0] }.sorted { $0.bytes > $1.bytes }
    }

    static func conversations(of sessions: [SessionSummary], kind: TrafficAddressKind) -> [TrafficConversationRow] {
        var rows: [String: TrafficConversationRow] = [:]
        var order: [String] = []
        for session in sessions {
            guard let (client, server) = endpoints(of: session, kind: kind) else {
                continue
            }
            let clientPort = kind.usesPorts ? client.port : nil
            let serverPort = kind.usesPorts ? server.port : nil
            let clientKey = key(client.ip, port: clientPort)
            let serverKey = key(server.ip, port: serverPort)
            let pairKey = [clientKey, serverKey].sorted().joined(separator: "|")
            if rows[pairKey] == nil {
                rows[pairKey] = TrafficConversationRow(
                    id: pairKey, addressA: client.ip, portA: clientPort, addressB: server.ip, portB: serverPort,
                    addressField: kind.addressField
                )
                order.append(pairKey)
            }
            guard var row = rows[pairKey] else {
                continue
            }
            // A is whoever started the first session between the two; later
            // sessions started from B add their "up" traffic to B→A.
            let clientIsA = key(row.addressA, port: row.portA) == clientKey
            row.sessionCount += 1
            if clientIsA {
                row.packetsAToB += session.packetsUp
                row.bytesAToB += session.bytesUp
                row.packetsBToA += session.packetsDown
                row.bytesBToA += session.bytesDown
            } else {
                row.packetsAToB += session.packetsDown
                row.bytesAToB += session.bytesDown
                row.packetsBToA += session.packetsUp
                row.bytesBToA += session.bytesUp
            }
            row.start = earliest(row.start, session.startTime)
            row.end = latest(row.end, end(of: session))
            rows[pairKey] = row
        }
        return order.compactMap { rows[$0] }.sorted { $0.bytes > $1.bytes }
    }

    /// Counts per kind, for the picker's labels ("IPv4 · 12").
    static func conversationCounts(of sessions: [SessionSummary]) -> [TrafficAddressKind: Int] {
        Dictionary(uniqueKeysWithValues: TrafficAddressKind.allCases
            .map { ($0, conversations(of: sessions, kind: $0).count) })
    }

    static func endpointCounts(of sessions: [SessionSummary]) -> [TrafficAddressKind: Int] {
        Dictionary(uniqueKeysWithValues: TrafficAddressKind.allCases
            .map { ($0, endpoints(of: sessions, kind: $0).count) })
    }

    /// `192.0.2.1:443`, `[2001:db8::1]:443`.
    static func endpointLabel(_ address: String, port: UInt16) -> String {
        address.contains(":") ? "[\(address)]:\(port)" : "\(address):\(port)"
    }

    /// Comma-separated values with a header row, for Copy.
    static func csv(_ rows: [TrafficEndpointRow]) -> String {
        let header = "Address,Port,Sessions,Packets,Bytes,Tx Packets,Tx Bytes,Rx Packets,Rx Bytes"
        let lines = rows.map { row in
            [
                row.address, row.port.map(String.init) ?? "", String(row.sessionCount), String(row.packets),
                String(row.bytes), String(row.txPackets), String(row.txBytes), String(row.rxPackets),
                String(row.rxBytes),
            ].joined(separator: ",")
        }
        return ([header] + lines).joined(separator: "\n")
    }

    static func csv(_ rows: [TrafficConversationRow]) -> String {
        let header = "Address A,Port A,Address B,Port B,Sessions,Packets,Bytes,Packets A→B,Bytes A→B,Packets B→A,Bytes B→A,Duration"
        let lines = rows.map { row in
            [
                row.addressA, row.portA.map(String.init) ?? "", row.addressB, row.portB.map(String.init) ?? "",
                String(row.sessionCount), String(row.packets), String(row.bytes), String(row.packetsAToB),
                String(row.bytesAToB), String(row.packetsBToA), String(row.bytesBToA),
                row.duration.map { String(format: "%.6f", $0) } ?? "",
            ].joined(separator: ",")
        }
        return ([header] + lines).joined(separator: "\n")
    }

    // MARK: Private

    private struct EndpointSide {
        let endpoint: IPEndpoint
        let sent: (packets: Int, bytes: Int)
        let received: (packets: Int, bytes: Int)
    }

    /// The client/server endpoints of a session when it belongs to `kind`.
    private static func endpoints(of session: SessionSummary, kind: TrafficAddressKind) -> (IPEndpoint, IPEndpoint)? {
        // Ethernet rows carry MAC addresses in the address slot, without ports.
        if kind == .ethernet {
            return session.macAddresses.map { (IPEndpoint(ip: $0.client, port: 0), IPEndpoint(ip: $0.server, port: 0)) }
        }
        guard let client = session.sourceEndpointValue, let server = session.destinationEndpointValue,
              let value = IPAddressValue(parsing: client.ip) else
        {
            return nil
        }
        let belongs = switch kind {
        // ARP names IPv4 addresses but is not carried over IP, so, as in Wireshark,
        // it is not an IPv4 conversation.
        case .ethernet: false
        case .ipv4: value.family == .v4 && !session.protocolStack.contains(.arp)
        case .ipv6: value.family == .v6
        case .tcp: session.protocolStack.contains(.tcp)
        case .udp: session.protocolStack.contains(.udp)
        }
        guard belongs else {
            return nil
        }
        return (client, server)
    }

    private static func key(_ address: String, port: UInt16?) -> String {
        port.map { "\(address)#\($0)" } ?? address
    }

    private static func end(of session: SessionSummary) -> Date? {
        guard let start = session.startTime else {
            return nil
        }
        return start.addingTimeInterval(session.duration ?? 0)
    }

    private static func earliest(_ lhs: Date?, _ rhs: Date?) -> Date? {
        guard let lhs else {
            return rhs
        }
        guard let rhs else {
            return lhs
        }
        return min(lhs, rhs)
    }

    private static func latest(_ lhs: Date?, _ rhs: Date?) -> Date? {
        guard let lhs else {
            return rhs
        }
        guard let rhs else {
            return lhs
        }
        return max(lhs, rhs)
    }
}
