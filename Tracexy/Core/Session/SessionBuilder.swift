import Foundation

nonisolated enum SessionBuilder {
    // MARK: Internal

    static func build(from frames: [CapturedFrame], linkType: UInt32) -> [SessionSummary] {
        let packets = frames.map { frame -> DecodedPacket in
            var packet = PacketDecoder.decode(
                PacketBuffer(frame.bytes), linkType: linkType,
                timestamp: frame.timestamp, originalLength: frame.originalLength
            )
            packet.rawBytes = frame.bytes
            packet.processName = frame.processName
            return packet
        }

        // IP → hostname, learned from DNS responses.
        var resolved: [String: String] = [:]
        for packet in packets where packet.appProtocol == .dns {
            guard let name = packet.dnsQuery, !name.isEmpty else {
                continue
            }
            for answer in packet.dnsAnswers where !answer.hasPrefix("CNAME") {
                resolved[answer] = name
            }
        }

        // Group by canonical 5-tuple, preserving first-seen order.
        var groups: [FiveTuple: [DecodedPacket]] = [:]
        var order: [FiveTuple] = []
        for packet in packets {
            guard let key = packet.fiveTuple else {
                continue
            }
            if groups[key] == nil {
                order.append(key)
            }
            groups[key, default: []].append(packet)
        }

        return order.compactMap { summary(for: groups[$0] ?? [], key: $0, resolved: resolved) }
            .sorted { $0.startTime > $1.startTime }
    }

    // MARK: Private

    private static func summary(
        for packets: [DecodedPacket], key: FiveTuple, resolved: [String: String]
    )
        -> SessionSummary?
    {
        let sorted = packets.sorted { $0.timestamp < $1.timestamp }
        guard let firstPacket = sorted.first, let lastPacket = sorted.last else {
            return nil
        }

        let client = firstPacket.sourceEndpoint
        let server = firstPacket.destinationEndpoint
        let rich = packets.max { $0.layers.count < $1.layers.count } ?? firstPacket

        let sni = packets.compactMap(\.sni).first
        let dnsQuery = packets.compactMap { $0.dnsQuery.flatMap { $0.isEmpty ? nil : $0 } }.first
        let httpHost = rich.layers.first { $0.proto == .http }?
            .fields.first { $0.name == "Host" }?.value
        let serverIP = server?.ip ?? ""

        let host = resolveHost(
            appProto: rich.appProtocol, dnsQuery: dnsQuery, sni: sni,
            httpHost: httpHost, serverIP: serverIP, resolved: resolved, clientIP: client?.ip
        )

        var bytesUp = 0
        var bytesDown = 0
        for packet in packets {
            if packet.sourceEndpoint == client {
                bytesUp += packet.originalLength
            } else {
                bytesDown += packet.originalLength
            }
        }

        let status = deriveStatus(packets: packets, rich: rich)
        let latency = dnsLatency(sorted: sorted)
        let stack = rich.protocolStack.filter { $0 != .ipv4 && $0 != .ipv6 }
        // Process attribution (pktap): the first non-empty name across the
        // session's packets — both directions share the local socket's process.
        let processName = packets.compactMap(\.processName).first { !$0.isEmpty }

        return SessionSummary(
            id: stableID("\(key.proto.rawValue)|\(key.a.display)|\(key.b.display)"),
            startTime: firstPacket.timestamp,
            duration: max(0, lastPacket.timestamp.timeIntervalSince(firstPacket.timestamp)),
            processName: processName,
            host: host,
            sourceEndpoint: client?.display ?? "—",
            destinationEndpoint: server?.display ?? "—",
            protocolStack: stack.isEmpty ? [rich.transport ?? .other] : stack,
            status: status,
            latencyMilliseconds: latency,
            bytesUp: bytesUp,
            bytesDown: bytesDown,
            decodedLayers: rich.layers,
            representativeBytes: rich.rawBytes,
            sni: sni,
            dnsQuery: dnsQuery,
            dnsAnswers: packets.flatMap(\.dnsAnswers)
        )
    }

    private static func resolveHost(
        appProto: ProtocolKind?, dnsQuery: String?, sni: String?,
        httpHost: String?, serverIP: String, resolved: [String: String], clientIP: String?
    )
        -> String
    {
        if appProto == .dns, let query = dnsQuery {
            return query
        }
        if let sni {
            return sni
        }
        if let host = httpHost, !host.isEmpty, host != "—" {
            return host
        }
        if let name = resolved[serverIP] {
            return name
        }
        if !serverIP.isEmpty {
            return serverIP
        }
        return clientIP ?? "unknown"
    }

    private static func deriveStatus(packets: [DecodedPacket], rich: DecodedPacket) -> SessionStatus {
        if hasTCPFlag(packets, "RST") {
            return .error
        }
        let appPresent = packets.contains { $0.appProtocol != nil }
        if !appPresent, rich.transport == .tcp {
            return .warning
        }
        return .ok
    }

    private static func dnsLatency(sorted: [DecodedPacket]) -> Double? {
        guard let query = sorted.first(where: { $0.appProtocol == .dns && $0.dnsAnswers.isEmpty }),
              let response = sorted.first(where: { $0.appProtocol == .dns && !$0.dnsAnswers.isEmpty }),
              response.timestamp > query.timestamp else
        {
            return nil
        }
        return response.timestamp.timeIntervalSince(query.timestamp) * 1_000
    }

    private static func hasTCPFlag(_ packets: [DecodedPacket], _ flag: String) -> Bool {
        packets.contains { packet in
            packet.layers.contains { layer in
                layer.proto == .tcp && (layer.fields.first { $0.name == "Flags" }?.value.contains(flag) ?? false)
            }
        }
    }

    /// A deterministic UUID derived from a string (two FNV-1a passes → 16 bytes).
    /// The same 5-tuple keeps the same session id across rebuilds, so the table
    /// selection survives when new packets arrive.
    private static func stableID(_ string: String) -> UUID {
        func fnv(_ seed: UInt64) -> UInt64 {
            var hash = seed
            for byte in string.utf8 {
                hash ^= UInt64(byte)
                hash &*= 1_099_511_628_211
            }
            return hash
        }
        let high = fnv(14_695_981_039_346_656_037).bigEndian
        let low = fnv(0xCBF29CE484222325).bigEndian
        return withUnsafeBytes(of: (high, low)) { raw in
            var uuid = uuid_t(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            withUnsafeMutableBytes(of: &uuid) { $0.copyMemory(from: raw) }
            return UUID(uuid: uuid)
        }
    }
}
