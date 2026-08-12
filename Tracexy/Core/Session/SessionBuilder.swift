import Foundation

nonisolated enum SessionBuilder {
    /// Decode and fold every frame through the shared `SessionAccumulator`, then
    /// emit summaries in first-seen five-tuple order.
    ///
    /// Frames arrive in capture order, so first-seen order is chronological
    /// (oldest→newest): a rebuild with later packets for known five-tuples leaves
    /// their rows at the same indices, and a genuinely new session appends at the
    /// tail instead of shifting the whole table down. This is the exact same fold
    /// the live `LiveSessionEngine` runs incrementally, so a snapshot after
    /// ingesting a set of frames equals this batch build over the same frames —
    /// byte for byte.
    static func build(from frames: [CapturedFrame], linkType: UInt32) -> [SessionSummary] {
        var accumulator = SessionAccumulator()
        for frame in frames {
            accumulator.add(decodePacket(frame, linkType: linkType))
        }
        return accumulator.summaries()
    }

    /// Decode one frame into a `DecodedPacket`, carrying its raw bytes and process
    /// name through. The frame's own link type wins when present (live helper
    /// frames each carry their DLT); otherwise the batch/file link type is used.
    ///
    /// This is the single decode step shared by the batch `build` and the
    /// incremental `LiveSessionEngine`, so both produce byte-identical decodes.
    static func decodePacket(_ frame: CapturedFrame, linkType: UInt32) -> DecodedPacket {
        var packet = PacketDecoder.decode(
            PacketBuffer(frame.bytes), linkType: frame.linkType ?? linkType,
            timestamp: frame.timestamp, originalLength: frame.originalLength
        )
        packet.rawBytes = frame.bytes
        packet.processName = frame.processName
        return packet
    }

    /// Fold one packet's DNS answers into the IP→hostname map. Applied in packet
    /// order (last write wins), identical whether accumulated incrementally or in
    /// a single batch pass.
    static func learnResolved(from packet: DecodedPacket, into resolved: inout [String: String]) {
        guard packet.appProtocol == .dns, let name = packet.dnsQuery, !name.isEmpty else {
            return
        }
        for answer in packet.dnsAnswers where !answer.hasPrefix("CNAME") {
            resolved[answer] = name
        }
    }

    /// Resolve the display host from the session's decoded signals, in priority
    /// order: DNS query name, TLS SNI, HTTP Host header, a reverse-resolved name
    /// for the server IP, the raw server IP, then the client IP. Shared with
    /// `SessionAccumulator` so batch and live builds agree.
    static func resolveHost(
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

    /// A deterministic UUID derived from a string (two FNV-1a passes → 16 bytes).
    /// The same 5-tuple keeps the same session id across rebuilds, so the table
    /// selection survives when new packets arrive. Shared with `SessionAccumulator`.
    static func stableID(_ string: String) -> UUID {
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
