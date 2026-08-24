import Foundation

// MARK: - LinkType

nonisolated enum LinkType {
    static let ethernet: UInt32 = 1
    static let null: UInt32 = 0
    static let raw: UInt32 = 101
}

// MARK: - PacketDecoder

nonisolated enum PacketDecoder {
    // MARK: Internal

    struct ReassembledTCPApplication: Sendable {
        let appProtocol: ProtocolKind
        let layers: [DecodedLayer]
        let sni: String?
        let dnsQuery: String?
        let dnsAnswers: [String]
        let dnsAnswersOmittedCount: Int
        let dnsFacts: DNSMessageFacts?
        /// Neutral TLS record facts recovered from the reassembled prefix and whether
        /// that walk hit the 32-record cap. Carried solely so the TLS evidence fold can
        /// exclude-count multi-frame records it may not cite (and count a recovered
        /// truncation indicator) — never propagated onto a representative packet.
        let tlsRecords: [TLSRecordFact], tlsRecordsTruncated: Bool
        let isComplete: Bool
    }

    static func decode(_ frame: PacketBuffer, linkType: UInt32, timestamp: Date, originalLength: Int) -> DecodedPacket {
        var packet = DecodedPacket(timestamp: timestamp, originalLength: originalLength)
        do {
            switch linkType {
            case LinkType.ethernet: try ethernet(frame, into: &packet)
            case LinkType.raw: try ipv4(frame, into: &packet)
            case LinkType.null: try loopback(frame, into: &packet)
            // VPN/tunnel (utun) and other point-to-point links report assorted
            // DLTs — auto-detect raw IP vs a 4-byte address-family header.
            default: try tunnel(frame, into: &packet)
            }
        } catch {
            // Partial decode is fine — keep whatever layers we parsed.
        }
        return packet
    }

    /// Classifies a bounded, contiguous TCP prefix assembled by the Session
    /// layer. Returned layers deliberately carry no frame byte ranges: their
    /// bytes can span multiple packets and must never highlight offsets in one
    /// representative frame.
    static func decodeReassembledTCPPayload(
        _ bytes: [UInt8], sourcePort: UInt16, destinationPort: UInt16
    )
        -> ReassembledTCPApplication?
    {
        var packet = DecodedPacket(timestamp: .distantPast, originalLength: bytes.count)
        let context = ApplicationMatchContext(
            payload: PacketBuffer(bytes), sourcePort: sourcePort, destinationPort: destinationPort
        )
        guard let complete = decodeReassembledApplication(context: context, into: &packet),
              let appProtocol = packet.appProtocol else
        {
            return nil
        }
        return ReassembledTCPApplication(
            appProtocol: appProtocol,
            layers: packet.layers.map(withoutByteRanges),
            sni: packet.sni,
            dnsQuery: packet.dnsQuery,
            dnsAnswers: packet.dnsAnswers,
            dnsAnswersOmittedCount: packet.dnsAnswersOmittedCount,
            dnsFacts: packet.dnsFacts,
            tlsRecords: packet.tlsRecords,
            tlsRecordsTruncated: packet.tlsRecordsTruncated,
            isComplete: complete
        )
    }

    // MARK: Private

    /// IPv6 extension-header protocol numbers (RFC 8200 order).
    private static let ipv6ExtensionHeaders: Set<UInt8> = [0, 43, 44, 51, 60, 135]

    /// STUN magic cookie (RFC 5389 §6): the fixed value at header offset 4 that
    /// disambiguates STUN from other UDP payloads regardless of port.
    private static let stunMagicCookie: UInt32 = 0x2112A442

    /// Largest number of valid DNS answer records a single decoded packet retains
    /// (values + display fields). Records beyond this are counted, not stored, so a
    /// pathological response cannot grow the decoded packet without bound.
    private static let dnsAnswerRetentionCap = 64

    /// The RFC 7323 window-scale semantic cap. A byte above this is not a valid
    /// scale; the raw value is still rendered, but no typed scale is retained and
    /// no shift is ever computed for it.
    private static let tcpMaxWindowScale: UInt8 = 14

    /// Decodes a tunnel/raw frame whose link-layer header is unknown: a bare IP
    /// packet, or one prefixed with a 4-byte BSD address family (NULL/LOOP).
    private static func tunnel(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        if let first = try? buf.u8(0) {
            switch first >> 4 {
            case 4: try ipv4(buf, into: &packet)
                return
            case 6: try ipv6(buf, into: &packet)
                return
            default: break
            }
        }
        try loopback(buf, into: &packet) // 4-byte address-family prefix
    }

    // MARK: Link layer

    private static func ethernet(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        let dst = try mac(buf, 0)
        let src = try mac(buf, 6)
        let etherType = try buf.u16(12)
        packet.layers.append(DecodedLayer(
            proto: .ethernet, title: "Ethernet II", summary: "\(src) → \(dst)",
            fields: [
                ranged("Destination", dst, in: buf, at: 0, 6),
                ranged("Source", src, in: buf, at: 6, 6),
                ranged("Type", etherTypeName(etherType), in: buf, at: 12, 2)
            ],
            byteRange: span(buf, 14)
        ))
        let payload = try buf.subset(from: 14)
        switch etherType {
        case 0x0800: try ipv4(payload, into: &packet)
        case 0x86DD: try ipv6(payload, into: &packet)
        case 0x0806: try arp(payload, into: &packet)
        default: break
        }
    }

    /// Address Resolution Protocol. Forms a session keyed on the protocol
    /// (IPv4) sender/target addresses (port 0) so it surfaces in the list.
    private static func arp(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        let oper = try buf.u16(6)
        let senderMac = try mac(buf, 8)
        let senderIP = try ipv4Address(buf, 14)
        let targetMac = try mac(buf, 18)
        let targetIP = try ipv4Address(buf, 24)
        let operName = oper == 1 ? "Request" : (oper == 2 ? "Reply" : "\(oper)")
        packet.transport = .arp
        packet.appProtocol = .arp
        packet.sourceEndpoint = IPEndpoint(ip: senderIP, port: 0)
        packet.destinationEndpoint = IPEndpoint(ip: targetIP, port: 0)
        packet.fiveTuple = FiveTuple(
            proto: .arp,
            source: IPEndpoint(ip: senderIP, port: 0),
            destination: IPEndpoint(ip: targetIP, port: 0)
        )
        packet.layers.append(DecodedLayer(
            proto: .arp, title: "Address Resolution Protocol", summary: "\(operName): who has \(targetIP)?",
            fields: [
                ranged("Operation", operName, in: buf, at: 6, 2),
                ranged("Sender MAC", senderMac, in: buf, at: 8, 6),
                ranged("Sender IP", senderIP, in: buf, at: 14, 4),
                ranged("Target MAC", targetMac, in: buf, at: 18, 6),
                ranged("Target IP", targetIP, in: buf, at: 24, 4),
            ],
            byteRange: span(buf, 28)
        ))
    }

    private static func loopback(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        // BSD loopback: 4-byte address family header.
        let family = try buf.u32le(0)
        let payload = try buf.subset(from: 4)
        if family == 2 {
            try ipv4(payload, into: &packet)
        } else {
            try ipv6(payload, into: &packet)
        }
    }

    // MARK: Network layer

    private static func ipv4(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        let versionIHL = try buf.u8(0)
        let ihl = Int(versionIHL & 0x0F) * 4
        let totalLength = try Int(buf.u16(2))
        let ttl = try buf.u8(8)
        let proto = try buf.u8(9)
        let src = try ipv4Address(buf, 12)
        let dst = try ipv4Address(buf, 16)
        var fields: [DecodedField] = [
            ranged("Version", "4", in: buf, at: 0, 1),
            ranged("Header Length", "\(ihl) bytes", in: buf, at: 0, 1),
            ranged("Total Length", "\(totalLength)", in: buf, at: 2, 2),
            ranged("TTL", "\(ttl)", in: buf, at: 8, 1),
            ranged("Protocol", ipProtoName(proto), in: buf, at: 9, 1),
            ranged("Source", src, in: buf, at: 12, 4),
            ranged("Destination", dst, in: buf, at: 16, 4),
        ]
        // IPv4 options (RFC 791) live between the 20-byte fixed header and IHL.
        if ihl > 20 {
            fields += (try? ipv4Options(buf, end: min(ihl, buf.length))) ?? []
        }
        packet.layers.append(DecodedLayer(
            proto: .ipv4, title: "Internet Protocol v4", summary: "\(src) → \(dst)",
            fields: fields,
            byteRange: span(buf, ihl)
        ))
        let payload = try buf.subset(from: ihl)
        try transport(payload, proto: proto, src: src, dst: dst, into: &packet)
    }

    /// Parses the IPv4 option list (offset 20 → `end`), RFC 791 type/length/value.
    private static func ipv4Options(_ buf: PacketBuffer, end: Int) throws -> [DecodedField] {
        var fields: [DecodedField] = []
        var offset = 20
        var guardCounter = 0
        while offset < end, guardCounter < 40 {
            guardCounter += 1
            let type = try buf.u8(offset)
            if type == 0 { // End of Option List
                break
            }
            if type == 1 { // No-Operation
                offset += 1
                continue
            }
            guard offset + 1 < end else {
                break
            }
            let length = try Int(buf.u8(offset + 1))
            guard length >= 2, offset + length <= end else {
                break
            }
            let range = (buf.start + offset) ..< (buf.start + offset + length)
            fields.append(DecodedField(
                name: "Option: \(ipv4OptionName(type))", value: "\(length) bytes", byteRange: range
            ))
            offset += length
        }
        return fields
    }

    private static func ipv4OptionName(_ type: UInt8) -> String {
        switch type & 0x1F { // option number (low 5 bits)
        case 3: "Loose Source Route"
        case 7: "Record Route"
        case 9: "Strict Source Route"
        case 4: "Timestamp"
        case 20: "Router Alert"
        case 2: "Security"
        default: "type \(type)"
        }
    }

    private static func ipv6(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        let byte0 = try buf.u8(0)
        let byte1 = try buf.u8(1)
        let trafficClass = (byte0 << 4) | (byte1 >> 4)
        let flowLabel = try (UInt32(byte1 & 0x0F) << 16) | (UInt32(buf.u8(2)) << 8) | UInt32(buf.u8(3))
        let payloadLength = try Int(buf.u16(4))
        let nextHeader = try buf.u8(6)
        let hopLimit = try buf.u8(7)
        let src = try ipv6Address(buf, 8)
        let dst = try ipv6Address(buf, 24)
        packet.layers.append(DecodedLayer(
            proto: .ipv6, title: "Internet Protocol v6", summary: "\(src) → \(dst)",
            fields: [
                ranged("Version", "6", in: buf, at: 0, 1),
                ranged("Traffic Class", String(format: "0x%02x", trafficClass), in: buf, at: 0, 2),
                ranged("Flow Label", String(format: "0x%05x", flowLabel), in: buf, at: 1, 3),
                ranged("Payload Length", "\(payloadLength)", in: buf, at: 4, 2),
                ranged("Next Header", ipProtoName(nextHeader), in: buf, at: 6, 1),
                ranged("Hop Limit", "\(hopLimit)", in: buf, at: 7, 1),
                ranged("Source", src, in: buf, at: 8, 16),
                ranged("Destination", dst, in: buf, at: 24, 16),
            ],
            byteRange: span(buf, 40)
        ))

        // Walk the IPv6 extension-header chain (HopByHop/Routing/Fragment/DestOpts/
        // AH/Mobility) before handing off to the transport layer. Ported from
        // PcapPlusPlus IPv6Extensions; field set cross-checked vs Wireshark's
        // packet-ipv6.c (concepts only — Wireshark is GPL, never copied).
        var proto = nextHeader
        var offset = 40
        var guardCounter = 0
        while Self.ipv6ExtensionHeaders.contains(proto), offset + 2 <= buf.length, guardCounter < 16 {
            guardCounter += 1
            let extNext = try buf.u8(offset)
            let extLen = try ipv6ExtensionLength(proto: proto, buf: buf, at: offset)
            packet.layers.append(DecodedLayer(
                proto: .ipv6, title: "IPv6 \(ipv6ExtensionName(proto))",
                summary: "next \(ipProtoName(extNext))",
                fields: [
                    ranged("Next Header", ipProtoName(extNext), in: buf, at: offset, 1),
                    ranged("Length", "\(extLen) bytes", in: buf, at: offset + 1, 1),
                ],
                byteRange: span(buf, offset + extLen)
            ))
            proto = extNext
            offset += extLen
        }

        guard offset < buf.length else {
            return
        }
        let payload = try buf.subset(from: offset)
        try transport(payload, proto: proto, src: src, dst: dst, into: &packet)
    }

    /// Byte length of an IPv6 extension header. Fragment is fixed 8 bytes; AH is
    /// counted in 4-byte units (+2); the rest in 8-byte units (+1) per RFC 8200.
    private static func ipv6ExtensionLength(proto: UInt8, buf: PacketBuffer, at offset: Int) throws -> Int {
        switch proto {
        case 44: 8 // Fragment header is fixed-size
        case 51: try (Int(buf.u8(offset + 1)) + 2) * 4 // Authentication Header
        default: try (Int(buf.u8(offset + 1)) + 1) * 8
        }
    }

    private static func ipv6ExtensionName(_ proto: UInt8) -> String {
        switch proto {
        case 0: "Hop-by-Hop Options"
        case 43: "Routing"
        case 44: "Fragment"
        case 51: "Authentication Header"
        case 60: "Destination Options"
        case 135: "Mobility"
        default: "Extension"
        }
    }

    // MARK: Transport layer

    private static func transport(
        _ buf: PacketBuffer,
        proto: UInt8,
        src: String,
        dst: String,
        into packet: inout DecodedPacket
    )
        throws
    {
        switch proto {
        case 6: try tcp(buf, src: src, dst: dst, into: &packet)
        case 17: try udp(buf, src: src, dst: dst, into: &packet)
        case 1: try icmp(buf, src: src, dst: dst, isV6: false, into: &packet)
        case 58: try icmp(buf, src: src, dst: dst, isV6: true, into: &packet)
        default: break
        }
    }

    /// ICMP / ICMPv6. Connectionless, so we key a session on the IP pair (port 0)
    /// to surface ping / unreachable / neighbor-discovery traffic in the list.
    private static func icmp(
        _ buf: PacketBuffer, src: String, dst: String, isV6: Bool, into packet: inout DecodedPacket
    )
        throws
    {
        let type = try buf.u8(0)
        let code = try buf.u8(1)
        // Both fixed bytes read — retain neutral family/type/code before building the
        // layer. Family is the already-known IP protocol, never inferred from the body.
        packet.icmpFacts = ICMPMessageFacts(family: isV6 ? .ipv6 : .ipv4, type: type, code: code)
        let kind: ProtocolKind = isV6 ? .icmpv6 : .icmp
        let typeName = isV6 ? icmpv6TypeName(type) : icmpTypeName(type)
        packet.transport = kind
        packet.appProtocol = kind
        packet.sourceEndpoint = IPEndpoint(ip: src, port: 0)
        packet.destinationEndpoint = IPEndpoint(ip: dst, port: 0)
        packet.fiveTuple = FiveTuple(
            proto: kind,
            source: IPEndpoint(ip: src, port: 0),
            destination: IPEndpoint(ip: dst, port: 0)
        )
        packet.layers.append(DecodedLayer(
            proto: kind, title: isV6 ? "Internet Control Message Protocol v6" : "Internet Control Message Protocol",
            summary: typeName,
            fields: [
                ranged("Type", "\(typeName) (\(type))", in: buf, at: 0, 1),
                ranged("Code", "\(code)", in: buf, at: 1, 1),
            ],
            byteRange: span(buf, min(8, buf.length))
        ))
    }

    private static func icmpTypeName(_ type: UInt8) -> String {
        switch type {
        case 0: "Echo Reply"
        case 3: "Destination Unreachable"
        case 5: "Redirect"
        case 8: "Echo Request"
        case 11: "Time Exceeded"
        default: "Type \(type)"
        }
    }

    private static func icmpv6TypeName(_ type: UInt8) -> String {
        switch type {
        case 1: "Destination Unreachable"
        case 2: "Packet Too Big"
        case 3: "Time Exceeded"
        case 128: "Echo Request"
        case 129: "Echo Reply"
        case 133: "Router Solicitation"
        case 134: "Router Advertisement"
        case 135: "Neighbor Solicitation"
        case 136: "Neighbor Advertisement"
        default: "Type \(type)"
        }
    }

    private static func tcp(_ buf: PacketBuffer, src: String, dst: String, into packet: inout DecodedPacket) throws {
        let srcPort = try buf.u16(0)
        let dstPort = try buf.u16(2)
        let seq = try buf.u32(4)
        let ack = try buf.u32(8)
        let dataOffset = try Int(buf.u8(12) >> 4) * 4
        guard dataOffset >= 20, dataOffset <= buf.length else {
            throw PacketError.malformed("Invalid TCP data offset")
        }
        let flags = try buf.u8(13)
        let window = try buf.u16(14)
        packet.transport = .tcp
        packet.sourceEndpoint = IPEndpoint(ip: src, port: srcPort)
        packet.destinationEndpoint = IPEndpoint(ip: dst, port: dstPort)
        packet.fiveTuple = FiveTuple(
            proto: .tcp,
            source: IPEndpoint(ip: src, port: srcPort),
            destination: IPEndpoint(ip: dst, port: dstPort)
        )
        var fields: [DecodedField] = [
            ranged("Source Port", "\(srcPort)", in: buf, at: 0, 2),
            ranged("Destination Port", "\(dstPort)", in: buf, at: 2, 2),
            ranged("Seq", "\(seq)", in: buf, at: 4, 4),
            ranged("Flags", tcpFlags(flags), in: buf, at: 13, 1),
        ]
        // Parse TCP options once (between the fixed 20-byte header and dataOffset)
        // for both the rendered fields and the typed option facts.
        var optionFacts = TCPOptionFacts()
        if dataOffset > 20, let parsed = try? tcpOptions(buf, end: min(dataOffset, buf.length)) {
            fields += parsed.fields
            optionFacts = parsed.facts
        }
        packet.layers.append(DecodedLayer(
            proto: .tcp, title: "Transmission Control Protocol", summary: "\(srcPort) → \(dstPort)",
            fields: fields,
            byteRange: span(buf, dataOffset)
        ))
        // Typed facts from exact header offsets. Acknowledgement is stored even
        // without the ACK flag; payload sequence consumes SYN exactly once; payload
        // length is the captured byte count. A bare/header-only segment still gets
        // a complete fact value (payloadLength == 0).
        let capturedPayloadLength = max(0, buf.length - dataOffset)
        packet.tcpFacts = TCPSegmentFacts(
            sequenceNumber: seq,
            acknowledgementNumber: ack,
            flags: TCPFlags(rawValue: flags),
            windowSize: window,
            headerLength: dataOffset,
            payloadSequence: seq &+ ((flags & 0x02) == 0 ? 0 : 1),
            payloadLength: capturedPayloadLength,
            options: optionFacts
        )
        guard dataOffset < buf.length else {
            return
        }
        let payload = try buf.subset(from: dataOffset)
        if payload.isEmpty {
            return
        }
        packet.tcpPayloadSequence = seq &+ ((flags & 0x02) == 0 ? 0 : 1)
        packet.tcpPayloadBytes = try payload.bytes(0, payload.length)
        try decodeFrameApplication(
            tcpFrameApplicationCandidates,
            context: ApplicationMatchContext(payload: payload, sourcePort: srcPort, destinationPort: dstPort),
            into: &packet
        )
    }

    /// Parses the TCP option list (offset 20 → `end`) into decoded fields. Our
    /// own walk of the kind/length/value TLV format (RFC 793/7323), referencing
    /// the option-parsing approach in PcapPlusPlus/libtins.
    private static func tcpOptions(
        _ buf: PacketBuffer, end: Int
    )
        throws -> (fields: [DecodedField], facts: TCPOptionFacts)
    {
        var fields: [DecodedField] = []
        var facts = TCPOptionFacts()
        var offset = 20
        var guardCounter = 0
        while offset < end, guardCounter < 40 {
            guardCounter += 1
            let kind = try buf.u8(offset)
            if kind == 0 { // End of Option List
                break
            }
            if kind == 1 { // No-Operation (single byte, no length)
                offset += 1
                continue
            }
            guard offset + 1 < end else {
                break
            }
            let length = try Int(buf.u8(offset + 1))
            guard length >= 2, offset + length <= end else {
                break
            }
            fields.append(tcpOptionField(kind: kind, buf: buf, at: offset, length: length, facts: &facts))
            offset += length
        }
        return (fields, facts)
    }

    private static func tcpOptionField(
        kind: UInt8, buf: PacketBuffer, at offset: Int, length: Int, facts: inout TCPOptionFacts
    )
        -> DecodedField
    {
        let range = (buf.start + offset) ..< (buf.start + offset + length)
        switch kind {
        case 2 where length == 4:
            let mss = (try? buf.u16(offset + 2)) ?? 0
            facts.maximumSegmentSize = mss
            return DecodedField(name: "Option: MSS", value: "\(mss)", byteRange: range)
        case 3 where length == 3:
            let shift = (try? buf.u8(offset + 2)) ?? 0
            facts.windowScaleRaw = shift
            // RFC 7323 section 2.3 requires an observed value above 14 to be
            // treated as 14. Preserve both raw and effective values and never
            // shift by the invalid raw byte.
            if shift <= tcpMaxWindowScale {
                facts.windowScale = shift
                return DecodedField(name: "Option: Window Scale", value: "\(shift) (×\(1 << shift))", byteRange: range)
            }
            facts.windowScale = tcpMaxWindowScale
            return DecodedField(
                name: "Option: Window Scale", value: "\(shift) (effective 14)", byteRange: range
            )
        case 4 where length == 2:
            facts.sackPermitted = true
            return DecodedField(name: "Option: SACK Permitted", value: "yes", byteRange: range)
        case 5:
            return DecodedField(name: "Option: SACK", value: "\(length - 2) bytes", byteRange: range)
        case 8 where length == 10:
            let tsval = (try? buf.u32(offset + 2)) ?? 0
            let tsecr = (try? buf.u32(offset + 6)) ?? 0
            facts.timestamps = TCPTimestamps(value: tsval, echoReply: tsecr)
            return DecodedField(name: "Option: Timestamps", value: "tsval=\(tsval) tsecr=\(tsecr)", byteRange: range)
        default:
            return DecodedField(name: "Option: kind \(kind)", value: "\(length) bytes", byteRange: range)
        }
    }

    private static func udp(_ buf: PacketBuffer, src: String, dst: String, into packet: inout DecodedPacket) throws {
        let srcPort = try buf.u16(0)
        let dstPort = try buf.u16(2)
        packet.transport = .udp
        packet.sourceEndpoint = IPEndpoint(ip: src, port: srcPort)
        packet.destinationEndpoint = IPEndpoint(ip: dst, port: dstPort)
        packet.fiveTuple = FiveTuple(
            proto: .udp,
            source: IPEndpoint(ip: src, port: srcPort),
            destination: IPEndpoint(ip: dst, port: dstPort)
        )
        packet.layers.append(DecodedLayer(
            proto: .udp, title: "User Datagram Protocol", summary: "\(srcPort) → \(dstPort)",
            fields: [
                ranged("Source Port", "\(srcPort)", in: buf, at: 0, 2),
                ranged("Destination Port", "\(dstPort)", in: buf, at: 2, 2)
            ],
            byteRange: span(buf, 8)
        ))
        let payload = try buf.subset(from: 8)
        try decodeFrameApplication(
            udpFrameApplicationCandidates,
            context: ApplicationMatchContext(payload: payload, sourcePort: srcPort, destinationPort: dstPort),
            into: &packet
        )
    }

    // MARK: Application layer

    private static func dns(_ input: PacketBuffer, into packet: inout DecodedPacket, tcp: Bool) throws {
        // DNS over TCP is length-prefixed (2 bytes).
        let buf = tcp ? try input.subset(from: 2) : input
        // Read the fixed 12-byte header exactly once and retain neutral facts before any
        // variable-body parsing. A short header throws inside the initializer, so
        // `dnsFacts` stays nil; an intact header with a malformed/truncated body keeps it.
        let facts = try DNSMessageFacts(dnsHeader: buf)
        packet.dnsFacts = facts
        let isResponse = facts.isResponse
        var offset = 12
        var firstName = ""
        var firstNameRange: Range<Int>?
        for index in 0 ..< max(Int(facts.questionCount), 0) {
            let nameStart = offset
            let (name, next) = try dnsName(buf, at: offset)
            if index == 0 {
                firstName = name
                firstNameRange = (buf.start + nameStart) ..< (buf.start + next)
            }
            offset = next + 4 // qtype + qclass
        }
        var ipAnswers: [String] = [] // bare IPs only (drives the domain→IP sidebar)
        var displayAnswers: [String] = [] // human-readable per-record values
        var answerFields: [DecodedField] = []
        var omittedAnswers = 0
        for index in 0 ..< max(Int(facts.answerCount), 0) {
            let (_, afterName) = try dnsName(buf, at: offset)
            let type = try buf.u16(afterName)
            let rdLength = try Int(buf.u16(afterName + 8))
            let rdataOffset = afterName + 10
            let rdataRange = (buf.start + rdataOffset) ..< (buf.start + min(rdataOffset + rdLength, buf.length))
            // Decode into a scratch IP list so the cap bounds every retained
            // collection identically. Structural validation continues past the cap
            // — reaching the retention limit never stops bounds-checked parsing.
            var recordIPs: [String] = []
            if let value = try dnsResourceValue(
                type: type,
                rdLength: rdLength,
                buf: buf,
                at: rdataOffset,
                ip: &recordIPs
            ) {
                if displayAnswers.count < dnsAnswerRetentionCap {
                    ipAnswers.append(contentsOf: recordIPs)
                    displayAnswers.append(value)
                    answerFields.append(DecodedField(name: "Answer \(index + 1)", value: value, byteRange: rdataRange))
                } else {
                    // A valid record beyond the retained cap — an omission, not a
                    // duplicate.
                    omittedAnswers += 1
                }
            }
            offset = rdataOffset + rdLength
        }
        packet.appProtocol = .dns
        packet.dnsQuery = firstName
        packet.dnsAnswers = ipAnswers
        packet.dnsAnswersOmittedCount = omittedAnswers
        var fields: [DecodedField] = [
            ranged("Type", isResponse ? "Response" : "Query", in: buf, at: 2, 2),
            DecodedField(name: "Query", value: firstName, byteRange: firstNameRange),
            .init(name: "Answers", value: displayAnswers.isEmpty ? "—" : displayAnswers.joined(separator: ", ")),
        ]
        fields += answerFields
        packet.layers.append(DecodedLayer(
            proto: .dns, title: "Domain Name System", summary: isResponse ? "response" : "query",
            fields: fields,
            byteRange: span(buf, buf.length)
        ))
    }

    /// Decodes one DNS resource record's RDATA into a display string, appending
    /// bare A/AAAA addresses to `ip`. Returns nil for record types we skip.
    private static func dnsResourceValue(
        type: UInt16, rdLength: Int, buf: PacketBuffer, at rdataOffset: Int, ip: inout [String]
    )
        throws -> String?
    {
        switch type {
        case 1 where rdLength == 4:
            let addr = try ipv4Address(buf, rdataOffset)
            ip.append(addr)
            return "A \(addr)"
        case 28 where rdLength == 16:
            let addr = try ipv6Address(buf, rdataOffset)
            ip.append(addr)
            return "AAAA \(addr)"
        case 5:
            return "CNAME " + ((try? dnsName(buf, at: rdataOffset).name) ?? "")
        case 2:
            return "NS " + ((try? dnsName(buf, at: rdataOffset).name) ?? "")
        case 12:
            return "PTR " + ((try? dnsName(buf, at: rdataOffset).name) ?? "")
        case 15:
            let preference = (try? buf.u16(rdataOffset)) ?? 0
            let host = (try? dnsName(buf, at: rdataOffset + 2).name) ?? ""
            return "MX \(preference) \(host)"
        case 16:
            let length = (try? Int(buf.u8(rdataOffset))) ?? 0
            let text = (try? asciiString(buf.bytes(rdataOffset + 1, min(length, max(rdLength - 1, 0))))) ?? ""
            return "TXT \"\(text)\""
        case 33:
            let port = (try? buf.u16(rdataOffset + 4)) ?? 0
            let target = (try? dnsName(buf, at: rdataOffset + 6).name) ?? ""
            return "SRV \(target):\(port)"
        case 6:
            return "SOA " + ((try? dnsName(buf, at: rdataOffset).name) ?? "")
        default:
            return "\(dnsTypeName(type)) (\(rdLength) bytes)"
        }
    }

    private static func dnsTypeName(_ type: UInt16) -> String {
        switch type {
        case 1: "A"
        case 2: "NS"
        case 5: "CNAME"
        case 6: "SOA"
        case 12: "PTR"
        case 15: "MX"
        case 16: "TXT"
        case 28: "AAAA"
        case 33: "SRV"
        case 65: "HTTPS"
        default: "TYPE\(type)"
        }
    }

    /// Walk all complete coalesced TLS records in one TCP payload. A final
    /// truncated record is still emitted once with an honest fragment label.
    private static func tlsRecords(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        var offset = 0
        var recordCount = 0
        while offset + 5 <= buf.length {
            let record = try buf.subset(from: offset)
            guard isTLS(record) else {
                break
            }
            // A further recognizable record begins past the 32-record cap: record the
            // explicit truncation and stop before decoding a 33rd record.
            if recordCount == 32 {
                packet.tlsRecordsTruncated = true
                break
            }
            let recordLength = try 5 + Int(record.u16(3))
            let boundedRecord = try record.subset(
                from: 0, count: min(recordLength, record.length)
            )
            // Bound both presentation and typed parsing to this record. A following
            // coalesced record must never satisfy fields missing from this one.
            try tls(boundedRecord, into: &packet)
            if let fact = TLSFactsDecoder.recordFact(boundedRecord) {
                packet.tlsRecords.append(fact)
            }
            recordCount += 1
            guard recordLength <= record.length else {
                break
            }
            offset += recordLength
        }
    }

    private static func tls(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        let contentType = try buf.u8(0)
        let recordVersion = try buf.u16(1)
        let declaredBody = try Int(buf.u16(3))
        let recordLength = 5 + declaredBody // declared record length (header + body)
        let capturedBody = max(0, min(recordLength, buf.length) - 5)
        let typeName = tlsContentTypeName(contentType)
        var layer = DecodedLayer(
            proto: .tls, title: "Transport Layer Security", summary: tlsVersionName(recordVersion),
            byteRange: span(buf, recordLength)
        )
        layer.fields.append(ranged("Content Type", "\(typeName) (\(contentType))", in: buf, at: 0, 1))
        layer.fields.append(ranged("Version", tlsVersionName(recordVersion), in: buf, at: 1, 2))
        // A packet — or even the bounded session prefix — may still contain only
        // part of a record. Label captured-vs-declared honestly.
        if capturedBody < declaredBody {
            layer.fields.append(ranged(
                "Record Length", "\(declaredBody) declared, \(capturedBody) captured (fragment)",
                in: buf, at: 3, 2
            ))
        } else {
            layer.fields.append(ranged("Record Length", "\(declaredBody)", in: buf, at: 3, 2))
        }
        packet.appProtocol = .tls
        // Only a Handshake record carries a handshake message; never read a handshake
        // byte for Application Data / Alert / Change Cipher Spec / Heartbeat records.
        // A truncated or malformed handshake leaves the record-level layer intact
        // (metadata only — this is not decryption or stream reassembly).
        if contentType == 22 {
            try? enrichTLSHandshake(
                buf, recordVersion: recordVersion, recordLength: recordLength, layer: &layer, packet: &packet
            )
        }
        packet.layers.append(layer)
    }

    /// Enriches a TLS *Handshake* record with ClientHello (SNI/ALPN/version/ciphers)
    /// or ServerHello (version/cipher) detail. Bounds-checked; a truncated handshake
    /// throws and the caller keeps the record-level layer. The caller gates this on
    /// the Handshake content type, so a handshake byte is never read for other records.
    private static func enrichTLSHandshake(
        _ buf: PacketBuffer, recordVersion: UInt16, recordLength: Int,
        layer: inout DecodedLayer, packet: inout DecodedPacket
    )
        throws
    {
        let handshakeType = try buf.u8(5)
        // Parse ClientHello for SNI + ALPN + version/ciphers.
        if handshakeType == 0x01 {
            var hello = DecodedLayer(
                proto: .tls, title: "Handshake: Client Hello", summary: "",
                byteRange: (buf.start + 5) ..< (buf.start + min(recordLength, buf.length))
            )
            // handshake: type(1) len(3) version(2) random(32) sessionIdLen(1)
            let helloVersion = try buf.u16(5 + 4)
            hello.fields.append(ranged("Version", tlsVersionName(helloVersion), in: buf, at: 5 + 4, 2))
            var offset = 5 + 4 + 2 + 32
            let sessionIdLen = try Int(buf.u8(offset))
            offset += 1 + sessionIdLen
            let cipherLen = try Int(buf.u16(offset))
            hello.fields.append(DecodedField(
                name: "Cipher Suites", value: "\(cipherLen / 2) offered",
                byteRange: (buf.start + offset) ..< (buf.start + offset + 2)
            ))
            offset += 2 + cipherLen
            let compLen = try Int(buf.u8(offset))
            offset += 1 + compLen
            let extTotal = try Int(buf.u16(offset))
            offset += 2
            let extEnd = offset + extTotal
            while offset + 4 <= min(extEnd, buf.length) {
                let extType = try buf.u16(offset)
                let extLen = try Int(buf.u16(offset + 2))
                let extData = offset + 4
                if extType == 0x0000 { // server_name
                    // serverNameList: listLen(2) nameType(1) nameLen(2) name
                    let nameLen = try Int(buf.u16(extData + 3))
                    let name = try asciiString(buf.bytes(extData + 5, nameLen))
                    packet.sni = name
                    hello.fields.append(ranged("server_name", name, in: buf, at: extData + 5, nameLen))
                } else if extType == 0x0010 { // application_layer_protocol_negotiation
                    if let alpn = try? alpnProtocols(
                        buf,
                        listStart: extData + 2,
                        end: min(extData + extLen, buf.length)
                    ) {
                        hello.fields.append(DecodedField(
                            name: "ALPN", value: alpn,
                            byteRange: (buf.start + extData) ..< (buf.start + extData + extLen)
                        ))
                    }
                }
                offset = extData + extLen
            }
            if let sni = packet.sni {
                layer.summary = "\(tlsVersionName(recordVersion)) · \(sni)"
            }
            layer.children.append(hello)
        } else if handshakeType == 0x02 { // ServerHello
            var serverHello = DecodedLayer(
                proto: .tls, title: "Handshake: Server Hello", summary: "",
                byteRange: (buf.start + 5) ..< (buf.start + min(recordLength, buf.length))
            )
            let serverVersion = try buf.u16(5 + 4)
            serverHello.fields.append(ranged("Version", tlsVersionName(serverVersion), in: buf, at: 5 + 4, 2))
            var offset = 5 + 4 + 2 + 32
            let sessionIdLen = try Int(buf.u8(offset))
            offset += 1 + sessionIdLen
            let cipher = try buf.u16(offset)
            serverHello.fields.append(DecodedField(
                name: "Cipher Suite", value: tlsCipherName(cipher),
                byteRange: (buf.start + offset) ..< (buf.start + offset + 2)
            ))
            layer.summary = "\(tlsVersionName(serverVersion)) · Server Hello"
            layer.children.append(serverHello)
        }
    }

    /// Parses a TLS ALPN protocol-name list into a comma-joined string.
    private static func alpnProtocols(_ buf: PacketBuffer, listStart: Int, end: Int) throws -> String {
        var protocols: [String] = []
        var offset = listStart
        var guardCounter = 0
        while offset < end, guardCounter < 16 {
            guardCounter += 1
            let length = try Int(buf.u8(offset))
            guard length > 0, offset + 1 + length <= end else {
                break
            }
            try protocols.append(asciiString(buf.bytes(offset + 1, length)))
            offset += 1 + length
        }
        return protocols.joined(separator: ", ")
    }

    private static func tlsCipherName(_ id: UInt16) -> String {
        switch id {
        case 0x1301: "TLS_AES_128_GCM_SHA256"
        case 0x1302: "TLS_AES_256_GCM_SHA384"
        case 0x1303: "TLS_CHACHA20_POLY1305_SHA256"
        case 0xC02B: "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        case 0xC02C: "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
        case 0xC02F: "ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        case 0xC030: "ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        default: String(format: "0x%04x", id)
        }
    }

    private static func http(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        let text = try asciiString(buf.bytes(0, min(buf.length, 512)))
        let firstLine = text.split(separator: "\r\n", maxSplits: 1, omittingEmptySubsequences: false).first
            .map(String.init) ?? ""
        var host = ""
        for line in text.split(separator: "\r\n") where line.lowercased().hasPrefix("host:") {
            host = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
            break
        }
        packet.appProtocol = .http
        let requestLength = min(firstLine.utf8.count, buf.length)
        packet.layers.append(DecodedLayer(
            proto: .http, title: "Hypertext Transfer Protocol", summary: firstLine,
            fields: [
                ranged("Request", firstLine, in: buf, at: 0, requestLength),
                .init(name: "Host", value: host.isEmpty ? "—" : host)
            ],
            byteRange: span(buf, buf.length)
        ))
    }

    /// Surfaces the clear-text QUIC long-header fields (RFC 9000 §17.2): packet
    /// type, version, and the destination/source connection IDs. The caller's
    /// `isQUIC` gate proved the long-header form bit; the fixed bit, packet-number
    /// space, and everything after the source CID are encrypted and never guessed.
    /// A version of 0 is Version Negotiation (§17.2.1). Any bounds failure — a
    /// short header slipping the gate, a CID length over the 20-byte cap, or a
    /// truncated header — falls back to honest identification only.
    private static func quic(_ buf: PacketBuffer, into packet: inout DecodedPacket) {
        packet.appProtocol = .quic
        guard let first = try? buf.u8(0),
              let version = try? buf.u32(1),
              let dcidLen = try? Int(buf.u8(5)), dcidLen <= 20,
              let dcid = try? buf.bytes(6, dcidLen),
              let scidLen = try? Int(buf.u8(6 + dcidLen)), scidLen <= 20,
              let scid = try? buf.bytes(7 + dcidLen, scidLen) else
        {
            packet.layers.append(DecodedLayer(proto: .quic, title: "QUIC", summary: "encrypted transport"))
            return
        }
        let scidLenOffset = 6 + dcidLen
        let isVersionNegotiation = version == 0
        let typeName = isVersionNegotiation ? "Version Negotiation" : quicLongPacketType(first, version: version)
        let versionText = isVersionNegotiation ? "Version Negotiation (0x00000000)" : String(format: "0x%08x", version)
        let summary = isVersionNegotiation ? "Version Negotiation" : "\(typeName) · encrypted transport"
        packet.layers.append(DecodedLayer(
            proto: .quic, title: "QUIC", summary: summary,
            fields: [
                ranged("Packet Type", typeName, in: buf, at: 0, 1),
                ranged("Version", versionText, in: buf, at: 1, 4),
                ranged(
                    "Destination CID", dcid.isEmpty ? "(zero-length)" : hexString(dcid),
                    in: buf, at: 5, 1 + dcidLen
                ),
                ranged(
                    "Source CID", scid.isEmpty ? "(zero-length)" : hexString(scid),
                    in: buf, at: scidLenOffset, 1 + scidLen
                ),
            ],
            byteRange: span(buf, scidLenOffset + 1 + scidLen)
        ))
    }

    /// Names a QUIC v1 long-header packet type from the two type bits (RFC 9000
    /// §17.2). The type-bit meaning is version-specific, so any non-v1 version
    /// renders the raw type value rather than assuming the v1 mapping.
    private static func quicLongPacketType(_ firstByte: UInt8, version: UInt32) -> String {
        let type = (firstByte >> 4) & 0x03
        guard version == 0x00000001 else {
            return "Long Header (type \(type))"
        }
        switch type {
        case 0x00: return "Initial"
        case 0x01: return "0-RTT"
        case 0x02: return "Handshake"
        default: return "Retry"
        }
    }

    /// Decodes the fixed 20-byte STUN header (RFC 5389 §6) and then walks the
    /// declared attribute TLVs. Metadata only — ICE negotiation state and TURN
    /// allocation state are deliberately not tracked; attributes are surfaced by
    /// name, with MAPPED-ADDRESS / XOR-MAPPED-ADDRESS IPv4 reflexive addresses
    /// decoded when fully present. `isSTUN` already proved the magic cookie and
    /// that the declared attribute region is 4-byte aligned and fully captured.
    private static func stun(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        let messageType = try buf.u16(0)
        let messageLength = try Int(buf.u16(2))
        let cookie = try buf.u32(4)
        let transactionID = try buf.bytes(8, 12)
        let typeName = stunMessageTypeName(messageType)
        packet.appProtocol = .stun
        var fields: [DecodedField] = [
            ranged("Message Type", "\(typeName) (\(String(format: "0x%04x", messageType)))", in: buf, at: 0, 2),
            ranged("Message Length", "\(messageLength)", in: buf, at: 2, 2),
            ranged("Magic Cookie", String(format: "0x%08x", cookie), in: buf, at: 4, 4),
            ranged("Transaction ID", hexString(transactionID), in: buf, at: 8, 12),
        ]
        fields += stunAttributes(buf, messageLength: messageLength)
        packet.layers.append(DecodedLayer(
            proto: .stun, title: "Session Traversal Utilities for NAT", summary: typeName,
            fields: fields,
            byteRange: span(buf, 20 + messageLength)
        ))
    }

    /// Walks the STUN attribute TLVs (RFC 5389 §15): 2-byte type, 2-byte value
    /// length, value padded to a 4-byte boundary, starting at offset 20. Every
    /// read is bounds-checked; a truncated or over-declared attribute stops the
    /// walk and keeps the header-level record intact rather than trapping.
    private static func stunAttributes(_ buf: PacketBuffer, messageLength: Int) -> [DecodedField] {
        var fields: [DecodedField] = []
        let end = min(20 + messageLength, buf.length)
        var offset = 20
        var guardCounter = 0
        while offset + 4 <= end, guardCounter < 64 {
            guardCounter += 1
            guard let type = try? buf.u16(offset),
                  let valueLength = try? Int(buf.u16(offset + 2)),
                  offset + 4 + valueLength <= end else
            {
                break
            }
            let valueStart = offset + 4
            let name = stunAttributeName(type)
            let value = stunAttributeValue(type: type, buf: buf, at: valueStart, length: valueLength)
            fields.append(DecodedField(
                name: "Attribute: \(name)", value: value,
                byteRange: (buf.start + offset) ..< (buf.start + valueStart + valueLength)
            ))
            // Advance past the value plus its 4-byte-boundary padding.
            offset = valueStart + ((valueLength + 3) & ~0x03)
        }
        return fields
    }

    /// Readable names for the RFC 5389 §18.2 attribute registry. Any other type
    /// (including ICE/TURN extensions we deliberately do not interpret) falls back
    /// to an honest hex rendering rather than a guessed label.
    private static func stunAttributeName(_ type: UInt16) -> String {
        switch type {
        case 0x0001: "MAPPED-ADDRESS"
        case 0x0006: "USERNAME"
        case 0x0008: "MESSAGE-INTEGRITY"
        case 0x0009: "ERROR-CODE"
        case 0x000A: "UNKNOWN-ATTRIBUTES"
        case 0x0014: "REALM"
        case 0x0015: "NONCE"
        case 0x0020: "XOR-MAPPED-ADDRESS"
        case 0x8022: "SOFTWARE"
        case 0x8023: "ALTERNATE-SERVER"
        case 0x8028: "FINGERPRINT"
        default: String(format: "0x%04x", type)
        }
    }

    /// Renders an attribute's value. MAPPED-ADDRESS / XOR-MAPPED-ADDRESS surface a
    /// decoded IPv4 `address:port` when the family is IPv4 and the value is fully
    /// present; every other attribute (and IPv6 or malformed address families)
    /// stays a metadata-only byte count — never a fabricated value.
    private static func stunAttributeValue(type: UInt16, buf: PacketBuffer, at offset: Int, length: Int) -> String {
        switch type {
        case 0x0001: stunMappedAddress(buf, at: offset, length: length, xor: false) ?? "\(length) bytes"
        case 0x0020: stunMappedAddress(buf, at: offset, length: length, xor: true) ?? "\(length) bytes"
        default: "\(length) bytes"
        }
    }

    /// Decodes a STUN (XOR-)MAPPED-ADDRESS value (RFC 5389 §15.1–15.2) for the
    /// IPv4 family only: reserved byte, family, port, 4-byte address. XOR form
    /// un-masks the port with the cookie's high half and the address with the full
    /// magic cookie. Returns nil for the IPv6 family or any short/malformed value.
    private static func stunMappedAddress(_ buf: PacketBuffer, at offset: Int, length: Int, xor: Bool) -> String? {
        guard length >= 8,
              let family = try? buf.u8(offset + 1), family == 0x01,
              var port = try? buf.u16(offset + 2),
              var octets = try? buf.bytes(offset + 4, 4) else
        {
            return nil
        }
        if xor {
            port ^= UInt16(stunMagicCookie >> 16)
            octets[0] ^= UInt8((stunMagicCookie >> 24) & 0xFF)
            octets[1] ^= UInt8((stunMagicCookie >> 16) & 0xFF)
            octets[2] ^= UInt8((stunMagicCookie >> 8) & 0xFF)
            octets[3] ^= UInt8(stunMagicCookie & 0xFF)
        }
        return "\(octets.map { "\($0)" }.joined(separator: ".")):\(port)"
    }

    /// Readable names for the canonical Binding method classes; any other valid
    /// STUN type falls back to an honest hex rendering rather than a guess.
    private static func stunMessageTypeName(_ type: UInt16) -> String {
        switch type {
        case 0x0001: "Binding Request"
        case 0x0011: "Binding Indication"
        case 0x0101: "Binding Success Response"
        case 0x0111: "Binding Error Response"
        default: String(format: "0x%04x", type)
        }
    }

    // MARK: Heuristics

    /// Content-based TLS record recognition, delegated to `TLSFactsDecoder` so record
    /// header validation lives beside the neutral TLS fact parsing.
    private static func isTLS(_ buf: PacketBuffer) -> Bool {
        TLSFactsDecoder.isTLSRecord(buf)
    }

    private static func isHTTP(_ buf: PacketBuffer) -> Bool {
        guard let bytes = try? buf.bytes(0, min(buf.length, 8)) else {
            return false
        }
        let prefix = asciiString(bytes)
        return ["GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI", "HTTP"].contains { prefix.hasPrefix($0) }
    }

    private static func containsHTTPHeaderTerminator(_ bytes: [UInt8]) -> Bool {
        guard bytes.count >= 4 else {
            return false
        }
        for index in 0 ... (bytes.count - 4)
            where bytes[index] == 13 && bytes[index + 1] == 10
            && bytes[index + 2] == 13 && bytes[index + 3] == 10
        {
            return true
        }
        return false
    }

    private static func withoutByteRanges(_ layer: DecodedLayer) -> DecodedLayer {
        DecodedLayer(
            proto: layer.proto,
            title: layer.title,
            summary: layer.summary,
            fields: layer.fields.map { DecodedField(name: $0.name, value: $0.value) },
            children: layer.children.map(withoutByteRanges)
        )
    }

    /// Conservative QUIC long-header recognition. A high bit by itself is far
    /// too weak on busy UDP/443 traffic, so require the complete clear-text
    /// prefix and RFC-bounded connection IDs. Non-zero versions also carry the
    /// fixed bit; Version Negotiation deliberately does not require it because
    /// those unused header bits are randomized.
    private static func isQUIC(_ buf: PacketBuffer) -> Bool {
        guard buf.length >= 7,
              let first = try? buf.u8(0), (first & 0x80) != 0,
              let version = try? buf.u32(1),
              version == 0 || (first & 0x40) != 0,
              let dcidLength = try? Int(buf.u8(5)), dcidLength <= 20,
              (try? buf.bytes(6, dcidLength)) != nil,
              let scidLength = try? Int(buf.u8(6 + dcidLength)), scidLength <= 20,
              (try? buf.bytes(7 + dcidLength, scidLength)) != nil else
        {
            return false
        }
        return true
    }

    /// STUN detection (RFC 5389): a ≥20-byte payload whose two leading type bits
    /// are zero, whose offset-4 word is the magic cookie, and whose declared
    /// attribute length is 4-byte aligned and fully present in the capture. All
    /// three together make a false positive on arbitrary UDP effectively impossible;
    /// truncated or oversized-length payloads fail the last check and stay UDP.
    private static func isSTUN(_ buf: PacketBuffer) -> Bool {
        guard buf.length >= 20,
              let typeByte = try? buf.u8(0), (typeByte & 0xC0) == 0,
              let cookie = try? buf.u32(4), cookie == stunMagicCookie,
              let messageLength = try? Int(buf.u16(2)),
              messageLength % 4 == 0,
              20 + messageLength <= buf.length else
        {
            return false
        }
        return true
    }

    // MARK: Byte-range helpers

    /// A field whose value lives at `offset` (relative to `buf`) for `size` bytes.
    /// `buf.start` is the layer's absolute offset within the frame, so the range
    /// is absolute into the frame's `rawBytes` — exactly what the hex pane needs.
    private static func ranged(
        _ name: String, _ value: String,
        in buf: PacketBuffer, at offset: Int, _ size: Int
    )
        -> DecodedField
    {
        DecodedField(name: name, value: value, byteRange: (buf.start + offset) ..< (buf.start + offset + size))
    }

    /// The absolute span of a whole layer (`length` bytes from `buf`'s start),
    /// clamped to the captured bytes.
    private static func span(_ buf: PacketBuffer, _ length: Int) -> Range<Int> {
        let clamped = max(0, min(length, buf.length))
        return buf.start ..< (buf.start + clamped)
    }

    // MARK: Field formatting

    private static func asciiString(_ bytes: [UInt8]) -> String {
        String(bytes: bytes, encoding: .utf8) ?? ""
    }

    private static func mac(_ buf: PacketBuffer, _ offset: Int) throws -> String {
        try (0 ..< 6).map { try String(format: "%02x", buf.u8(offset + $0)) }.joined(separator: ":")
    }

    /// Lower-case contiguous hex (e.g. a STUN transaction ID), no separators.
    private static func hexString(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    private static func ipv4Address(_ buf: PacketBuffer, _ offset: Int) throws -> String {
        try "\(buf.u8(offset)).\(buf.u8(offset + 1)).\(buf.u8(offset + 2)).\(buf.u8(offset + 3))"
    }

    private static func ipv6Address(_ buf: PacketBuffer, _ offset: Int) throws -> String {
        try (0 ..< 8).map { try String(format: "%x", buf.u16(offset + $0 * 2)) }.joined(separator: ":")
    }

    private static func dnsName(_ buf: PacketBuffer, at start: Int) throws -> (name: String, next: Int) {
        var labels: [String] = []
        var offset = start
        var next = -1
        var guardCounter = 0
        while guardCounter < 128 {
            guardCounter += 1
            let len = try buf.u8(offset)
            if len == 0 {
                if next < 0 {
                    next = offset + 1
                }
                break
            }
            if len & 0xC0 == 0xC0 { // compression pointer
                if next < 0 {
                    next = offset + 2
                }
                let pointer = try Int(buf.u16(offset) & 0x3FFF)
                offset = pointer
                continue
            }
            let label = try asciiString(buf.bytes(offset + 1, Int(len)))
            labels.append(label)
            offset += 1 + Int(len)
        }
        return (labels.joined(separator: "."), next < 0 ? offset : next)
    }

    private static func etherTypeName(_ type: UInt16) -> String {
        switch type {
        case 0x0800: "IPv4 (0x0800)"
        case 0x86DD: "IPv6 (0x86DD)"
        case 0x0806: "ARP (0x0806)"
        default: String(format: "0x%04x", type)
        }
    }

    private static func ipProtoName(_ proto: UInt8) -> String {
        switch proto {
        case 6: "TCP (6)"
        case 17: "UDP (17)"
        case 1: "ICMP (1)"
        case 58: "ICMPv6 (58)"
        default: "\(proto)"
        }
    }

    private static func tcpFlags(_ flags: UInt8) -> String {
        var parts: [String] = []
        if flags & 0x02 != 0 {
            parts.append("SYN")
        }
        if flags & 0x10 != 0 {
            parts.append("ACK")
        }
        if flags & 0x08 != 0 {
            parts.append("PSH")
        }
        if flags & 0x01 != 0 {
            parts.append("FIN")
        }
        if flags & 0x04 != 0 {
            parts.append("RST")
        }
        return parts.isEmpty ? "·" : parts.joined(separator: ", ")
    }

    /// Human-readable TLS record content-type name (RFC 8446 §5.1). Only 20…24 are
    /// defined; anything else is rendered honestly rather than guessed.
    private static func tlsContentTypeName(_ type: UInt8) -> String {
        switch type {
        case 20: "Change Cipher Spec"
        case 21: "Alert"
        case 22: "Handshake"
        case 23: "Application Data"
        case 24: "Heartbeat"
        default: "type \(type)"
        }
    }

    private static func tlsVersionName(_ version: UInt16) -> String {
        switch version {
        case 0x0301: "TLS 1.0"
        case 0x0302: "TLS 1.1"
        case 0x0303: "TLS 1.2"
        case 0x0304: "TLS 1.3"
        default: String(format: "0x%04x", version)
        }
    }
}

// MARK: - Application matcher registry

/// The centralized, first-match-wins application classifiers. These live in a same-file
/// extension purely so the primary `PacketDecoder` enum stays within its body-length
/// budget; `private` members here remain reachable from the enum in the same file. The
/// three ordered arrays preserve the exact predicate composition, precedence, thrown-error
/// behavior and completion rules of the former inline `if`/`else if` chains — this only
/// centralizes them; it is deliberately *not* a generic decoder architecture.
private extension PacketDecoder {
    // MARK: Internal

    /// The fixed context every application matcher sees: the transport payload — a
    /// whole-frame TCP/UDP payload, or the bounded reassembled TCP prefix — plus the
    /// connection's ports. For the reassembled buffer `payload.length` equals the
    /// assembled byte count, so length checks read the same as the old `bytes.count`.
    struct ApplicationMatchContext {
        let payload: PacketBuffer
        let sourcePort: UInt16
        let destinationPort: UInt16
    }

    // MARK: Fileprivate

    /// One immutable, first-match-wins application candidate: a pure `matches` gate
    /// and the `decode` action run when it is the first gate to pass. `decode` returns
    /// the reassembled `isComplete` value, or nil to abort a reassembled decode; the
    /// whole-frame driver ignores the returned value. A candidate whose `decode`
    /// throws never falls through to a lower-priority candidate.
    struct ApplicationCandidate {
        let matches: (ApplicationMatchContext) -> Bool
        let decode: (ApplicationMatchContext, inout DecodedPacket) throws -> Bool?
    }

    /// Whole-frame TCP order: content-detected TLS → port-53 DNS → content-detected HTTP.
    static let tcpFrameApplicationCandidates: [ApplicationCandidate] = [
        ApplicationCandidate(
            matches: { isTLS($0.payload) },
            decode: { context, packet in
                try tlsRecords(context.payload, into: &packet)
                return nil
            }
        ),
        ApplicationCandidate(
            matches: { $0.sourcePort == 53 || $0.destinationPort == 53 },
            decode: { context, packet in
                try dns(context.payload, into: &packet, tcp: true)
                return nil
            }
        ),
        ApplicationCandidate(
            matches: { isHTTP($0.payload) },
            decode: { context, packet in
                try http(context.payload, into: &packet)
                return nil
            }
        ),
    ]

    /// Whole-frame UDP order: content-detected STUN (port-independent — STUN rides on
    /// ephemeral ICE ports, not a well-known one; the UDP five-tuple/session grouping
    /// set by `udp` is preserved and this only enriches the app layer) → port-53 DNS →
    /// port-443 QUIC (a 443 endpoint plus the conservative content predicate).
    static let udpFrameApplicationCandidates: [ApplicationCandidate] = [
        ApplicationCandidate(
            matches: { isSTUN($0.payload) },
            decode: { context, packet in
                try stun(context.payload, into: &packet)
                return nil
            }
        ),
        ApplicationCandidate(
            matches: { $0.sourcePort == 53 || $0.destinationPort == 53 },
            decode: { context, packet in
                try dns(context.payload, into: &packet, tcp: false)
                return nil
            }
        ),
        ApplicationCandidate(
            matches: { ($0.sourcePort == 443 || $0.destinationPort == 443) && isQUIC($0.payload) },
            decode: { context, packet in
                quic(context.payload, into: &packet)
                return nil
            }
        ),
    ]

    /// Reassembled TCP order: content-detected TLS → port-53 DNS (only once the
    /// two-byte length prefix is present) → content-detected HTTP. Each `decode`
    /// yields the record's `isComplete`, or nil to fail the whole reassembled decode.
    static let reassembledApplicationCandidates: [ApplicationCandidate] = [
        ApplicationCandidate(
            matches: { isTLS($0.payload) },
            decode: { context, packet in
                try tlsRecords(context.payload, into: &packet)
                let declared = try 5 + Int(context.payload.u16(3))
                return context.payload.length >= declared
            }
        ),
        ApplicationCandidate(
            matches: { ($0.sourcePort == 53 || $0.destinationPort == 53) && $0.payload.length >= 2 },
            decode: { context, packet in
                let declared = try Int(context.payload.u16(0))
                guard declared > 0, context.payload.length >= 2 + declared else {
                    return nil
                }
                try dns(context.payload, into: &packet, tcp: true)
                return true
            }
        ),
        ApplicationCandidate(
            matches: { isHTTP($0.payload) },
            decode: { context, packet in
                try http(context.payload, into: &packet)
                return try containsHTTPHeaderTerminator(context.payload.bytes(0, context.payload.length))
            }
        ),
    ]

    /// Runs the whole-frame application chain: the first candidate whose gate passes
    /// decodes and returns; a throw propagates (kept partial by `decode`'s top-level
    /// catch) and never falls through. No match leaves the frame at its transport layer.
    static func decodeFrameApplication(
        _ candidates: [ApplicationCandidate],
        context: ApplicationMatchContext,
        into packet: inout DecodedPacket
    )
        throws
    {
        for candidate in candidates where candidate.matches(context) {
            _ = try candidate.decode(context, &packet)
            return
        }
    }

    /// Runs the reassembled TCP application chain: the first passing gate decodes and
    /// returns its `isComplete`; a nil result, a throw, or no match fails the decode
    /// (nil) without falling through to a lower-priority candidate.
    static func decodeReassembledApplication(
        context: ApplicationMatchContext,
        into packet: inout DecodedPacket
    )
        -> Bool?
    {
        for candidate in reassembledApplicationCandidates where candidate.matches(context) {
            // A throwing candidate fails the whole reassembled decode (nil) rather than
            // falling through to a lower-priority gate — `try?` flattens both to nil.
            return try? candidate.decode(context, &packet)
        }
        return nil
    }
}
