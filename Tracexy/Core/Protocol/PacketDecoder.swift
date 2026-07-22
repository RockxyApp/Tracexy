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

    // MARK: Private

    /// IPv6 extension-header protocol numbers (RFC 8200 order).
    private static let ipv6ExtensionHeaders: Set<UInt8> = [0, 43, 44, 51, 60, 135]

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
        let dataOffset = try Int(buf.u8(12) >> 4) * 4
        let flags = try buf.u8(13)
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
        // Parse TCP options (between the fixed 20-byte header and dataOffset).
        if dataOffset > 20 {
            fields += (try? tcpOptions(buf, end: min(dataOffset, buf.length))) ?? []
        }
        packet.layers.append(DecodedLayer(
            proto: .tcp, title: "Transmission Control Protocol", summary: "\(srcPort) → \(dstPort)",
            fields: fields,
            byteRange: span(buf, dataOffset)
        ))
        guard dataOffset < buf.length else {
            return
        }
        let payload = try buf.subset(from: dataOffset)
        if payload.isEmpty {
            return
        }
        if isTLS(payload) {
            try tls(payload, into: &packet)
        } else if srcPort == 53 || dstPort == 53 {
            try dns(payload, into: &packet, tcp: true)
        } else if isHTTP(payload) {
            try http(payload, into: &packet)
        }
    }

    /// Parses the TCP option list (offset 20 → `end`) into decoded fields. Our
    /// own walk of the kind/length/value TLV format (RFC 793/7323), referencing
    /// the option-parsing approach in PcapPlusPlus/libtins.
    private static func tcpOptions(_ buf: PacketBuffer, end: Int) throws -> [DecodedField] {
        var fields: [DecodedField] = []
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
            fields.append(tcpOptionField(kind: kind, buf: buf, at: offset, length: length))
            offset += length
        }
        return fields
    }

    private static func tcpOptionField(kind: UInt8, buf: PacketBuffer, at offset: Int, length: Int) -> DecodedField {
        let range = (buf.start + offset) ..< (buf.start + offset + length)
        switch kind {
        case 2 where length == 4:
            let mss = (try? buf.u16(offset + 2)) ?? 0
            return DecodedField(name: "Option: MSS", value: "\(mss)", byteRange: range)
        case 3 where length == 3:
            let shift = (try? buf.u8(offset + 2)) ?? 0
            return DecodedField(name: "Option: Window Scale", value: "\(shift) (×\(1 << shift))", byteRange: range)
        case 4:
            return DecodedField(name: "Option: SACK Permitted", value: "yes", byteRange: range)
        case 5:
            return DecodedField(name: "Option: SACK", value: "\(length - 2) bytes", byteRange: range)
        case 8 where length == 10:
            let tsval = (try? buf.u32(offset + 2)) ?? 0
            let tsecr = (try? buf.u32(offset + 6)) ?? 0
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
        if srcPort == 53 || dstPort == 53 {
            try dns(payload, into: &packet, tcp: false)
        } else if srcPort == 443 || dstPort == 443, isQUIC(payload) {
            quicLayer(&packet)
        }
    }

    // MARK: Application layer

    private static func dns(_ input: PacketBuffer, into packet: inout DecodedPacket, tcp: Bool) throws {
        // DNS over TCP is length-prefixed (2 bytes).
        let buf = tcp ? try input.subset(from: 2) : input
        let flags = try buf.u16(2)
        let qdCount = try Int(buf.u16(4))
        let anCount = try Int(buf.u16(6))
        let isResponse = (flags & 0x8000) != 0
        var offset = 12
        var firstName = ""
        var firstNameRange: Range<Int>?
        for index in 0 ..< max(qdCount, 0) {
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
        for index in 0 ..< max(anCount, 0) {
            let (_, afterName) = try dnsName(buf, at: offset)
            let type = try buf.u16(afterName)
            let rdLength = try Int(buf.u16(afterName + 8))
            let rdataOffset = afterName + 10
            let rdataRange = (buf.start + rdataOffset) ..< (buf.start + min(rdataOffset + rdLength, buf.length))
            if let value = try dnsResourceValue(
                type: type,
                rdLength: rdLength,
                buf: buf,
                at: rdataOffset,
                ip: &ipAnswers
            ) {
                displayAnswers.append(value)
                answerFields.append(DecodedField(name: "Answer \(index + 1)", value: value, byteRange: rdataRange))
            }
            offset = rdataOffset + rdLength
        }
        packet.appProtocol = .dns
        packet.dnsQuery = firstName
        packet.dnsAnswers = ipAnswers
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

    private static func tls(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        let recordVersion = try buf.u16(1)
        let handshakeType = try buf.u8(5)
        let recordLength = (try? buf.u16(3)).map { 5 + Int($0) } ?? buf.length
        var layer = DecodedLayer(
            proto: .tls, title: "Transport Layer Security", summary: tlsVersionName(recordVersion),
            byteRange: span(buf, recordLength)
        )
        layer.fields.append(ranged("Content Type", "Handshake (22)", in: buf, at: 0, 1))
        packet.appProtocol = .tls
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
        packet.layers.append(layer)
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

    private static func quicLayer(_ packet: inout DecodedPacket) {
        packet.appProtocol = .quic
        packet.layers.append(DecodedLayer(proto: .quic, title: "QUIC", summary: "encrypted transport"))
    }

    // MARK: Heuristics

    private static func isTLS(_ buf: PacketBuffer) -> Bool {
        guard let type = try? buf.u8(0), let major = try? buf.u8(1) else {
            return false
        }
        return type == 0x16 && major == 0x03
    }

    private static func isHTTP(_ buf: PacketBuffer) -> Bool {
        guard let bytes = try? buf.bytes(0, min(buf.length, 8)) else {
            return false
        }
        let prefix = asciiString(bytes)
        return ["GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI", "HTTP"].contains { prefix.hasPrefix($0) }
    }

    private static func isQUIC(_ buf: PacketBuffer) -> Bool {
        guard let first = try? buf.u8(0) else {
            return false
        }
        return (first & 0x80) != 0 // long-header form
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
