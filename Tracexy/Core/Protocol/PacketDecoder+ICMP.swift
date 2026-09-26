import Foundation

// MARK: - PacketDecoder ICMP

/// ICMP and ICMPv6 decoding, kept beside the decoder rather than inside it.
///
/// Two jobs live here. The first is the ordinary one: name the message's family,
/// type and code, key a session on the IP pair (port 0, since ICMP is
/// connectionless) and render one layer. The second is the quotation — an ICMP
/// *error* carries back the head of the datagram that provoked it, and reading it
/// is what lets an error be reported against the flow it was actually about rather
/// than only against the ICMP conversation that delivered it.
///
/// The quotation is read into typed flow identity and nothing else: no quoted
/// payload, sequence number, identifier, TTL or byte is retained. Every read is
/// bounds-checked and the whole path fails closed, so a truncated, fragmented or
/// exotic quotation yields no flow rather than a guessed one.
extension PacketDecoder {
    /// ICMP / ICMPv6. Connectionless, so we key a session on the IP pair (port 0)
    /// to surface ping / unreachable / neighbor-discovery traffic in the list.
    /// Internal so the transport dispatch in `PacketDecoder` can reach it.
    static func icmp(
        _ buf: PacketBuffer, src: String, dst: String, isV6: Bool, into packet: inout DecodedPacket
    )
        throws
    {
        let type = try buf.u8(0)
        let code = try buf.u8(1)
        let family: ICMPFamily = isV6 ? .ipv6 : .ipv4
        // Both fixed bytes read — retain neutral family/type/code before building the
        // layer. Family is the already-known IP protocol, never inferred from the body.
        // An error type additionally quotes the datagram that provoked it; that
        // quotation is read into typed flow identity only, and only when it is
        // complete and unambiguous (see `icmpQuotedFlow`).
        let quotedFlow = icmpQuotedFlow(buf, family: family, type: type)
        packet.icmpFacts = ICMPMessageFacts(family: family, type: type, code: code, quotedFlow: quotedFlow)
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
        var fields = [
            ranged("Type", "\(typeName) (\(type))", in: buf, at: 0, 1),
            ranged("Code", "\(code)", in: buf, at: 1, 1),
        ]
        if let checksum = try? buf.u16(2) {
            fields.append(ranged("Checksum", hex(checksum, digits: 4), in: buf, at: 2, 2))
        }
        var layerLength = min(8, buf.length)
        if let quotedFlow {
            // The quoted datagram starts at offset 8. The fields name only what was
            // read: the original flow's protocol and its two endpoints.
            fields.append(ranged("Original Protocol", quotedFlow.proto.label, in: buf, at: 8, 1))
            fields.append(ranged("Original Source", quotedFlow.source.display, in: buf, at: 8, 1))
            fields.append(ranged("Original Destination", quotedFlow.destination.display, in: buf, at: 8, 1))
            layerLength = buf.length
        }
        packet.layers.append(DecodedLayer(
            proto: kind, title: isV6 ? "Internet Control Message Protocol v6" : "Internet Control Message Protocol",
            summary: typeName,
            fields: fields,
            byteRange: span(buf, layerLength)
        ))
    }

    /// The flow an ICMP error message quotes back, or `nil`.
    ///
    /// Only the types that actually quote the invoking datagram are read — IPv4
    /// destination unreachable / source quench / redirect / time exceeded /
    /// parameter problem (RFC 792), IPv6 destination unreachable / packet too big /
    /// time exceeded / parameter problem (RFC 4443 §3). The quotation begins at
    /// offset 8, after the type, code, checksum and the four type-specific bytes.
    ///
    /// Every read is bounds-checked and the whole function fails closed to `nil`:
    /// a quotation whose IP version disagrees with the ICMP family, a non-first
    /// fragment (whose transport header travelled elsewhere), a transport other
    /// than TCP or UDP, an IPv6 quotation carrying extension headers, or a
    /// quotation cut short by the snapshot length all yield nothing rather than a
    /// guessed flow. No quoted byte, sequence number or identifier is retained.
    private static func icmpQuotedFlow(
        _ buf: PacketBuffer, family: ICMPFamily, type: UInt8
    )
        -> ICMPQuotedFlowFacts?
    {
        switch (family, type) {
        case (.ipv4, 3),
             (.ipv4, 4),
             (.ipv4, 5),
             (.ipv4, 11),
             (.ipv4, 12),
             (.ipv6, 1),
             (.ipv6, 2),
             (.ipv6, 3),
             (.ipv6, 4):
            break
        default:
            return nil
        }
        guard let quoted = try? buf.subset(from: 8) else {
            return nil
        }
        return switch family {
        case .ipv4: quotedIPv4Flow(quoted)
        case .ipv6: quotedIPv6Flow(quoted)
        }
    }

    /// The quoted IPv4 datagram's flow identity: version 4, a header length within
    /// the buffer, fragment offset zero, and a TCP/UDP transport whose two ports
    /// are present.
    private static func quotedIPv4Flow(_ buf: PacketBuffer) -> ICMPQuotedFlowFacts? {
        guard let versionIHL = try? buf.u8(0), versionIHL >> 4 == 4 else {
            return nil
        }
        let headerLength = Int(versionIHL & 0x0F) * 4
        guard headerLength >= 20,
              let flagsFragment = try? buf.u16(6), flagsFragment & 0x1FFF == 0,
              let proto = try? buf.u8(9), let kind = quotedTransportKind(proto),
              let source = try? ipv4Address(buf, 12), let destination = try? ipv4Address(buf, 16),
              let sourcePort = try? buf.u16(headerLength),
              let destinationPort = try? buf.u16(headerLength + 2) else
        {
            return nil
        }
        return ICMPQuotedFlowFacts(
            proto: kind,
            source: IPEndpoint(ip: source, port: sourcePort),
            destination: IPEndpoint(ip: destination, port: destinationPort)
        )
    }

    /// The quoted IPv6 datagram's flow identity: version 6 and a TCP/UDP next
    /// header immediately after the fixed 40-byte header. An extension header is a
    /// refusal rather than a walk — the quotation is bounded and a mis-walk would
    /// invent ports.
    private static func quotedIPv6Flow(_ buf: PacketBuffer) -> ICMPQuotedFlowFacts? {
        guard let byte0 = try? buf.u8(0), byte0 >> 4 == 6,
              let nextHeader = try? buf.u8(6), let kind = quotedTransportKind(nextHeader),
              let source = try? ipv6Address(buf, 8), let destination = try? ipv6Address(buf, 24),
              let sourcePort = try? buf.u16(40), let destinationPort = try? buf.u16(42) else
        {
            return nil
        }
        return ICMPQuotedFlowFacts(
            proto: kind,
            source: IPEndpoint(ip: source, port: sourcePort),
            destination: IPEndpoint(ip: destination, port: destinationPort)
        )
    }

    /// The two transports whose first four bytes are the source and destination
    /// ports, so a quotation of 8 bytes is enough to name the flow.
    private static func quotedTransportKind(_ proto: UInt8) -> ProtocolKind? {
        switch proto {
        case 6: .tcp
        case 17: .udp
        default: nil
        }
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
}
