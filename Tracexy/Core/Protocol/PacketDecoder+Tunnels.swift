import Foundation

// MARK: - PacketDecoder tunnels

/// GRE (RFC 2784/2890), VXLAN (RFC 7348) and IP in IP (RFC 2003 IPIP, RFC 4213 6in4):
/// the outer header becomes one layer and the inner packet is decoded as if it had
/// been captured on its own, so the session is the *inner* conversation, tagged with
/// the tunnel it rode in. Nesting is bounded;
/// a tunnel inside more than ``maximumTunnelDepth`` tunnels is left undecoded rather
/// than recursed into. Every read is bounds-checked, and a GRE version, flag or
/// payload type this decoder does not know stops at the GRE layer.
extension PacketDecoder {
    // MARK: Internal

    static let maximumTunnelDepth = 2

    static func gre(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        let flags = try buf.u8(0)
        let version = try buf.u8(1) & 0x07
        let protocolType = try buf.u16(2)
        let hasChecksum = flags & 0x80 != 0
        let hasKey = flags & 0x20 != 0
        let hasSequence = flags & 0x10 != 0
        var headerLength = 4
        var fields: [DecodedField] = [
            ranged(
                "Protocol type",
                String(format: "0x%04X (%@)", protocolType, greTypeName(protocolType)),
                in: buf,
                at: 2,
                2
            ),
        ]
        if hasChecksum {
            headerLength += 4
        }
        if hasKey {
            try fields.append(ranged(
                "Key",
                String(format: "0x%08X", buf.u32(headerLength)),
                in: buf,
                at: headerLength,
                4
            ))
            headerLength += 4
        }
        if hasSequence {
            try fields.append(ranged("Sequence", "\(buf.u32(headerLength))", in: buf, at: headerLength, 4))
            headerLength += 4
        }
        packet.layers.append(DecodedLayer(
            proto: .gre, title: "Generic Routing Encapsulation", summary: greTypeName(protocolType),
            fields: fields, byteRange: span(buf, headerLength)
        ))
        // Version 1 is PPTP's enhanced GRE, which carries PPP, not a packet decoded here.
        guard version == 0, packet.tunnelDepth < maximumTunnelDepth else {
            return
        }
        let inner = try buf.subset(from: headerLength)
        packet.tunnelDepth += 1
        switch protocolType {
        case 0x0800: try ipv4(inner, into: &packet)
        case 0x86DD: try ipv6(inner, into: &packet)
        case 0x6558: try ethernet(inner, into: &packet)
        default: break
        }
    }

    /// IP protocol 4 or 41 (next header 4 or 41 in IPv6): an IPv4 or IPv6 packet
    /// carried directly, with no tunnel header of its own. The inner header must be of
    /// the version the protocol number names.
    static func ipInIP(_ buf: PacketBuffer, version: UInt8, into packet: inout DecodedPacket) throws {
        guard packet.tunnelDepth < maximumTunnelDepth, try buf.u8(0) >> 4 == version else {
            return
        }
        packet.tunnelDepth += 1
        if version == 4 {
            try ipv4(buf, into: &packet)
        } else {
            try ipv6(buf, into: &packet)
        }
    }

    /// VXLAN on UDP 4789: an 8-byte header whose I flag marks a valid 24-bit VNI,
    /// followed by a whole inner Ethernet frame.
    static func vxlan(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        let vni = try (buf.u32(4)) >> 8
        packet.layers.append(DecodedLayer(
            proto: .vxlan, title: "Virtual eXtensible LAN", summary: "VNI \(vni)",
            fields: [ranged("VNI", "\(vni)", in: buf, at: 4, 3)],
            byteRange: span(buf, 8)
        ))
        guard packet.tunnelDepth < maximumTunnelDepth else {
            return
        }
        packet.tunnelDepth += 1
        try ethernet(buf.subset(from: 8), into: &packet)
    }

    /// The I flag set, the reserved bits clear, and room for an inner Ethernet header.
    static func isVXLAN(_ buf: PacketBuffer) -> Bool {
        guard buf.length >= 8 + 14, let flags = try? buf.u8(0), let reserved = try? buf.u8(7) else {
            return false
        }
        return flags == 0x08 && reserved == 0
    }

    // MARK: Private

    private static func greTypeName(_ type: UInt16) -> String {
        switch type {
        case 0x0800: "IPv4"
        case 0x86DD: "IPv6"
        case 0x6558: "Transparent Ethernet"
        case 0x880B: "PPP"
        case 0x88BE: "ERSPAN"
        default: "unknown"
        }
    }
}
