import Foundation

// MARK: - LinkType

nonisolated enum LinkType {
    static let ethernet: UInt32 = 1
    static let null: UInt32 = 0
    static let raw: UInt32 = 101
    /// Linux cooked capture (`LINKTYPE_LINUX_SLL`): a 16-byte synthetic header.
    static let linuxSLL: UInt32 = 113
    /// Linux cooked capture v2 (`LINKTYPE_LINUX_SLL2`): a 20-byte synthetic header.
    static let linuxSLL2: UInt32 = 276
}

// MARK: - PacketDecoder link layer

/// Link-layer framing and DLT dispatch.
///
/// Every framing decoder here stops at one typed network handoff
/// (``PacketDecoder/network(_:_:into:)``): it names IPv4, IPv6 or ARP and the
/// existing, unchanged network decoders carry on into transport and application
/// parsing. Nothing in this file parses a transport or application byte, and
/// nothing here is a generic decoder registry — it is the same fixed dispatch the
/// decoder has always had, with Linux cooked capture added beside Ethernet, BSD
/// loopback and raw IP.
extension PacketDecoder {
    // MARK: Internal

    /// Decode the frame's link layer for `linkType`. A throw leaves whatever
    /// layers were already parsed in place, exactly as the per-case `try?` in
    /// ``PacketDecoder/decode(_:linkType:timestamp:originalLength:)`` did before.
    static func linkLayer(_ frame: PacketBuffer, linkType: UInt32, into packet: inout DecodedPacket) throws {
        switch linkType {
        case LinkType.ethernet: try ethernet(frame, into: &packet)
        case LinkType.raw: try rawIP(frame, into: &packet)
        case LinkType.null: try loopback(frame, into: &packet)
        case LinkType.linuxSLL: try linuxCooked(frame, version: .sll, into: &packet)
        case LinkType.linuxSLL2: try linuxCooked(frame, version: .sll2, into: &packet)
        // VPN/tunnel (utun) and other point-to-point links report assorted
        // DLTs — auto-detect raw IP vs a 4-byte address-family header.
        default: try tunnel(frame, into: &packet)
        }
    }

    // MARK: Private

    /// IEEE 802.1Q (C-VLAN) and 802.1ad (S-VLAN / QinQ) tag protocol identifiers.
    private static let vlanTagEtherTypes: Set<UInt16> = [0x8100, 0x88A8]

    private static func ethernet(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        let dst = try mac(buf, 0)
        let src = try mac(buf, 6)
        var etherType = try buf.u16(12)
        packet.layers.append(DecodedLayer(
            proto: .ethernet, title: "Ethernet II", summary: "\(src) → \(dst)",
            fields: [
                ranged("Destination", dst, in: buf, at: 0, 6),
                ranged("Source", src, in: buf, at: 6, 6),
                ranged("Type", etherTypeName(etherType), in: buf, at: 12, 2)
            ],
            byteRange: span(buf, 14)
        ))
        // VLAN tags sit between the source address and the real EtherType: a
        // 2-byte TCI followed by the encapsulated type. A tagged frame from a
        // trunk-port or mirrored capture otherwise reads as "type 0x8100" and
        // silently yields no session. At most two tags (QinQ) are walked; the
        // tag is framing, so like Ethernet itself it never enters a protocol stack.
        var offset = 14
        var tagCount = 0
        while Self.vlanTagEtherTypes.contains(etherType), tagCount < 2 {
            tagCount += 1
            let tci = try buf.u16(offset)
            let inner = try buf.u16(offset + 2)
            let vlanID = tci & 0x0FFF
            let priority = tci >> 13
            try packet.layers.append(DecodedLayer(
                proto: .ethernet,
                title: etherType == 0x88A8 ? "802.1ad Service VLAN" : "802.1Q Virtual LAN",
                summary: "VLAN \(vlanID)",
                fields: [
                    ranged("Priority", "\(priority)", in: buf, at: offset, 1),
                    ranged("VLAN ID", "\(vlanID)", in: buf, at: offset, 2),
                    ranged("Type", etherTypeName(inner), in: buf, at: offset + 2, 2)
                ],
                byteRange: span(buf.subset(from: offset), 4)
            ))
            etherType = inner
            offset += 4
        }
        let payload = try buf.subset(from: offset)
        switch etherType {
        case 0x0800: try network(.ipv4, payload, into: &packet)
        case 0x86DD: try network(.ipv6, payload, into: &packet)
        case 0x0806: try network(.arp, payload, into: &packet)
        default: break
        }
    }

    /// `LINKTYPE_RAW` carries a bare IP packet with no link header at all. The
    /// registered type covers IPv4 *and* IPv6, so the version nibble chooses.
    /// Any other nibble is not an IP packet: it is reported rather than read as
    /// an IPv4 header that was never there.
    private static func rawIP(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        let version = try buf.u8(0) >> 4
        switch version {
        case 4: try network(.ipv4, buf, into: &packet)
        case 6: try network(.ipv6, buf, into: &packet)
        default: throw PacketError.malformed("Raw IP frame declares no IPv4 or IPv6 version")
        }
    }

    private static func loopback(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        // BSD loopback: 4-byte address family header.
        let family = try buf.u32le(0)
        let payload = try buf.subset(from: 4)
        if family == 2 {
            try network(.ipv4, payload, into: &packet)
        } else {
            try network(.ipv6, payload, into: &packet)
        }
    }

    /// Decodes a tunnel/raw frame whose link-layer header is unknown: a bare IP
    /// packet, or one prefixed with a 4-byte BSD address family (NULL/LOOP).
    private static func tunnel(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        if let first = try? buf.u8(0) {
            switch first >> 4 {
            case 4: try network(.ipv4, buf, into: &packet)
                return
            case 6: try network(.ipv6, buf, into: &packet)
                return
            default: break
            }
        }
        try loopback(buf, into: &packet) // 4-byte address-family prefix
    }

    // MARK: Linux cooked capture

    /// Linux cooked capture (SLL / SLL2) — the synthetic framing a Linux
    /// any-interface capture produces.
    ///
    /// The single address field holds the packet sender's link-layer address;
    /// it does not provide an Ethernet source/destination pair. No local interface
    /// name or direction relative to this Mac is invented from it.
    /// The SLL2 interface index stays the
    /// capture machine's own number, unknown to any interface here.
    ///
    /// A short fixed header publishes nothing at all. A complete header always
    /// keeps its facts; the payload is handed to a network decoder only when the
    /// hardware type actually gives the protocol field its EtherType meaning, the
    /// protocol value is one this build decodes, and the payload really carries
    /// that network header. Otherwise the frame stays at its link layer with no
    /// endpoints and no session.
    private static func linuxCooked(
        _ buf: PacketBuffer,
        version: LinuxCookedHeader.Version,
        into packet: inout DecodedPacket
    )
        throws
    {
        let header = try LinuxCookedHeader.parse(buf, version: version)
        packet.layers.append(linuxCookedLayer(header, in: buf))
        guard header.usesEtherTypePayload,
              let kind = linuxCookedNetworkPayload(header.protocolNumber),
              let payload = try? buf.subset(from: version.headerLength),
              carriesDeclaredNetworkHeader(kind, payload) else
        {
            return
        }
        try network(kind, payload, into: &packet)
    }

    /// The header layer, with every field cited at its exact version-specific
    /// offset. SLL2 reorders the same facts and adds the reserved word and the
    /// capture machine's interface index, so the two field lists are built
    /// separately rather than sharing one guessed layout.
    private static func linuxCookedLayer(_ header: LinuxCookedHeader, in buf: PacketBuffer) -> DecodedLayer {
        let packetType = linuxPacketTypeName(header.packetType)
        let hardware = linuxHardwareTypeName(header.hardwareType)
        // Only an EtherType-carrying hardware type gives the protocol field its
        // EtherType meaning; otherwise the number is shown as the raw value it is.
        let protocolValue = header.usesEtherTypePayload
            ? etherTypeName(header.protocolNumber)
            : String(format: "0x%04x", header.protocolNumber)
        var fields: [DecodedField] = []
        switch header.version {
        case .sll:
            fields.append(ranged("Packet Type", packetType, in: buf, at: 0, 2))
            fields.append(ranged("Hardware Type", hardware, in: buf, at: 2, 2))
            fields.append(ranged("Address Length", "\(header.declaredAddressLength)", in: buf, at: 4, 2))
            fields.append(linuxCookedAddressField(header, in: buf, at: 6))
            fields.append(ranged("Protocol", protocolValue, in: buf, at: 14, 2))
        case .sll2:
            fields.append(ranged("Protocol", protocolValue, in: buf, at: 0, 2))
            if let reserved = header.reserved {
                fields.append(ranged("Reserved", String(format: "0x%04x", reserved), in: buf, at: 2, 2))
            }
            if let interfaceIndex = header.interfaceIndex {
                fields.append(ranged("Capture Interface Index", "\(interfaceIndex)", in: buf, at: 4, 4))
            }
            fields.append(ranged("Hardware Type", hardware, in: buf, at: 8, 2))
            fields.append(ranged("Packet Type", packetType, in: buf, at: 10, 1))
            fields.append(ranged("Address Length", "\(header.declaredAddressLength)", in: buf, at: 11, 1))
            fields.append(linuxCookedAddressField(header, in: buf, at: 12))
        }
        return DecodedLayer(
            proto: .linuxCooked,
            title: header.version == .sll ? "Linux Cooked Capture" : "Linux Cooked Capture v2",
            summary: "\(packetType) · \(protocolValue)",
            fields: fields,
            byteRange: span(buf, header.version.headerLength)
        )
    }

    /// The header's one link-layer address. At most eight bytes are stored even
    /// when the declared length is larger, so an over-long address is labelled as
    /// the prefix it is instead of being presented as the whole address. A
    /// zero-length address is a legitimate value here and cites no bytes.
    private static func linuxCookedAddressField(
        _ header: LinuxCookedHeader, in buf: PacketBuffer, at offset: Int
    )
        -> DecodedField
    {
        let declared = Int(header.declaredAddressLength)
        let stored = header.addressPrefix.count
        guard stored > 0 else {
            return DecodedField(name: "Address", value: "(none)")
        }
        let text = header.addressPrefix.map { String(format: "%02x", $0) }.joined(separator: ":")
        let value = declared > stored ? "\(text) (first \(stored) of \(declared) bytes)" : text
        return ranged("Address", value, in: buf, at: offset, stored)
    }

    /// The strict set of cooked protocol values this build hands on: exactly the
    /// EtherType values whose network decoders already exist. Anything else —
    /// including values a future decoder might cover — keeps its header facts and
    /// stops, rather than being guessed into an IP shape.
    private static func linuxCookedNetworkPayload(_ protocolNumber: UInt16) -> NetworkPayload? {
        switch protocolNumber {
        case 0x0800: .ipv4
        case 0x86DD: .ipv6
        case 0x0806: .arp
        default: nil
        }
    }

    /// Whether `buf` really begins with the network header the cooked header's
    /// protocol field claims. The existing network decoders are bounds-checked but
    /// deliberately trusting about *shape*; a mislabelled, truncated or padded
    /// cooked payload must leave the frame at its link layer rather than produce an
    /// endpoint pair and a session that were never on the wire.
    private static func carriesDeclaredNetworkHeader(_ kind: NetworkPayload, _ buf: PacketBuffer) -> Bool {
        switch kind {
        case .ipv4:
            guard buf.length >= 20, let versionIHL = try? buf.u8(0), versionIHL >> 4 == 4 else {
                return false
            }
            let headerLength = Int(versionIHL & 0x0F) * 4
            return headerLength >= 20 && headerLength <= buf.length
        case .ipv6:
            guard buf.length >= 40, let version = try? buf.u8(0), version >> 4 == 6 else {
                return false
            }
            return true
        case .arp:
            // Only the Ethernet/IPv4 ARP shape the existing decoder reads at fixed
            // offsets: hardware 1, protocol IPv4, six-byte hardware and four-byte
            // protocol addresses, and the complete 28-byte message.
            guard buf.length >= 28,
                  let hardware = try? buf.u16(0), hardware == 1,
                  let protocolType = try? buf.u16(2), protocolType == 0x0800,
                  let hardwareLength = try? buf.u8(4), hardwareLength == 6,
                  let protocolLength = try? buf.u8(5), protocolLength == 4 else
            {
                return false
            }
            return true
        }
    }

    /// The Linux `PACKET_*` audience/direction values. They describe the capture
    /// machine's relationship to the frame, never this Mac's.
    private static func linuxPacketTypeName(_ type: UInt16) -> String {
        switch type {
        case 0: "To capture host (0)"
        case 1: "Broadcast (1)"
        case 2: "Multicast (2)"
        case 3: "To another host (3)"
        case 4: "Sent by capture host (4)"
        default: "type \(type)"
        }
    }

    /// `ARPHRD_` hardware types. Only values whose meaning is certain are named;
    /// anything else renders as its number rather than a guess. Naming a type is
    /// not the same as trusting its payload — Frame Relay (770), radiotap (803)
    /// and Netlink (824) are excluded from the handoff by
    /// ``LinuxCookedHeader/usesEtherTypePayload``, while GRE-over-IP (778) is not:
    /// a recognized protocol value there still names an ordinary IP payload.
    private static func linuxHardwareTypeName(_ type: UInt16) -> String {
        let name: String? = switch type {
        case 1: "Ethernet"
        case 768: "IPIP tunnel"
        case 770: "Frame Relay"
        case 772: "Loopback"
        case 776: "IPv6-in-IPv4"
        case 778: "GRE over IP"
        case 803: "802.11 radiotap"
        case 824: "Netlink"
        default: nil
        }
        guard let name else {
            return "\(type)"
        }
        return "\(name) (\(type))"
    }

    private static func etherTypeName(_ type: UInt16) -> String {
        switch type {
        case 0x0800: "IPv4 (0x0800)"
        case 0x86DD: "IPv6 (0x86DD)"
        case 0x0806: "ARP (0x0806)"
        case 0x8100: "802.1Q VLAN (0x8100)"
        case 0x88A8: "802.1ad VLAN (0x88A8)"
        default: String(format: "0x%04x", type)
        }
    }
}
