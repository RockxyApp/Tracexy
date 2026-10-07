import Foundation

// MARK: - IP fragments

nonisolated extension PacketDecoder {
    /// The fragment facts of an IPv4 header whose More Fragments flag or offset is
    /// set. The payload is bounded by the declared total length, as for any IPv4
    /// payload; a declared length past the captured bytes marks it incomplete.
    static func ipv4Fragment(
        _ buf: PacketBuffer,
        headerLength: Int,
        totalLength: Int,
        source: String,
        destination: String,
        identification: UInt16,
        protocolNumber: UInt8,
        flagsFragment: UInt16
    )
        -> IPFragmentFacts
    {
        let declared = totalLength >= headerLength && totalLength > 0
        let end = declared ? min(totalLength, buf.length) : buf.length
        let payloadStart = buf.start + min(headerLength, buf.length)
        return IPFragmentFacts(
            version: .v4,
            source: source,
            destination: destination,
            identification: UInt32(identification),
            protocolNumber: protocolNumber,
            offset: Int(flagsFragment & 0x1FFF) * 8,
            moreFragments: flagsFragment & 0x2000 != 0,
            payloadRange: payloadStart ..< max(payloadStart, buf.start + end),
            isPayloadComplete: declared && totalLength <= buf.length
        )
    }

    /// Reads an IPv6 Fragment extension header at `offset` (RFC 8200 §4.5: offset in
    /// 8-octet units in the high 13 bits, M flag in bit 0), adding its fields to
    /// `fields`. Returns the fragment facts when the header marks a fragment.
    static func ipv6FragmentHeader(
        _ buf: PacketBuffer,
        at offset: Int,
        declaredEnd: Int?,
        source: String,
        destination: String,
        nextHeader: UInt8,
        fields: inout [DecodedField]
    )
        -> IPFragmentFacts?
    {
        guard let fragmentField = try? buf.u16(offset + 2) else {
            return nil
        }
        let fragmentOffset = Int(fragmentField >> 3) * 8
        let moreFragments = fragmentField & 0x01 != 0
        fields.append(ranged(
            "Fragment", "offset \(fragmentOffset)\(moreFragments ? ", more fragments" : ", last fragment")",
            in: buf, at: offset + 2, 2
        ))
        guard moreFragments || fragmentOffset > 0, let identification = try? buf.u32(offset + 4) else {
            return nil
        }
        fields.append(ranged("Identification", hex(identification, digits: 8), in: buf, at: offset + 4, 4))
        return ipv6Fragment(
            buf, headerEnd: offset + 8, declaredEnd: declaredEnd, source: source, destination: destination,
            identification: identification, nextHeader: nextHeader, fragmentField: fragmentField
        )
    }

    /// The fragment facts of an IPv6 Fragment extension header (RFC 8200 §4.5). The
    /// payload follows the 8-byte Fragment header and ends where the fixed header's
    /// Payload Length says; `declaredEnd` is `nil` when that length was zero.
    static func ipv6Fragment(
        _ buf: PacketBuffer,
        headerEnd: Int,
        declaredEnd: Int?,
        source: String,
        destination: String,
        identification: UInt32,
        nextHeader: UInt8,
        fragmentField: UInt16
    )
        -> IPFragmentFacts
    {
        let end = min(declaredEnd ?? buf.length, buf.length)
        let payloadStart = buf.start + min(headerEnd, buf.length)
        return IPFragmentFacts(
            version: .v6,
            source: source,
            destination: destination,
            identification: identification,
            protocolNumber: nextHeader,
            offset: Int(fragmentField >> 3) * 8,
            moreFragments: fragmentField & 0x01 != 0,
            payloadRange: payloadStart ..< max(payloadStart, buf.start + end),
            isPayloadComplete: declaredEnd.map { $0 <= buf.length } ?? false
        )
    }

    /// Walks the IPv6 extension headers at the start of a reassembled datagram
    /// (bounded as the fixed-header walk is). Returns the transport protocol, where
    /// it starts and a byte-range-free layer per extension header.
    private static func ipv6ExtensionChain(
        _ buffer: PacketBuffer,
        from first: UInt8
    )
        -> (proto: UInt8, start: Int, layers: [DecodedLayer])
    {
        var proto = first
        var offset = 0
        var layers: [DecodedLayer] = []
        while ipv6ExtensionHeaders.contains(proto), proto != 44, layers.count < 16,
              let next = try? buffer.u8(offset),
              let length = try? ipv6ExtensionLength(proto: proto, buf: buffer, at: offset),
              length > 0, offset + length <= buffer.length
        {
            layers.append(DecodedLayer(
                proto: .ipv6,
                title: "IPv6 \(ipv6ExtensionName(proto))",
                summary: "next \(ipProtoName(next))",
                fields: [
                    DecodedField(name: "Next Header", value: ipProtoName(next)),
                    DecodedField(name: "Length", value: "\(length) bytes"),
                ]
            ))
            proto = next
            offset += length
        }
        return (proto, offset, layers)
    }

    /// Decodes a reassembled datagram onto the frame that completed it. The frame
    /// keeps its own link and IP layers; a "Reassembled" layer names the frames the
    /// datagram came from; the transport and application layers follow, decoded
    /// from the datagram's bytes and carrying no byte ranges, since those bytes span
    /// several frames and must never highlight offsets in this one.
    static func applyReassembly(
        _ datagram: [UInt8],
        fragment: IPFragmentFacts,
        frames: [UInt64],
        to packet: inout DecodedPacket
    ) {
        var inner = DecodedPacket(timestamp: packet.timestamp, originalLength: packet.originalLength)
        let buffer = PacketBuffer(datagram)
        // An IPv6 datagram's fragmentable part may open with extension headers
        // (Destination Options, Routing, AH) before the transport header.
        let (proto, start, extensionLayers) = fragment.version == .v6
            ? ipv6ExtensionChain(buffer, from: fragment.protocolNumber)
            : (fragment.protocolNumber, 0, [])
        do {
            try transport(
                buffer.subset(from: start),
                proto: proto,
                src: fragment.source,
                dst: fragment.destination,
                into: &inner
            )
        } catch let PacketError.malformed(reason) {
            inner.decodeStop = .malformed(reason)
        } catch {
            inner.decodeStop = .malformed("A header runs past the end of the reassembled datagram")
        }
        let version = fragment.version == .v4 ? "IPv4" : "IPv6"
        let frameList = frames.map(String.init).joined(separator: ", ")
        let reassembled = DecodedLayer(
            proto: fragment.version == .v4 ? .ipv4 : .ipv6,
            title: "Reassembled \(version) Datagram",
            summary: "\(datagram.count) bytes in \(frames.count) fragments",
            fields: [
                DecodedField(name: "Reassembled Length", value: "\(datagram.count) bytes"),
                DecodedField(name: "Fragment Frames", value: frameList),
            ]
        )
        var result = inner
        result.layers = packet.layers + [reassembled] + extensionLayers + inner.layers.map(withoutByteRanges)
        result.rawBytes = packet.rawBytes
        result.processName = packet.processName
        result.tunnelDepth = packet.tunnelDepth
        result.ipFragment = packet.ipFragment
        result.reassembly = IPReassemblyFacts(version: fragment.version, length: datagram.count, frames: frames)
        // The datagram's payload is not in this frame's bytes: hand it over as bytes.
        if let range = inner.udpPayloadRange, range.upperBound <= datagram.count {
            result.reassembledUDPPayload = Array(datagram[range])
        }
        result.udpPayloadRange = nil
        packet = result
    }
}
