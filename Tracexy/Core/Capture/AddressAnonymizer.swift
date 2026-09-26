import Foundation

// MARK: - AddressAnonymizer

/// Replaces the addresses in captured packet headers for an export that can be
/// shared: Ethernet/SLL MAC addresses, ARP sender and target, IPv4 and IPv6 source
/// and destination, and the IP header an ICMP error quotes. Each distinct address
/// maps to one stand-in for the whole export, in first-seen order, so conversations
/// still line up: IPv4 → `10.x.y.z`, IPv6 → `fd00::/8` unique-local, MAC → locally
/// administered `02:00:…`. Broadcast, multicast, unspecified and loopback addresses
/// keep their meaning and are left as they are.
///
/// The IPv4 header checksum is recomputed, and so are TCP, UDP, ICMP and ICMPv6
/// checksums when the whole segment was captured (they cover the addresses, or the
/// quoted header). **Payloads are not changed**: a DNS answer, an HTTP Host header
/// or a TLS server name still carries whatever it carried — callers say so.
///
/// Frames of a link type this cannot parse, or too short to hold the header they
/// claim, are refused (`nil`) rather than written with addresses left in them.
nonisolated struct AddressAnonymizer: Sendable {
    // MARK: Internal

    /// How many distinct addresses of each family were replaced so far.
    var replacedIPv4Count: Int {
        ipv4.count
    }

    var replacedIPv6Count: Int {
        ipv6.count
    }

    var replacedMACCount: Int {
        mac.count
    }

    /// `bytes` with its header addresses replaced, or `nil` when the frame cannot be
    /// anonymized safely.
    mutating func anonymize(_ bytes: [UInt8], linkType: UInt32) -> [UInt8]? {
        var frame = bytes
        switch linkType {
        case LinkType.ethernet:
            guard frame.count >= 14 else {
                return nil
            }
            replaceMAC(&frame, at: 0)
            replaceMAC(&frame, at: 6)
            var offset = 12
            var etherType = Self.u16(frame, 12)
            // 802.1Q / 802.1ad tags, at most two.
            for _ in 0 ..< 2 where etherType == 0x8100 || etherType == 0x88A8 {
                guard frame.count >= offset + 6 else {
                    return nil
                }
                offset += 4
                etherType = Self.u16(frame, offset)
            }
            return network(&frame, etherType: etherType, at: offset + 2) ? frame : nil
        case LinkType.null,
             108:
            guard frame.count >= 4 else {
                return nil
            }
            let family = linkType == 108
                ? UInt32(Self.u16(frame, 0)) << 16 | UInt32(Self.u16(frame, 2))
                : UInt32(frame[0]) | UInt32(frame[1]) << 8 | UInt32(frame[2]) << 16 | UInt32(frame[3]) << 24
            let etherType: UInt16 = family == 2 ? 0x0800 : [24, 28, 30].contains(family) ? 0x86DD : 0
            return network(&frame, etherType: etherType, at: 4) ? frame : nil
        case LinkType.raw,
             228,
             229:
            guard let first = frame.first else {
                return nil
            }
            let etherType: UInt16 = first >> 4 == 4 ? 0x0800 : first >> 4 == 6 ? 0x86DD : 0
            return network(&frame, etherType: etherType, at: 0) ? frame : nil
        case LinkType.linuxSLL:
            guard frame.count >= 16 else {
                return nil
            }
            if Self.u16(frame, 4) == 6 {
                replaceMAC(&frame, at: 6)
            } else {
                frame.replaceSubrange(6 ..< 14, with: [UInt8](repeating: 0, count: 8))
            }
            return network(&frame, etherType: Self.u16(frame, 14), at: 16) ? frame : nil
        case LinkType.linuxSLL2:
            guard frame.count >= 20 else {
                return nil
            }
            if frame[11] == 6 {
                replaceMAC(&frame, at: 12)
            } else {
                frame.replaceSubrange(12 ..< 20, with: [UInt8](repeating: 0, count: 8))
            }
            return network(&frame, etherType: Self.u16(frame, 0), at: 20) ? frame : nil
        default:
            return nil
        }
    }

    // MARK: Private

    private var ipv4: [[UInt8]: [UInt8]] = [:]
    private var ipv6: [[UInt8]: [UInt8]] = [:]
    private var mac: [[UInt8]: [UInt8]] = [:]

    private static func u16(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    private static func put16(_ value: UInt16, into bytes: inout [UInt8], at offset: Int) {
        bytes[offset] = UInt8(value >> 8)
        bytes[offset + 1] = UInt8(value & 0xFF)
    }

    /// One's-complement sum of `bytes` as big-endian 16-bit words.
    private static func sum(_ bytes: ArraySlice<UInt8>, into total: inout UInt32) {
        var index = bytes.startIndex
        while index + 1 < bytes.endIndex {
            total &+= UInt32(bytes[index]) << 8 | UInt32(bytes[index + 1])
            index += 2
        }
        if index < bytes.endIndex {
            total &+= UInt32(bytes[index]) << 8
        }
    }

    private static func fold(_ total: UInt32) -> UInt16 {
        var value = total
        while value >> 16 != 0 {
            value = (value & 0xFFFF) + (value >> 16)
        }
        return ~UInt16(value)
    }

    /// Replace the network layer at `offset`; `false` when it cannot be done safely.
    private mutating func network(_ frame: inout [UInt8], etherType: UInt16, at offset: Int) -> Bool {
        switch etherType {
        case 0x0800: ipv4Packet(&frame, at: offset, depth: 0)
        case 0x86DD: ipv6Packet(&frame, at: offset, depth: 0)
        case 0x0806: arp(&frame, at: offset)
        default:
            // Anything else carries no IP address field this knows; its frame is
            // refused rather than exported unexamined.
            false
        }
    }

    private mutating func arp(_ frame: inout [UInt8], at offset: Int) -> Bool {
        guard frame.count >= offset + 28, Self.u16(frame, offset) == 1, Self.u16(frame, offset + 2) == 0x0800,
              frame[offset + 4] == 6, frame[offset + 5] == 4 else
        {
            return false
        }
        replaceMAC(&frame, at: offset + 8)
        replaceIPv4(&frame, at: offset + 14)
        replaceMAC(&frame, at: offset + 18)
        replaceIPv4(&frame, at: offset + 24)
        return true
    }

    /// `depth` 1 is an IPv4 header quoted inside an ICMP error: addresses and the
    /// header checksum are rewritten, the (truncated) payload is not parsed further.
    private mutating func ipv4Packet(_ frame: inout [UInt8], at offset: Int, depth: Int) -> Bool {
        guard frame.count >= offset + 20, frame[offset] >> 4 == 4 else {
            return false
        }
        let headerLength = Int(frame[offset] & 0x0F) * 4
        guard headerLength >= 20, frame.count >= offset + headerLength else {
            return false
        }
        replaceIPv4(&frame, at: offset + 12)
        replaceIPv4(&frame, at: offset + 16)
        Self.put16(0, into: &frame, at: offset + 10)
        var total: UInt32 = 0
        Self.sum(frame[offset ..< offset + headerLength], into: &total)
        Self.put16(Self.fold(total), into: &frame, at: offset + 10)
        guard depth == 0 else {
            return true
        }
        let totalLength = Int(Self.u16(frame, offset + 2))
        let fragment = Self.u16(frame, offset + 6) & 0x3FFF != 0
        let proto = frame[offset + 9]
        let transport = offset + headerLength
        let end = offset + totalLength
        // Only a whole, unfragmented segment's checksum can be recomputed.
        guard !fragment, totalLength >= headerLength, end <= frame.count else {
            return true
        }
        var pseudo: UInt32 = 0
        Self.sum(frame[offset + 12 ..< offset + 20], into: &pseudo)
        pseudo &+= UInt32(proto) + UInt32(end - transport)
        return transportChecksum(&frame, proto: proto, from: transport, to: end, pseudo: pseudo, icmpUsesPseudo: false)
    }

    private mutating func ipv6Packet(_ frame: inout [UInt8], at offset: Int, depth: Int) -> Bool {
        guard frame.count >= offset + 40, frame[offset] >> 4 == 6 else {
            return false
        }
        replaceIPv6(&frame, at: offset + 8)
        replaceIPv6(&frame, at: offset + 24)
        guard depth == 0 else {
            return true
        }
        let payloadLength = Int(Self.u16(frame, offset + 4))
        let next = frame[offset + 6]
        let transport = offset + 40
        let end = transport + payloadLength
        // Extension headers or a cut segment: addresses are replaced; the
        // transport checksum is left as captured.
        guard [6, 17, 58].contains(next), end <= frame.count else {
            return true
        }
        var pseudo: UInt32 = 0
        Self.sum(frame[offset + 8 ..< offset + 40], into: &pseudo)
        pseudo &+= UInt32(end - transport) + UInt32(next)
        return transportChecksum(&frame, proto: next, from: transport, to: end, pseudo: pseudo, icmpUsesPseudo: true)
    }

    private mutating func transportChecksum(
        _ frame: inout [UInt8],
        proto: UInt8,
        from start: Int,
        to end: Int,
        pseudo: UInt32,
        icmpUsesPseudo: Bool
    )
        -> Bool
    {
        let checksumOffset: Int
        var total: UInt32 = 0
        switch proto {
        case 6:
            guard end - start >= 20 else {
                return true
            }
            checksumOffset = start + 16
            total = pseudo
        case 17:
            guard end - start >= 8 else {
                return true
            }
            checksumOffset = start + 6
            // An IPv4 UDP checksum of zero means "none"; keep it that way.
            if !icmpUsesPseudo, Self.u16(frame, checksumOffset) == 0 {
                return true
            }
            total = pseudo
        case 1,
             58:
            guard end - start >= 8 else {
                return true
            }
            checksumOffset = start + 2
            let type = frame[start]
            // ICMP errors quote the offending packet's header after 8 bytes.
            let quotesPacket = proto == 1 ? [3, 4, 5, 11, 12].contains(type) : [1, 2, 3, 4].contains(type)
            if quotesPacket, end - start >= 8 + 20 {
                if proto == 1 {
                    _ = ipv4Packet(&frame, at: start + 8, depth: 1)
                } else if end - start >= 8 + 40 {
                    _ = ipv6Packet(&frame, at: start + 8, depth: 1)
                }
            }
            total = icmpUsesPseudo ? pseudo : 0
        default:
            return true
        }
        Self.put16(0, into: &frame, at: checksumOffset)
        Self.sum(frame[start ..< end], into: &total)
        var checksum = Self.fold(total)
        if proto == 17, checksum == 0 {
            checksum = 0xFFFF
        }
        Self.put16(checksum, into: &frame, at: checksumOffset)
        return true
    }

    private mutating func replaceMAC(_ frame: inout [UInt8], at offset: Int) {
        let original = Array(frame[offset ..< offset + 6])
        // Group (multicast/broadcast) and all-zero addresses keep their meaning.
        guard original[0] & 0x01 == 0, original != [0, 0, 0, 0, 0, 0] else {
            return
        }
        let replacement = mac[original] ?? {
            let index = mac.count + 1
            return [0x02, 0x00, 0x00, UInt8(index >> 16 & 0xFF), UInt8(index >> 8 & 0xFF), UInt8(index & 0xFF)]
        }()
        mac[original] = replacement
        frame.replaceSubrange(offset ..< offset + 6, with: replacement)
    }

    private mutating func replaceIPv4(_ frame: inout [UInt8], at offset: Int) {
        let original = Array(frame[offset ..< offset + 4])
        let first = original[0]
        // Unspecified, "this network", loopback, multicast, reserved and broadcast
        // keep their meaning.
        guard first != 0, first != 127, first < 224 else {
            return
        }
        let replacement = ipv4[original] ?? {
            let index = ipv4.count + 1
            return [10, UInt8(index >> 16 & 0xFF), UInt8(index >> 8 & 0xFF), UInt8(index & 0xFF)]
        }()
        ipv4[original] = replacement
        frame.replaceSubrange(offset ..< offset + 4, with: replacement)
    }

    private mutating func replaceIPv6(_ frame: inout [UInt8], at offset: Int) {
        let original = Array(frame[offset ..< offset + 16])
        let loopback = [UInt8](repeating: 0, count: 15) + [1]
        // Multicast, unspecified and loopback keep their meaning.
        guard original[0] != 0xFF, original != [UInt8](repeating: 0, count: 16), original != loopback else {
            return
        }
        let replacement = ipv6[original] ?? {
            let index = ipv6.count + 1
            return [
                0xFD,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                UInt8(index >> 24 & 0xFF),
                UInt8(index >> 16 & 0xFF),
                UInt8(index >> 8 & 0xFF),
                UInt8(index & 0xFF)
            ]
        }()
        ipv6[original] = replacement
        frame.replaceSubrange(offset ..< offset + 16, with: replacement)
    }
}
