import Foundation
import Testing
@testable import Tracexy

/// 802.1Q / 802.1ad tagged Ethernet frames — the shape every trunk-port or
/// mirror-port capture has — must reach the same network decoders as untagged
/// frames instead of stopping at an opaque "type 0x8100".
@Suite("VLAN-tagged Ethernet decode")
struct VLANDecodeTests {
    // MARK: Internal

    @Test("An 802.1Q tag is walked to the encapsulated IPv4 session")
    func singleTagReachesTransport() {
        let frame = tagged(PacketBuilder.dnsQueryFrame(name: "example.com", src: "10.0.0.1", dst: "10.0.0.53"), tags: [
            (tpid: 0x8100, tci: 0x6064) // priority 3, VLAN 100
        ])
        let packet = decode(frame)
        #expect(packet.layers.map(\.proto) == [.ethernet, .ethernet, .ipv4, .udp, .dns])
        let vlan = packet.layers[1]
        #expect(vlan.title == "802.1Q Virtual LAN")
        #expect(vlan.summary == "VLAN 100")
        #expect(vlan.fields.contains { $0.name == "VLAN ID" && $0.value == "100" })
        #expect(vlan.fields.contains { $0.name == "Priority" && $0.value == "3" })
        #expect(vlan.byteRange == 14 ..< 18)
        #expect(packet.fiveTuple?.proto == .udp)
        #expect(packet.dnsQuery == "example.com")
        // Framing never enters the session's protocol stack.
        #expect(!packet.protocolStack.contains(.ethernet))
        // The IPv4 layer's byte range accounts for the 4-byte tag.
        #expect(packet.layers[2].byteRange == 18 ..< 38)
    }

    @Test("QinQ (802.1ad outer + 802.1Q inner) is walked through both tags")
    func doubleTagReachesTransport() {
        let frame = tagged(
            PacketBuilder.tcpSynFrame(src: "10.0.0.1", dst: "10.0.0.2", srcPort: 4_000, dstPort: 80),
            tags: [
                (tpid: 0x88A8, tci: 0x0007),
                (tpid: 0x8100, tci: 0x0008),
            ]
        )
        let packet = decode(frame)
        #expect(packet.layers.map(\.title).prefix(3) == ["Ethernet II", "802.1ad Service VLAN", "802.1Q Virtual LAN"])
        #expect(packet.fiveTuple?.proto == .tcp)
        #expect(packet.destinationEndpoint?.port == 80)
    }

    @Test("A tag with a truncated inner type keeps the Ethernet layer and forms no session")
    func truncatedTagStopsAtFraming() {
        let base = PacketBuilder.tcpSynFrame(src: "10.0.0.1", dst: "10.0.0.2", srcPort: 4_000, dstPort: 80)
        let frame = Array(base.prefix(12)) + [0x81, 0x00, 0x00, 0x05]
        let packet = decode(frame)
        #expect(packet.layers.map(\.proto) == [.ethernet])
        #expect(packet.fiveTuple == nil)
    }

    @Test("An unknown encapsulated type after the tag forms no session")
    func unknownInnerTypeStopsAfterTag() {
        let base = PacketBuilder.tcpSynFrame(src: "10.0.0.1", dst: "10.0.0.2", srcPort: 4_000, dstPort: 80)
        var frame = tagged(base, tags: [(tpid: 0x8100, tci: 0x0001)])
        frame[16] = 0x88
        frame[17] = 0xCC // LLDP
        let packet = decode(frame)
        #expect(packet.layers.map(\.proto) == [.ethernet, .ethernet])
        #expect(packet.fiveTuple == nil)
    }

    // MARK: Private

    /// Inserts VLAN tags between the source MAC and the original EtherType.
    private func tagged(_ frame: [UInt8], tags: [(tpid: UInt16, tci: UInt16)]) -> [UInt8] {
        var tagBytes: [UInt8] = []
        for tag in tags {
            tagBytes += [UInt8(tag.tpid >> 8), UInt8(tag.tpid & 0xFF), UInt8(tag.tci >> 8), UInt8(tag.tci & 0xFF)]
        }
        return Array(frame.prefix(12)) + tagBytes + Array(frame.dropFirst(12))
    }

    private func decode(_ frame: [UInt8]) -> DecodedPacket {
        PacketDecoder.decode(
            PacketBuffer(frame), linkType: LinkType.ethernet,
            timestamp: Date(), originalLength: frame.count
        )
    }
}
