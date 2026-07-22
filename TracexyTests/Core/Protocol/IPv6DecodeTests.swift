import Foundation
import Testing
@testable import Tracexy

@Suite("IPv6 decode")
struct IPv6DecodeTests {
    // MARK: Internal

    @Test
    func plainIPv6ToUDPToDNS() {
        let dns = PacketBuilder.dnsQuery(name: "ipv6.example.com")
        let udp = PacketBuilder.udp(srcPort: 5_353, dstPort: 53, payload: dns)
        let frame = PacketBuilder.ethernetIPv6(
            nextHeader: 17, // UDP
            src: [0xFE80], dst: [0x2606, 0x4700],
            payload: udp
        )
        let titles = decodeTitles(frame)
        #expect(titles.contains("Internet Protocol v6"))
        #expect(titles.contains("User Datagram Protocol"))
        #expect(titles.contains("Domain Name System"))
    }

    @Test
    func ipv6ExtensionHeaderIsWalked() {
        // IPv6 (next = HopByHop) → HopByHop (next = UDP) → UDP → DNS.
        let dns = PacketBuilder.dnsQuery(name: "ext.example.com")
        let udp = PacketBuilder.udp(srcPort: 5_353, dstPort: 53, payload: dns)
        let ext = PacketBuilder.ipv6HopByHop(nextHeader: 17) // next = UDP
        let frame = PacketBuilder.ethernetIPv6(
            nextHeader: 0, // HopByHop
            src: [0xFE80], dst: [0x2606, 0x4700],
            payload: ext + udp
        )
        let titles = decodeTitles(frame)
        #expect(titles.contains("Internet Protocol v6"))
        #expect(titles.contains("IPv6 Hop-by-Hop Options"))
        // The transport + application layers are reached only if the extension
        // header was correctly skipped.
        #expect(titles.contains("User Datagram Protocol"))
        #expect(titles.contains("Domain Name System"))
    }

    @Test
    func ipv6CarriesRicherFields() {
        let frame = PacketBuilder.ethernetIPv6(
            nextHeader: 17, src: [0xFE80], dst: [0x2606, 0x4700],
            payload: PacketBuilder.udp(srcPort: 1, dstPort: 53, payload: PacketBuilder.dnsQuery(name: "a.b"))
        )
        let packet = decode(frame)
        let ipv6 = packet.layers.first { $0.title == "Internet Protocol v6" }
        #expect(ipv6?.fields.contains(DecodedField(name: "Version", value: "6")) == true)
        #expect(ipv6?.fields.contains(where: { $0.name == "Payload Length" }) == true)
        #expect(ipv6?.fields.contains(where: { $0.name == "Hop Limit" }) == true)
    }

    // MARK: Private

    private func decode(_ frame: [UInt8]) -> DecodedPacket {
        PacketDecoder.decode(
            PacketBuffer(frame), linkType: LinkType.ethernet,
            timestamp: Date(), originalLength: frame.count
        )
    }

    private func decodeTitles(_ frame: [UInt8]) -> [String] {
        decode(frame).layers.map(\.title)
    }
}
