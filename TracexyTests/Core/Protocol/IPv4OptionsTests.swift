import Foundation
import Testing
@testable import Tracexy

@Suite("IPv4 options decode")
struct IPv4OptionsTests {
    @Test
    func parsesRouterAlertOption() {
        let frame = PacketBuilder.ethernetIPv4RouterAlert(
            proto: 17,
            src: "192.168.1.10",
            dst: "224.0.0.22",
            payload: PacketBuilder.udp(srcPort: 5_000, dstPort: 53, payload: PacketBuilder.dnsQuery(name: "a.b"))
        )
        let packet = PacketDecoder.decode(
            PacketBuffer(frame), linkType: LinkType.ethernet,
            timestamp: Date(), originalLength: frame.count
        )
        let ipv4 = packet.layers.first { $0.title == "Internet Protocol v4" }
        #expect(ipv4?.fields.contains { $0.name == "Option: Router Alert" } == true)
        // Option parsing must not break the rest of the stack.
        #expect(packet.layers.contains { $0.title == "User Datagram Protocol" })
        #expect(packet.layers.contains { $0.title == "Domain Name System" })
    }
}
