import Foundation
import Testing
@testable import Tracexy

@Suite("TCP options decode")
struct TCPOptionsTests {
    @Test
    func parsesCommonSynOptions() {
        let frame = PacketBuilder.ethernetIPv4(
            proto: 6,
            src: "192.168.1.10",
            dst: "93.184.216.34",
            payload: PacketBuilder.tcpSynWithOptions(srcPort: 51_000, dstPort: 443)
        )
        let packet = PacketDecoder.decode(
            PacketBuffer(frame), linkType: LinkType.ethernet,
            timestamp: Date(), originalLength: frame.count
        )
        guard let tcp = packet.layers.first(where: { $0.title == "Transmission Control Protocol" }) else {
            Issue.record("no TCP layer")
            return
        }
        let names = tcp.fields.map(\.name)
        #expect(names.contains("Option: MSS"))
        #expect(names.contains("Option: Window Scale"))
        #expect(names.contains("Option: SACK Permitted"))
        #expect(names.contains("Option: Timestamps"))
        #expect(tcp.fields.first { $0.name == "Option: MSS" }?.value == "1460")
    }

    @Test
    func plainSegmentHasNoOptions() {
        // A 20-byte TCP header (no options) must not emit option fields.
        let frame = PacketBuilder.httpRequestFrame(
            host: "example.com", path: "/", src: "192.168.1.10", dst: "93.184.216.34"
        )
        let packet = PacketDecoder.decode(
            PacketBuffer(frame), linkType: LinkType.ethernet,
            timestamp: Date(), originalLength: frame.count
        )
        let tcp = packet.layers.first { $0.title == "Transmission Control Protocol" }
        #expect(tcp?.fields.contains { $0.name.hasPrefix("Option:") } == false)
    }
}
