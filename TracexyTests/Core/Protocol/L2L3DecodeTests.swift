import Foundation
import Testing
@testable import Tracexy

@Suite("ARP / ICMP / DNS-RR decode")
struct L2L3DecodeTests {
    // MARK: Internal

    @Test
    func arpDecodesAndFormsSession() {
        let frame = PacketBuilder.arpRequestFrame(senderIP: "192.168.1.10", targetIP: "192.168.1.1")
        let packet = decode(frame)
        let arp = packet.layers.first { $0.title == "Address Resolution Protocol" }
        #expect(arp != nil)
        #expect(arp?.fields.contains(DecodedField(name: "Sender IP", value: "192.168.1.10")) == true)
        #expect(arp?.fields.contains(DecodedField(name: "Target IP", value: "192.168.1.1")) == true)
        // ARP forms a session (so it surfaces in the list).
        #expect(packet.fiveTuple != nil)

        let sessions = SessionBuilder.build(
            from: [CapturedFrame(bytes: frame, timestamp: Date(), originalLength: frame.count)],
            linkType: LinkType.ethernet
        )
        #expect(sessions.contains { $0.protocolStack.contains(.arp) })
    }

    @Test
    func icmpEchoDecodes() {
        let frame = PacketBuilder.icmpEchoRequestFrame(src: "192.168.1.10", dst: "8.8.8.8")
        let packet = decode(frame)
        let icmp = packet.layers.first { $0.title == "Internet Control Message Protocol" }
        #expect(icmp != nil)
        #expect(icmp?.fields.contains { $0.name == "Type" && $0.value.contains("Echo Request") } == true)
        #expect(packet.fiveTuple != nil)
    }

    @Test
    func dnsMXRecordDecodes() {
        let frame = PacketBuilder.dnsResponseMXFrame(name: "example.com", src: "8.8.8.8", dst: "192.168.1.10")
        let packet = decode(frame)
        let dns = packet.layers.first { $0.title == "Domain Name System" }
        #expect(dns != nil)
        #expect(dns?.fields.contains { $0.value.hasPrefix("MX 10 mail.example.com") } == true)
        // An MX answer is not an IP, so it must not pollute the resolved-IP set.
        #expect(packet.dnsAnswers.isEmpty)
    }

    // MARK: Private

    private func decode(_ frame: [UInt8]) -> DecodedPacket {
        PacketDecoder.decode(
            PacketBuffer(frame), linkType: LinkType.ethernet,
            timestamp: Date(), originalLength: frame.count
        )
    }
}
