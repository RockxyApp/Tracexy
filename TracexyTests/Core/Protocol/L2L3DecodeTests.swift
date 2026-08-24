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
    func icmpFactsPinFamilyTypeCode() {
        // IPv4 Echo Request: family ipv4, type 8, code 0.
        let v4 = PacketBuilder.icmpEchoRequestFrame(src: "192.168.1.10", dst: "8.8.8.8")
        let v4Facts = try? #require(decode(v4).icmpFacts)
        if let v4Facts {
            #expect(v4Facts.family == .ipv4)
            #expect(v4Facts.type == 8)
            #expect(v4Facts.code == 0)
        }

        // ICMPv6 Echo Request (type 128, code 0) over IPv6 (next header 58).
        let v6 = PacketBuilder.ethernetIPv6(
            nextHeader: 58,
            src: [0xFE80], dst: [0xFE80, 0, 0, 0, 0, 0, 0, 1],
            payload: [128, 0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]
        )
        let v6Facts = try? #require(decode(v6).icmpFacts)
        if let v6Facts {
            #expect(v6Facts.family == .ipv6)
            #expect(v6Facts.type == 128)
            #expect(v6Facts.code == 0)
        }
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
