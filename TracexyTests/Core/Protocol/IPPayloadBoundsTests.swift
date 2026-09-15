import Foundation
import Testing
@testable import Tracexy

/// The IP layer bounds the transport payload by its own declared length and stops
/// at non-first fragments. Without both, link-layer padding becomes TCP sequence
/// space and mid-datagram fragment bytes become ports — fabricated evidence that
/// feeds false overlap/retransmission findings and phantom sessions.
@Suite("IP payload bounds and fragments")
struct IPPayloadBoundsTests {
    // MARK: Internal

    @Test("Ethernet padding after an IPv4 TCP segment is not TCP payload")
    func ethernetPaddingIsNotTCPPayload() throws {
        // A bare ACK: 14 + 20 + 20 = 54 bytes, padded to the 60-byte Ethernet minimum.
        let segment = PacketBuilder.tcp(srcPort: 50_000, dstPort: 443, flags: 0x10, payload: [], sequence: 100)
        var frame = PacketBuilder.ethernetIPv4(proto: 6, src: "10.0.0.1", dst: "10.0.0.2", payload: segment)
        frame += [UInt8](repeating: 0, count: 6)
        let packet = decode(frame)
        let facts = try #require(packet.tcpFacts)
        #expect(facts.payloadLength == 0)
        #expect(packet.tcpPayloadBytes.isEmpty)
        #expect(packet.fiveTuple != nil)
        // The padded ACK must occupy no sequence space, so the next real segment is
        // classified as an ordinary advance, never an overlap.
        var tracker = TCPSequenceTracker()
        #expect(tracker.ingest(facts).disposition == .noSequenceSpace)
        let data = PacketBuilder.tcp(srcPort: 50_000, dstPort: 443, flags: 0x18, payload: [1, 2, 3], sequence: 100)
        let dataFrame = PacketBuilder.ethernetIPv4(proto: 6, src: "10.0.0.1", dst: "10.0.0.2", payload: data)
        let dataFacts = try #require(decode(dataFrame).tcpFacts)
        #expect(tracker.ingest(dataFacts).disposition == .initialized)
    }

    @Test("Ethernet padding after an IPv4 UDP datagram does not reach the application decoder")
    func ethernetPaddingIsNotUDPPayload() {
        let datagram = PacketBuilder.udp(srcPort: 5_000, dstPort: 6_000, payload: [0xAB])
        var frame = PacketBuilder.ethernetIPv4(proto: 17, src: "10.0.0.1", dst: "10.0.0.2", payload: datagram)
        frame += [UInt8](repeating: 0, count: 17)
        let packet = decode(frame)
        let udp = packet.layers.first { $0.proto == .udp }
        #expect(udp != nil)
        #expect(packet.fiveTuple?.proto == .udp)
        // The IPv4 layer still spans only its header; the trailer is not cited.
        let ip = packet.layers.first { $0.proto == .ipv4 }
        #expect(ip?.byteRange == 14 ..< 34)
    }

    @Test("A zero IPv4 total length (segmentation offload) keeps the captured payload")
    func zeroTotalLengthKeepsCapturedPayload() throws {
        let segment = PacketBuilder.tcp(srcPort: 50_000, dstPort: 80, flags: 0x18, payload: [1, 2, 3, 4], sequence: 1)
        var frame = PacketBuilder.ethernetIPv4(proto: 6, src: "10.0.0.1", dst: "10.0.0.2", payload: segment)
        frame[16] = 0
        frame[17] = 0
        let facts = try #require(decode(frame).tcpFacts)
        #expect(facts.payloadLength == 4)
    }

    @Test("A total length beyond the captured bytes (snapshot truncation) keeps the captured payload")
    func oversizedTotalLengthKeepsCapturedPayload() throws {
        let segment = PacketBuilder.tcp(srcPort: 50_000, dstPort: 80, flags: 0x18, payload: [1, 2, 3, 4], sequence: 1)
        var frame = PacketBuilder.ethernetIPv4(proto: 6, src: "10.0.0.1", dst: "10.0.0.2", payload: segment)
        frame[16] = 0x05
        frame[17] = 0xDC // 1500 declared, 44 captured
        let facts = try #require(decode(frame).tcpFacts)
        #expect(facts.payloadLength == 4)
    }

    @Test("An IPv4 header length below 20 bytes stops at the IP layer")
    func bogusHeaderLengthStopsAtIPLayer() {
        let segment = PacketBuilder.tcp(srcPort: 50_000, dstPort: 80, flags: 0x02, payload: [], sequence: 1)
        var frame = PacketBuilder.ethernetIPv4(proto: 6, src: "10.0.0.1", dst: "10.0.0.2", payload: segment)
        frame[14] = 0x42 // version 4, IHL 2 (8 bytes)
        let packet = decode(frame)
        #expect(packet.layers.contains { $0.proto == .ipv4 })
        #expect(packet.transport == nil)
        #expect(packet.fiveTuple == nil)
        #expect(packet.tcpFacts == nil)
    }

    @Test("A non-first IPv4 fragment never yields transport endpoints")
    func laterIPv4FragmentHasNoTransport() {
        // Fragment offset 185 (×8 = 1480 bytes), no more fragments: the bytes after
        // the IP header are the tail of some UDP datagram, not a UDP header.
        let tail: [UInt8] = [0x00, 0x35, 0x00, 0x35, 0x00, 0x10, 0x00, 0x00, 1, 2, 3, 4]
        var frame = PacketBuilder.ethernetIPv4(proto: 17, src: "10.0.0.1", dst: "10.0.0.2", payload: tail)
        frame[20] = 0x00
        frame[21] = 0xB9 // flags 0, offset 185
        let packet = decode(frame)
        let ip = packet.layers.first { $0.proto == .ipv4 }
        #expect(ip?.fields.contains { $0.name == "Fragment" && $0.value == "offset 1480, last fragment" } == true)
        #expect(packet.transport == nil)
        #expect(packet.fiveTuple == nil)
        #expect(!packet.layers.contains { $0.proto == .udp })
    }

    @Test("The first IPv4 fragment still decodes its transport header")
    func firstIPv4FragmentDecodesTransport() {
        let datagram = PacketBuilder.udp(srcPort: 53, dstPort: 40_000, payload: [1, 2, 3, 4])
        var frame = PacketBuilder.ethernetIPv4(proto: 17, src: "10.0.0.1", dst: "10.0.0.2", payload: datagram)
        frame[20] = 0x20
        frame[21] = 0x00 // more fragments, offset 0
        let packet = decode(frame)
        let ip = packet.layers.first { $0.proto == .ipv4 }
        #expect(ip?.fields.contains { $0.name == "Fragment" && $0.value == "offset 0, more fragments" } == true)
        #expect(packet.fiveTuple?.proto == .udp)
        #expect(packet.sourceEndpoint?.port == 53)
    }

    @Test("Ethernet padding after an IPv6 TCP segment is not TCP payload")
    func ipv6PayloadLengthBoundsTransport() throws {
        let segment = PacketBuilder.tcp(srcPort: 50_000, dstPort: 443, flags: 0x10, payload: [], sequence: 7)
        var frame = PacketBuilder.ethernetIPv6(
            nextHeader: 6, src: [0x2001, 0xDB8, 0, 0, 0, 0, 0, 1], dst: [0x2001, 0xDB8, 0, 0, 0, 0, 0, 2],
            payload: segment
        )
        frame += [UInt8](repeating: 0, count: 9)
        let facts = try #require(decode(frame).tcpFacts)
        #expect(facts.payloadLength == 0)
    }

    @Test("A non-first IPv6 fragment never yields transport endpoints")
    func laterIPv6FragmentHasNoTransport() {
        // Fragment header: next 17 (UDP), reserved, offset 1 (×8) | M=0, identification.
        let fragmentHeader: [UInt8] = [17, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01]
        let tail: [UInt8] = [0x00, 0x35, 0x00, 0x35, 0x00, 0x10, 0x00, 0x00, 1, 2, 3, 4]
        let frame = PacketBuilder.ethernetIPv6(
            nextHeader: 44, src: [0x2001, 0xDB8, 0, 0, 0, 0, 0, 1], dst: [0x2001, 0xDB8, 0, 0, 0, 0, 0, 2],
            payload: fragmentHeader + tail
        )
        let packet = decode(frame)
        let fragment = packet.layers.first { $0.title == "IPv6 Fragment" }
        #expect(fragment?.fields.contains { $0.name == "Fragment" && $0.value == "offset 8, last fragment" } == true)
        #expect(packet.transport == nil)
        #expect(packet.fiveTuple == nil)
    }

    @Test("The first IPv6 fragment still decodes its transport header")
    func firstIPv6FragmentDecodesTransport() {
        let fragmentHeader: [UInt8] = [17, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01] // offset 0, M=1
        let datagram = PacketBuilder.udp(srcPort: 53, dstPort: 40_000, payload: [1, 2, 3, 4])
        let frame = PacketBuilder.ethernetIPv6(
            nextHeader: 44, src: [0x2001, 0xDB8, 0, 0, 0, 0, 0, 1], dst: [0x2001, 0xDB8, 0, 0, 0, 0, 0, 2],
            payload: fragmentHeader + datagram
        )
        let packet = decode(frame)
        #expect(packet.fiveTuple?.proto == .udp)
        #expect(packet.sourceEndpoint?.port == 53)
    }

    // MARK: Private

    private func decode(_ frame: [UInt8]) -> DecodedPacket {
        PacketDecoder.decode(
            PacketBuffer(frame), linkType: LinkType.ethernet,
            timestamp: Date(), originalLength: frame.count
        )
    }
}
