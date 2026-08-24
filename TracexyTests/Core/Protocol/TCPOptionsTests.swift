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

        // The same single parse also produced typed option facts.
        let options = try? #require(packet.tcpFacts?.options)
        if let options {
            #expect(options.maximumSegmentSize == 1_460)
            #expect(options.windowScale == 7)
            #expect(options.sackPermitted)
            #expect(options.timestamps == TCPTimestamps(value: 123_456, echoReply: 0))
        }
    }

    @Test
    func outOfRangeWindowScalePreservesRawAndUsesEffectiveCap() {
        // A SYN carrying a Window Scale shift of 200 — outside the RFC 7323 0…14
        // range. It must not trap or drive `1 << 200`: no typed scale is retained
        // and the raw byte is rendered safely.
        let segment: [UInt8] =
            [0xC7, 0x38, 0x01, 0xBB] + // srcPort 51000, dstPort 443
            [0x00, 0x00, 0x00, 0x01] + // seq
            [0x00, 0x00, 0x00, 0x00] + // ack
            [0x60, 0x02] + // data offset 6 words (24 bytes), SYN
            [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00] + // window, checksum, urgent
            [3, 3, 200, 0] // Window Scale shift 200, padded to a 4-byte boundary
        let frame = PacketBuilder.ethernetIPv4(
            proto: 6, src: "192.168.1.10", dst: "93.184.216.34", payload: segment
        )
        let packet = PacketDecoder.decode(
            PacketBuffer(frame), linkType: LinkType.ethernet,
            timestamp: Date(), originalLength: frame.count
        )
        #expect(packet.tcpFacts?.options.windowScaleRaw == 200)
        #expect(packet.tcpFacts?.options.windowScale == 14)

        guard let tcp = packet.layers.first(where: { $0.title == "Transmission Control Protocol" }) else {
            Issue.record("no TCP layer")
            return
        }
        // Preserve the raw invalid byte and the RFC-required effective cap without
        // shifting by 200.
        #expect(tcp.fields.first { $0.name == "Option: Window Scale" }?.value == "200 (effective 14)")
    }

    @Test
    func validWindowScaleStillRendersMultiplier() {
        // The upper valid bound (14) keeps the existing display for valid input.
        let frame = PacketBuilder.ethernetIPv4(
            proto: 6, src: "192.168.1.10", dst: "93.184.216.34",
            payload: PacketBuilder.tcpSynWithOptions(srcPort: 51_000, dstPort: 443)
        )
        let packet = PacketDecoder.decode(
            PacketBuffer(frame), linkType: LinkType.ethernet,
            timestamp: Date(), originalLength: frame.count
        )
        let tcp = packet.layers.first { $0.title == "Transmission Control Protocol" }
        #expect(tcp?.fields.first { $0.name == "Option: Window Scale" }?.value == "7 (×128)")
        #expect(packet.tcpFacts?.options.windowScaleRaw == 7)
        #expect(packet.tcpFacts?.options.windowScale == 7)
    }

    @Test
    func malformedSackPermittedLengthIsNotTypedAsValid() {
        let segment: [UInt8] =
            [0xC7, 0x38, 0x01, 0xBB] +
            [0x00, 0x00, 0x00, 0x01] +
            [0x00, 0x00, 0x00, 0x00] +
            [0x60, 0x02] +
            [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00] +
            [4, 3, 0, 0] // SACK-Permitted must have length 2, not 3.
        let frame = PacketBuilder.ethernetIPv4(
            proto: 6, src: "192.168.1.10", dst: "93.184.216.34", payload: segment
        )
        let packet = PacketDecoder.decode(
            PacketBuffer(frame), linkType: LinkType.ethernet,
            timestamp: Date(), originalLength: frame.count
        )
        #expect(packet.tcpFacts?.options.sackPermitted == false)
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
