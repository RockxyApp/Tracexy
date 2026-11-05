import Foundation
import Testing
@testable import Tracexy

@Suite("TCP options decode")
struct TCPOptionsTests {
    // MARK: Internal

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
    func decodesSACKBlockEdgesInWireOrderWithExactRanges() {
        let left: UInt32 = 0x01020304
        let right: UInt32 = 0xA0B0C0D0
        let options = Self.sackOption([(left, right)]) + [0, 0]
        let packet = Self.decodeTCP(options: options)

        #expect(packet.tcpFacts?.options.sackBlocks == [TCPSACKBlock(leftEdge: left, rightEdge: right)])
        let tcp = packet.layers.first { $0.title == "Transmission Control Protocol" }
        #expect(tcp?.fields.first { $0.name == "Option: SACK" }?.value == "1 block")
        #expect(tcp?.fields.first { $0.name == "SACK Block 1 Left Edge" }?.byteRange == 56 ..< 60)
        #expect(tcp?.fields.first { $0.name == "SACK Block 1 Right Edge" }?.byteRange == 60 ..< 64)
    }

    @Test
    func preservesWrappingAndDSSACKShapedRangesAcrossRepeatedOptions() {
        let ranges: [(UInt32, UInt32)] = [
            (0xFFFFFFF0, 0x00000010), // raw edges straddle sequence wrap
            (40, 50), // below the cumulative ACK: keep as an observation
            (45, 55), // contained/overlapping shape is not normalized
            (1_000, 1_100),
        ]
        let options = Self.sackOption(Array(ranges.prefix(2)))
            + Self.sackOption(Array(ranges.suffix(2)))
            + [0, 0, 0, 0]
        let packet = Self.decodeTCP(options: options, acknowledgement: 500)

        #expect(packet.tcpFacts?.acknowledgementNumber == 500)
        #expect(packet.tcpFacts?.options.sackBlocks == ranges.map {
            TCPSACKBlock(leftEdge: $0.0, rightEdge: $0.1)
        })
        let tcp = packet.layers.first { $0.title == "Transmission Control Protocol" }
        #expect(tcp?.fields.first { $0.name == "SACK Block 3 Left Edge" }?.value == "45")
        #expect(tcp?.fields.first { $0.name == "SACK Block 4 Right Edge" }?.value == "1100")
        #expect(tcp?.fields.first { $0.name == "SACK Block 3 Left Edge" }?.byteRange == 74 ..< 78)
    }

    @Test(arguments: [2, 9, 11])
    func malformedSACKBlockLengthsProduceNoTypedRanges(length: Int) {
        let option = [UInt8(5), UInt8(length)] + Array(repeating: UInt8(0x11), count: length - 2)
        let padded = option + Array(repeating: UInt8(0), count: (4 - option.count % 4) % 4)
        let packet = Self.decodeTCP(options: padded)

        #expect(packet.tcpFacts?.options.sackBlocks.isEmpty == true)
        let tcp = packet.layers.first { $0.title == "Transmission Control Protocol" }
        #expect(tcp?.fields.first { $0.name == "Option: SACK" }?.value == "Malformed block length")
        #expect(tcp?.fields.contains { $0.name.hasPrefix("SACK Block ") } == false)
    }

    @Test
    func ignoresSACKOptionThatExtendsBeyondDeclaredTCPHeader() {
        let packet = Self.decodeTCP(
            options: Self.sackOption([(1, 2)]) + [0, 0],
            declaredHeaderLength: 24
        )

        #expect(packet.tcpFacts?.options.sackBlocks.isEmpty == true)
        let tcp = packet.layers.first { $0.title == "Transmission Control Protocol" }
        #expect(tcp?.fields.contains { $0.name == "Option: SACK" } == false)
    }

    @Test
    func truncatedTCPOptionsDoNotFabricateSACKRanges() {
        let packet = Self.decodeTCP(
            options: Self.sackOption([(1, 2)]) + [0, 0],
            capturedOptionBytes: 4
        )

        #expect(packet.tcpFacts == nil)
        #expect(packet.decodeStop != nil)
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

    // MARK: Private

    private static func sackOption(_ ranges: [(UInt32, UInt32)]) -> [UInt8] {
        var bytes: [UInt8] = [5, UInt8(2 + ranges.count * 8)]
        for (left, right) in ranges {
            bytes += bigEndian(left) + bigEndian(right)
        }
        return bytes
    }

    private static func decodeTCP(
        options: [UInt8],
        acknowledgement: UInt32 = 0,
        declaredHeaderLength: Int? = nil,
        capturedOptionBytes: Int? = nil
    )
        -> DecodedPacket
    {
        let headerLength = declaredHeaderLength ?? 20 + options.count
        precondition(headerLength.isMultiple(of: 4) && (20 ... 60).contains(headerLength))
        var segment: [UInt8] = [0xC7, 0x38, 0x01, 0xBB] // ports 51000 and 443
        segment += bigEndian(1) + bigEndian(acknowledgement)
        segment += [UInt8((headerLength / 4) << 4), 0x10]
        segment += [0xFF, 0xFF, 0, 0, 0, 0]
        segment += options
        let frame = PacketBuilder.ethernetIPv4(
            proto: 6, src: "192.168.1.10", dst: "93.184.216.34", payload: segment
        )
        let originalLength = frame.count
        var capturedFrame = frame
        if let capturedOptionBytes, capturedOptionBytes < options.count {
            capturedFrame.removeLast(options.count - capturedOptionBytes)
        }
        return PacketDecoder.decode(
            PacketBuffer(capturedFrame), linkType: LinkType.ethernet,
            timestamp: Date(), originalLength: originalLength
        )
    }

    private static func bigEndian(_ value: UInt32) -> [UInt8] {
        [
            UInt8(truncatingIfNeeded: value >> 24), UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value),
        ]
    }
}
