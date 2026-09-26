import Foundation
import Testing
@testable import Tracexy

/// View ▸ Validate Checksums checks the IPv4 header, TCP, UDP and ICMP
/// checksums of one frame. The expected values and verdicts match tshark with
/// checksum validation turned on.
struct ChecksumValidationTests {
    // MARK: Internal

    @Test
    func onesComplementSumFollowsRFC1071() {
        // RFC 1071 §3 worked example: 00 01 f2 03 f4 f5 f6 f7 sums to 0xddf2.
        #expect(ChecksumValidation.onesComplementSum([0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7]) == 0xDDF2)
        // An odd trailing byte is padded with zero.
        #expect(ChecksumValidation.onesComplementSum([0x01]) == 0x0100)
    }

    @Test
    func verdictsMatchWireshark() throws {
        let zeroed = Self.tcpFrame
        let before = Self.statuses(zeroed)
        guard case let .incorrect(ipExpected) = before["Internet Protocol v4"],
              case let .incorrect(tcpExpected) = before["Transmission Control Protocol"] else
        {
            Issue.record("zero checksums should be incorrect: \(before)")
            return
        }
        var fixed = Self.patch(zeroed, at: 24, ipExpected)
        fixed = Self.patch(fixed, at: 50, tcpExpected)
        #expect(Self.statuses(fixed)["Internet Protocol v4"] == .correct)
        #expect(Self.statuses(fixed)["Transmission Control Protocol"] == .correct)

        // A pseudo-header-only TCP checksum is the offload signature.
        let pseudo = Self.pseudoOnly(fixed)
        #expect(Self.statuses(pseudo)["Transmission Control Protocol"] == .partial)

        // UDP over IPv4 with a zero checksum: not present, not wrong.
        let dns = Self.patch(Self.udpFrame, at: 24, 0)
        #expect(Self.statuses(dns)["User Datagram Protocol"] == .notPresent)

        // UDP over IPv6 and ICMP: fix the computed values, then they validate.
        guard case let .incorrect(udp6Expected) = Self.statuses(Self.udp6Frame)["User Datagram Protocol"],
              case let .incorrect(icmpExpected) = Self.statuses(Self.icmpFrame)["Internet Control Message Protocol"] else {
            Issue.record("zero UDPv6 and ICMP checksums should be incorrect")
            return
        }
        let udp6 = Self.patch(Self.udp6Frame, at: 60, udp6Expected)
        #expect(Self.statuses(udp6)["User Datagram Protocol"] == .correct)
        var icmp = Self.patch(Self.icmpFrame, at: 36, icmpExpected)
        if case let .incorrect(icmpIP) = Self.statuses(icmp)["Internet Protocol v4"] {
            icmp = Self.patch(icmp, at: 24, icmpIP)
        }
        #expect(Self.statuses(icmp)["Internet Control Message Protocol"] == .correct)

        // A frame cut short cannot be checked.
        let cut = Array(fixed.dropLast(3))
        #expect(Self.statuses(cut)["Transmission Control Protocol"] == .unverified)

        // The note reads as Wireshark's does.
        #expect(ChecksumStatus.incorrect(expected: 0x1A2B).note == "[incorrect, should be 0x1a2b]")
        let annotated = ChecksumValidation.annotate(Self.decode(zeroed), bytes: zeroed)
        let tcpChecksum = annotated.first { $0.proto == .tcp }?.fields.first { $0.name == "Checksum" }?.value
        #expect(tcpChecksum == "0x0000 [incorrect, should be \(PacketDecoder.hex(tcpExpected, digits: 4))]")

        guard WiresharkOracle.isAvailable else {
            return
        }
        try Self.expectWireshark(
            frames: [zeroed, fixed, udp6, icmp],
            calculated: [ipExpected, tcpExpected, udp6Expected]
        )
    }

    // MARK: Private

    private static let tcpFrame = PacketBuilder.ethernetIPv4(
        proto: 6, src: "10.0.0.5", dst: "203.0.113.9",
        payload: PacketBuilder.tcp(srcPort: 50_000, dstPort: 443, flags: 0x18, payload: Array("hello!!".utf8))
    )

    private static let udpFrame = PacketBuilder.dnsQueryFrame(name: "example.com", src: "10.0.0.5", dst: "10.0.0.1")

    private static let udp6Frame = PacketBuilder.ethernetIPv6(
        nextHeader: 17, src: [0x2001, 0xDB8, 0, 0, 0, 0, 0, 1], dst: [0x2001, 0xDB8, 0, 0, 0, 0, 0, 2],
        payload: PacketBuilder.udp(srcPort: 5_353, dstPort: 9_999, payload: Array("abc".utf8))
    )

    private static let icmpFrame = PacketBuilder.icmpEchoRequestFrame(src: "10.0.0.5", dst: "10.0.0.1")

    private static func decode(_ frame: [UInt8]) -> [DecodedLayer] {
        PacketDecoder.decode(
            PacketBuffer(frame), linkType: LinkType.ethernet, timestamp: nil, originalLength: frame.count
        ).layers
    }

    private static func statuses(_ frame: [UInt8]) -> [String: ChecksumStatus] {
        ChecksumValidation.statuses(decode(frame), bytes: frame)
    }

    private static func patch(_ frame: [UInt8], at offset: Int, _ value: UInt16) -> [UInt8] {
        var copy = frame
        copy[offset] = UInt8(value >> 8)
        copy[offset + 1] = UInt8(value & 0xFF)
        return copy
    }

    /// The TCP checksum field set to the pseudo-header sum alone, as a sending
    /// network card leaves it for the hardware to finish.
    private static func pseudoOnly(_ frame: [UInt8]) -> [UInt8] {
        let segmentLength = UInt32(frame.count - 34)
        let pseudo = ChecksumValidation.onesComplementSum(
            frame[26 ..< 34], initial: 6 + segmentLength
        )
        return patch(frame, at: 50, pseudo)
    }

    private static func expectWireshark(frames: [[UInt8]], calculated: [UInt16]) throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("checksums-\(UUID().uuidString).pcap")
        let records = frames.enumerated().map {
            ReplayCorpus.Frame(bytes: $0.element, offsetSeconds: $0.offset, linkType: LinkType.ethernet)
        }
        try Data(ReplayCorpus.classicPcapBytes(records)).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let rows = try WiresharkOracle.tsharkFields(
            url,
            fields: [
                "ip.checksum_calculated", "ip.checksum.status", "tcp.checksum_calculated", "tcp.checksum.status",
                "udp.checksum_calculated", "udp.checksum.status", "icmp.checksum.status",
            ],
            extraArguments: [
                "-o", "ip.check_checksum:TRUE", "-o", "tcp.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE",
            ]
        )
        #expect(rows.count == 4)
        guard rows.count == 4 else {
            return
        }
        // Frame 1: both wrong, and Wireshark computes the same expected values.
        #expect(UInt16(rows[0][0].dropFirst(2), radix: 16) == calculated[0])
        #expect(UInt16(rows[0][2].dropFirst(2), radix: 16) == calculated[1])
        #expect(rows[0][1] == "0" && rows[0][3] == "0")
        // Frame 2: both good (status 1). Frame 3: UDP over IPv6 good. Frame 4: ICMP good.
        #expect(rows[1][1] == "1" && rows[1][3] == "1")
        #expect(UInt16(rows[2][4].dropFirst(2), radix: 16) == calculated[2])
        #expect(rows[2][5] == "1")
        #expect(rows[3][6] == "1")
    }
}
