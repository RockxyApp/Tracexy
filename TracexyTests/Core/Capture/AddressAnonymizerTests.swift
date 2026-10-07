import Foundation
import Testing
@testable import Tracexy

/// Header addresses replaced consistently, special addresses kept,
/// checksums still valid, payloads untouched, unparseable frames refused — and
/// Export Frames' "Replace addresses" option uses it end to end.
struct AddressAnonymizerTests {
    // MARK: Internal

    @Test
    func addressesAreReplacedConsistentlyAndSpecialOnesKept() throws {
        var anonymizer = AddressAnonymizer()
        let outResult = anonymizer.anonymize(Self.tcpFrame(from: "192.0.2.10", to: "203.0.113.5"), linkType: 1)
        let out = try #require(outResult)
        let backResult = anonymizer.anonymize(Self.tcpFrame(from: "203.0.113.5", to: "192.0.2.10"), linkType: 1)
        let back = try #require(backResult)
        #expect(Array(out[26 ..< 30]) == [10, 0, 0, 1])
        #expect(Array(out[30 ..< 34]) == [10, 0, 0, 2])
        // The reply maps the same two hosts the other way round.
        #expect(Array(back[26 ..< 30]) == [10, 0, 0, 2])
        #expect(Array(back[30 ..< 34]) == [10, 0, 0, 1])
        #expect(Array(out[0 ..< 6]) == [2, 0, 0, 0, 0, 1])
        #expect(Self.ipv4ChecksumIsValid(out, at: 14))
        // The payload is untouched.
        #expect(Array(out.suffix(4)) == [0xDE, 0xAD, 0xBE, 0xEF])

        let broadcast = PacketBuilder.ethernetIPv4(
            proto: 17, src: "0.0.0.0", dst: "255.255.255.255",
            payload: PacketBuilder.udp(srcPort: 68, dstPort: 67, payload: [1, 2, 3, 4])
        )
        let keptResult = anonymizer.anonymize(broadcast, linkType: 1)
        let kept = try #require(keptResult)
        #expect(Array(kept[26 ..< 34]) == [0, 0, 0, 0, 255, 255, 255, 255])

        let arpResult = anonymizer.anonymize(
            PacketBuilder.arpRequestFrame(senderIP: "192.0.2.10", targetIP: "192.0.2.1"), linkType: 1
        )
        let arp = try #require(arpResult)
        #expect(Array(arp[28 ..< 32]) == [10, 0, 0, 1])
        #expect(Array(arp[32 ..< 38]) == [0, 0, 0, 0, 0, 0])

        let lldp = [UInt8](repeating: 6, count: 12) + [0x88, 0xCC] + [UInt8](repeating: 0, count: 20)
        let refusedLLDP = anonymizer.anonymize(lldp, linkType: 1)
        #expect(refusedLLDP == nil)
        let refusedShort = anonymizer.anonymize([1, 2, 3], linkType: 1)
        #expect(refusedShort == nil)
        let refusedLink = anonymizer.anonymize(Self.tcpFrame(from: "192.0.2.1", to: "192.0.2.2"), linkType: 147)
        #expect(refusedLink == nil)
    }

    @Test
    func exportFramesReplacesAddressesWithValidChecksums() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("anon-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let source = directory.appendingPathComponent("source.pcap")
        let udp = PacketBuilder.ethernetIPv4(
            proto: 17, src: "192.0.2.10", dst: "198.51.100.53",
            payload: PacketBuilder.udp(srcPort: 53_000, dstPort: 53, payload: [0, 1, 2, 3, 4, 5, 6, 7])
        )
        // An ICMP port unreachable quoting that UDP datagram's header.
        let quoted = Array(udp[14 ..< 42])
        let icmp = PacketBuilder.ethernetIPv4(
            proto: 1, src: "198.51.100.53", dst: "192.0.2.10", payload: [3, 3, 0, 0, 0, 0, 0, 0] + quoted
        )
        let v6 = PacketBuilder.ethernetIPv6(
            nextHeader: 6, src: [0x2001, 0xDB8, 0, 0, 0, 0, 0, 1], dst: [0x2001, 0xDB8, 0, 0, 0, 0, 0, 2],
            payload: PacketBuilder.tcp(srcPort: 50_000, dstPort: 443, flags: 0x18, payload: [9, 9, 9])
        )
        let lldp = [UInt8](repeating: 6, count: 12) + [0x88, 0xCC] + [UInt8](repeating: 0, count: 20)
        let frames = [Self.tcpFrame(from: "192.0.2.10", to: "203.0.113.5"), udp, icmp, v6, lldp]
        try PcapWriter.write(
            linkType: LinkType.ethernet,
            frames: frames.enumerated().map { index, bytes in
                CapturedFrame(
                    bytes: bytes, timestamp: Date(timeIntervalSince1970: 1_800_000_000 + Double(index)),
                    originalLength: bytes.count
                )
            },
            to: source
        )
        let output = directory.appendingPathComponent("shared.pcapng")
        var options = FrameExportOptions()
        options.anonymizesAddresses = true
        options.captureComments = ["note naming 192.0.2.10"]
        let summary = try CaptureFrameExporter.export(from: source, scope: .wholeCapture, options: options, to: output)
        #expect(summary.writtenFrameCount == 4)
        #expect(summary.unanonymizedFrameCount == 1)
        #expect(summary.replacedAddressCount > 0)

        let bytes = try Data(contentsOf: output)
        for original in ["192.0.2.10", "203.0.113.5", "198.51.100.53"] {
            let raw = Data(original.split(separator: ".").compactMap { UInt8($0) })
            #expect(bytes.range(of: raw) == nil, "\(original) is still in the export")
        }
        #expect(bytes.range(of: Data("192.0.2.10".utf8)) == nil)

        if WiresharkOracle.isAvailable {
            let rows = try WiresharkOracle.tsharkFields(
                output,
                fields: [
                    "ip.src",
                    "ip.checksum.status",
                    "tcp.checksum.status",
                    "udp.checksum.status",
                    "icmp.checksum.status",
                    "ipv6.src"
                ],
                extraArguments: [
                    "-o", "ip.check_checksum:TRUE", "-o", "tcp.check_checksum:TRUE",
                    "-o", "udp.check_checksum:TRUE",
                ]
            )
            // Every checksum reads Good (1) or Not present (3, the UDP "no checksum"
            // the source carried); none is Bad (0) or unverified (2).
            for row in rows {
                for status in row[1 ... 4] where !status.isEmpty {
                    #expect(status.split(separator: ",").allSatisfy { $0 == "1" || $0 == "3" }, "\(row)")
                }
            }
            #expect(rows.contains { $0[2] == "1" })
            #expect(rows.first?.first == "10.0.0.1")
            #expect(rows.last?.last?.hasPrefix("fd00::") == true)
        }
    }

    // MARK: Private

    private static func tcpFrame(from source: String, to destination: String) -> [UInt8] {
        PacketBuilder.ethernetIPv4(
            proto: 6, src: source, dst: destination,
            payload: PacketBuilder.tcp(srcPort: 50_000, dstPort: 443, flags: 0x18, payload: [0xDE, 0xAD, 0xBE, 0xEF])
        )
    }

    private static func ipv4ChecksumIsValid(_ frame: [UInt8], at offset: Int) -> Bool {
        var total: UInt32 = 0
        var index = offset
        while index < offset + 20 {
            total += UInt32(frame[index]) << 8 | UInt32(frame[index + 1])
            index += 2
        }
        while total >> 16 != 0 {
            total = (total & 0xFFFF) + (total >> 16)
        }
        return total == 0xFFFF
    }
}
