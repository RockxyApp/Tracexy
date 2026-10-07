import Foundation
import Testing
@testable import Tracexy

/// File ▸ Show File Structure lists a capture file's own blocks, as
/// Wireshark's Reload as File Format/Capture (tshark `-X read_format:"MIME Files Format"`).
struct CaptureFileStructureTests {
    // MARK: Internal

    @Test
    func pcapngBlocksMatchWireshark() throws {
        let url = try Self.write(Self.pcapng())
        defer { try? FileManager.default.removeItem(at: url) }
        let structure = try CaptureFileStructure.read(contentsOf: url)
        #expect(structure.format == "pcapng")
        #expect(structure.blocks.map(\.title) == [
            "Section Header Block", "Interface Description Block", "Enhanced Packet Block", "Enhanced Packet Block",
            "Name Resolution Block", "Interface Statistics Block", "Decryption Secrets Block",
        ])
        #expect(structure.blocks[2].detail == "Frame 1, interface 0, 42 of 60 bytes captured")
        #expect(structure.blocks[6].detail == "TLS key log, 13 bytes (not shown)")
        #expect(structure.blocks.map(\.offset).first == 0)
        #expect(structure.stoppedEarly == nil)
        #expect(FileStructureWindow.breakdown(structure).hasPrefix("2 Enhanced Packet Block"))

        guard WiresharkOracle.isAvailable else {
            return
        }
        let types = try WiresharkOracle.tsharkFields(
            url, fields: ["pcapng.block.type", "pcapng.block.length"], filter: nil,
            extraArguments: ["-X", "read_format:MIME Files Format"]
        )
        let typeText = try #require(types.first?[0])
        let theirTypes = typeText.split(separator: ",").compactMap { word in UInt32(word.dropFirst(2), radix: 16) }
        let theirLengths = try #require(types.first?[1]).split(separator: ",").compactMap { UInt64($0) }
        #expect(structure.blocks.compactMap(\.type) == theirTypes)
        #expect(structure.blocks.map(\.length) == theirLengths)
    }

    @Test
    func classicPcapRecords() throws {
        let frame = [UInt8](repeating: 0xAB, count: 30)
        var bytes = Self.le32(0xA1B2C3D4) + [2, 0, 4, 0] + Self.le32(0) + Self.le32(0) + Self.le32(65_535) + Self
            .le32(1)
        bytes += Self.le32(1_800_000_000) + Self.le32(0) + Self.le32(30) + Self.le32(60) + frame
        bytes += Self.le32(1_800_000_001) + Self.le32(0) + Self.le32(30) + Self.le32(30) + frame.prefix(10)
        let url = try Self.write(bytes)
        defer { try? FileManager.default.removeItem(at: url) }
        let structure = try CaptureFileStructure.read(contentsOf: url)
        #expect(structure.format == "pcap")
        #expect(structure.blocks.map(\.title) == ["File Header", "Packet Record"])
        #expect(structure.blocks[0].detail.contains("Ethernet (1)"))
        #expect(structure.blocks[1].detail == "Frame 1, 30 of 60 bytes captured")
        #expect(structure.stoppedEarly == "The last record is cut short.")
    }

    // MARK: Private

    private static func le32(_ value: UInt32) -> [UInt8] {
        (0 ..< 4).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
    }

    private static func block(_ type: UInt32, _ body: [UInt8]) -> [UInt8] {
        let padded = body + [UInt8](repeating: 0, count: (4 - body.count % 4) % 4)
        let length = UInt32(12 + padded.count)
        return le32(type) + le32(length) + padded + le32(length)
    }

    private static func pcapng() -> [UInt8] {
        let frame = PacketBuilder.ethernetIPv4(
            proto: 17, src: "192.0.2.10", dst: "198.51.100.7",
            payload: PacketBuilder.udp(srcPort: 40_000, dstPort: 53, payload: [])
        )
        func packet(_ seconds: UInt64) -> [UInt8] {
            let ticks = seconds * 1_000_000
            return block(
                6,
                le32(0) + le32(UInt32(ticks >> 32)) + le32(UInt32(ticks & 0xFFFFFFFF))
                    + le32(UInt32(frame.count)) + le32(60) + frame
            )
        }
        // Name Resolution: one IPv4 record for 192.0.2.10 "a.test", then end of records.
        let record: [UInt8] = [1, 0, 11, 0, 192, 0, 2, 10] + Array("a.test".utf8) + [0, 0] + [0, 0, 0, 0]
        let secrets = Array("CLIENT_RANDOM".utf8)
        return block(0x0A0D0D0A, le32(0x1A2B3C4D) + [1, 0, 0, 0] + [UInt8](repeating: 0xFF, count: 8))
            + block(1, [1, 0, 0, 0] + le32(262_144))
            + packet(1_800_000_000) + packet(1_800_000_001)
            + block(4, record)
            + block(5, le32(0) + le32(0) + le32(0))
            + block(10, le32(0x544C534B) + le32(UInt32(secrets.count)) + secrets)
    }

    private static func write(_ bytes: [UInt8]) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("structure-\(UUID().uuidString).pcapng")
        try Data(bytes).write(to: url)
        return url
    }
}
