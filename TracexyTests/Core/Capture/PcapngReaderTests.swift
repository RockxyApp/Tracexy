import Foundation
import Testing
@testable import Tracexy

struct PcapngReaderTests {
    // MARK: Internal

    @Test
    func parsesLittleEndianEnhancedPacket() throws {
        let payload: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        let ticks: UInt64 = 1_700_000_000_500_000 // microseconds since the epoch

        var file: [UInt8] = []
        appendBlock(&file, type: 0x0A0D0D0A) { body in // Section Header Block
            append32(&body, 0x1A2B3C4D) // byte-order magic
            append16(&body, 1)
            append16(&body, 0) // version 1.0
            append64(&body, 0xFFFFFFFFFFFFFFFF) // section length = unspecified
        }
        appendBlock(&file, type: 0x00000001) { body in // Interface Description Block
            append16(&body, 1) // link type: Ethernet
            append16(&body, 0) // reserved
            append32(&body, 262_144) // snaplen
        }
        appendBlock(&file, type: 0x00000006) { body in // Enhanced Packet Block
            append32(&body, 0) // interface id
            append32(&body, UInt32(ticks >> 32))
            append32(&body, UInt32(ticks & 0xFFFFFFFF))
            append32(&body, UInt32(payload.count)) // captured length
            append32(&body, UInt32(payload.count)) // original length
            body += payload
        }

        #expect(PcapngReader.isPcapng(file))
        let result = try PcapngReader.read(file)
        #expect(result.linkType == LinkType.ethernet)
        #expect(result.frames.count == 1)
        #expect(result.frames[0].bytes == payload)
        #expect(result.frames[0].linkType == LinkType.ethernet)
        #expect(abs(result.frames[0].timestamp.timeIntervalSince1970 - 1_700_000_000.5) < 0.0001)
    }

    @Test
    func captureFileReaderSniffsClassicPcap() throws {
        // A classic .pcap must still route correctly through the sniffing reader.
        let frame = CapturedFrame(bytes: [0x01, 0x02], timestamp: Date(timeIntervalSince1970: 1), originalLength: 2)
        let pcap = [UInt8](PcapWriter.data(linkType: LinkType.ethernet, frames: [frame]))
        #expect(!PcapngReader.isPcapng(pcap))
        let result = try CaptureFileReader.read(pcap)
        #expect(result.frames.count == 1)
        #expect(result.frames[0].bytes == [0x01, 0x02])
    }

    // MARK: - Corrected array reader (strictness)

    @Test
    func arrayReaderParsesMultipleSectionsAndInterfaces() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        file += PcapngFixture.enhancedPacket(little: true, ticks: 1_000_000, captured: [0xAA])
        file += PcapngFixture.sectionHeader(little: false)
        file += PcapngFixture.interfaceDescription(little: false, linkType: 101)
        file += PcapngFixture.enhancedPacket(little: false, ticks: 2_000_000, captured: [0xBB, 0xCC])

        let result = try PcapngReader.read(file)
        #expect(result.linkType == LinkType.ethernet) // first declared IDB
        #expect(result.frames.map(\.bytes) == [[0xAA], [0xBB, 0xCC]])
        #expect(result.frames.map(\.linkType) == [LinkType.ethernet, LinkType.raw])
    }

    @Test
    func arrayReaderParsesSimplePacket() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1, snapLength: 4)
        file += PcapngFixture.simplePacket(little: true, originalLength: 9, captured: [0x01, 0x02, 0x03, 0x04])

        let result = try PcapngReader.read(file)
        #expect(result.frames.count == 1)
        #expect(result.frames[0].bytes == [0x01, 0x02, 0x03, 0x04])
        #expect(result.frames[0].originalLength == 9)
        #expect(result.frames[0].linkType == LinkType.ethernet)
    }

    @Test
    func arrayReaderTreatsZeroSnapLengthAsUnlimited() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1, snapLength: 0)
        file += PcapngFixture.simplePacket(
            little: true,
            originalLength: 5,
            captured: [0x01, 0x02, 0x03, 0x04, 0x05]
        )

        let result = try PcapngReader.read(file)
        #expect(result.frames.map(\.bytes) == [[0x01, 0x02, 0x03, 0x04, 0x05]])
    }

    @Test
    func arrayReaderRejectsTrailerMismatch() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        var body = PcapngFixture.u16(1, true) + PcapngFixture.u16(0, true)
        body += PcapngFixture.u32(262_144, true)
        var badBlock = PcapngFixture.u32(0x00000001, true) + PcapngFixture.u32(20, true)
        badBlock += body
        badBlock += PcapngFixture.u32(24, true) // wrong trailer
        file += badBlock

        #expect(throws: PacketError.self) {
            _ = try PcapngReader.read(file)
        }
    }

    @Test
    func arrayReaderRejectsUndeclaredInterface() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        file += PcapngFixture.enhancedPacket(little: true, interfaceID: 4, ticks: 0, captured: [0x01])

        #expect(throws: PacketError.self) {
            _ = try PcapngReader.read(file)
        }
    }

    @Test
    func arrayReaderRejectsUnsupportedVersion() throws {
        let file = PcapngFixture.sectionHeader(little: true, major: 2)
        #expect(throws: PacketError.self) {
            _ = try PcapngReader.read(file)
        }
    }

    @Test
    func arrayReaderRejectsFileWithoutInterface() throws {
        let file = PcapngFixture.sectionHeader(little: true)
        #expect(throws: PacketError.self) {
            _ = try PcapngReader.read(file)
        }
    }

    // MARK: - Stream adapter and array equivalence

    @Test
    func urlAdapterMatchesArrayReaderOnWellFormedCorpus() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1, tsresol: 9)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 101, tsresol: 0x80 | 10, tsoffset: 5)
        file += PcapngFixture.enhancedPacket(little: true, interfaceID: 0, ticks: 2_500_000_000, captured: [0x01, 0x02])
        file += PcapngFixture.enhancedPacket(little: true, interfaceID: 1, ticks: 2_048, captured: [0x03])
        file += PcapngFixture.simplePacket(little: true, originalLength: 2, captured: [0x04, 0x05])
        file += PcapngFixture.sectionHeader(little: false)
        file += PcapngFixture.interfaceDescription(little: false, linkType: 1)
        file += PcapngFixture.enhancedPacket(little: false, ticks: 7_000_000, captured: [0x06, 0x07, 0x08])

        let inMemory = try PcapngReader.read(file)
        try Self.withTempFile(file) { url in
            let streamed = try PcapngReader.read(contentsOf: url)
            #expect(streamed.linkType == inMemory.linkType)
            #expect(streamed.frames.count == inMemory.frames.count)
            for (lhs, rhs) in zip(streamed.frames, inMemory.frames) {
                #expect(lhs.bytes == rhs.bytes)
                #expect(lhs.originalLength == rhs.originalLength)
                #expect(lhs.linkType == rhs.linkType)
                #expect(abs(lhs.timestamp.timeIntervalSince1970 - rhs.timestamp.timeIntervalSince1970) < 1e-9)
            }
        }
    }

    @Test
    func urlAdapterPreservesFramesOnTruncatedTail() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        file += PcapngFixture.enhancedPacket(little: true, ticks: 1_000_000, captured: [0x01, 0x02])
        file += [0xAA, 0xBB, 0xCC] // partial block header tail

        try Self.withTempFile(file) { url in
            let result = try PcapngReader.read(contentsOf: url)
            #expect(result.linkType == LinkType.ethernet)
            #expect(result.frames.map(\.bytes) == [[0x01, 0x02]])
        }
    }

    @Test
    func urlAdapterErrorsWithoutInterface() throws {
        let file = PcapngFixture.sectionHeader(little: true)
        try Self.withTempFile(file) { url in
            #expect(throws: PacketError.self) {
                _ = try PcapngReader.read(contentsOf: url)
            }
        }
    }

    // MARK: Private

    private static func withTempFile(_ bytes: [UInt8], _ body: (URL) throws -> Void) throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("pcapngarray-\(UUID().uuidString).pcapng")
        try Data(bytes).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        try body(url)
    }

    private func append16(_ data: inout [UInt8], _ value: UInt16) {
        withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) }
    }

    private func append32(_ data: inout [UInt8], _ value: UInt32) {
        withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) }
    }

    private func append64(_ data: inout [UInt8], _ value: UInt64) {
        withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) }
    }

    /// Frames a block body with the type / total-length / trailing-length envelope,
    /// padding the body to a 32-bit boundary as the spec requires.
    private func appendBlock(_ data: inout [UInt8], type: UInt32, body build: (inout [UInt8]) -> Void) {
        var body: [UInt8] = []
        build(&body)
        while body.count % 4 != 0 {
            body.append(0)
        }
        let total = UInt32(12 + body.count)
        append32(&data, type)
        append32(&data, total)
        data.append(contentsOf: body)
        append32(&data, total)
    }
}
