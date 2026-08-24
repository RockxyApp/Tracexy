import Foundation
import Testing
@testable import Tracexy

struct PcapReaderTests {
    // MARK: Internal

    // MARK: - Tests

    @Test
    func littleEndianReadsBothFrames() throws {
        let dns = PacketBuilder.dnsQueryFrame(name: "example.com", src: "192.168.1.2", dst: "1.1.1.1")
        let tls = PacketBuilder.tlsClientHelloFrame(sni: "example.com", src: "192.168.1.2", dst: "93.184.16.34")

        var file = littleEndianHeader()
        file += littleEndianRecord(dns, tsSec: 1_700_000_000, tsUsec: 500_000)
        file += littleEndianRecord(tls, tsSec: 1_700_000_001, tsUsec: 0)

        let result = try PcapReader.read(file)

        #expect(result.linkType == 1)
        #expect(result.frames.count == 2)
        #expect(result.frames[0].originalLength == dns.count)
        #expect(result.frames[0].bytes == dns)
        #expect(result.frames[1].originalLength == tls.count)
        #expect(result.frames[1].bytes == tls)
    }

    @Test
    func littleEndianTimestampDecodes() throws {
        let dns = PacketBuilder.dnsQueryFrame(name: "example.com", src: "192.168.1.2", dst: "1.1.1.1")
        var file = littleEndianHeader()
        file += littleEndianRecord(dns, tsSec: 1_700_000_000, tsUsec: 500_000)

        let result = try PcapReader.read(file)
        let expected = Date(timeIntervalSince1970: 1_700_000_000.5)
        #expect(abs(result.frames[0].timestamp.timeIntervalSince1970 - expected.timeIntervalSince1970) < 0.0001)
    }

    @Test
    func framesRoundTripThroughDecoder() throws {
        let dns = PacketBuilder.dnsQueryFrame(name: "example.com", src: "192.168.1.2", dst: "1.1.1.1")
        let tls = PacketBuilder.tlsClientHelloFrame(sni: "example.com", src: "192.168.1.2", dst: "93.184.16.34")

        var file = littleEndianHeader()
        file += littleEndianRecord(dns, tsSec: 1_700_000_000, tsUsec: 0)
        file += littleEndianRecord(tls, tsSec: 1_700_000_001, tsUsec: 0)

        let result = try PcapReader.read(file)

        let firstFrame = result.frames[0]
        let firstDecoded = PacketDecoder.decode(
            PacketBuffer(firstFrame.bytes),
            linkType: result.linkType,
            timestamp: firstFrame.timestamp,
            originalLength: firstFrame.originalLength
        )
        #expect(firstDecoded.appProtocol == .dns)
        #expect(firstDecoded.dnsQuery == "example.com")

        let secondFrame = result.frames[1]
        let secondDecoded = PacketDecoder.decode(
            PacketBuffer(secondFrame.bytes),
            linkType: result.linkType,
            timestamp: secondFrame.timestamp,
            originalLength: secondFrame.originalLength
        )
        #expect(secondDecoded.sni == "example.com")
    }

    @Test
    func bigEndianReadsBothFrames() throws {
        let dns = PacketBuilder.dnsQueryFrame(name: "example.com", src: "192.168.1.2", dst: "1.1.1.1")
        let tls = PacketBuilder.tlsClientHelloFrame(sni: "example.com", src: "192.168.1.2", dst: "93.184.16.34")

        var file = bigEndianHeader()
        file += bigEndianRecord(dns, tsSec: 1_700_000_000, tsUsec: 0)
        file += bigEndianRecord(tls, tsSec: 1_700_000_001, tsUsec: 0)

        let result = try PcapReader.read(file)

        #expect(result.linkType == 1)
        #expect(result.frames.count == 2)
        #expect(result.frames[0].bytes == dns)
        #expect(result.frames[1].bytes == tls)

        let decoded = PacketDecoder.decode(
            PacketBuffer(result.frames[0].bytes),
            linkType: result.linkType,
            timestamp: result.frames[0].timestamp,
            originalLength: result.frames[0].originalLength
        )
        #expect(decoded.appProtocol == .dns)
    }

    @Test
    func truncatedFinalRecordIsIgnored() throws {
        let dns = PacketBuilder.dnsQueryFrame(name: "example.com", src: "192.168.1.2", dst: "1.1.1.1")
        var file = littleEndianHeader()
        file += littleEndianRecord(dns, tsSec: 1_700_000_000, tsUsec: 0)
        // A second record header claiming a payload that isn't present.
        file += le32(1_700_000_001) + le32(0) + le32(9_999) + le32(9_999)
        file += [0x01, 0x02, 0x03] // far fewer than 9999 bytes

        let result = try PcapReader.read(file)
        #expect(result.frames.count == 1)
        #expect(result.frames[0].bytes == dns)
    }

    @Test
    func malformedMagicThrows() {
        var file: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        file += [UInt8](repeating: 0, count: 20) // pad to a full 24-byte header
        #expect(throws: PacketError.self) {
            _ = try PcapReader.read(file)
        }
    }

    @Test
    func shortFileThrows() {
        let file: [UInt8] = [0xD4, 0xC3, 0xB2, 0xA1] // only the magic, no full header
        #expect(throws: PacketError.self) {
            _ = try PcapReader.read(file)
        }
    }

    // MARK: - URL adapter (streaming)

    @Test
    func urlAdapterMatchesInMemoryRead() throws {
        let dns = PacketBuilder.dnsQueryFrame(name: "example.com", src: "192.168.1.2", dst: "1.1.1.1")
        let tls = PacketBuilder.tlsClientHelloFrame(sni: "example.com", src: "192.168.1.2", dst: "93.184.16.34")

        var file = bigEndianHeader()
        file += bigEndianRecord(dns, tsSec: 1_700_000_000, tsUsec: 500_000)
        file += bigEndianRecord(tls, tsSec: 1_700_000_001, tsUsec: 0)

        let inMemory = try PcapReader.read(file)
        try withTempFile(file) { url in
            let streamed = try PcapReader.read(contentsOf: url)
            #expect(streamed.linkType == inMemory.linkType)
            #expect(streamed.frames.count == inMemory.frames.count)
            for (streamedFrame, memoryFrame) in zip(streamed.frames, inMemory.frames) {
                #expect(streamedFrame.bytes == memoryFrame.bytes)
                #expect(streamedFrame.originalLength == memoryFrame.originalLength)
                #expect(streamedFrame.capturedLength == memoryFrame.capturedLength)
                #expect(abs(
                    streamedFrame.timestamp.timeIntervalSince1970
                        - memoryFrame.timestamp.timeIntervalSince1970
                ) < 0.0001)
            }
        }
    }

    @Test
    func urlAdapterRecoversTruncatedTail() throws {
        let dns = PacketBuilder.dnsQueryFrame(name: "example.com", src: "192.168.1.2", dst: "1.1.1.1")
        var file = littleEndianHeader()
        file += littleEndianRecord(dns, tsSec: 1_700_000_000, tsUsec: 0)
        // A record header claiming 9999 payload bytes with only 3 present.
        file += le32(1_700_000_001) + le32(0) + le32(9_999) + le32(9_999)
        file += [0x01, 0x02, 0x03]

        try withTempFile(file) { url in
            let result = try PcapReader.read(contentsOf: url)
            #expect(result.frames.count == 1)
            #expect(result.frames[0].bytes == dns)
        }
    }

    // MARK: Private

    // MARK: - Helpers

    /// Write `bytes` to a unique temp `.pcap`, run `body`, and always clean up.
    private func withTempFile(_ bytes: [UInt8], _ body: (URL) throws -> Void) throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("pcapreader-\(UUID().uuidString).pcap")
        try Data(bytes).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        try body(url)
    }

    /// Little-endian 32-bit encoding.
    private func le32(_ value: UInt32) -> [UInt8] {
        [
            UInt8(value & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 24) & 0xFF)
        ]
    }

    /// Little-endian 16-bit encoding.
    private func le16(_ value: UInt16) -> [UInt8] {
        [UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF)]
    }

    /// Big-endian 32-bit encoding.
    private func be32(_ value: UInt32) -> [UInt8] {
        [
            UInt8((value >> 24) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8(value & 0xFF)
        ]
    }

    /// Big-endian 16-bit encoding.
    private func be16(_ value: UInt16) -> [UInt8] {
        [UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]
    }

    /// A little-endian classic .pcap global header (Ethernet link type).
    private func littleEndianHeader() -> [UInt8] {
        // The magic identifies byte order by how it reads big-endian; lay the
        // bytes down literally as D4 C3 B2 A1 so a big-endian read yields the value.
        var header = be32(0xD4C3B2A1) // magic (little-endian, microsecond)
        header += le16(2) + le16(4) // version major/minor
        header += le32(0) // thiszone
        header += le32(0) // sigfigs
        header += le32(65_535) // snaplen
        header += le32(1) // network = Ethernet
        return header
    }

    /// A big-endian classic .pcap global header (Ethernet link type).
    private func bigEndianHeader() -> [UInt8] {
        var header = be32(0xA1B2C3D4) // magic (big-endian, microsecond)
        header += be16(2) + be16(4) // version major/minor
        header += be32(0) // thiszone
        header += be32(0) // sigfigs
        header += be32(65_535) // snaplen
        header += be32(1) // network = Ethernet
        return header
    }

    /// A little-endian per-packet record wrapping `frame`.
    private func littleEndianRecord(_ frame: [UInt8], tsSec: UInt32, tsUsec: UInt32) -> [UInt8] {
        var record = le32(tsSec) + le32(tsUsec)
        record += le32(UInt32(frame.count)) // incl_len
        record += le32(UInt32(frame.count)) // orig_len
        return record + frame
    }

    /// A big-endian per-packet record wrapping `frame`.
    private func bigEndianRecord(_ frame: [UInt8], tsSec: UInt32, tsUsec: UInt32) -> [UInt8] {
        var record = be32(tsSec) + be32(tsUsec)
        record += be32(UInt32(frame.count)) // incl_len
        record += be32(UInt32(frame.count)) // orig_len
        return record + frame
    }
}
