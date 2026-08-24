import Foundation
import Testing
@testable import Tracexy

// MARK: - CaptureStreamReaderTests

/// The format-neutral reader must sniff PCAP vs PCAPNG from the leading magic and
/// expose both through one uniform frame/reference/progress/completeness API,
/// preserving per-frame link types for a mixed-interface pcapng.
struct CaptureStreamReaderTests {
    // MARK: Internal

    // MARK: - PCAP adaptation

    @Test
    func sniffsClassicPcapAndExposesUniformFrames() throws {
        let first: [UInt8] = [0x11, 0x22, 0x33, 0x44]
        let second: [UInt8] = [0x55, 0x66]
        let file = Self.pcapFile(linkType: 1, records: [
            Record(payload: first, tsSec: 5, tsFrac: 0, origLen: 9),
            Record(payload: second, tsSec: 6, tsFrac: 0),
        ])
        try Self.withTempFile(file, ext: "pcap") { url in
            let reader = try CaptureStreamReader(contentsOf: url)
            #expect(reader.format == .pcap)
            #expect(reader.defaultLinkType == 1)
            #expect(reader.identity.size == UInt64(file.count))

            let event = try Self.expectFrame(reader.next())
            #expect(event.bytes == first)
            #expect(event.reference.payloadOffset == 40) // 24 global + 16 record header
            #expect(event.reference.capturedLength == first.count)
            #expect(event.reference.originalLength == 9)
            #expect(event.reference.linkType == 1)
            #expect(event.progress.bytesConsumed == UInt64(40 + first.count))
            #expect(event.progress.totalBytes == UInt64(file.count))

            let secondEvent = try Self.expectFrame(reader.next())
            #expect(secondEvent.bytes == second)
            #expect(secondEvent.progress.bytesConsumed > event.progress.bytesConsumed)

            let end = try Self.expectEnd(reader.next())
            #expect(end.reason == .cleanEndOfFile)
            #expect(end.progress.bytesConsumed == UInt64(file.count))
        }
    }

    @Test
    func classicPcapPartialHeaderAndPayloadMapToUniformTerminals() throws {
        // Partial record header: a stray tail shorter than a 16-byte header.
        var headerCut = Self.pcapFile(linkType: 1, records: [Record(payload: [0x01], tsSec: 1, tsFrac: 0)])
        headerCut += [0xAA, 0xBB, 0xCC]
        try Self.withTempFile(headerCut, ext: "pcap") { url in
            let reader = try CaptureStreamReader(contentsOf: url)
            _ = try Self.expectFrame(reader.next())
            #expect(try Self.expectEnd(reader.next()).reason == .partialHeader)
        }

        // Partial payload: a complete header declaring more than remains.
        var bodyCut = Self.pcapFile(linkType: 1, records: [Record(payload: [0x01], tsSec: 1, tsFrac: 0)])
        bodyCut += Self.leRecordHeader(tsSec: 2, tsFrac: 0, inclLen: 16, origLen: 16)
        bodyCut += [0x09, 0x08]
        try Self.withTempFile(bodyCut, ext: "pcap") { url in
            let reader = try CaptureStreamReader(contentsOf: url)
            _ = try Self.expectFrame(reader.next())
            #expect(try Self.expectEnd(reader.next()).reason == .partialBody)
        }
    }

    @Test
    func classicPcapBadMagicThrowsAtConstruction() throws {
        var file: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        file += [UInt8](repeating: 0, count: 20)
        try Self.withTempFile(file, ext: "pcap") { url in
            #expect(throws: PacketError.self) {
                _ = try CaptureStreamReader(contentsOf: url)
            }
        }
    }

    @Test
    func classicPcapOverLimitCapturedLengthRejected() throws {
        var file = Self.pcapGlobalHeader(linkType: 1)
        file += Self.leRecordHeader(tsSec: 1, tsFrac: 0, inclLen: 100, origLen: 100)
        try Self.withTempFile(file, ext: "pcap") { url in
            let reader = try CaptureStreamReader(contentsOf: url, configuration: .init(maxCapturedLength: 4))
            #expect(throws: PacketError.self) {
                _ = try reader.next()
            }
        }
    }

    // MARK: - PCAPNG adaptation

    @Test
    func sniffsPcapngAndPreservesPerFrameLinkTypesAcrossSectionsAndInterfaces() throws {
        let firstPayload: [UInt8] = [0xAA, 0xBB]
        let secondPayload: [UInt8] = [0xCC, 0xDD, 0xEE]
        // Section one, interface link type 1 (Ethernet), then a second section in
        // the opposite byte order with interface link type 101 (Raw).
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        file += PcapngFixture.enhancedPacket(little: true, ticks: 1_000_000, captured: firstPayload)
        file += PcapngFixture.sectionHeader(little: false)
        file += PcapngFixture.interfaceDescription(little: false, linkType: 101)
        file += PcapngFixture.enhancedPacket(little: false, ticks: 3_000_000, captured: secondPayload)

        try Self.withTempFile(file, ext: "pcapng") { url in
            let reader = try CaptureStreamReader(contentsOf: url)
            #expect(reader.format == .pcapng)

            let first = try Self.expectFrame(reader.next())
            #expect(first.bytes == firstPayload)
            #expect(first.reference.linkType == LinkType.ethernet)
            // First declared IDB drives the compatibility default.
            #expect(reader.defaultLinkType == LinkType.ethernet)

            let second = try Self.expectFrame(reader.next())
            #expect(second.bytes == secondPayload)
            #expect(second.reference.linkType == LinkType.raw)

            #expect(try Self.expectEnd(reader.next()).reason == .cleanEndOfFile)
        }
    }

    @Test
    func pcapngPartialBodyMapsToUniformTerminal() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        // A declared enhanced packet block whose body is cut off.
        let full = PcapngFixture.enhancedPacket(little: true, ticks: 0, captured: [0x01, 0x02, 0x03, 0x04])
        file += full.dropLast(6)
        try Self.withTempFile(file, ext: "pcapng") { url in
            let reader = try CaptureStreamReader(contentsOf: url)
            #expect(try Self.expectEnd(reader.next()).reason == .partialBody)
        }
    }

    @Test
    func cancellationThrowsAndYieldsNoFrame() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        file += PcapngFixture.enhancedPacket(little: true, ticks: 0, captured: [0x01])
        try Self.withTempFile(file, ext: "pcapng") { url in
            let reader = try CaptureStreamReader(contentsOf: url, configuration: .init(isCancelled: { true }))
            #expect(throws: CancellationError.self) {
                _ = try reader.next()
            }
        }
    }

    // MARK: Private

    private struct Record {
        // MARK: Lifecycle

        init(payload: [UInt8], tsSec: UInt32, tsFrac: UInt32, origLen: UInt32? = nil) {
            self.payload = payload
            self.tsSec = tsSec
            self.tsFrac = tsFrac
            self.origLen = origLen
        }

        // MARK: Internal

        let payload: [UInt8]
        let tsSec: UInt32
        let tsFrac: UInt32
        let origLen: UInt32?
    }

    private static func expectFrame(_ outcome: CaptureStreamOutcome) throws -> CaptureFrameEvent {
        guard case let .frame(event) = outcome else {
            Issue.record("expected a frame, got \(outcome)")
            throw CancellationError()
        }
        return event
    }

    private static func expectEnd(_ outcome: CaptureStreamOutcome) throws -> CaptureStreamCompletion {
        guard case let .end(completion) = outcome else {
            Issue.record("expected an end, got \(outcome)")
            throw CancellationError()
        }
        return completion
    }

    // MARK: - PCAP byte builders (little-endian, microsecond)

    private static func le16(_ value: UInt16) -> [UInt8] {
        [UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF)]
    }

    private static func le32(_ value: UInt32) -> [UInt8] {
        [UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF), UInt8((value >> 16) & 0xFF), UInt8((value >> 24) & 0xFF)]
    }

    private static func pcapGlobalHeader(linkType: UInt32) -> [UInt8] {
        // Magic laid down so a big-endian read yields 0xD4C3B2A1 (little-endian μs).
        var header: [UInt8] = [0xD4, 0xC3, 0xB2, 0xA1]
        header += le16(2) + le16(4)
        header += le32(0) + le32(0)
        header += le32(65_535)
        header += le32(linkType)
        return header
    }

    private static func leRecordHeader(tsSec: UInt32, tsFrac: UInt32, inclLen: UInt32, origLen: UInt32) -> [UInt8] {
        le32(tsSec) + le32(tsFrac) + le32(inclLen) + le32(origLen)
    }

    private static func pcapFile(linkType: UInt32, records: [Record]) -> [UInt8] {
        var bytes = pcapGlobalHeader(linkType: linkType)
        for record in records {
            let incl = UInt32(record.payload.count)
            bytes += leRecordHeader(
                tsSec: record.tsSec, tsFrac: record.tsFrac, inclLen: incl, origLen: record.origLen ?? incl
            )
            bytes += record.payload
        }
        return bytes
    }

    // MARK: - Temp files

    private static func withTempFile(_ bytes: [UInt8], ext: String, _ body: (URL) throws -> Void) throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("capturestream-\(UUID().uuidString).\(ext)")
        try Data(bytes).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        try body(url)
    }
}
