import Foundation
import Testing
@testable import Tracexy

// MARK: - PcapngFixture

/// Programmatic pcapng block builders shared by the streaming and array reader
/// tests. Every builder lays bytes down in the requested byte order so a single
/// fixture can be produced little- or big-endian, and the section-header type
/// bytes stay byte-order independent as the format requires.
enum PcapngFixture {
    static func sectionHeader(
        little: Bool,
        major: UInt16 = 1,
        minor: UInt16 = 0,
        sectionLength: UInt64 = .max
    )
        -> [UInt8]
    {
        var body = u32(0x1A2B3C4D, little) // byte-order magic (raw, section order)
        body += u16(major, little)
        body += u16(minor, little)
        body += u64(sectionLength, little)
        return block(type: 0x0A0D0D0A, little: little, body: body)
    }

    static func interfaceDescription(
        little: Bool,
        linkType: UInt16 = 1,
        snapLength: UInt32 = 262_144,
        tsresol: UInt8? = nil,
        tsoffset: Int64? = nil
    )
        -> [UInt8]
    {
        var body = u16(linkType, little)
        body += u16(0, little) // reserved
        body += u32(snapLength, little)
        if let tsresol {
            body += option(code: 9, value: [tsresol], little: little)
        }
        if let tsoffset {
            body += option(code: 14, value: u64(UInt64(bitPattern: tsoffset), little), little: little)
        }
        if tsresol != nil || tsoffset != nil {
            body += option(code: 0, value: [], little: little) // opt_endofopt
        }
        return block(type: 0x00000001, little: little, body: body)
    }

    static func enhancedPacket(
        little: Bool,
        interfaceID: UInt32 = 0,
        ticks: UInt64,
        captured: [UInt8],
        originalLength: UInt32? = nil,
        trailingOptions: [UInt8] = []
    )
        -> [UInt8]
    {
        var body = u32(interfaceID, little)
        body += u32(UInt32(ticks >> 32), little)
        body += u32(UInt32(ticks & 0xFFFFFFFF), little)
        body += u32(UInt32(captured.count), little)
        body += u32(originalLength ?? UInt32(captured.count), little)
        body += captured
        while body.count % 4 != 0 {
            body.append(0) // packet-data padding to a 32-bit boundary
        }
        body += trailingOptions
        return block(type: 0x00000006, little: little, body: body)
    }

    static func simplePacket(little: Bool, originalLength: UInt32, captured: [UInt8]) -> [UInt8] {
        var body = u32(originalLength, little)
        body += captured
        return block(type: 0x00000003, little: little, body: body)
    }

    static func nameResolutionBlock(little: Bool, records: [(UInt16, [UInt8])]) -> [UInt8] {
        var body: [UInt8] = []
        for (type, value) in records {
            body += u16(type, little) + u16(UInt16(value.count), little) + value
            while body.count % 4 != 0 {
                body.append(0)
            }
        }
        body += u16(0, little) + u16(0, little)
        return block(type: 4, little: little, body: body)
    }

    /// Frame a block body with the type / total-length / trailing-length envelope,
    /// padding the body to a 32-bit boundary.
    static func block(type: UInt32, little: Bool, body: [UInt8]) -> [UInt8] {
        var padded = body
        while padded.count % 4 != 0 {
            padded.append(0)
        }
        let total = UInt32(12 + padded.count)
        var out = u32(type, little)
        out += u32(total, little)
        out += padded
        out += u32(total, little)
        return out
    }

    static func option(code: UInt16, value: [UInt8], little: Bool) -> [UInt8] {
        var out = u16(code, little)
        out += u16(UInt16(value.count), little)
        out += value
        while out.count % 4 != 0 {
            out.append(0)
        }
        return out
    }

    static func u16(_ value: UInt16, _ little: Bool) -> [UInt8] {
        let bytes = [UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF)]
        return little ? bytes : Array(bytes.reversed())
    }

    static func u32(_ value: UInt32, _ little: Bool) -> [UInt8] {
        let bytes = [
            UInt8(value & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 24) & 0xFF),
        ]
        return little ? bytes : Array(bytes.reversed())
    }

    static func u64(_ value: UInt64, _ little: Bool) -> [UInt8] {
        var bytes: [UInt8] = []
        for index in 0 ..< 8 {
            bytes.append(UInt8((value >> (8 * index)) & 0xFF))
        }
        return little ? bytes : Array(bytes.reversed())
    }
}

// MARK: - PcapngStreamReaderTests

struct PcapngStreamReaderTests {
    // MARK: Internal

    // MARK: - Single-section endianness and offsets

    @Test
    func littleEndianEnhancedPacketExactOffsetsAndProgress() throws {
        let payload: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        file += PcapngFixture.enhancedPacket(little: true, ticks: 1_700_000_000_500_000, captured: payload)

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            #expect(reader.metadata.identity.size == UInt64(file.count))

            let event = try Self.expectFrame(reader.next())
            #expect(event.bytes == payload)
            #expect(event.reference.blockOffset == 48) // 28 (SHB) + 20 (IDB)
            #expect(event.reference.payloadOffset == 76) // block + 28-byte fixed header
            #expect(event.reference.capturedLength == payload.count)
            #expect(event.reference.originalLength == payload.count)
            #expect(event.reference.sectionIndex == 0)
            #expect(event.reference.interfaceID == 0)
            #expect(event.reference.linkType == LinkType.ethernet)
            #expect(event.progress.bytesConsumed == UInt64(file.count))
            #expect(event.progress.totalBytes == UInt64(file.count))
            let instant = try #require(event.reference.timestamp)
            #expect(abs(instant.timeIntervalSince1970 - 1_700_000_000.5) < 1e-6)

            #expect(try reader.next() == .end(PcapngStreamCompletion(
                reason: .cleanEndOfFile,
                progress: PcapStreamProgress(bytesConsumed: UInt64(file.count), totalBytes: UInt64(file.count))
            )))
            #expect(try reader.next() == .end(PcapngStreamCompletion(
                reason: .cleanEndOfFile,
                progress: PcapStreamProgress(bytesConsumed: UInt64(file.count), totalBytes: UInt64(file.count))
            )))
        }
    }

    @Test
    func packetOptionsExcludeEndMarkerOnlyLists() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true)
        file += PcapngFixture.enhancedPacket(
            little: true, ticks: 1, captured: [0xAA], trailingOptions: PcapngFixture.option(
                code: 0,
                value: [],
                little: true
            )
        )
        file += PcapngFixture.enhancedPacket(
            little: true, ticks: 2, captured: [0xBB], trailingOptions: PcapngFixture.option(
                code: 1, value: Array("comment".utf8), little: true
            ) + PcapngFixture.option(code: 0, value: [], little: true)
        )

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            #expect(try Self.expectFrame(reader.next()).reference.hasOptions == false)
            #expect(try Self.expectFrame(reader.next()).reference.hasOptions)
        }
    }

    @Test
    func bigEndianEnhancedPacketDecodes() throws {
        let payload: [UInt8] = [0x01, 0x02, 0x03]
        var file = PcapngFixture.sectionHeader(little: false)
        file += PcapngFixture.interfaceDescription(little: false, linkType: 1)
        file += PcapngFixture.enhancedPacket(little: false, ticks: 2_000_000, captured: payload)

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            let event = try Self.expectFrame(reader.next())
            #expect(event.bytes == payload)
            let instant = try #require(event.reference.timestamp)
            #expect(abs(instant.timeIntervalSince1970 - 2.0) < 1e-6)
        }
    }

    @Test
    func packetDirectionFlagsSurviveBothByteOrdersAndPipeParsing() throws {
        for little in [true, false] {
            let flags = PcapngFixture.option(code: 2, value: PcapngFixture.u32(2, little), little: little)
                + PcapngFixture.option(code: 0, value: [], little: little)
            var file = PcapngFixture.sectionHeader(little: little)
            file += PcapngFixture.interfaceDescription(little: little)
            file += PcapngFixture.enhancedPacket(
                little: little, ticks: 1_000_000, captured: [0xAA], trailingOptions: flags
            )
            #expect(try PcapngReader.read(file).frames.map(\.direction) == [.outbound])
            try Self.withTempFile(file) { url in
                let reader = try CaptureStreamReader(contentsOf: url)
                guard case let .frame(event) = try reader.next() else {
                    Issue.record("Missing directed frame")
                    return
                }
                #expect(event.reference.direction == .outbound)
            }
            var pipe = CaptureByteStreamParser()
            #expect(try pipe.append(file).map(\.frame.direction) == [.outbound])
        }
    }

    @Test
    func duplicatePacketDirectionFlagsAreRejected() throws {
        let one = PcapngFixture.option(code: 2, value: PcapngFixture.u32(1, true), little: true)
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true)
        file += PcapngFixture.enhancedPacket(
            little: true, ticks: 1_000_000, captured: [0xAA], trailingOptions: one + one
        )
        #expect(throws: PacketError.self) { _ = try PcapngReader.read(file) }
        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            #expect(throws: PacketError.self) { _ = try reader.next() }
        }
        var pipe = CaptureByteStreamParser()
        #expect(throws: CaptureByteStreamParser.Failure.self) { _ = try pipe.append(file) }
    }

    @Test
    func packetIDsSurviveBothByteOrdersAndPipeParsing() throws {
        for little in [true, false] {
            let options = PcapngFixture.option(code: 5, value: PcapngFixture.u64(UInt64.max, little), little: little)
                + PcapngFixture.option(code: 0, value: [], little: little)
            var file = PcapngFixture.sectionHeader(little: little)
            file += PcapngFixture.interfaceDescription(little: little)
            file += PcapngFixture.enhancedPacket(
                little: little, ticks: 1_000_000, captured: [0xAA], trailingOptions: options
            )
            #expect(try PcapngReader.read(file).frames.map(\.packetID) == [UInt64.max])
            try Self.withTempFile(file) { url in
                let reader = try CaptureStreamReader(contentsOf: url)
                guard case let .frame(event) = try reader.next() else {
                    Issue.record("Missing packet ID frame")
                    return
                }
                #expect(event.reference.packetID == UInt64.max)
            }
            var pipe = CaptureByteStreamParser()
            #expect(try pipe.append(file).map(\.frame.packetID) == [UInt64.max])
        }
    }

    @Test
    func duplicatePacketIDsAreRejected() throws {
        let one = PcapngFixture.option(code: 5, value: PcapngFixture.u64(7, true), little: true)
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true)
        file += PcapngFixture.enhancedPacket(
            little: true, ticks: 1_000_000, captured: [0xAA], trailingOptions: one + one
        )
        #expect(throws: PacketError.self) { _ = try PcapngReader.read(file) }
        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            #expect(throws: PacketError.self) { _ = try reader.next() }
        }
        var pipe = CaptureByteStreamParser()
        #expect(throws: CaptureByteStreamParser.Failure.self) { _ = try pipe.append(file) }
    }

    // MARK: - Multiple sections and interfaces

    @Test
    func multipleSectionsSwitchEndianAndResetInterfaceZero() throws {
        let firstPayload: [UInt8] = [0xAA, 0xBB]
        let secondPayload: [UInt8] = [0xCC, 0xDD, 0xEE]
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        file += PcapngFixture.enhancedPacket(little: true, ticks: 1_000_000, captured: firstPayload)
        // A second section in the opposite byte order reusing interface id 0.
        file += PcapngFixture.sectionHeader(little: false)
        file += PcapngFixture.interfaceDescription(little: false, linkType: 101)
        file += PcapngFixture.enhancedPacket(little: false, ticks: 3_000_000, captured: secondPayload)

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            let first = try Self.expectFrame(reader.next())
            #expect(first.bytes == firstPayload)
            #expect(first.reference.sectionIndex == 0)
            #expect(first.reference.linkType == LinkType.ethernet)

            let second = try Self.expectFrame(reader.next())
            #expect(second.bytes == secondPayload)
            #expect(second.reference.sectionIndex == 1)
            #expect(second.reference.interfaceID == 0)
            #expect(second.reference.linkType == LinkType.raw)
            let secondInstant = try #require(second.reference.timestamp)
            #expect(abs(secondInstant.timeIntervalSince1970 - 3.0) < 1e-6)
        }
    }

    @Test
    func multipleInterfacesCarryDistinctLinkTypesAndResolutions() throws {
        let payloadA: [UInt8] = [0x10]
        let payloadB: [UInt8] = [0x20, 0x21]
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1, tsresol: 9) // decimal nanoseconds
        file += PcapngFixture.interfaceDescription(little: true, linkType: 101, tsresol: 0x80 | 10) // binary 2^10
        file += PcapngFixture.enhancedPacket(little: true, interfaceID: 0, ticks: 2_500_000_000, captured: payloadA)
        file += PcapngFixture.enhancedPacket(little: true, interfaceID: 1, ticks: 2_048, captured: payloadB)

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            let first = try Self.expectFrame(reader.next())
            #expect(first.reference.interfaceID == 0)
            #expect(first.reference.linkType == LinkType.ethernet)
            // 2_500_000_000 ticks / 10^9 == 2.5 s
            let firstInstant = try #require(first.reference.timestamp)
            #expect(abs(firstInstant.timeIntervalSince1970 - 2.5) < 1e-6)

            let second = try Self.expectFrame(reader.next())
            #expect(second.reference.interfaceID == 1)
            #expect(second.reference.linkType == LinkType.raw)
            // 2_048 ticks / 2^10 == 2.0 s
            let secondInstant = try #require(second.reference.timestamp)
            #expect(abs(secondInstant.timeIntervalSince1970 - 2.0) < 1e-6)
        }
    }

    @Test
    func signedTimestampOffsetShiftsFrameTime() throws {
        let payload: [UInt8] = [0x55]
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1, tsresol: 6, tsoffset: -1_000)
        file += PcapngFixture.enhancedPacket(little: true, ticks: 500_000, captured: payload) // 0.5 s

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            let event = try Self.expectFrame(reader.next())
            let instant = try #require(event.reference.timestamp)
            #expect(abs(instant.timeIntervalSince1970 - -999.5) < 1e-6)
        }
    }

    // MARK: - Simple Packet Block

    @Test
    func nameResolutionBlockReadsIPv4AndIPv6InBothByteOrders() throws {
        for little in [true, false] {
            var file = PcapngFixture.sectionHeader(little: little)
            file += PcapngFixture.nameResolutionBlock(little: little, records: [
                (1, [192, 0, 2, 7] + Array("api.example.test\0".utf8)),
                (
                    2,
                    [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                        + Array("v6.example.test\0".utf8)
                ),
            ])
            try Self.withTempFile(file) { url in
                let reader = try PcapngStreamReader(contentsOf: url)
                guard case .end = try reader.next() else {
                    Issue.record("expected end")
                    return
                }
                #expect(reader.nameResolutionRecords.map(\.address) == ["192.0.2.7", "2001:db8::1"])
                #expect(reader.nameResolutionRecords.map(\.name.text) == ["api.example.test", "v6.example.test"])
                #expect(reader.fileProperties.blockInventory.nameResolutionBlockCount == 1)
            }
        }
    }

    @Test
    func nameResolutionBlockMalformedRecordFailsWithoutInventingMappings() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.block(type: 4, little: true, body: [1, 0, 20, 0, 192, 0, 2, 1])
        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            #expect(throws: (any Error).self) { try reader.next() }
            #expect(reader.nameResolutionRecords.isEmpty)
        }
    }

    @Test
    func nameResolutionRetentionLimitReportsOmittedMappings() throws {
        let records = (0 ..< 501).map { index in
            (UInt16(1), [192, 0, 2, UInt8(index % 255)] + Array("host-\(index).test\0".utf8))
        }
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.nameResolutionBlock(little: true, records: records)
        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            guard case .end = try reader.next() else {
                Issue.record("expected end")
                return
            }
            #expect(reader.nameResolutionRecords.count == 500)
            #expect(reader.fileProperties.blockInventory.nameResolutionMappingCount == 500)
            #expect(reader.fileProperties.blockInventory.nameResolutionMappingOmittedCount == 1)
        }
    }

    @Test
    func oversizedNameResolutionBlockIsReportedAsSkipped() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.nameResolutionBlock(little: true, records: [
            (1, [192, 0, 2, 1] + [UInt8](repeating: 0x61, count: 65_530)),
        ])
        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            guard case .end = try reader.next() else {
                Issue.record("expected end")
                return
            }
            #expect(reader.nameResolutionRecords.isEmpty)
            #expect(reader.fileProperties.blockInventory.oversizedNameResolutionBlockCount == 1)
        }
    }

    @Test
    func simplePacketUsesInterfaceZeroSnapLengthAndUnknownTime() throws {
        let payload: [UInt8] = [0x71, 0x72, 0x73, 0x74, 0x75, 0x76]
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1, snapLength: 6)
        file += PcapngFixture.simplePacket(little: true, originalLength: 6, captured: payload)

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            let event = try Self.expectFrame(reader.next())
            #expect(event.bytes == payload)
            #expect(event.reference.capturedLength == 6)
            #expect(event.reference.originalLength == 6)
            #expect(event.reference.interfaceID == 0)
            #expect(event.reference.linkType == LinkType.ethernet)
            // A Simple Packet Block has no timestamp field, so the capture instant
            // is unknown — deliberately not the Unix epoch, which a real capture
            // can legitimately carry (see `realEpochTimestampStaysKnown`).
            #expect(event.reference.timestamp == nil)
        }
    }

    @Test("An Enhanced Packet Block at tick zero is a real, known Unix-epoch instant")
    func realEpochTimestampStaysKnown() throws {
        let payload: [UInt8] = [0x01]
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        file += PcapngFixture.enhancedPacket(little: true, ticks: 0, captured: payload)

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            let event = try Self.expectFrame(reader.next())
            #expect(event.reference.timestamp == Date(timeIntervalSince1970: 0))
        }
    }

    @Test
    func simplePacketTruncatesToSnapLength() throws {
        // Snap length below the original length: only snapLen bytes are captured.
        let captured: [UInt8] = [0x01, 0x02, 0x03, 0x04]
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1, snapLength: 4)
        file += PcapngFixture.simplePacket(little: true, originalLength: 9, captured: captured)

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            let event = try Self.expectFrame(reader.next())
            #expect(event.bytes == captured)
            #expect(event.reference.capturedLength == 4)
            #expect(event.reference.originalLength == 9)
        }
    }

    @Test
    func simplePacketTreatsZeroSnapLengthAsUnlimited() throws {
        let captured: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05]
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1, snapLength: 0)
        file += PcapngFixture.simplePacket(little: true, originalLength: 5, captured: captured)

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            let event = try Self.expectFrame(reader.next())
            #expect(event.bytes == captured)
            #expect(event.reference.capturedLength == captured.count)
            #expect(event.reference.originalLength == captured.count)
        }
    }

    // MARK: - Unknown block skip

    @Test
    func unknownBlockIsSkippedByCheckedOffsets() throws {
        let payload: [UInt8] = [0x42, 0x43]
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        // A large unknown block (type 0x00000005 = Interface Statistics) with a
        // 64-byte body must be skipped without allocation.
        file += PcapngFixture.block(type: 0x00000005, little: true, body: [UInt8](repeating: 0x00, count: 64))
        file += PcapngFixture.enhancedPacket(little: true, ticks: 1_000_000, captured: payload)

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            let event = try Self.expectFrame(reader.next())
            #expect(event.bytes == payload)
        }
    }

    // MARK: - Terminals

    @Test
    func partialBlockHeaderTerminalPreservesPriorFrame() throws {
        let payload: [UInt8] = [0x01, 0x02]
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        file += PcapngFixture.enhancedPacket(little: true, ticks: 1_000_000, captured: payload)
        file += [0xAA, 0xBB, 0xCC] // 3 stray bytes: fewer than a block header

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            _ = try Self.expectFrame(reader.next())
            let end = try Self.expectEnd(reader.next())
            #expect(end.reason == .partialBlockHeader)
            #expect(end.progress.bytesConsumed == UInt64(file.count))
        }
    }

    @Test
    func partialBlockBodyTerminalPreservesPriorFrame() throws {
        let payload: [UInt8] = [0x01, 0x02]
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        file += PcapngFixture.enhancedPacket(little: true, ticks: 1_000_000, captured: payload)
        // A well-formed block header declaring 40 bytes but only 8 present.
        file += PcapngFixture.u32(0x00000006, true) + PcapngFixture.u32(40, true)

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            _ = try Self.expectFrame(reader.next())
            let end = try Self.expectEnd(reader.next())
            #expect(end.reason == .partialBlockBody)
            #expect(end.progress.bytesConsumed == UInt64(file.count))
        }
    }

    @Test
    func laterSectionHeaderWithoutByteOrderMagicIsPartialBody() throws {
        let payload: [UInt8] = [0x01]
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        file += PcapngFixture.enhancedPacket(little: true, ticks: 1_000_000, captured: payload)
        // Section header type + a length, but fewer than 12 bytes before EOF, so
        // its byte-order magic is missing.
        file += PcapngFixture.u32(0x0A0D0D0A, true) + PcapngFixture.u32(28, true) + [0x00, 0x01]

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            _ = try Self.expectFrame(reader.next())
            let end = try Self.expectEnd(reader.next())
            #expect(end.reason == .partialBlockBody)
        }
    }

    // MARK: - Malformed metadata

    @Test
    func firstBlockNotSectionHeaderThrows() throws {
        let file = PcapngFixture.interfaceDescription(little: true, linkType: 1)
        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            #expect(throws: PacketError.self) {
                _ = try reader.next()
            }
        }
    }

    @Test
    func badByteOrderMagicThrows() throws {
        var body = PcapngFixture.u32(0xDEADBEEF, true) // wrong magic
        body += PcapngFixture.u16(1, true) + PcapngFixture.u16(0, true)
        body += PcapngFixture.u64(.max, true)
        let file = PcapngFixture.block(type: 0x0A0D0D0A, little: true, body: body)

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            #expect(throws: PacketError.self) {
                _ = try reader.next()
            }
        }
    }

    @Test
    func unsupportedVersionThrows() throws {
        let file = PcapngFixture.sectionHeader(little: true, major: 2)
        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            #expect(throws: PacketError.self) {
                _ = try reader.next()
            }
        }
    }

    @Test
    func misalignedBlockLengthThrows() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        // A block with a non-32-bit-aligned declared length (30).
        file += PcapngFixture.u32(0x00000001, true) + PcapngFixture.u32(30, true)
        file += [UInt8](repeating: 0, count: 22)
        file += PcapngFixture.u32(30, true)

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            #expect(throws: PacketError.self) {
                _ = try reader.next()
            }
        }
    }

    @Test
    func belowMinimumBlockLengthThrows() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        // An Enhanced Packet Block whose declared length (16) is below the 32-byte
        // minimum for that block type.
        file += PcapngFixture.u32(0x00000006, true) + PcapngFixture.u32(16, true)
        file += [UInt8](repeating: 0, count: 8)
        file += PcapngFixture.u32(16, true)

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            #expect(throws: PacketError.self) {
                _ = try reader.next()
            }
        }
    }

    @Test
    func trailerMismatchThrows() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        // An IDB whose trailing length disagrees with the leading length.
        var body = PcapngFixture.u16(1, true) + PcapngFixture.u16(0, true)
        body += PcapngFixture.u32(262_144, true)
        var badBlock = PcapngFixture.u32(0x00000001, true) + PcapngFixture.u32(20, true)
        badBlock += body
        badBlock += PcapngFixture.u32(24, true) // wrong trailer
        file += badBlock

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            #expect(throws: PacketError.self) {
                _ = try reader.next()
            }
        }
    }

    @Test
    func enhancedPacketWithUndeclaredInterfaceThrows() throws {
        let payload: [UInt8] = [0x01]
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        file += PcapngFixture.enhancedPacket(little: true, interfaceID: 5, ticks: 0, captured: payload)

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            #expect(throws: PacketError.self) {
                _ = try reader.next()
            }
        }
    }

    @Test
    func originalLengthBelowCapturedLengthThrows() throws {
        let payload: [UInt8] = [0x01, 0x02, 0x03, 0x04]
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        file += PcapngFixture.enhancedPacket(little: true, ticks: 0, captured: payload, originalLength: 2)

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            #expect(throws: PacketError.self) {
                _ = try reader.next()
            }
        }
    }

    @Test
    func overLimitCapturedLengthRejectedBeforeAllocation() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        // Declare a 100-byte capture but ship none of it; a cap of 4 must reject it
        // on the fixed header before any payload allocation.
        var body = PcapngFixture.u32(0, true) // interface id
        body += PcapngFixture.u32(0, true) + PcapngFixture.u32(0, true) // timestamp
        body += PcapngFixture.u32(100, true) + PcapngFixture.u32(100, true) // captured / original
        // A truthful envelope for a 100-byte payload so only the cap trips.
        file += PcapngFixture.block(type: 0x00000006, little: true, body: body + [UInt8](repeating: 0, count: 100))

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(
                contentsOf: url,
                configuration: .init(maxCapturedLength: 4)
            )
            #expect(throws: PacketError.self) {
                _ = try reader.next()
            }
        }
    }

    @Test
    func outOfRangeDecimalResolutionThrows() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1, tsresol: 20) // decimal exponent > 19
        file += PcapngFixture.enhancedPacket(little: true, ticks: 0, captured: [0x01])

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            #expect(throws: PacketError.self) {
                _ = try reader.next()
            }
        }
    }

    @Test
    func outOfRangeBinaryResolutionThrows() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1, tsresol: 0x80 | 64)

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            #expect(throws: PacketError.self) {
                _ = try reader.next()
            }
        }
    }

    @Test
    func endOfOptionsWithPayloadThrows() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        var body = PcapngFixture.u16(1, true) + PcapngFixture.u16(0, true)
        body += PcapngFixture.u32(262_144, true)
        body += PcapngFixture.option(code: 0, value: [0x01, 0x02, 0x03, 0x04], little: true)
        file += PcapngFixture.block(type: 0x00000001, little: true, body: body)

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            #expect(throws: PacketError.self) {
                _ = try reader.next()
            }
        }
    }

    // MARK: - Cancellation & poisoning

    @Test
    func injectedCancellationBeforeFirstBlockThrows() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        file += PcapngFixture.enhancedPacket(little: true, ticks: 0, captured: [0x01])

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(
                contentsOf: url,
                configuration: .init(isCancelled: { true })
            )
            #expect(throws: CancellationError.self) {
                _ = try reader.next()
            }
        }
    }

    @Test
    func cancellationBetweenHeaderAndPayloadPoisonsReader() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        file += PcapngFixture.enhancedPacket(little: true, ticks: 0, captured: [0x01, 0x02, 0x03])

        try Self.withTempFile(file) { url in
            // Consultations before the enhanced packet's payload read, in order:
            // 1 SHB block, 2 SHB body, 3 IDB block, 4 IDB body, 5 EPB block,
            // 6 EPB fixed header, 7 EPB pre-payload. Trip the seventh.
            let counter = Counter()
            let reader = try PcapngStreamReader(
                contentsOf: url,
                configuration: .init(isCancelled: { counter.next() == 7 })
            )
            #expect(throws: CancellationError.self) {
                _ = try reader.next()
            }
            // The descriptor already consumed the packet's fixed header. The reader
            // must stay poisoned rather than reinterpret payload bytes as a block.
            #expect(throws: CancellationError.self) {
                _ = try reader.next()
            }
        }
    }

    @Test
    func malformedFailurePoisonsReader() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        file += PcapngFixture.enhancedPacket(little: true, interfaceID: 9, ticks: 0, captured: [0x01])

        try Self.withTempFile(file) { url in
            let reader = try PcapngStreamReader(contentsOf: url)
            #expect(throws: PacketError.self) {
                _ = try reader.next()
            }
            // A malformed block that advanced the cursor poisons the reader.
            #expect(throws: PacketError.self) {
                _ = try reader.next()
            }
        }
    }

    @Test
    func defaultCancellationHonoursCurrentTask() async throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        file += PcapngFixture.enhancedPacket(little: true, ticks: 0, captured: [0x01])
        let url = try Self.makeTempURL()
        defer { try? FileManager.default.removeItem(at: url) }
        try Data(file).write(to: url)

        let cancelled = await Task {
            guard let reader = try? PcapngStreamReader(contentsOf: url) else {
                return false
            }
            withUnsafeCurrentTask { $0?.cancel() }
            do {
                _ = try reader.next()
                return false
            } catch is CancellationError {
                return true
            } catch {
                return false
            }
        }.value
        #expect(cancelled)
    }

    @Test
    func sparseMultiGigabyteFileStartsIncrementallyAndCancels() throws {
        var prefix = PcapngFixture.sectionHeader(little: true)
        prefix += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        prefix += PcapngFixture.enhancedPacket(little: true, ticks: 1_000_000, captured: [0x01])
        let url = try Self.makeTempURL()
        defer { try? FileManager.default.removeItem(at: url) }
        try Data(prefix).write(to: url)

        let sparseSize: UInt64 = 4 * 1_024 * 1_024 * 1_024
        let writer = try FileHandle(forWritingTo: url)
        try writer.truncate(atOffset: sparseSize)
        try writer.close()

        let gate = CancelGate()
        let reader = try PcapngStreamReader(
            contentsOf: url,
            configuration: .init(isCancelled: { gate.isCancelled })
        )
        #expect(reader.metadata.identity.size == sparseSize)

        let event = try Self.expectFrame(reader.next())
        #expect(event.bytes == [0x01])
        #expect(event.progress.bytesConsumed == UInt64(prefix.count))
        #expect(event.progress.totalBytes == sparseSize)

        // Cancel before walking or allocating the sparse 4 GiB tail.
        gate.isCancelled = true
        #expect(throws: CancellationError.self) {
            _ = try reader.next()
        }
    }

    // MARK: Private

    /// Lock-guarded counter for the `@Sendable` cancellation closure.
    private final class Counter: @unchecked Sendable {
        // MARK: Internal

        func next() -> Int {
            lock.lock()
            defer { lock.unlock() }
            count += 1
            return count
        }

        // MARK: Private

        private let lock = NSLock()
        private var count = 0
    }

    /// Lock-guarded settable flag for the `@Sendable` cancellation closure.
    private final class CancelGate: @unchecked Sendable {
        // MARK: Internal

        var isCancelled: Bool {
            get {
                lock.lock()
                defer { lock.unlock() }
                return flag
            }
            set {
                lock.lock()
                defer { lock.unlock() }
                flag = newValue
            }
        }

        // MARK: Private

        private let lock = NSLock()
        private var flag = false
    }

    private static func expectFrame(_ outcome: PcapngStreamOutcome) throws -> PcapngFrameEvent {
        guard case let .frame(event) = outcome else {
            Issue.record("expected a frame, got \(outcome)")
            throw CancellationError()
        }
        return event
    }

    private static func expectEnd(_ outcome: PcapngStreamOutcome) throws -> PcapngStreamCompletion {
        guard case let .end(completion) = outcome else {
            Issue.record("expected an end, got \(outcome)")
            throw CancellationError()
        }
        return completion
    }

    private static func makeTempURL() throws -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("pcapngstream-\(UUID().uuidString).pcapng")
    }

    private static func withTempFile(_ bytes: [UInt8], _ body: (URL) throws -> Void) throws {
        let url = try makeTempURL()
        try Data(bytes).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        try body(url)
    }
}
