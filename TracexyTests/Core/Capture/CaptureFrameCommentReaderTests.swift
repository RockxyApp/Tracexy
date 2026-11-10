import Foundation
import Testing
@testable import Tracexy

struct CaptureFrameCommentReaderTests {
    @Test
    func readsOnlyTheSelectedPacketsCommentsInEitherSectionByteOrder() throws {
        for little in [true, false] {
            var bytes = PcapngFixture.sectionHeader(little: little)
            bytes += PcapngFixture.interfaceDescription(little: little)
            let comment = Array("source comment".utf8)
            let neighboringComment = Array("neighbor frame only".utf8)
            let oversized = [UInt8](repeating: 0x61, count: CaptureBoundedText.maxBytes + 5)
            let options = PcapngFixture.option(code: 1, value: comment, little: little)
                + PcapngFixture.option(code: 1, value: oversized, little: little)
                + PcapngFixture.option(code: 0, value: [], little: little)
            let neighboringOptions = PcapngFixture.option(code: 1, value: neighboringComment, little: little)
                + PcapngFixture.option(code: 0, value: [], little: little)
            bytes += PcapngFixture.enhancedPacket(
                little: little, ticks: 1, captured: [0x01, 0x02], trailingOptions: options
            )
            bytes += PcapngFixture.enhancedPacket(
                little: little, ticks: 2, captured: [0x03, 0x04], trailingOptions: neighboringOptions
            )

            let url = FileManager.default.temporaryDirectory
                .appendingPathComponent("frame-comment-\(UUID().uuidString).pcapng")
            defer { try? FileManager.default.removeItem(at: url) }
            try Data(bytes).write(to: url)

            let reader = try CaptureStreamReader(contentsOf: url)
            guard case let .frame(event) = try reader.next(),
                  let reference = event.reference.frameCommentReference else
            {
                Issue.record("expected a commented pcapng frame")
                continue
            }
            guard case let .frame(neighboringEvent) = try reader.next(),
                  let neighboringReference = neighboringEvent.reference.frameCommentReference else
            {
                Issue.record("expected a second commented pcapng frame")
                continue
            }
            let result = try CaptureFrameCommentReader.read(
                reference, from: url, expectedIdentity: reader.identity
            )
            let neighboringResult = try CaptureFrameCommentReader.read(
                neighboringReference, from: url, expectedIdentity: reader.identity
            )
            #expect(result.comments.count == 2)
            #expect(result.comments[0] == CaptureBoundedText(text: "source comment"))
            #expect(result.comments[1].text == String(repeating: "a", count: CaptureBoundedText.maxBytes))
            #expect(result.comments[1].isTruncated)
            #expect(result.omittedCount == 0)
            #expect(neighboringResult.comments.map(\.text) == ["neighbor frame only"])
        }
    }

    @Test
    func refusesAChangedSourceBeforeReadingComments() throws {
        var bytes = PcapngFixture.sectionHeader(little: true)
        bytes += PcapngFixture.interfaceDescription(little: true)
        let options = PcapngFixture.option(code: 1, value: Array("note".utf8), little: true)
            + PcapngFixture.option(code: 0, value: [], little: true)
        bytes += PcapngFixture.enhancedPacket(little: true, ticks: 1, captured: [0x01], trailingOptions: options)
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("frame-comment-identity-\(UUID().uuidString).pcapng")
        defer { try? FileManager.default.removeItem(at: url) }
        try Data(bytes).write(to: url)

        let reader = try CaptureStreamReader(contentsOf: url)
        guard case let .frame(event) = try reader.next(),
              let reference = event.reference.frameCommentReference else
        {
            Issue.record("expected a commented pcapng frame")
            return
        }
        let handle = try FileHandle(forWritingTo: url)
        try handle.seekToEnd()
        try handle.write(contentsOf: Data([0x00]))
        try handle.close()

        #expect(throws: FollowStreamError.identityMismatch) {
            try CaptureFrameCommentReader.read(reference, from: url, expectedIdentity: reader.identity)
        }
    }

    @Test
    func reportsEmptyLossyAndOmittedCommentsExplicitly() throws {
        var bytes = PcapngFixture.sectionHeader(little: true)
        bytes += PcapngFixture.interfaceDescription(little: true)
        var options = PcapngFixture.option(code: 1, value: [0xFF], little: true)
            + PcapngFixture.option(code: 1, value: [], little: true)
        for _ in 0 ..< CaptureBoundedTextList.maxCount {
            options += PcapngFixture.option(code: 1, value: [0x78], little: true)
        }
        options += PcapngFixture.option(code: 0, value: [], little: true)
        bytes += PcapngFixture.enhancedPacket(little: true, ticks: 1, captured: [0x01], trailingOptions: options)
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("frame-comment-bounds-\(UUID().uuidString).pcapng")
        defer { try? FileManager.default.removeItem(at: url) }
        try Data(bytes).write(to: url)

        let reader = try CaptureStreamReader(contentsOf: url)
        guard case let .frame(event) = try reader.next(),
              let reference = event.reference.frameCommentReference else
        {
            Issue.record("expected a commented pcapng frame")
            return
        }
        let result = try CaptureFrameCommentReader.read(reference, from: url, expectedIdentity: reader.identity)
        #expect(result.comments.count == CaptureBoundedTextList.maxCount)
        #expect(result.comments[0].isLossy)
        #expect(result.comments[1].text.isEmpty)
        #expect(result.omittedCount == 2)
    }

    @Test
    func honorsCancellationAndRejectsAnOversizedOptionRange() throws {
        var bytes = PcapngFixture.sectionHeader(little: true)
        bytes += PcapngFixture.interfaceDescription(little: true)
        let options = PcapngFixture.option(code: 1, value: Array("note".utf8), little: true)
            + PcapngFixture.option(code: 0, value: [], little: true)
        bytes += PcapngFixture.enhancedPacket(little: true, ticks: 1, captured: [0x01], trailingOptions: options)
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("frame-comment-cancel-\(UUID().uuidString).pcapng")
        defer { try? FileManager.default.removeItem(at: url) }
        try Data(bytes).write(to: url)

        let reader = try CaptureStreamReader(contentsOf: url)
        guard case let .frame(event) = try reader.next(),
              let reference = event.reference.frameCommentReference else
        {
            Issue.record("expected a commented pcapng frame")
            return
        }
        #expect(throws: CancellationError.self) {
            try CaptureFrameCommentReader.read(
                reference, from: url, expectedIdentity: reader.identity, isCancelled: { true }
            )
        }
        let oversizedReference = CaptureFrameCommentReference(
            optionsRange: 0 ..< UInt64.max, littleEndian: true
        )
        #expect(throws: PacketError.self) {
            try CaptureFrameCommentReader.read(
                oversizedReference, from: url, expectedIdentity: reader.identity
            )
        }
    }
}
