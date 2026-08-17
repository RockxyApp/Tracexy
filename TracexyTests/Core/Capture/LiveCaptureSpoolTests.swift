import Foundation
import Testing
@testable import Tracexy

@Suite("Disk-backed live capture spool")
struct LiveCaptureSpoolTests {
    // MARK: Internal

    @Test("Spool round-trips every appended frame across batches")
    func roundTrip() async throws {
        let spool = LiveCaptureSpool(directoryName: "LiveCaptureSpoolTests")
        try await spool.reset(epoch: 7)
        let first = frame(byte: 1, timestamp: 1, linkType: LinkType.ethernet)
        let second = frame(byte: 2, timestamp: 2, linkType: LinkType.raw)

        try await spool.append([first], defaultLinkType: LinkType.ethernet, epoch: 7)
        try await spool.append([second], defaultLinkType: LinkType.ethernet, epoch: 7)
        let capture = try await spool.capture()

        #expect(capture.frames.count == 2)
        #expect(capture.frames.map(\.bytes) == [first.bytes, second.bytes])
        #expect(capture.frames.map(\.originalLength) == [first.originalLength, second.originalLength])
        #expect(capture.frames.map(\.linkType) == [LinkType.ethernet, LinkType.raw])
    }

    @Test("Stale capture generations cannot append into a new spool")
    func staleEpochIgnored() async throws {
        let spool = LiveCaptureSpool(directoryName: "LiveCaptureSpoolTests")
        try await spool.reset(epoch: 2)
        try await spool.append([frame(byte: 1, timestamp: 1)], defaultLinkType: LinkType.ethernet, epoch: 1)
        try await spool.append([frame(byte: 2, timestamp: 2)], defaultLinkType: LinkType.ethernet, epoch: 2)

        let capture = try await spool.capture()
        #expect(capture.frames.map(\.bytes) == [[2, 2, 2]])
    }

    // MARK: Private

    private func frame(byte: UInt8, timestamp: TimeInterval, linkType: UInt32? = nil) -> CapturedFrame {
        CapturedFrame(
            bytes: [byte, byte, byte],
            timestamp: Date(timeIntervalSince1970: timestamp),
            originalLength: 7,
            linkType: linkType
        )
    }
}
