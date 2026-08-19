import Foundation
import Testing
@testable import Tracexy

@Suite("Disk-backed live capture spool")
struct LiveCaptureSpoolTests {
    // MARK: Internal

    @Test("Spool round-trips every appended frame across batches")
    func roundTrip() async throws {
        let directory = Self.uniqueDirectory()
        let spool = LiveCaptureSpool(directory: directory)
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
        let directory = Self.uniqueDirectory()
        let spool = LiveCaptureSpool(directory: directory)
        try await spool.reset(epoch: 2)
        try await spool.append([frame(byte: 1, timestamp: 1)], defaultLinkType: LinkType.ethernet, epoch: 1)
        try await spool.append([frame(byte: 2, timestamp: 2)], defaultLinkType: LinkType.ethernet, epoch: 2)

        let capture = try await spool.capture()
        #expect(capture.frames.map(\.bytes) == [[2, 2, 2]])
    }

    @Test("Normal teardown removes the spool's own current file")
    func teardownRemovesCurrentFile() async throws {
        let directory = Self.uniqueDirectory()
        // Confine the spool to a helper whose frame is destroyed on return, so the
        // actor's last reference is dropped and its deinit runs before we observe.
        try await Self.writeThenRelease(in: directory)
        try await Self.waitUntil { Self.spoolFiles(in: directory).isEmpty }
        #expect(Self.spoolFiles(in: directory).isEmpty)
    }

    @Test("Reset removes an inactive orphan left by a prior instance")
    func cleanupRemovesUnlockedOrphan() async throws {
        let directory = Self.uniqueDirectory()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let orphan = directory.appendingPathComponent("capture-orphan.pcapng")
        try Data([0x0A]).write(to: orphan)

        let spool = LiveCaptureSpool(directory: directory)
        try await spool.reset(epoch: 1)

        #expect(!FileManager.default.fileExists(atPath: orphan.path))
        withExtendedLifetime(spool) {}
    }

    @Test("Reset removes an inactive staging orphan left by a crash")
    func cleanupRemovesUnlockedStagingOrphan() async throws {
        let directory = Self.uniqueDirectory()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let orphan = directory.appendingPathComponent(".capture-orphan.pcapng.staging")
        try Data([0x0A]).write(to: orphan)

        let spool = LiveCaptureSpool(directory: directory)
        try await spool.reset(epoch: 1)

        #expect(!FileManager.default.fileExists(atPath: orphan.path))
        withExtendedLifetime(spool) {}
    }

    @Test("Reset preserves an actively locked candidate")
    func cleanupPreservesLockedCandidate() async throws {
        let directory = Self.uniqueDirectory()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let active = directory.appendingPathComponent("capture-active.pcapng")
        try Data([0x0A]).write(to: active)

        // Simulate a concurrent live spool holding an exclusive advisory lock.
        let descriptor = open(active.path, O_RDONLY)
        #expect(descriptor >= 0)
        #expect(flock(descriptor, LOCK_EX | LOCK_NB) == 0)
        defer { close(descriptor) }

        let spool = LiveCaptureSpool(directory: directory)
        try await spool.reset(epoch: 1)

        #expect(FileManager.default.fileExists(atPath: active.path))
        withExtendedLifetime(spool) {}
    }

    @Test("Reset never removes files outside the exact spool pattern")
    func cleanupPreservesUnrelatedFiles() async throws {
        let directory = Self.uniqueDirectory()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let unrelated = ["readme.txt", "session.pcapng", "capture-note.txt", "capturex.pcapng"]
        for name in unrelated {
            try Data([0x0A]).write(to: directory.appendingPathComponent(name))
        }

        let spool = LiveCaptureSpool(directory: directory)
        try await spool.reset(epoch: 1)

        for name in unrelated {
            #expect(FileManager.default.fileExists(atPath: directory.appendingPathComponent(name).path))
        }
        withExtendedLifetime(spool) {}
    }

    @Test("Reset never removes a directory named like a spool file")
    func cleanupPreservesMatchingDirectory() async throws {
        let directory = Self.uniqueDirectory()
        let matchingDirectory = directory.appendingPathComponent("capture-not-a-file.pcapng", isDirectory: true)
        try FileManager.default.createDirectory(at: matchingDirectory, withIntermediateDirectories: true)
        let child = matchingDirectory.appendingPathComponent("keep.txt")
        try Data([0x0A]).write(to: child)

        let spool = LiveCaptureSpool(directory: directory)
        try await spool.reset(epoch: 1)

        #expect(FileManager.default.fileExists(atPath: child.path))
        withExtendedLifetime(spool) {}
    }

    // MARK: Private

    private static func writeThenRelease(in directory: URL) async throws {
        let spool = LiveCaptureSpool(directory: directory)
        try await spool.reset(epoch: 1)
        let frame = CapturedFrame(
            bytes: [1, 1, 1],
            timestamp: Date(timeIntervalSince1970: 1),
            originalLength: 7,
            linkType: nil
        )
        try await spool.append([frame], defaultLinkType: LinkType.ethernet, epoch: 1)
        #expect(spoolFiles(in: directory).count == 1)
    }

    private static func uniqueDirectory() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("LiveCaptureSpoolTests-\(UUID().uuidString)", isDirectory: true)
    }

    private static func spoolFiles(in directory: URL) -> [String] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        return names.filter { $0.hasPrefix("capture-") && $0.hasSuffix(".pcapng") }
    }

    private static func waitUntil(_ condition: () -> Bool) async throws {
        for _ in 0 ..< 100 {
            if condition() {
                return
            }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
    }

    private func frame(byte: UInt8, timestamp: TimeInterval, linkType: UInt32? = nil) -> CapturedFrame {
        CapturedFrame(
            bytes: [byte, byte, byte],
            timestamp: Date(timeIntervalSince1970: timestamp),
            originalLength: 7,
            linkType: linkType
        )
    }
}
