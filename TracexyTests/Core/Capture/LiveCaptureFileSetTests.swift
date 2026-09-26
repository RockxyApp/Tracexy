import Foundation
import Testing
@testable import Tracexy

/// With a file set on, the live spool closes its file into the set at a
/// time or size limit, keeps evidence in closed files readable, deletes past a keep
/// limit only when asked (evidence then fails closed as rotated out), completes the
/// set at the end, and Save Capture still gets every kept frame.
@Suite("Live capture file set")
struct LiveCaptureFileSetTests {
    // MARK: Internal

    @Test("A duration limit closes files into a navigable set; closed evidence stays readable")
    func durationRotationKeepsEvidence() async throws {
        let (spool, setDirectory) = try await Self.spool(duration: 10)
        var locators: [SessionEvidenceLocator] = []
        for second in [0.0, 4, 9, 10, 15, 21] {
            locators += try await Self.appended(spool.append(
                [Self.frame(UInt8(second), at: second)], defaultLinkType: LinkType.ethernet, epoch: 1
            ))
        }
        // [0, 4, 9] | [10, 15] | [21] open.
        #expect(Set(locators.map(\.sourceToken)).count == 3)
        #expect(Self.members(setDirectory).count == 2)
        for (locator, second) in zip(locators, [0, 4, 9, 10, 15, 21]) {
            let bytes = try await spool.readCurrentSource(locator, capturedLength: 3)
            #expect(bytes == [UInt8(second), UInt8(second), UInt8(second)])
        }

        let summary = try #require(try await spool.finishFileSet())
        #expect(summary.files.count == 3)
        let set = try #require(CaptureFileSet(member: summary.files[0]))
        #expect(set.count == 3)
        let counts = try summary.files.map { try SavedCaptureStreamLoader(contentsOf: $0).load().totalFrames }
        #expect(counts == [3, 2, 1])

        let whole = setDirectory.deletingLastPathComponent().appendingPathComponent("whole.pcapng")
        try await spool.copyWholeCapture(to: whole)
        #expect(try SavedCaptureStreamLoader(contentsOf: whole).load().totalFrames == 6)
    }

    @Test("Keeping only the newest files deletes older ones and their evidence fails as rotated out")
    func keepLimitRotatesOut() async throws {
        let (spool, setDirectory) = try await Self.spool(duration: 10, keep: 2)
        var locators: [SessionEvidenceLocator] = []
        for second in [0.0, 10, 20, 30] {
            locators += try await Self.appended(spool.append(
                [Self.frame(1, at: second)], defaultLinkType: LinkType.ethernet, epoch: 1
            ))
        }
        // Kept: one closed file plus the open one.
        #expect(Self.members(setDirectory).count == 1)
        await #expect(throws: LiveCaptureSpool.Failure.self) {
            _ = try await spool.readCurrentSource(locators[0], capturedLength: 3)
        }
        do {
            _ = try await spool.readCurrentSource(locators[0], capturedLength: 3)
        } catch let failure as LiveCaptureSpool.Failure {
            #expect(failure.errorDescription?.contains("file-set limit") == true)
        }
        #expect(try await spool.readCurrentSource(locators[2], capturedLength: 3) == [1, 1, 1])
        let summary = try #require(try await spool.finishFileSet())
        #expect(summary.removedFileCount == 2)
        #expect(summary.files.count == 2)
    }

    @Test("A size limit rotates, and no file set means nothing is written beside the spool")
    func sizeRotationAndOff() async throws {
        let (spool, setDirectory) = try await Self.spool(bytes: 200)
        for index in 0 ..< 6 {
            try await spool.append(
                [Self.frame(UInt8(index), at: Double(index), size: 60)], defaultLinkType: LinkType.ethernet, epoch: 1
            )
        }
        #expect(Self.members(setDirectory).count >= 1)

        let plainDirectory = Self.uniqueDirectory()
        let plain = LiveCaptureSpool(directory: plainDirectory)
        try await plain.reset(epoch: 1, fileSet: nil)
        try await plain.append([Self.frame(1, at: 0)], defaultLinkType: LinkType.ethernet, epoch: 1)
        #expect(try await plain.finishFileSet() == nil)
        #expect(await plain.hasClosedFileSetFiles() == false)
    }

    @Test("Settings resolve to a policy in the Project's Captures folder")
    func settingsResolve() throws {
        let suite = "file-set-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let captures = URL(fileURLWithPath: "/tmp/Captures")
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        #expect(CaptureFileSetSettings.policy(defaults: defaults, capturesDirectory: captures, startedAt: start) == nil)
        defaults.set(100, forKey: SettingsKeys.fileSetMegabytes)
        defaults.set(20, forKey: SettingsKeys.fileSetKeep)
        let policy = try #require(CaptureFileSetSettings.policy(
            defaults: defaults, capturesDirectory: captures, startedAt: start, timeZone: TimeZone.gmt
        ))
        #expect(policy.maxFileBytes == 100_000_000)
        #expect(policy.maxFileDuration == nil)
        #expect(policy.keepFiles == 20)
        #expect(policy.directory.path == "/tmp/Captures/File Sets/Capture 2027-01-15 08.00.00")
    }

    // MARK: Private

    private static func spool(
        duration: TimeInterval? = nil,
        bytes: UInt64? = nil,
        keep: Int = 0
    )
        async throws -> (LiveCaptureSpool, URL)
    {
        let root = uniqueDirectory()
        let setDirectory = root.appendingPathComponent("set", isDirectory: true)
        let spool = LiveCaptureSpool(directory: root.appendingPathComponent("spool", isDirectory: true))
        try await spool.reset(epoch: 1, fileSet: .init(
            maxFileBytes: bytes, maxFileDuration: duration, keepFiles: keep, directory: setDirectory
        ))
        return (spool, setDirectory)
    }

    private static func members(_ directory: URL) -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []).filter {
            CaptureFileSet.isMemberName(URL(fileURLWithPath: $0))
        }
    }

    private static func uniqueDirectory() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(
            "FileSetTests-\(UUID().uuidString)",
            isDirectory: true
        )
    }

    private static func frame(_ byte: UInt8, at seconds: TimeInterval, size: Int = 3) -> CapturedFrame {
        CapturedFrame(
            bytes: [UInt8](repeating: byte, count: size),
            timestamp: Date(timeIntervalSince1970: 1_800_000_000 + seconds),
            originalLength: size
        )
    }

    private static func appended(_ result: LiveCaptureSpool.AppendResult) throws -> [SessionEvidenceLocator] {
        guard case let .appended(locators) = result else {
            throw CancellationError()
        }
        return locators
    }
}
