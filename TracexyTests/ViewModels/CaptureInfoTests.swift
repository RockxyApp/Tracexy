import CryptoKit
import Foundation
import Testing
@testable import Tracexy

// MARK: - CaptureInfoTests

/// Get Info: the snapshot the window renders, the plain-text report, on-demand
/// digests (with cancel and reset), and the per-session capture-interface fold.
@MainActor
@Suite("Get Info window model")
struct CaptureInfoTests {
    // MARK: Internal

    @Test("Snapshot reflects the open saved capture and its container facts")
    func snapshotForSavedCapture() async throws {
        let env = try await makeEnvironment()
        defer { env.tearDown() }
        #expect(env.coordinator.captureInfoSnapshot == nil)
        #expect(!env.coordinator.canShowCaptureInfo)

        let source = try env.showcase("showcase")
        env.coordinator.openExternalCapture(source, copiesIntoLibrary: false)
        await env.coordinator.waitForExternalCaptureOpen()
        let snapshot = try #require(env.coordinator.captureInfoSnapshot)
        #expect(env.coordinator.canShowCaptureInfo)
        #expect(snapshot.title == "showcase")
        #expect(snapshot.fileName == "showcase.pcapng")
        #expect(!snapshot.isLive)
        let properties = try #require(snapshot.properties)
        #expect(properties.interfaceCount == 2)
        #expect(snapshot.sessionCount == env.coordinator.sessions.count)
        #expect(snapshot.hashState == .idle)
        #expect(env.coordinator.captureInfoIdentityToken.hasPrefix("saved:"))

        let report = CaptureInfoReport.text(for: snapshot)
        #expect(report.contains("Format: PCAPNG"))
        #expect(report.contains("Hardware: Mac16,10"))
        #expect(report.contains("Interface 0: en0"))
        #expect(report.contains("Filter: tcp or udp"))
        #expect(report.contains("Decryption secrets blocks: TLS key log"))
        #expect(!report.contains("CLIENT_RANDOM"))
    }

    @Test("Sessions know which interface their frames came from")
    func sessionsCarryInterfaceIDs() async throws {
        let env = try await makeEnvironment()
        defer { env.tearDown() }
        let source = try env.showcase("interfaces")
        env.coordinator.openExternalCapture(source, copiesIntoLibrary: false)
        await env.coordinator.waitForExternalCaptureOpen()
        let sessions = env.coordinator.sessions
        #expect(!sessions.isEmpty)
        #expect(sessions.allSatisfy { !$0.captureInterfaceIDs.isEmpty })
        #expect(sessions.contains { $0.captureInterfaceIDs == [1] })
        #expect(sessions.contains { $0.captureInterfaceIDs == [0] })
        let overflowed = sessions.contains { $0.captureInterfaceOverflow }
        #expect(!overflowed)
    }

    @Test("Digests are computed on demand, match an independent hash, and reset with the capture")
    func digestsOnDemand() async throws {
        let env = try await makeEnvironment()
        defer { env.tearDown() }
        let source = try env.showcase("hashed")
        env.coordinator.openExternalCapture(source, copiesIntoLibrary: false)
        await env.coordinator.waitForExternalCaptureOpen()

        env.coordinator.beginCaptureHash()
        #expect(env.coordinator.captureHashState.isComputing)
        await env.coordinator.captureHashTask?.value
        guard case let .done(digests) = env.coordinator.captureHashState else {
            Issue.record("expected digests, got \(env.coordinator.captureHashState)")
            return
        }
        let expected = try SHA256.hash(data: Data(contentsOf: source)).map { String(format: "%02x", $0) }.joined()
        #expect(digests.sha256 == expected)
        #expect(digests.sha1.count == 40)
        let hashedSnapshot = try #require(env.coordinator.captureInfoSnapshot)
        let hashedReport = CaptureInfoReport.text(for: hashedSnapshot)
        #expect(hashedReport.contains("SHA-256: \(expected)"))

        if WiresharkOracle.isAvailable {
            let report = try WiresharkOracle.capinfos(source)
            #expect(report["SHA256"] == digests.sha256)
            #expect(report["SHA1"] == digests.sha1)
        }

        env.coordinator.closeCapture()
        #expect(env.coordinator.captureHashState == .idle)
        #expect(env.coordinator.captureInfoSnapshot == nil)
    }

    @Test("Cancelling a digest computation returns to idle")
    func digestCancel() async throws {
        let env = try await makeEnvironment()
        defer { env.tearDown() }
        let source = try env.showcase("cancel")
        env.coordinator.openExternalCapture(source, copiesIntoLibrary: false)
        await env.coordinator.waitForExternalCaptureOpen()
        env.coordinator.beginCaptureHash()
        env.coordinator.cancelCaptureHash()
        #expect(env.coordinator.captureHashState == .idle)
        await env.coordinator.captureHashTask?.value
        #expect(env.coordinator.captureHashState == .idle)
    }

    @Test("A changed file refuses digests instead of hashing the wrong bytes")
    func digestRefusesChangedFile() async throws {
        let env = try await makeEnvironment()
        defer { env.tearDown() }
        let source = try env.showcase("changed")
        env.coordinator.openExternalCapture(source, copiesIntoLibrary: false)
        await env.coordinator.waitForExternalCaptureOpen()
        try Data(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())).write(to: source)
        try FileManager.default.setAttributes(
            [.modificationDate: Date(timeIntervalSinceNow: 5)],
            ofItemAtPath: source.path
        )
        env.coordinator.beginCaptureHash()
        await env.coordinator.captureHashTask?.value
        guard case .failed = env.coordinator.captureHashState else {
            Issue.record("expected failure, got \(env.coordinator.captureHashState)")
            return
        }
    }

    @Test("Formatting helpers mirror capinfos wording")
    func formatting() {
        #expect(CaptureInfoFormatting.elapsed(90_061) == "1 day(s) 01:01:01")
        #expect(CaptureInfoFormatting.elapsed(1.5) == "00:00:01.500")
        #expect(CaptureInfoFormatting.snapLength(0) == "unlimited")
        #expect(CaptureInfoFormatting.resolution(1_000_000_000) == "nanoseconds")
        #expect(CaptureInfoFormatting.linkType(1) == "Ethernet (1)")
        #expect(CaptureInfoFormatting.linkType(999) == "Link type 999")
    }

    // MARK: Private

    @MainActor
    private struct Environment {
        let coordinator: MainContentCoordinator
        let root: URL
        let isolation: ProjectIsolationEnvironment

        func showcase(_ name: String) throws -> URL {
            let url = root.appendingPathComponent("\(name).pcapng")
            try Data(CaptureContainerFixtures.showcasePcapng()).write(to: url)
            return url
        }

        func tearDown() {
            coordinator.clearRecentCaptures()
            isolation.tearDown()
            try? FileManager.default.removeItem(at: root)
        }
    }

    private func makeEnvironment(function: String = #function) async throws -> Environment {
        let isolation = ProjectIsolationEnvironment(name: function)
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-info-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return Environment(coordinator: coordinator, root: root, isolation: isolation)
    }
}
