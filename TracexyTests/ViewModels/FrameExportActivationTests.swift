import Foundation
import Testing
@testable import Tracexy

// MARK: - FrameExportActivationTests

/// Export Frames… through the coordinator: panel context, source hold, saved and
/// stopped-live sources, cancellation, and outcome reporting.
@MainActor
@Suite("Export Frames activation")
struct FrameExportActivationTests {
    // MARK: Internal

    @Test("Panel context offers whole capture, selected session and time range with PCAP gating")
    func panelContext() async throws {
        let env = try await makeEnvironment()
        defer { env.teardown() }
        let coordinator = env.coordinator
        #expect(!coordinator.canExportFrames)
        let url = env.directory.appendingPathComponent("showcase.pcapng")
        try Data(CaptureContainerFixtures.showcasePcapng()).write(to: url)
        coordinator.openExternalCapture(url, copiesIntoLibrary: false)
        await coordinator.waitForExternalCaptureOpen()
        #expect(coordinator.canExportFrames)
        let session = try #require(coordinator.sessions.first)
        coordinator.select(session)

        let context = coordinator.frameExportContext(preselectedSessions: nil)
        #expect(context.baseName == "showcase")
        #expect(context.sourceIsPcapng)
        #expect(context.scopes.first?.title == "Whole capture")
        #expect(context.scopes.first?.frameEstimate == coordinator.savedCaptureProperties?.totalFrames)
        #expect(context.scopes.contains { $0.title == "Selected session" })
        #expect(context.scopes.contains { $0.title == "Time range" })
        #expect(context.timeBounds != nil)
        // The showcase mixes Ethernet and raw IP interfaces, so PCAP is gated.
        #expect(context.pcapUnavailableReason != nil)

        let preset = coordinator.frameExportContext(preselectedSessions: [session.id])
        #expect(preset.scopes[preset.initialScopeIndex].title == "Selected session")
        #expect(preset.baseName.hasSuffix("session"))
    }

    @Test("Saved capture export writes the file, holds the source meanwhile, and reports the outcome")
    func savedExport() async throws {
        let env = try await makeEnvironment()
        defer { env.teardown() }
        let coordinator = env.coordinator
        let url = env.directory.appendingPathComponent("conv.pcap")
        try Data(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())).write(to: url)
        coordinator.openExternalCapture(url, copiesIntoLibrary: false)
        await coordinator.waitForExternalCaptureOpen()
        let dns = try #require(coordinator.sessions.first { $0.protocolStack.contains(.dns) })

        let output = env.directory.appendingPathComponent("dns-out.pcapng")
        coordinator.exportFrames(to: output, scope: .sessions([dns.id]), options: .init())
        #expect(coordinator.isExportingFrames)
        #expect(coordinator.isCaptureSourceHeld)
        #expect(!coordinator.canExportFrames)
        await coordinator.waitForFrameExport()
        #expect(!coordinator.isExportingFrames)
        #expect(!coordinator.isCaptureSourceHeld)
        #expect(coordinator.captureError == nil)
        let loaded = try SavedCaptureStreamLoader(contentsOf: output).load()
        #expect(loaded.sessions.map(\.id) == [dns.id])
        #expect(coordinator.canExportFrames)
    }

    @Test("A refused format surfaces the exporter's reason")
    func refusedFormat() async throws {
        let env = try await makeEnvironment()
        defer { env.teardown() }
        let coordinator = env.coordinator
        let url = env.directory.appendingPathComponent("mixed.pcapng")
        try Data(ReplayCorpus.pcapngMixedDLTBytes()).write(to: url)
        coordinator.openExternalCapture(url, copiesIntoLibrary: false)
        await coordinator.waitForExternalCaptureOpen()
        let output = env.directory.appendingPathComponent("mixed.pcap")
        coordinator.exportFrames(to: output, scope: .wholeCapture, options: .init(format: .pcap))
        await coordinator.waitForFrameExport()
        #expect(coordinator.captureError?.contains("link type") == true)
        #expect(!FileManager.default.fileExists(atPath: output.path))
        #expect(!coordinator.isCaptureSourceHeld)
    }

    @Test("Stopped live capture exports from the spool copy")
    func stoppedLiveExport() async throws {
        let env = try await makeEnvironment()
        defer { env.teardown() }
        let coordinator = env.coordinator
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        try await coordinator.liveCaptureSpool.reset(epoch: 70)
        _ = try await coordinator.liveCaptureSpool.append(frames, defaultLinkType: LinkType.ethernet, epoch: 70)
        coordinator.startGeneration = 71
        coordinator.publishLiveDetailed(
            InvestigationSnapshot(fold: SessionBuilder.buildDetailed(from: frames, linkType: LinkType.ethernet)),
            expectedGeneration: 71,
            isCapturing: false
        )
        for _ in 0 ..< 50 {
            await Task.yield()
        }
        #expect(coordinator.canExportFrames)
        let output = env.directory.appendingPathComponent("live-out.pcap")
        coordinator.exportFrames(to: output, scope: .wholeCapture, options: .init(format: .pcap))
        await coordinator.waitForFrameExport()
        #expect(coordinator.captureError == nil)
        let loaded = try SavedCaptureStreamLoader(contentsOf: output).load()
        #expect(loaded.totalFrames == frames.count)
    }

    @Test("Warning text summarises omissions")
    func warningText() {
        let clean = FrameExportSummary(
            scannedFrameCount: 10, writtenFrameCount: 10, writtenByteCount: 100,
            unrepresentableFrameCount: 0, omittedFrameOptionCount: 0, omittedInterfaceOptionCount: 0,
            completeness: .complete
        )
        #expect(MainContentCoordinator.frameExportWarning(clean) == nil)
        let lossy = FrameExportSummary(
            scannedFrameCount: 10, writtenFrameCount: 9, writtenByteCount: 100,
            unrepresentableFrameCount: 0, omittedFrameOptionCount: 2, omittedInterfaceOptionCount: 1,
            completeness: .incompleteTruncatedTail(.partialBody)
        )
        let text = try? #require(MainContentCoordinator.frameExportWarning(lossy))
        #expect(text?.contains("9 frames") == true)
        #expect(text?.contains("2 frame comment") == true)
        #expect(text?.contains("mid-record") == true)
    }

    // MARK: Private

    @MainActor
    private struct Environment {
        let coordinator: MainContentCoordinator
        let directory: URL
        let teardown: () -> Void
    }

    private func makeEnvironment(function: String = #function) async throws -> Environment {
        let isolation = ProjectIsolationEnvironment(name: function)
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let directory = isolation.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return Environment(coordinator: coordinator, directory: directory) {
            coordinator.clearRecentCaptures()
            isolation.tearDown()
        }
    }
}
