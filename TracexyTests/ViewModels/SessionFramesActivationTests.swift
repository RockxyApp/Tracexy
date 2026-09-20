import Foundation
import Testing
@testable import Tracexy

// MARK: - SessionFramesActivationTests

/// The Frames facet through the coordinator: saved and stopped-live sources,
/// selection/generation guards, cancellation, and row → exact frame navigation.
@MainActor
@Suite("Frames facet activation")
struct SessionFramesActivationTests {
    // MARK: Internal

    @Test("Saved capture lists the selected session's frames and a row loads that exact frame")
    func savedCaptureFrames() async throws {
        let env = try await makeEnvironment()
        defer { env.teardown() }
        let coordinator = env.coordinator
        let url = env.directory.appendingPathComponent("tcp.pcap")
        try Data(ReplayCorpus.classicPcapBytes(ReplayCorpus.tcpConnectionFrames())).write(to: url)
        coordinator.openExternalCapture(url, copiesIntoLibrary: false)
        await coordinator.waitForExternalCaptureOpen()

        let session = try #require(coordinator.sessions.first { $0.protocolStack.contains(.tcp) })
        #expect(!coordinator.hasSessionFrameSource)
        coordinator.select(session)
        #expect(coordinator.hasSessionFrameSource)
        #expect(coordinator.sessionFramesUnavailableReason == nil)

        coordinator.loadSelectedSessionFrames()
        #expect(coordinator.isLoadingSessionFrames)
        await coordinator.waitForSessionFrames()
        let result = try #require(coordinator.sessionFramesResult)
        #expect(result.sessionID == session.id)
        #expect(result.matchedFrameCount > 2)
        #expect(coordinator.sessionFramesError == nil)
        #expect(!coordinator.isLoadingSessionFrames)

        // A second call for the same session is a no-op; the result is retained.
        coordinator.loadSelectedSessionFrames()
        #expect(coordinator.sessionFramesTask == nil)

        // Row activation → the cited-frame path loads exactly that frame.
        let frame = try #require(result.frames.last)
        coordinator.inspectSessionFrame(frame)
        await coordinator.waitForCitedFrame()
        guard case let .loaded(evidence) = coordinator.citedFrame.state else {
            Issue.record("expected loaded frame, got \(coordinator.citedFrame.state)")
            return
        }
        #expect(evidence.provenance.ordinal == frame.provenance.ordinal)
        #expect(evidence.bytes.count == frame.provenance.capturedLength)
        #expect(coordinator.activeWorkspace.inspectorTab == .layers)
    }

    @Test("Changing the selection retires the previous list; clearing the capture clears it")
    func selectionAndClearGuards() async throws {
        let env = try await makeEnvironment()
        defer { env.teardown() }
        let coordinator = env.coordinator
        let url = env.directory.appendingPathComponent("conv.pcap")
        try Data(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())).write(to: url)
        coordinator.openExternalCapture(url, copiesIntoLibrary: false)
        await coordinator.waitForExternalCaptureOpen()
        let dns = try #require(coordinator.sessions.first { $0.protocolStack.contains(.dns) })
        let other = try #require(coordinator.sessions.first { !$0.protocolStack.contains(.dns) })

        coordinator.select(dns)
        coordinator.loadSelectedSessionFrames()
        await coordinator.waitForSessionFrames()
        #expect(coordinator.sessionFramesResult?.sessionID == dns.id)

        coordinator.select(other)
        coordinator.loadSelectedSessionFrames()
        await coordinator.waitForSessionFrames()
        #expect(coordinator.sessionFramesResult?.sessionID == other.id)

        coordinator.closeCapture()
        #expect(coordinator.sessionFramesResult == nil)
        #expect(!coordinator.hasSessionFrameSource)
    }

    @Test("Cancel leaves no result and no loading state")
    func cancellation() async throws {
        let env = try await makeEnvironment()
        defer { env.teardown() }
        let coordinator = env.coordinator
        let url = env.directory.appendingPathComponent("cancel.pcap")
        try Data(ReplayCorpus.classicPcapBytes(ReplayCorpus.tcpConnectionFrames())).write(to: url)
        coordinator.openExternalCapture(url, copiesIntoLibrary: false)
        await coordinator.waitForExternalCaptureOpen()
        let session = try #require(coordinator.sessions.first)
        coordinator.select(session)
        coordinator.loadSelectedSessionFrames()
        coordinator.cancelSessionFrames(clearResult: true)
        await coordinator.waitForSessionFrames()
        #expect(coordinator.sessionFramesResult == nil)
        #expect(!coordinator.isLoadingSessionFrames)
        #expect(coordinator.sessionFramesError == nil)
    }

    @Test("Stopped live capture lists frames from a spool copy and rows resolve against the spool")
    func stoppedLiveFrames() async throws {
        let env = try await makeEnvironment()
        defer { env.teardown() }
        let coordinator = env.coordinator
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let captureEpoch = 90
        let stoppedGeneration = 91

        try await coordinator.liveCaptureSpool.reset(epoch: captureEpoch)
        _ = try await coordinator.liveCaptureSpool.append(
            frames,
            defaultLinkType: LinkType.ethernet,
            epoch: captureEpoch
        )
        coordinator.startGeneration = stoppedGeneration
        coordinator.publishLiveDetailed(
            InvestigationSnapshot(fold: SessionBuilder.buildDetailed(from: frames, linkType: LinkType.ethernet)),
            expectedGeneration: stoppedGeneration,
            isCapturing: false
        )
        for _ in 0 ..< 50 {
            await Task.yield()
        }
        let session = try #require(coordinator.sessions.first { $0.protocolStack.contains(.tcp) })
        coordinator.select(session)
        #expect(coordinator.hasSessionFrameSource)
        #expect(coordinator.sessionFramesUnavailableReason == nil)

        coordinator.loadSelectedSessionFrames()
        await coordinator.waitForSessionFrames()
        let result = try #require(coordinator.sessionFramesResult)
        #expect(result.matchedFrameCount > 0)

        let frame = try #require(result.frames.first)
        coordinator.inspectSessionFrame(frame)
        await coordinator.waitForCitedFrame()
        guard case let .loaded(evidence) = coordinator.citedFrame.state else {
            Issue.record("expected loaded frame, got \(coordinator.citedFrame.state)")
            return
        }
        #expect(evidence.bytes.count == frame.provenance.capturedLength)
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
