import Foundation
import Testing
@testable import Tracexy

@MainActor
@Suite("Follow Stream coordinator activation")
struct FollowStreamActivationTests {
    // MARK: Internal

    @Test("Saved capture follows the selected TCP tuple from its identity-checked source")
    func savedCaptureActivation() async throws {
        let environment = try await makeEnvironment()
        defer { environment.teardown() }
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let capture = try writeCapture(named: "saved-follow", frames: frames, in: environment.directory)

        let coordinator = environment.coordinator
        coordinator.openSavedCapture(capture)
        await coordinator.waitForSavedCaptureOpen()
        let tuple = try #require(coordinator.connectionSnapshot.summaries.first?.tuple)
        let session = try #require(
            coordinator.sessions.first { $0.id == SessionBuilder.sessionID(for: tuple) }
        )
        coordinator.select(session)

        #expect(coordinator.followStreamUnavailableReason == nil)
        coordinator.followSelectedTCPStream()
        await coordinator.waitForFollowStream()

        let result = try #require(coordinator.followStreamResult)
        #expect(result.tuple == tuple)
        #expect(result.matchedFrameCount > 0)
        #expect(result.aToB.retainedByteCount + result.bToA.retainedByteCount > 0)
        #expect(coordinator.followStreamFraction == 1)
        #expect(coordinator.followStreamError == nil)
        #expect(!coordinator.isLoadingFollowStream)
    }

    @Test("Stopped live capture copies a finalized spool before following")
    func stoppedLiveActivation() async throws {
        let environment = try await makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let captureEpoch = 80
        let stoppedGeneration = 81

        try await coordinator.liveCaptureSpool.reset(epoch: captureEpoch)
        _ = try await coordinator.liveCaptureSpool.append(
            frames,
            defaultLinkType: LinkType.ethernet,
            epoch: captureEpoch
        )
        coordinator.startGeneration = stoppedGeneration
        coordinator.publishLiveDetailed(
            InvestigationSnapshot(
                fold: SessionBuilder.buildDetailed(from: frames, linkType: LinkType.ethernet)
            ),
            expectedGeneration: stoppedGeneration,
            isCapturing: false
        )
        await drainMainActor()

        let tuple = try #require(coordinator.connectionSnapshot.summaries.first?.tuple)
        let session = try #require(
            coordinator.sessions.first { $0.id == SessionBuilder.sessionID(for: tuple) }
        )
        coordinator.select(session)
        #expect(coordinator.stoppedCaptureReadyGeneration == stoppedGeneration)
        #expect(coordinator.followStreamUnavailableReason == nil)

        coordinator.followSelectedTCPStream()
        await coordinator.waitForFollowStream()

        let result = try #require(coordinator.followStreamResult)
        #expect(result.tuple == tuple)
        #expect(result.matchedFrameCount > 0)
        #expect(result.aToB.retainedByteCount + result.bToA.retainedByteCount > 0)
        #expect(coordinator.followStreamError == nil)
    }

    @Test("Active capture rejects Follow Stream without scanning the growing spool")
    func activeCaptureIsUnavailable() async throws {
        let environment = try await makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let capture = try writeCapture(named: "active-refusal", frames: frames, in: environment.directory)
        coordinator.openSavedCapture(capture)
        await coordinator.waitForSavedCaptureOpen()
        let tuple = try #require(coordinator.connectionSnapshot.summaries.first?.tuple)
        try coordinator.select(#require(
            coordinator.sessions.first { $0.id == SessionBuilder.sessionID(for: tuple) }
        ))
        coordinator.isCapturing = true

        #expect(coordinator.followStreamUnavailableReason?.contains("Stop the live capture") == true)
        coordinator.followSelectedTCPStream()

        #expect(coordinator.followStreamTask == nil)
        #expect(coordinator.followStreamResult == nil)
        #expect(coordinator.followStreamError?.contains("Stop the live capture") == true)
    }

    @Test("Selection change retires previously loaded raw stream bytes")
    func selectionChangeClearsResult() async throws {
        let environment = try await makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let capture = try writeCapture(named: "selection-retirement", frames: frames, in: environment.directory)
        coordinator.openSavedCapture(capture)
        await coordinator.waitForSavedCaptureOpen()
        let tuple = try #require(coordinator.connectionSnapshot.summaries.first?.tuple)
        let selected = try #require(
            coordinator.sessions.first { $0.id == SessionBuilder.sessionID(for: tuple) }
        )
        coordinator.select(selected)
        coordinator.followSelectedTCPStream()
        await coordinator.waitForFollowStream()
        #expect(coordinator.followStreamResult != nil)

        let other = try #require(coordinator.sessions.first { $0.id != selected.id })
        coordinator.select(other)

        #expect(coordinator.followStreamResult == nil)
        #expect(coordinator.followStreamProgress == nil)
        #expect(coordinator.followStreamError == nil)
        #expect(!coordinator.isLoadingFollowStream)
    }

    // MARK: Private

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
            isolation.tearDown()
        }
    }

    private func writeCapture(
        named name: String,
        frames: [CapturedFrame],
        in directory: URL
    )
        throws -> SavedCapture
    {
        let url = directory.appendingPathComponent("\(name).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        let byteCount = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        return SavedCapture(url: url, name: name, date: Date(), byteCount: byteCount)
    }

    private func drainMainActor() async {
        for _ in 0 ..< 50 {
            await Task.yield()
        }
    }
}
