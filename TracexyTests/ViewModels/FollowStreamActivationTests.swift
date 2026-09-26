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
        coordinator.followSelectedStream()
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

        coordinator.followSelectedStream()
        await coordinator.waitForFollowStream()

        let result = try #require(coordinator.followStreamResult)
        #expect(result.tuple == tuple)
        #expect(result.matchedFrameCount > 0)
        #expect(result.aToB.retainedByteCount + result.bToA.retainedByteCount > 0)
        #expect(coordinator.followStreamError == nil)
    }

    @Test("A UDP session is followed datagram by datagram with navigable frames")
    func savedUDPConversationActivation() async throws {
        let environment = try await makeEnvironment()
        defer { environment.teardown() }
        let frames = [
            PacketBuilder.dnsQueryFrame(name: "www.example.test", src: "10.0.0.5", dst: "192.0.2.53"),
            PacketBuilder.dnsResponseFrame(
                name: "www.example.test", answers: ["192.0.2.80"], src: "192.0.2.53", dst: "10.0.0.5"
            ),
        ].enumerated().map { index, bytes in
            CapturedFrame(
                bytes: bytes,
                timestamp: Date(timeIntervalSince1970: 1_800_000_000 + Double(index) * 0.02),
                originalLength: bytes.count,
                capturedLength: bytes.count,
                linkType: LinkType.ethernet
            )
        }
        let capture = try writeCapture(named: "saved-udp-follow", frames: frames, in: environment.directory)
        let coordinator = environment.coordinator
        coordinator.openSavedCapture(capture)
        await coordinator.waitForSavedCaptureOpen()
        let session = try #require(coordinator.sessions.first { $0.protocolStack.contains(.udp) })
        coordinator.select(session)

        #expect(coordinator.followsSelectedSessionAsDatagrams)
        #expect(coordinator.followStreamUnavailableReason == nil)
        coordinator.followSelectedStream()
        await coordinator.waitForFollowStream()

        let result = try #require(coordinator.followDatagramResult)
        #expect(coordinator.followStreamResult == nil)
        #expect(result.messages.count == 2)
        #expect(result.messages[1].dns?.pairedMessageIndex == 0)
        #expect(result.messages[1].dns?.answerRecords == ["A 192.0.2.80"])
        let provenance = result.messages[1].provenance
        #expect(provenance.locator != nil)

        coordinator.inspectFollowedFrame(provenance)
        await coordinator.waitForCitedFrame()
        guard case let .loaded(evidence) = coordinator.citedFrame.state else {
            Issue.record("the cited datagram did not load")
            return
        }
        #expect(evidence.provenance.ordinal == provenance.ordinal)
        #expect(evidence.bytes.count == frames[1].bytes.count)
        #expect(coordinator.activeWorkspace.inspectorTab == .layers)
    }

    @Test("A TCP follow from a saved file makes each run's first frame navigable")
    func savedStreamRunsAreNavigable() async throws {
        let environment = try await makeEnvironment()
        defer { environment.teardown() }
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let capture = try writeCapture(named: "saved-follow-navigation", frames: frames, in: environment.directory)
        let coordinator = environment.coordinator
        coordinator.openSavedCapture(capture)
        await coordinator.waitForSavedCaptureOpen()
        let tuple = try #require(coordinator.connectionSnapshot.summaries.first?.tuple)
        try coordinator.select(#require(
            coordinator.sessions.first { $0.id == SessionBuilder.sessionID(for: tuple) }
        ))
        coordinator.followSelectedStream()
        await coordinator.waitForFollowStream()

        let result = try #require(coordinator.followStreamResult)
        let run = try #require((result.aToB.runs + result.bToA.runs).first)
        let provenance = try #require(run.firstProvenance)
        #expect(provenance.ordinal.rawValue == UInt64(run.firstCaptureOrdinal))
        coordinator.inspectFollowedFrame(provenance)
        await coordinator.waitForCitedFrame()
        guard case let .loaded(evidence) = coordinator.citedFrame.state else {
            Issue.record("the run's first frame did not load")
            return
        }
        #expect(evidence.bytes == frames[run.firstCaptureOrdinal - 1].bytes)
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
        coordinator.followSelectedStream()

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
        coordinator.followSelectedStream()
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
