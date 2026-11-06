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
        coordinator.allFrames.ignored = [2, 7]
        let ignoredSnapshot = coordinator.frameExportContext(preselectedSessions: nil)
        #expect(ignoredSnapshot.ignoredFrameOrdinals == [2, 7])
        #expect(context.ignoredFrameOrdinals.isEmpty)
        // The showcase mixes Ethernet and raw IP interfaces, so PCAP is gated.
        #expect(context.pcapUnavailableReason != nil)

        coordinator.allFrames.marked = [1, 2]
        let selectedFrame = coordinator.frameExportContext(
            preselectedSessions: nil,
            preselectedFrameOrdinals: [3]
        )
        #expect(selectedFrame.scopes[selectedFrame.initialScopeIndex].scope == .frames([3]))
        #expect(selectedFrame.scopes[selectedFrame.initialScopeIndex].frameEstimate == 1)
        #expect(selectedFrame.baseName == "showcase – frame 3")
        #expect(coordinator.allFrames.marked == [1, 2])

        let preset = coordinator.frameExportContext(preselectedSessions: [session.id])
        #expect(preset.scopes[preset.initialScopeIndex].title == "Selected session")
        #expect(preset.baseName.hasSuffix("session"))

        coordinator.allFrames.frameExpressionDraft = "udp.port == 53"
        coordinator.allFrames.applyFrameExpression()
        let matching = coordinator.frameExportContext(
            preselectedSessions: nil,
            prefersAppliedFrameExpression: true
        )
        #expect(matching.scopes.contains { $0.title == "Frames matching the applied Frame Expression" })
        #expect(matching.scopes[matching.initialScopeIndex].title == "Frames matching the applied Frame Expression")
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

    @Test("Panel selection continues while its own source hold is active")
    func panelSelectionContinuesWithExportHold() async throws {
        let env = try await makeEnvironment()
        defer { env.teardown() }
        let coordinator = env.coordinator
        let source = env.directory.appendingPathComponent("conversation.pcap")
        let frames = ReplayCorpus.conversationCapturedFrames()
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: source)
        coordinator.openExternalCapture(source, copiesIntoLibrary: false)
        await coordinator.waitForExternalCaptureOpen()

        var parser = FrameExpressionParser()
        let expression = try parser.parse("udp.port == 53")
        let originProjectID = coordinator.activeRuntime.projectID
        let originGeneration = coordinator.startGeneration
        let output = env.directory.appendingPathComponent("matching-frames.pcapng")
        let choice = FrameExportPanel.Choice(url: output, scope: .frameExpression(expression), options: .init())
        coordinator.setSessionExporting(true)
        #expect(coordinator.isCaptureSourceHeld)
        #expect(!coordinator.canExportFrames)

        coordinator.continueFrameExportAfterPanel(
            choice, originProjectID: originProjectID, originGeneration: originGeneration
        )
        await coordinator.waitForFrameExport()

        #expect(coordinator.captureError == nil)
        #expect(try PcapngReader.read(contentsOf: output).frames.count == 4)
        #expect(!coordinator.isCaptureSourceHeld)
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

    @Test("A finalized sessionless live capture still allows whole-capture export")
    func stoppedSessionlessExport() async throws {
        let env = try await makeEnvironment()
        defer { env.teardown() }
        let coordinator = env.coordinator
        // An Ethertype in the local-experimental range, so the fold below is
        // empty because the frame folds into nothing — not because the test
        // handed the coordinator an empty fold. An SCTP frame stood here once
        // and no longer qualifies: SCTP folds into a session.
        let bytes: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xB5, 0xAA]
        let frame = CapturedFrame(
            bytes: bytes, timestamp: Date(timeIntervalSince1970: 1_800_000_000),
            originalLength: bytes.count, linkType: LinkType.ethernet
        )
        try await coordinator.liveCaptureSpool.reset(epoch: 70)
        _ = try await coordinator.liveCaptureSpool.append([frame], defaultLinkType: LinkType.ethernet, epoch: 70)
        coordinator.startGeneration = 71
        coordinator.publishLiveDetailed(
            InvestigationSnapshot(fold: SessionBuilder.buildDetailed(from: [frame], linkType: LinkType.ethernet)),
            expectedGeneration: 71,
            isCapturing: false
        )
        for _ in 0 ..< 50 {
            await Task.yield()
        }
        #expect(coordinator.sessions.isEmpty)
        #expect(coordinator.canExportFrames)

        let output = env.directory.appendingPathComponent("sessionless-out.pcapng")
        coordinator.exportFrames(to: output, scope: .wholeCapture, options: .init())
        await coordinator.waitForFrameExport()
        #expect(coordinator.captureError == nil)
        let loaded = try SavedCaptureStreamLoader(contentsOf: output).load()
        #expect(loaded.totalFrames == 1)
    }

    @Test("A finalized SCTP-only live capture folds one session and still exports")
    func stoppedSCTPOnlyExport() async throws {
        let env = try await makeEnvironment()
        defer { env.teardown() }
        let coordinator = env.coordinator
        let bytes = sctpFrame()
        let frame = CapturedFrame(
            bytes: bytes, timestamp: Date(timeIntervalSince1970: 1_800_000_000),
            originalLength: bytes.count, linkType: LinkType.ethernet
        )
        try await coordinator.liveCaptureSpool.reset(epoch: 70)
        _ = try await coordinator.liveCaptureSpool.append([frame], defaultLinkType: LinkType.ethernet, epoch: 70)
        coordinator.startGeneration = 71
        coordinator.publishLiveDetailed(
            InvestigationSnapshot(fold: SessionBuilder.buildDetailed(from: [frame], linkType: LinkType.ethernet)),
            expectedGeneration: 71,
            isCapturing: false
        )
        for _ in 0 ..< 50 {
            await Task.yield()
        }
        #expect(coordinator.sessions.count == 1)
        #expect(coordinator.sessions.first?.protocolStack.contains(.sctp) == true)
        #expect(coordinator.canExportFrames)

        let output = env.directory.appendingPathComponent("sctp-only-out.pcapng")
        coordinator.exportFrames(to: output, scope: .wholeCapture, options: .init())
        await coordinator.waitForFrameExport()
        #expect(coordinator.captureError == nil)
        let loaded = try SavedCaptureStreamLoader(contentsOf: output).load()
        #expect(loaded.totalFrames == 1)
    }

    @Test("An empty stopped spool does not unlock frame export")
    func emptyStoppedSpoolCannotExport() async throws {
        let env = try await makeEnvironment()
        defer { env.teardown() }
        let coordinator = env.coordinator
        try await coordinator.liveCaptureSpool.reset(epoch: 70)
        coordinator.startGeneration = 71
        coordinator.publishLiveDetailed(
            InvestigationSnapshot(fold: SessionBuilder.buildDetailed(from: [], linkType: LinkType.ethernet)),
            expectedGeneration: 71,
            isCapturing: false
        )
        for _ in 0 ..< 50 {
            await Task.yield()
        }
        #expect(!coordinator.canExportFrames)
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
        #expect(text?.contains("2 packet option list") == true)
        #expect(text?.contains("mid-record") == true)
        var inventoryBounded = clean
        inventoryBounded.sourceMetadataInventoryTruncated = true
        #expect(
            MainContentCoordinator.frameExportWarning(inventoryBounded)?
                .contains("section or interface metadata may not have been copied") == true
        )
        var sectionOptionsOmitted = clean
        sectionOptionsOmitted.omittedSectionOptionCount = 2
        #expect(
            MainContentCoordinator.frameExportWarning(sectionOptionsOmitted)?
                .contains("2 section option(s) were omitted") == true
        )
        let unknown = FrameExportSummary(
            scannedFrameCount: 10, writtenFrameCount: 2, writtenByteCount: 100,
            unrepresentableFrameCount: 0, omittedFrameOptionCount: 0, omittedInterfaceOptionCount: 0,
            completeness: .complete, unknownExpressionFrameCount: 3
        )
        #expect(MainContentCoordinator.frameExportWarning(unknown)?.contains("3 frame(s) were omitted") == true)
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

    private func sctpFrame() -> [UInt8] {
        let source = [UInt8]([192, 0, 2, 1])
        let destination = [UInt8]([192, 0, 2, 2])
        let sctp = SyntheticIPPacketEnvelope.word(5_000)
            + SyntheticIPPacketEnvelope.word(5_001)
            + SyntheticIPPacketEnvelope.doubleWord(0x12345678)
            + [0, 0, 0, 0, 1, 0, 0, 4]
        let ip = SyntheticIPPacketEnvelope.ipHeader(
            source: source, destination: destination,
            transportLength: sctp.count, protocolNumber: 132, ipv6: false
        )
        return SyntheticIPPacketEnvelope.ethernetHeader(inbound: false, ipv6: false) + ip + sctp
    }
}
