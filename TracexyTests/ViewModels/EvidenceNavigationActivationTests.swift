import Foundation
import Testing
@testable import Tracexy

// MARK: - EvidenceNavigationActivationTests

/// The coordinator's evidence-navigation package must project the selected session's
/// connection/TLS evidence off-main behind request/workspace/session/generation
/// guards, resolve exactly one cited frame from a saved or live source with those
/// same guards, treat a nil locator as explicit unavailable, and retire both the
/// projection and the raw cited frame at every selection/capture/source boundary.
@MainActor
@Suite("Evidence navigation coordinator activation")
struct EvidenceNavigationActivationTests {
    // MARK: Internal

    @Test("Selecting a session publishes its projection; a new selection supersedes it")
    func projectionPublishesAndSupersedes() async throws {
        let environment = try await makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        try await openConnectionCapture(coordinator, in: environment.directory)

        let sessions = coordinator.sessions
        try #require(sessions.count >= 2)
        let first = sessions[0]
        coordinator.select(first)
        await coordinator.waitForEvidenceProjection()
        #expect(coordinator.evidenceProjection.selection?.sessionID == first.id)

        let second = try #require(sessions.first { $0.id != first.id })
        coordinator.select(second)
        await coordinator.waitForEvidenceProjection()
        #expect(coordinator.evidenceProjection.selection?.sessionID == second.id)
    }

    @Test("A late projection cannot publish across a session/workspace/generation guard")
    func projectionGuardsRejectStalePublication() async throws {
        let environment = try await makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        try await openConnectionCapture(coordinator, in: environment.directory)
        let selected = try #require(coordinator.sessions.first)
        coordinator.select(selected)
        await coordinator.waitForEvidenceProjection()
        let published = coordinator.evidenceProjection.selection

        let stale = SessionEvidenceSelection(
            sessionID: UUID(), connections: [], tls: nil,
            connectionCoverage: .empty, tlsCoverage: .empty
        )
        // Stale request id — rejected.
        coordinator.publishSelectedSessionEvidenceProjection(
            stale, sessionID: selected.id, workspaceID: coordinator.activeWorkspace.id,
            requestID: -1, expectedGeneration: coordinator.startGeneration
        )
        // Wrong workspace — rejected.
        coordinator.publishSelectedSessionEvidenceProjection(
            stale, sessionID: selected.id, workspaceID: UUID(),
            requestID: coordinator.evidenceProjection.requestID, expectedGeneration: coordinator.startGeneration
        )
        // Wrong generation — rejected.
        coordinator.publishSelectedSessionEvidenceProjection(
            stale, sessionID: selected.id, workspaceID: coordinator.activeWorkspace.id,
            requestID: coordinator.evidenceProjection.requestID, expectedGeneration: coordinator.startGeneration + 99
        )
        #expect(coordinator.evidenceProjection.selection == published)
    }

    @Test("A saved cited frame reads and decodes exactly the cited bytes")
    func savedCitedFrameSucceeds() async throws {
        let environment = try await makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        try await openConnectionCapture(coordinator, in: environment.directory)
        let (session, provenance) = try citedProvenance(coordinator)
        coordinator.select(session)

        coordinator.inspectCitedFrame(sessionID: session.id, provenance: provenance)
        await coordinator.waitForCitedFrame()

        guard case let .loaded(evidence) = coordinator.citedFrame.state else {
            Issue.record("expected a loaded cited frame, got \(coordinator.citedFrame.state)")
            return
        }
        #expect(evidence.sessionID == session.id)
        #expect(evidence.provenance == provenance)
        #expect(!evidence.bytes.isEmpty)
        #expect(evidence.bytes.count == provenance.capturedLength)
        #expect(!evidence.layers.isEmpty)
    }

    @Test("A forged source token fails the saved cited-frame read with neutral copy")
    func savedCitedFrameWrongTokenFails() async throws {
        let environment = try await makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        try await openConnectionCapture(coordinator, in: environment.directory)
        let (session, provenance) = try citedProvenance(coordinator)
        coordinator.select(session)

        let forged = Self.reprovenance(provenance, locator: SessionEvidenceLocator(
            sourceToken: UUID(), offset: provenance.locator?.offset ?? 0
        ))
        coordinator.inspectCitedFrame(sessionID: session.id, provenance: forged)
        await coordinator.waitForCitedFrame()

        guard case let .failed(message) = coordinator.citedFrame.state else {
            Issue.record("expected a failed cited frame, got \(coordinator.citedFrame.state)")
            return
        }
        // Neutral copy: no path or source token.
        #expect(!message.contains(environment.directory.path))
        #expect(!message.contains(session.id.uuidString))
    }

    @Test("A nil locator is an explicit unavailable state and triggers no read")
    func nilLocatorIsUnavailable() async throws {
        let environment = try await makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        try await openConnectionCapture(coordinator, in: environment.directory)
        let (session, provenance) = try citedProvenance(coordinator)
        coordinator.select(session)

        coordinator.inspectCitedFrame(
            sessionID: session.id,
            provenance: Self.reprovenance(provenance, locator: nil)
        )
        #expect(coordinator.citedFrame.state == .unavailable)
        #expect(coordinator.citedFrame.task == nil)
    }

    @Test("A current-epoch active-live spool read resolves exactly one frame")
    func liveCitedFrameSucceeds() async throws {
        let environment = try await makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let epoch = 200

        try await coordinator.liveCaptureSpool.reset(epoch: epoch)
        let appendResult = try await coordinator.liveCaptureSpool.append(
            frames, defaultLinkType: LinkType.ethernet, epoch: epoch
        )
        guard case let .appended(locators) = appendResult, let locator = locators.first else {
            Issue.record("spool append produced no locators")
            return
        }
        coordinator.startGeneration = epoch
        coordinator.isCapturing = true
        coordinator.sessions = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)
        let session = try #require(coordinator.sessions.first)
        coordinator.select(session)

        let provenance = Self.provenance(for: frames[0], locator: locator)
        coordinator.inspectCitedFrame(sessionID: session.id, provenance: provenance)
        await coordinator.waitForCitedFrame()

        guard case let .loaded(evidence) = coordinator.citedFrame.state else {
            Issue.record("expected a loaded live cited frame, got \(coordinator.citedFrame.state)")
            return
        }
        #expect(evidence.bytes == frames[0].bytes)
        #expect(!evidence.layers.isEmpty)
    }

    @Test("A stopped-live generation still resolves a citation from its finalized spool")
    func stoppedLiveCitedFrameSucceeds() async throws {
        let environment = try await makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let epoch = 300

        try await coordinator.liveCaptureSpool.reset(epoch: epoch)
        let appendResult = try await coordinator.liveCaptureSpool.append(
            frames, defaultLinkType: LinkType.ethernet, epoch: epoch
        )
        guard case let .appended(locators) = appendResult, let locator = locators.first else {
            Issue.record("spool append produced no locators")
            return
        }
        // Stop advances the coordinator generation, but deliberately preserves
        // the just-finalized spool and its source token.
        coordinator.startGeneration = epoch + 1
        coordinator.sessions = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)
        let session = try #require(coordinator.sessions.first)
        coordinator.select(session)

        coordinator.inspectCitedFrame(
            sessionID: session.id,
            provenance: Self.provenance(for: frames[0], locator: locator)
        )
        await coordinator.waitForCitedFrame()

        guard case let .loaded(evidence) = coordinator.citedFrame.state else {
            Issue.record("expected a loaded stopped-live cited frame, got \(coordinator.citedFrame.state)")
            return
        }
        #expect(evidence.bytes == frames[0].bytes)
    }

    @Test("A locator from a superseded live spool fails without reading another frame")
    func liveCitedFrameStaleSourceFails() async throws {
        let environment = try await makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let oldEpoch = 400

        try await coordinator.liveCaptureSpool.reset(epoch: oldEpoch)
        let appendResult = try await coordinator.liveCaptureSpool.append(
            frames, defaultLinkType: LinkType.ethernet, epoch: oldEpoch
        )
        guard case let .appended(locators) = appendResult, let staleLocator = locators.first else {
            Issue.record("spool append produced no locators")
            return
        }

        let currentEpoch = oldEpoch + 1
        try await coordinator.liveCaptureSpool.reset(epoch: currentEpoch)
        coordinator.startGeneration = currentEpoch
        coordinator.sessions = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)
        let session = try #require(coordinator.sessions.first)
        coordinator.select(session)

        coordinator.inspectCitedFrame(
            sessionID: session.id,
            provenance: Self.provenance(for: frames[0], locator: staleLocator)
        )
        await coordinator.waitForCitedFrame()

        guard case .failed = coordinator.citedFrame.state else {
            Issue.record("expected a failed stale-source cited frame, got \(coordinator.citedFrame.state)")
            return
        }
    }

    @Test("Selection and capture boundaries retire the cited frame and projection")
    func boundariesRetireEvidenceNavigation() async throws {
        let environment = try await makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        try await openConnectionCapture(coordinator, in: environment.directory)
        let (session, provenance) = try citedProvenance(coordinator)
        coordinator.select(session)
        coordinator.inspectCitedFrame(sessionID: session.id, provenance: provenance)
        await coordinator.waitForCitedFrame()
        await coordinator.waitForEvidenceProjection()
        #expect(coordinator.evidenceProjection.selection != nil)
        guard case .loaded = coordinator.citedFrame.state else {
            Issue.record("expected a loaded cited frame before the boundary")
            return
        }

        // A different selection retires the previously cited frame.
        let other = try #require(coordinator.sessions.first { $0.id != session.id })
        coordinator.select(other)
        #expect(coordinator.citedFrame.state == .idle)

        // A capture boundary retires both pipelines.
        coordinator.clearSessions()
        #expect(coordinator.citedFrame.state == .idle)
        #expect(coordinator.evidenceProjection.selection == nil)
    }

    // MARK: Private

    private struct Environment {
        let coordinator: MainContentCoordinator
        let directory: URL
        let teardown: () -> Void
    }

    private static func provenance(
        for frame: CapturedFrame,
        locator: SessionEvidenceLocator
    )
        -> SessionFrameProvenance
    {
        SessionFrameProvenance(
            ordinal: FrameOrdinal(0),
            timestamp: frame.timestamp,
            capturedLength: frame.bytes.count,
            originalLength: frame.originalLength,
            linkType: LinkType.ethernet,
            locator: locator
        )
    }

    private static func reprovenance(
        _ provenance: SessionFrameProvenance,
        locator: SessionEvidenceLocator?
    )
        -> SessionFrameProvenance
    {
        SessionFrameProvenance(
            ordinal: provenance.ordinal,
            timestamp: provenance.timestamp,
            capturedLength: provenance.capturedLength,
            originalLength: provenance.originalLength,
            linkType: provenance.linkType,
            locator: locator
        )
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

    private func openConnectionCapture(
        _ coordinator: MainContentCoordinator,
        in directory: URL
    )
        async throws
    {
        let url = directory.appendingPathComponent("evidence-nav.pcap")
        try PcapWriter.write(
            linkType: LinkType.ethernet,
            frames: ReplayCorpus.tcpConnectionCapturedFrames(),
            to: url
        )
        let byteCount = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        coordinator.openSavedCapture(SavedCapture(url: url, name: "evidence-nav", date: Date(), byteCount: byteCount))
        await coordinator.waitForSavedCaptureOpen()
    }

    /// A selected session plus a real saved cited-frame provenance for it.
    private func citedProvenance(
        _ coordinator: MainContentCoordinator
    )
        throws -> (SessionSummary, SessionFrameProvenance)
    {
        let summary = try #require(coordinator.connectionSnapshot.summaries.first)
        let sessionID = SessionBuilder.sessionID(for: summary.tuple)
        let session = try #require(coordinator.sessions.first { $0.id == sessionID })
        #expect(summary.firstProvenance.locator != nil)
        return (session, summary.firstProvenance)
    }
}
