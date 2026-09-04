import Foundation
import Testing
@testable import Tracexy

// MARK: - ProjectHistoryResumeTests

/// A Project change cancels the outgoing Project's in-flight History reads, so its
/// bucket parks `.loading` with no reader behind it. Nothing on the History surface
/// would ever start one again — its `task` reads only from `.idle`, and it
/// auto-selects a capture only when nothing is selected — so a restored Project
/// would sit on a spinner forever.
///
/// These tests interrupt exactly the state a cancelled *first-page* read leaves
/// behind, round-trip the Project, and assert the surface reaches real data. They
/// never sleep for a race: every read is awaited through
/// ``MainContentCoordinator/waitForHistory()``, and every Project change through
/// ``MainContentCoordinator/waitForProjectTransition()``. Every store, spool and
/// preferences suite lives inside one throwaway environment.
@MainActor
@Suite("Project History read resumption")
struct ProjectHistoryResumeTests {
    // MARK: Internal

    @Test("A failed resumed capture read does not strand its cancelled session reader")
    func failedCaptureResumeSettlesSessionPaneAndRetries() async throws {
        let environment = ProjectIsolationEnvironment(name: "history-resume-failure")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let projectA = coordinator.projectStore.activeProjectID
        let url = environment.root.appendingPathComponent("ReadFailure.sqlite")
        let store = try SessionStore(configuration: .init(location: .file(url)))
        coordinator.sessionStore = store
        let capture = Self.capture(startedAt: 1_000, endedAt: 1_100)
        try await store.replaceCapture(capture, sessions: [Self.session(host: "a.example")])
        coordinator.selectedHistoryCaptureID = capture.captureID
        Self.interruptFirstCapturePage(of: coordinator)
        Self.interruptFirstSessionPage(of: coordinator)
        // Reversible schema fault in this test's own database, never production.
        let fault = try SQLiteDatabase(path: url.path, readOnly: false)
        defer { fault.close() }
        try fault.execute("ALTER TABLE captures RENAME TO temporarily_unreadable_captures;")
        _ = try #require(await Self.created(coordinator, named: "Bravo"))
        #expect(await Self.switched(coordinator, to: projectA))
        await coordinator.waitForHistory()
        if case .failed = coordinator.historyAvailability {} else {
            Issue.record("The temporary schema fault must fail the capture read")
        }
        #expect(coordinator.historySessionTask == nil)
        #expect(coordinator.historySessionsAvailability != .loading)
        try fault.execute("ALTER TABLE temporarily_unreadable_captures RENAME TO captures;")
        coordinator.retryHistory()
        await coordinator.waitForHistory()
        #expect(coordinator.historyAvailability == .loaded)
        #expect(coordinator.historySessionsAvailability == .loaded)
        #expect(coordinator.historySessions.map(\.host) == ["a.example"])
    }

    @Test("An interrupted first capture page is re-read when its Project comes back")
    func interruptedCapturePageResumesOnRestore() async throws {
        let environment = ProjectIsolationEnvironment(name: "history-resume-captures")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        let store = try #require(coordinator.sessionStore)
        let capture = Self.capture(startedAt: 1_000, endedAt: 1_100)
        try await store.replaceCapture(capture, sessions: [Self.session(host: "a.example")])
        Self.interruptFirstCapturePage(of: coordinator)

        let projectB = try #require(await Self.created(coordinator, named: "Bravo"))
        // B owns its own store and its own read state: it never inherits A's
        // interrupted read.
        #expect(coordinator.historyAvailability == .idle)
        #expect(coordinator.historyCaptures.isEmpty)

        #expect(await Self.switched(coordinator, to: projectA))
        await coordinator.waitForHistory()

        #expect(coordinator.historyAvailability == .loaded)
        #expect(coordinator.historyCaptures.map(\.id) == [capture.captureID])
        #expect(Self.captureSurface(of: coordinator) == .content)
        // A refreshed first page with no surviving selection leaves the selection to
        // the surface, so the session pane is empty-by-selection, not a spinner.
        #expect(coordinator.selectedHistoryCaptureID == nil)
        #expect(Self.sessionSurface(of: coordinator) == .noSelection)

        // B is untouched by A's resumed read.
        #expect(await Self.switched(coordinator, to: projectB.id))
        #expect(coordinator.historyAvailability == .idle)
        #expect(coordinator.historyCaptures.isEmpty)
    }

    @Test("An interrupted first session page is re-read against its own restored store")
    func interruptedSessionPageResumesOnRestore() async throws {
        let environment = ProjectIsolationEnvironment(name: "history-resume-sessions")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        let store = try #require(coordinator.sessionStore)
        let capture = Self.capture(startedAt: 1_000, endedAt: 1_100)
        try await store.replaceCapture(capture, sessions: [Self.session(host: "a.example")])

        coordinator.refreshHistory()
        await coordinator.waitForHistory()
        coordinator.selectHistoryCapture(capture.captureID)
        await coordinator.waitForHistory()
        #expect(coordinator.historyAvailability == .loaded)
        #expect(coordinator.historySessionsAvailability == .loaded)

        // Only the selected capture's page read is interrupted. The capture list
        // stays loaded and keeps its selection, which is exactly the case a demotion
        // to `.idle` would strand: the surface re-selects nothing, so nobody reads.
        Self.interruptFirstSessionPage(of: coordinator)
        #expect(coordinator.historyAvailability == .loaded)
        #expect(Self.sessionSurface(of: coordinator) == .loading)

        let projectB = try #require(await Self.created(coordinator, named: "Bravo"))
        #expect(coordinator.historySessionsAvailability == .idle)
        #expect(coordinator.selectedHistoryCaptureID == nil)

        #expect(await Self.switched(coordinator, to: projectA))
        await coordinator.waitForHistory()

        #expect(coordinator.selectedHistoryCaptureID == capture.captureID)
        #expect(coordinator.historySessionsAvailability == .loaded)
        #expect(coordinator.historySessions.map(\.host) == ["a.example"])
        #expect(Self.sessionSurface(of: coordinator) == .content)
        // The already-loaded capture page was preserved, not re-read.
        #expect(coordinator.historyCaptures.map(\.id) == [capture.captureID])

        #expect(await Self.switched(coordinator, to: projectB.id))
        #expect(coordinator.historySessions.isEmpty)
        #expect(coordinator.selectedHistoryCaptureID == nil)
    }

    /// `loadMore` appends behind `.loaded`, so an interrupted page *append* is not a
    /// stranded first page. Restoring must leave the loaded rows and the cursor
    /// exactly as they were rather than restarting the list from the newest page.
    @Test("An interrupted page append keeps its loaded rows and cursor")
    func interruptedPageAppendIsNotRestarted() async throws {
        let environment = ProjectIsolationEnvironment(name: "history-resume-paging")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        let store = try #require(coordinator.sessionStore)
        let newest = Self.capture(startedAt: 3_000, endedAt: 3_100)
        let middle = Self.capture(startedAt: 2_000, endedAt: 2_100)
        let oldest = Self.capture(startedAt: 1_000, endedAt: 1_100)
        for capture in [oldest, middle, newest] {
            try await store.replaceCapture(capture, sessions: [])
        }

        coordinator.refreshHistory()
        await coordinator.waitForHistory()
        #expect(coordinator.historyCaptures.count == 3)

        // A page append that was in flight when the Project changed: availability
        // stays `.loaded`, and the rows and cursor already accepted are the ones the
        // restored Project must come back to.
        let loaded = Array(coordinator.historyCaptures.prefix(2))
        let cursor = HistoryCaptureCursor(endedAt: middle.endedAt, captureID: middle.captureID)
        coordinator.historyTask?.cancel()
        coordinator.historyTask = nil
        coordinator.historyRequestID &+= 1
        coordinator.historyCaptures = loaded
        coordinator.historyCaptureCursor = cursor

        _ = try #require(await Self.created(coordinator, named: "Bravo"))
        #expect(await Self.switched(coordinator, to: projectA))
        await coordinator.waitForHistory()

        #expect(coordinator.historyAvailability == .loaded)
        #expect(coordinator.historyCaptures.map(\.id) == loaded.map(\.id))
        #expect(coordinator.historyCaptureCursor == cursor)

        // Paging still resumes from that exact cursor rather than a re-read list.
        coordinator.loadMoreHistoryCaptures()
        await coordinator.waitForHistory()
        #expect(coordinator.historyCaptures.map(\.id) == [newest.captureID, middle.captureID, oldest.captureID])
    }

    // MARK: Private

    // MARK: Interruption fixtures

    /// Exactly what a Project change leaves behind for a first capture page:
    /// ``MainContentCoordinator/invalidateOutgoingProjectWork()`` cancels the read
    /// and retires its request id, so `.loading` is parked with no reader.
    private static func interruptFirstCapturePage(of coordinator: MainContentCoordinator) {
        coordinator.historyTask?.cancel()
        coordinator.historyTask = nil
        coordinator.historyRequestID &+= 1
        coordinator.historyAvailability = .loading
        coordinator.historyCaptures = []
        coordinator.historyCaptureCursor = nil
    }

    /// The same, for the selected capture's first session page.
    private static func interruptFirstSessionPage(of coordinator: MainContentCoordinator) {
        coordinator.historySessionTask?.cancel()
        coordinator.historySessionTask = nil
        coordinator.historySessionRequestID &+= 1
        coordinator.historySessionsAvailability = .loading
        coordinator.historySessions = []
        coordinator.historySessionCursor = nil
    }

    // MARK: Surface state

    private static func captureSurface(of coordinator: MainContentCoordinator) -> HistoryCaptureSurfaceState {
        HistoryCaptureSurfaceState.resolve(
            availability: coordinator.historyAvailability,
            captureCount: coordinator.historyCaptures.count,
            unavailableReason: coordinator.historyError
        )
    }

    private static func sessionSurface(of coordinator: MainContentCoordinator) -> HistorySessionSurfaceState {
        HistorySessionSurfaceState.resolve(
            selectedCaptureID: coordinator.selectedHistoryCaptureID,
            availability: coordinator.historySessionsAvailability,
            sessionCount: coordinator.historySessions.count
        )
    }

    // MARK: Project fixtures

    private static func switched(_ coordinator: MainContentCoordinator, to id: UUID) async -> Bool {
        guard coordinator.switchToProject(id: id) else {
            return false
        }
        return await coordinator.waitForProjectTransition()
    }

    private static func created(
        _ coordinator: MainContentCoordinator,
        named name: String
    )
        async -> Project?
    {
        guard let project = coordinator.createProject(named: name),
              await coordinator.waitForProjectTransition() else
        {
            return nil
        }
        return project
    }

    // MARK: Record fixtures

    private static func capture(startedAt: Double, endedAt: Double) -> HistoryCaptureRecord {
        HistoryCaptureRecord(
            captureID: UUID(),
            startedAt: startedAt,
            endedAt: endedAt,
            sourceKind: .live,
            completeness: .complete
        )
    }

    private static func session(host: String) -> HistorySessionRecord {
        HistorySessionRecord(
            sessionID: UUID(),
            startTime: 1_000,
            duration: 5,
            processName: "curl",
            host: host,
            sourceEndpoint: "10.0.0.1:5000",
            destinationEndpoint: "93.184.216.34:443",
            protocols: ["tcp", "tls"],
            status: .ok,
            latencyMilliseconds: 12.5,
            bytesUp: 100,
            bytesDown: 200
        )
    }
}
