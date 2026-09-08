import Foundation
import Testing
@testable import Tracexy

/// The cited-frame return path: an accepted citation is the one place that moves
/// the inspector to Layers, it remembers the *first* facet it interrupted, only
/// the explicit Clear Citation returns to that facet, and an ordinary cancel,
/// selection change or source boundary discards it without moving the user.
@MainActor
@Suite("Cited frame facet return")
struct CitationReturnTests {
    // MARK: Internal

    @Test("An accepted citation records the interrupted facet and the explicit clear returns to it")
    func explicitClearReturnsToTheInterruptedFacet() async throws {
        let environment = try await makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let session = try #require(coordinator.presentedSessions.first)
        coordinator.select(session)
        await coordinator.waitForEvidenceProjection()
        coordinator.activeWorkspace.inspectorTab = .evidence

        coordinator.inspectCitedFrame(sessionID: session.id, provenance: Self.provenance())

        #expect(coordinator.activeWorkspace.inspectorTab == .layers)
        #expect(coordinator.citedFrame.returnInspectorTab == .evidence)
        #expect(coordinator.citedFrame.state == .unavailable)

        coordinator.clearCitedFrameAndReturn()

        #expect(coordinator.activeWorkspace.inspectorTab == .evidence)
        #expect(coordinator.citedFrame.state == .idle)
        #expect(coordinator.citedFrame.returnInspectorTab == nil)
    }

    @Test("Repeated citations keep the facet the first one interrupted")
    func repeatedCitationsKeepTheOriginalFacet() async throws {
        let environment = try await makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let session = try #require(coordinator.presentedSessions.first)
        coordinator.select(session)
        await coordinator.waitForEvidenceProjection()
        coordinator.activeWorkspace.inspectorTab = .timeline

        coordinator.inspectCitedFrame(sessionID: session.id, provenance: Self.provenance())
        coordinator.inspectCitedFrame(sessionID: session.id, provenance: Self.provenance(ordinal: 4))
        coordinator.inspectCitedFrame(sessionID: session.id, provenance: Self.provenance(ordinal: 9))

        // Layers is never recorded as the place to go back to.
        #expect(coordinator.citedFrame.returnInspectorTab == .timeline)

        coordinator.clearCitedFrameAndReturn()
        #expect(coordinator.activeWorkspace.inspectorTab == .timeline)
    }

    @Test("An ordinary cancel discards the remembered facet and leaves the inspector alone")
    func ordinaryCancelDiscardsTheFacet() async throws {
        let environment = try await makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let session = try #require(coordinator.presentedSessions.first)
        coordinator.select(session)
        await coordinator.waitForEvidenceProjection()
        coordinator.activeWorkspace.inspectorTab = .evidence
        coordinator.inspectCitedFrame(sessionID: session.id, provenance: Self.provenance())

        coordinator.cancelCitedFrame()

        #expect(coordinator.activeWorkspace.inspectorTab == .layers)
        #expect(coordinator.citedFrame.returnInspectorTab == nil)

        // A later explicit clear has nothing to restore and must not guess.
        coordinator.clearCitedFrameAndReturn()
        #expect(coordinator.activeWorkspace.inspectorTab == .layers)
    }

    @Test("A selection change or source boundary discards the remembered facet")
    func selectionAndSourceBoundariesDiscardTheFacet() async throws {
        let environment = try await makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let sessions = coordinator.presentedSessions
        let session = try #require(sessions.first)
        let other = try #require(sessions.last { $0.id != session.id })
        coordinator.select(session)
        await coordinator.waitForEvidenceProjection()
        coordinator.activeWorkspace.inspectorTab = .evidence
        coordinator.inspectCitedFrame(sessionID: session.id, provenance: Self.provenance())

        coordinator.select(other)
        await coordinator.waitForEvidenceProjection()

        #expect(coordinator.citedFrame.returnInspectorTab == nil)
        coordinator.clearCitedFrameAndReturn()
        #expect(coordinator.activeWorkspace.inspectorTab == .layers)

        // The same holds at a capture/source boundary.
        coordinator.select(other)
        await coordinator.waitForEvidenceProjection()
        coordinator.activeWorkspace.inspectorTab = .timeline
        coordinator.inspectCitedFrame(sessionID: other.id, provenance: Self.provenance())
        try #require(coordinator.citedFrame.returnInspectorTab == .timeline)

        coordinator.clearEvidenceNavigation()
        #expect(coordinator.citedFrame.returnInspectorTab == nil)
        #expect(coordinator.activeWorkspace.inspectorTab == .layers)
    }

    @Test("A citation for a session that is not selected moves nothing and records nothing")
    func rejectedCitationDoesNotMoveTheInspector() async throws {
        let environment = try await makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let sessions = coordinator.presentedSessions
        let session = try #require(sessions.first)
        let other = try #require(sessions.last { $0.id != session.id })
        coordinator.select(session)
        await coordinator.waitForEvidenceProjection()
        coordinator.activeWorkspace.inspectorTab = .evidence

        coordinator.inspectCitedFrame(sessionID: other.id, provenance: Self.provenance())

        #expect(coordinator.activeWorkspace.inspectorTab == .evidence)
        #expect(coordinator.citedFrame.returnInspectorTab == nil)
        #expect(coordinator.citedFrame.state == .idle)
    }

    // MARK: Private

    private struct Environment {
        let coordinator: MainContentCoordinator
        let teardown: () -> Void
    }

    /// A citation with no locator: an explicit unavailable state that reaches the
    /// same accepted-entry path without starting any read.
    private static func provenance(ordinal: UInt64 = 1) -> SessionFrameProvenance {
        SessionFrameProvenance(
            ordinal: FrameOrdinal(ordinal),
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            capturedLength: 64,
            originalLength: 64,
            linkType: LinkType.ethernet,
            locator: nil
        )
    }

    private func makeEnvironment(function: String = #function) async throws -> Environment {
        let isolation = ProjectIsolationEnvironment(name: function)
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        coordinator.sessions = SessionBuilder.build(
            from: SampleCapture.frames(now: Date()),
            linkType: LinkType.ethernet
        )
        try #require(coordinator.presentedSessions.count >= 2)
        return Environment(coordinator: coordinator) {
            isolation.tearDown()
        }
    }
}
