import Foundation
import Testing
@testable import Tracexy

@MainActor
@Suite("Session scope reset")
struct SessionScopeResetTests {
    // MARK: Internal

    @Test("A sidebar-only lens is reported as scope and cleared by the reset")
    func sidebarOnlyResetReturnsToSessions() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        workspace.sidebarSelection = .dns
        workspace.sessionGrouping = .host
        workspace.isSearchEnabled = false

        #expect(coordinator.sessionScope().descriptors.map(\.kind) == [.protocolLens])

        coordinator.resetSessionFilters()

        #expect(workspace.sidebarSelection == .sessions)
        #expect(!workspace.hasActiveFilters)
        #expect(coordinator.sessionScope().descriptors.isEmpty)
        // The reset clears filtering, not the user's view preferences.
        #expect(workspace.sessionGrouping == .host)
        #expect(!workspace.isSearchEnabled)
    }

    @Test("Resetting from Overview or Flow does not navigate away from it")
    func resetPreservesNonProtocolLocation() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace

        for location in [SidebarItem.overview, .flow] {
            workspace.sidebarSelection = location
            workspace.filterText = "cdn"
            workspace.categoryFilters = [.tls]
            workspace.hostFilter = "example.com"
            workspace.processFilter = "Safari"
            workspace.ipFilter = "192.0.2.10"
            workspace.filterRules = [SessionFilterRule(field: .host, value: "cdn")]
            workspace.isAdvancedFilterVisible = true

            coordinator.resetSessionFilters()

            #expect(workspace.sidebarSelection == location)
            #expect(workspace.filterText.isEmpty)
            #expect(workspace.categoryFilters.isEmpty)
            #expect(workspace.hostFilter == nil)
            #expect(workspace.processFilter == nil)
            #expect(workspace.ipFilter == nil)
            #expect(workspace.activeFilterRules.isEmpty)
            #expect(workspace.filterRules.count == 1)
            #expect(!workspace.isAdvancedFilterVisible)
        }
    }

    @Test("The reset retires an accepted Investigation query")
    func resetClearsAcceptedQuery() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let draft = InvestigationQueryDraft(rows: [
            InvestigationQueryDraftRow(predicate: .protocolStackContains(.tcp)),
        ])
        coordinator.applyInvestigationQuery(draft, in: workspace)
        await coordinator.waitForInvestigationQuery(in: workspace)
        try #require(workspace.hasActiveInvestigationQuery)

        coordinator.resetSessionFilters()

        #expect(workspace.acceptedInvestigationDraft == nil)
        #expect(workspace.investigationMatchedSessionIDs.isEmpty)
        #expect(workspace.investigationIndeterminateSessionIDs.isEmpty)
        #expect(!workspace.isEvaluatingInvestigationQuery)
        #expect(coordinator.investigationQueryTasks[workspace.id] == nil)
        #expect(coordinator.visibleSessions(in: workspace).count == coordinator.sessions.count)
    }

    @Test("An evaluation still in flight cannot re-narrow the list after the reset")
    func resetCancelsInFlightQuery() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let draft = InvestigationQueryDraft(rows: [
            InvestigationQueryDraftRow(predicate: .protocolStackContains(.tcp)),
        ])

        // Deliberately not awaited: the reset lands while the evaluation is live.
        coordinator.applyInvestigationQuery(draft, in: workspace)
        try #require(workspace.isEvaluatingInvestigationQuery)
        let requestID = workspace.investigationQueryRequestID

        coordinator.resetSessionFilters()
        #expect(workspace.investigationQueryRequestID > requestID)
        #expect(coordinator.investigationQueryTasks[workspace.id] == nil)

        // Give the superseded evaluation every chance to land; its request ID no
        // longer matches, so it must adopt nothing.
        try await Task.sleep(nanoseconds: 50_000_000)
        for _ in 0 ..< 10 {
            await Task.yield()
        }

        #expect(workspace.acceptedInvestigationDraft == nil)
        #expect(workspace.investigationMatchedSessionIDs.isEmpty)
        #expect(!workspace.isEvaluatingInvestigationQuery)
        #expect(workspace.investigationQueryError == nil)
    }

    @Test("Resetting one workspace leaves every other workspace untouched")
    func resetLeavesOtherWorkspacesAlone() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let first = coordinator.activeWorkspace
        let second = try coordinator.workspaces.addWorkspace(title: "Second")
        second.sidebarSelection = .tcp
        second.filterText = "example"
        second.categoryFilters = [.dns]
        second.hostFilter = "example.com"
        second.filterRules = [SessionFilterRule(field: .host, value: "example")]
        let draft = InvestigationQueryDraft(rows: [
            InvestigationQueryDraftRow(predicate: .protocolStackContains(.tcp)),
        ])
        coordinator.applyInvestigationQuery(draft, in: second)
        await coordinator.waitForInvestigationQuery(in: second)
        let secondMatches = second.investigationMatchedSessionIDs
        first.filterText = "cdn"
        first.categoryFilters = [.tls]

        coordinator.resetSessionFilters(in: first)

        #expect(first.filterText.isEmpty)
        #expect(first.categoryFilters.isEmpty)
        #expect(second.sidebarSelection == .tcp)
        #expect(second.filterText == "example")
        #expect(second.categoryFilters == [.dns])
        #expect(second.hostFilter == "example.com")
        #expect(second.activeFilterRules.count == 1)
        #expect(second.acceptedInvestigationDraft == draft)
        #expect(second.investigationMatchedSessionIDs == secondMatches)
    }

    @Test("Noise Control and removed rows survive the filter reset and stay visible as scope")
    func resetPreservesNoiseAndRemovedRows() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let mutedHost = try #require(coordinator.sessions.first?.host)
        let removedID = try #require(coordinator.sessions.last?.id)
        coordinator.toggleMuteHost(mutedHost)
        coordinator.removeSessionsFromView([removedID])
        workspace.filterText = "cdn"
        workspace.sidebarSelection = .tcp

        coordinator.resetSessionFilters()

        #expect(coordinator.mutedHosts == [mutedHost])
        #expect(coordinator.removedSessionIDs == [removedID])
        let scope = coordinator.sessionScope()
        #expect(scope.descriptors.map(\.kind) == [.noise, .removed])
        #expect(!scope.hasClearableFilters)
        #expect(scope.capturedCount == coordinator.sessions.count)
        #expect(scope.removedCount == 1)
    }

    @Test("The summary counts what the surface actually shows")
    func scopeSummaryMatchesVisibility() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let host = try #require(coordinator.sessions.first?.host)
        workspace.hostFilter = host

        let scope = coordinator.sessionScope()

        #expect(scope.shownCount == coordinator.visibleSessions.count)
        #expect(scope.capturedCount == coordinator.sessions.count)
        #expect(scope.shownCount > 0)
        #expect(scope.emptyClassification == .rowsVisible)

        // A scope that matches nothing is hidden results, never "no sessions".
        workspace.hostFilter = "no-such-host.invalid"
        let empty = coordinator.sessionScope()
        #expect(empty.shownCount == 0)
        #expect(empty.emptyClassification == .hiddenByScope)
        #expect(empty.hasClearableFilters)
    }

    // MARK: Private

    private struct Environment {
        let coordinator: MainContentCoordinator
        let teardown: () -> Void
    }

    /// A coordinator holding a real decoded capture, so visibility counts come
    /// from actual sessions rather than fabricated summaries.
    private func makeLoadedCoordinator(function: String = #function) async throws -> Environment {
        let isolation = ProjectIsolationEnvironment(name: function)
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tracexy-scope-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("sample.pcap")
        let frames = SampleCapture.frames(now: Date())
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)

        coordinator.openSavedCapture(
            SavedCapture(url: url, name: "sample", date: Date(), byteCount: frames.count)
        )
        await coordinator.waitForSavedCaptureOpen()
        try #require(!coordinator.sessions.isEmpty)

        return Environment(coordinator: coordinator) {
            isolation.tearDown()
            try? FileManager.default.removeItem(at: directory)
        }
    }
}
