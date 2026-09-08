import Foundation
import Testing
@testable import Tracexy

/// The bounded drill-in return path: only the four explicit drill-ins record a
/// way back, the record is capped and workspace-local, an entry from an older
/// capture generation is dropped rather than reapplied, and returning restores
/// exactly the recorded fields — never a removed session, another workspace, or
/// any saved rule, query, search text, noise or removal decision.
@MainActor
@Suite("Session scope return")
struct SessionScopeReturnTests {
    // MARK: Internal

    @Test("A host drill-in records the scope it replaced and restores it, selection included")
    func hostDrillInRestoresScopeAndSelection() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        workspace.sidebarSelection = .overview
        workspace.categoryFilters = [.tls]
        workspace.isFilterBarVisible = false
        let sessions = coordinator.presentedSessions
        let origin = try #require(sessions.first)
        let other = try #require(sessions.last { $0.id != origin.id })
        coordinator.select(origin)
        await coordinator.waitForEvidenceProjection()

        coordinator.selectHost("cdn.fastly.net")
        coordinator.select(other)
        await coordinator.waitForEvidenceProjection()
        #expect(workspace.hostFilter == "cdn.fastly.net")
        #expect(workspace.sidebarSelection == .sessions)
        #expect(workspace.sessionScopeReturnStack.count == 1)
        #expect(coordinator.canReturnToPreviousSessionScope)

        #expect(coordinator.returnToPreviousSessionScope())
        await coordinator.waitForEvidenceProjection()

        #expect(workspace.sidebarSelection == .overview)
        #expect(workspace.hostFilter == nil)
        #expect(!workspace.isFilterBarVisible)
        #expect(workspace.categoryFilters == [.tls])
        #expect(workspace.selectedSessionID == origin.id)
        // The return is consumed, so a second press cannot re-enter the drill-in.
        #expect(workspace.sessionScopeReturnStack.isEmpty)
        #expect(!coordinator.canReturnToPreviousSessionScope)
        #expect(!coordinator.returnToPreviousSessionScope())
    }

    @Test("Process and IP drill-ins nest and unwind in order")
    func drillInsNestAndUnwind() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace

        coordinator.selectHost("api.example.com")
        coordinator.selectProcess("Safari")
        coordinator.selectIP("93.184.16.34")
        #expect(workspace.sessionScopeReturnStack.count == 3)

        #expect(coordinator.returnToPreviousSessionScope())
        #expect(workspace.processFilter == "Safari")
        #expect(workspace.ipFilter == nil)

        #expect(coordinator.returnToPreviousSessionScope())
        #expect(workspace.hostFilter == "api.example.com")
        #expect(workspace.processFilter == nil)

        #expect(coordinator.returnToPreviousSessionScope())
        #expect(workspace.hostFilter == nil)
        #expect(!coordinator.canReturnToPreviousSessionScope)
    }

    @Test("The record is capped at eight and a repeated drill-in records nothing")
    func stackIsBoundedAndIgnoresNoOps() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace

        for index in 0 ..< 10 {
            coordinator.selectHost("host-\(index).example")
        }
        #expect(workspace.sessionScopeReturnStack.count == SessionScopeReturnPoint.maximumDepth)
        // Ten drill-ins recorded ten origins; the two oldest were dropped, so the
        // deepest scope still reachable is the one `host-1` replaced.
        #expect(workspace.sessionScopeReturnStack.first?.hostFilter == "host-1.example")

        // The same drill-in again changes nothing, so it records nothing.
        coordinator.selectHost("host-9.example")
        #expect(workspace.sessionScopeReturnStack.count == SessionScopeReturnPoint.maximumDepth)

        for _ in 0 ..< SessionScopeReturnPoint.maximumDepth {
            #expect(coordinator.returnToPreviousSessionScope())
        }
        // Unwinding stops at the oldest surviving record: the unbounded history
        // back to "no host at all" was dropped, not silently kept.
        #expect(workspace.hostFilter == "host-1.example")
        #expect(!coordinator.canReturnToPreviousSessionScope)
    }

    @Test("A drill-in and its return never touch another workspace")
    func returnIsWorkspaceLocal() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let first = coordinator.activeWorkspace
        first.hostFilter = "first.example"
        let second = try coordinator.workspaces.addWorkspace(title: "Second")

        coordinator.selectHost("second.example")
        #expect(second.sessionScopeReturnStack.count == 1)
        #expect(first.sessionScopeReturnStack.isEmpty)

        // Back in the first workspace there is nothing to return to, and the
        // second workspace's record is untouched by asking.
        coordinator.workspaces.activeWorkspaceID = first.id
        #expect(!coordinator.canReturnToPreviousSessionScope)
        #expect(!coordinator.returnToPreviousSessionScope())
        #expect(second.sessionScopeReturnStack.count == 1)
        #expect(first.hostFilter == "first.example")

        coordinator.workspaces.activeWorkspaceID = second.id
        #expect(coordinator.returnToPreviousSessionScope())
        #expect(second.hostFilter == nil)
        #expect(first.hostFilter == "first.example")
        #expect(first.sessionScopeReturnStack.isEmpty)
    }

    @Test("An entry from an earlier capture generation is dropped, never reapplied")
    func staleGenerationEntriesAreDropped() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        coordinator.selectHost("api.example.com")
        try #require(coordinator.canReturnToPreviousSessionScope)

        // A capture/source/Project rebase advances the generation.
        coordinator.startGeneration &+= 1

        #expect(!coordinator.canReturnToPreviousSessionScope)
        #expect(!coordinator.returnToPreviousSessionScope())
        // Pruned rather than left to be reapplied, and the current scope is
        // untouched: going back must never resurrect a source.
        #expect(workspace.sessionScopeReturnStack.isEmpty)
        #expect(workspace.hostFilter == "api.example.com")

        // A drill-in under the new generation starts a fresh, valid record.
        coordinator.selectHost("cdn.fastly.net")
        #expect(workspace.sessionScopeReturnStack.count == 1)
        #expect(coordinator.canReturnToPreviousSessionScope)
    }

    @Test("Reset Session Filters clears the return record")
    func resetClearsTheStack() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        coordinator.selectHost("api.example.com")
        coordinator.selectProcess("Safari")
        try #require(workspace.sessionScopeReturnStack.count == 2)

        coordinator.resetSessionFilters()

        #expect(workspace.sessionScopeReturnStack.isEmpty)
        #expect(!coordinator.canReturnToPreviousSessionScope)
        #expect(!coordinator.returnToPreviousSessionScope())
    }

    @Test("A selection removed from view or gone from the capture is cleared, not restored")
    func removedOrMissingSelectionIsCleared() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let removed = try #require(coordinator.presentedSessions.first)
        let survivor = try #require(coordinator.presentedSessions.last { $0.id != removed.id })
        coordinator.select(removed)
        await coordinator.waitForEvidenceProjection()
        coordinator.selectHost("cdn.fastly.net")
        coordinator.select(survivor)
        await coordinator.waitForEvidenceProjection()
        coordinator.removeSessionsFromView([removed.id])

        #expect(coordinator.returnToPreviousSessionScope())
        await coordinator.waitForEvidenceProjection()
        #expect(workspace.selectedSessionID == nil)
        #expect(coordinator.evidenceProjection.selection == nil)
        // Restoring a scope is not a route back to a row the user removed.
        #expect(coordinator.removedSessionIDs == [removed.id])

        // The same holds for a session that simply left the capture.
        let dropped = try #require(coordinator.presentedSessions.first)
        coordinator.select(dropped)
        await coordinator.waitForEvidenceProjection()
        coordinator.selectProcess("Safari")
        coordinator.sessions = coordinator.sessions.filter { $0.id != dropped.id }

        #expect(coordinator.returnToPreviousSessionScope())
        await coordinator.waitForEvidenceProjection()
        #expect(workspace.selectedSessionID == nil)
    }

    @Test("Findings drill-in records a return; sidebar navigation and search focus do not")
    func onlyExplicitDrillInsRecord() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        workspace.sidebarSelection = .overview

        coordinator.selectSidebarItem(.flow)
        #expect(workspace.sessionScopeReturnStack.isEmpty)
        coordinator.beginSessionSearch()
        #expect(workspace.sessionScopeReturnStack.isEmpty)

        coordinator.showAggregateFindingSessions()
        #expect(workspace.aggregateRequiresFindings)
        #expect(workspace.sessionScopeReturnStack.count == 1)

        #expect(coordinator.returnToPreviousSessionScope())
        #expect(!workspace.aggregateRequiresFindings)
        #expect(workspace.sidebarSelection == .sessions)
        #expect(workspace.isSearchEnabled)
    }

    @Test("The return restores only the recorded fields, never rules, query, text or noise")
    func returnLeavesOtherDecisionsAlone() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let mutedHost = try #require(coordinator.sessions.first?.host)
        coordinator.toggleMuteHost(mutedHost)
        coordinator.selectHost("api.example.com")

        // Everything the user changed *after* the drill-in stays theirs.
        workspace.filterText = "cdn"
        workspace.filterRules = [SessionFilterRule(field: .host, value: "cdn")]
        workspace.isAdvancedFilterVisible = true
        let draft = InvestigationQueryDraft(rows: [
            InvestigationQueryDraftRow(predicate: .protocolStackContains(.tcp)),
        ])
        coordinator.applyInvestigationQuery(draft, in: workspace)
        await coordinator.waitForInvestigationQuery(in: workspace)

        #expect(coordinator.returnToPreviousSessionScope())

        #expect(workspace.hostFilter == nil)
        #expect(workspace.filterText == "cdn")
        #expect(workspace.activeFilterRules.count == 1)
        #expect(workspace.isAdvancedFilterVisible)
        #expect(workspace.acceptedInvestigationDraft == draft)
        #expect(coordinator.mutedHosts == [mutedHost])
    }

    @Test("Follow Stream records no return entry and changes no filter")
    func followStreamRecordsNothing() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let session = try #require(coordinator.presentedSessions.first { $0.protocolStack.contains(.tcp) })
        coordinator.select(session)
        await coordinator.waitForEvidenceProjection()
        workspace.categoryFilters = [.tls]

        coordinator.followSelectedTCPStream()
        await coordinator.waitForFollowStream()

        #expect(workspace.sessionScopeReturnStack.isEmpty)
        #expect(!coordinator.canReturnToPreviousSessionScope)
        #expect(workspace.categoryFilters == [.tls])
        #expect(workspace.hostFilter == nil)
        #expect(workspace.selectedSessionID == session.id)
        coordinator.cancelFollowStream(clearResult: true)
    }

    // MARK: Private

    private struct Environment {
        let coordinator: MainContentCoordinator
        let teardown: () -> Void
    }

    /// A coordinator holding a real decoded capture, so selection restoration is
    /// exercised against actual sessions rather than fabricated summaries.
    private func makeLoadedCoordinator(function: String = #function) async throws -> Environment {
        let isolation = ProjectIsolationEnvironment(name: function)
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tracexy-scope-return-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("sample.pcap")
        let frames = SampleCapture.frames(now: Date())
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)

        coordinator.openSavedCapture(
            SavedCapture(url: url, name: "sample", date: Date(), byteCount: frames.count)
        )
        await coordinator.waitForSavedCaptureOpen()
        try #require(coordinator.presentedSessions.count >= 2)

        return Environment(coordinator: coordinator) {
            isolation.tearDown()
            try? FileManager.default.removeItem(at: directory)
        }
    }
}
