import Foundation
import Testing
@testable import Tracexy

@MainActor
@Suite("Live session following")
struct LiveSessionFollowingTests {
    // MARK: Internal

    @Test("enabling follows the chronologically newest visible session")
    func enablingReconcilesVisibleChronology() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace

        coordinator.setFollowingLiveSessions(true)

        #expect(workspace.isFollowingLiveSessions)
        #expect(workspace.selectedSessionID == newest(in: coordinator.visibleSessions)?.id)

        let host = try #require(coordinator.sessions.first?.host)
        workspace.hostFilter = host
        coordinator.reconcileLiveFollowing(in: workspace)

        #expect(workspace.selectedSessionID == newest(in: coordinator.visibleSessions)?.id)
    }

    @Test("an empty scope stays armed and clears stale selection")
    func emptyScopeStaysArmed() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace

        coordinator.setFollowingLiveSessions(true)
        try #require(workspace.selectedSessionID != nil)
        workspace.hostFilter = "not-present.invalid"
        coordinator.reconcileLiveFollowing(in: workspace)

        #expect(workspace.isFollowingLiveSessions)
        #expect(workspace.selectedSessionID == nil)
    }

    @Test("a batch without a visible match preserves selection and remains armed")
    func nonmatchingBatchPreservesSelection() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let hosts = Dictionary(grouping: coordinator.sessions, by: \.host)
        let visibleGroup = try #require(hosts.values.first { group in
            coordinator.sessions.contains { $0.host != group[0].host }
        })
        let hidden = try #require(coordinator.sessions.first { $0.host != visibleGroup[0].host })

        workspace.hostFilter = visibleGroup[0].host
        coordinator.setFollowingLiveSessions(true)
        let selectedBefore = try #require(workspace.selectedSessionID)

        coordinator.reconcileLiveFollowing(
            in: workspace,
            acceptedSessionIDs: [hidden.id]
        )

        #expect(workspace.isFollowingLiveSessions)
        #expect(workspace.selectedSessionID == selectedBefore)
    }

    @Test("following is independent across active and inactive workspaces")
    func inactiveWorkspaceUsesItsOwnVisibility() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let firstWorkspace = coordinator.activeWorkspace
        let firstHost = try #require(coordinator.sessions.first?.host)
        let secondHost = try #require(coordinator.sessions.first { $0.host != firstHost }?.host)

        firstWorkspace.hostFilter = firstHost
        firstWorkspace.isFollowingLiveSessions = true
        let secondWorkspace = try coordinator.workspaces.addWorkspace(title: "Second")
        secondWorkspace.hostFilter = secondHost
        secondWorkspace.isFollowingLiveSessions = true
        coordinator.workspaces.activeWorkspaceID = firstWorkspace.id

        coordinator.followLatestVisibleSession(
            acceptedSessionIDs: Set(coordinator.sessions.map(\.id))
        )

        #expect(firstWorkspace.selectedSessionID == newest(
            in: coordinator.visibleSessions(in: firstWorkspace)
        )?.id)
        #expect(secondWorkspace.selectedSessionID == newest(
            in: coordinator.visibleSessions(in: secondWorkspace)
        )?.id)
    }

    @Test("user navigation yields but Jump to Latest preserves the mode")
    func userNavigationAndJumpHaveDistinctSemantics() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace

        coordinator.setFollowingLiveSessions(true)
        coordinator.userDidNavigateSessionHistory()
        #expect(!workspace.isFollowingLiveSessions)

        coordinator.setFollowingLiveSessions(true)
        coordinator.jumpToLatestVisibleSession()
        #expect(workspace.isFollowingLiveSessions)
        #expect(workspace.selectedSessionID == coordinator.visibleSessions.last?.id)
    }

    @Test("chronological choice is independent of input presentation order")
    func chronologicalChoiceIgnoresPresentationOrder() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let sessions = environment.coordinator.sessions
        let expected = try #require(newest(in: sessions))

        #expect(MainContentCoordinator.newestChronologicalSession(in: sessions.reversed())?.id == expected.id)
    }

    // MARK: Private

    private struct Environment {
        let coordinator: MainContentCoordinator
        let teardown: () -> Void
    }

    private func newest(in sessions: [SessionSummary]) -> SessionSummary? {
        MainContentCoordinator.newestChronologicalSession(in: sessions)
    }

    private func makeLoadedCoordinator(function: String = #function) async throws -> Environment {
        let suiteName = "com.amunx.tracexy.tests.\(function).\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        let coordinator = MainContentCoordinator(
            layoutPreferences: WorkspaceLayoutPreferences(defaults: defaults)
        )
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tracexy-follow-tests-\(UUID().uuidString)", isDirectory: true)
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
            defaults.removePersistentDomain(forName: suiteName)
            try? FileManager.default.removeItem(at: directory)
        }
    }
}
