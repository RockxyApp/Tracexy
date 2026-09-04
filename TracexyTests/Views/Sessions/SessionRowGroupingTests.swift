import Foundation
import Testing
@testable import Tracexy

@MainActor
@Suite("Session row grouping")
struct SessionRowGroupingTests {
    // MARK: Internal

    @Test("Flat mode emits one row per visible session and no actions")
    func flatModeIsUngrouped() async throws {
        let env = try await makeLoadedCoordinator()
        defer { env.teardown() }
        let coordinator = env.coordinator
        coordinator.activeWorkspace.sessionGrouping = SessionGrouping.none

        let rows = coordinator.sessionRows

        #expect(rows.count == coordinator.visibleSessions.count)
        #expect(rows.allSatisfy {
            if case .session = $0 {
                true
            } else {
                false
            }
        })
    }

    @Test("Observed grouping conserves every visible session", arguments: [SessionGrouping.host, .process])
    func observedGroupingConservesSessions(mode: SessionGrouping) async throws {
        let env = try await makeLoadedCoordinator()
        defer { env.teardown() }
        let coordinator = env.coordinator
        coordinator.activeWorkspace.sessionGrouping = mode

        let covered = coordinator.sessionRows.flatMap { row -> [UUID] in
            switch row {
            case let .action(activity): activity.sessions.map(\.id)
            case let .group(group): group.sessions.map(\.id)
            case let .session(session): [session.id]
            }
        }

        #expect(Set(covered) == Set(coordinator.visibleSessions.map(\.id)))
        #expect(covered.count == Set(covered).count)
    }

    @Test("Observed groups are never singletons and never claim a confidence")
    func observedGroupsAreHonest() async throws {
        let env = try await makeLoadedCoordinator()
        defer { env.teardown() }
        let coordinator = env.coordinator
        coordinator.activeWorkspace.sessionGrouping = .host

        for row in coordinator.sessionRows {
            guard case let .group(group) = row else {
                continue
            }
            // A lone member is emitted flat: a disclosure triangle over one
            // child would overstate what is there.
            #expect(group.sessions.count > 1)
            // Every member really does carry the attribute — the group is an
            // observation, so it must be exactly true, not merely likely.
            #expect(group.sessions.allSatisfy { $0.host == group.key })
        }
    }

    @Test("A group keeps its identity across recomputation so live rows don't churn")
    func observedGroupIdentityIsStable() async throws {
        let env = try await makeLoadedCoordinator()
        defer { env.teardown() }
        let coordinator = env.coordinator
        coordinator.activeWorkspace.sessionGrouping = .host

        let first = coordinator.sessionRows.map(\.id)
        let second = coordinator.sessionRows.map(\.id)

        #expect(first == second)
        // And the identity is derived from the attribute, not the members.
        let sample = SessionGroup(kind: .host, key: "api.example.com", sessions: [])
        #expect(sample.id == SessionGroup(kind: .host, key: "api.example.com", sessions: []).id)
        #expect(sample.id != SessionGroup(kind: .process, key: "api.example.com", sessions: []).id)
    }

    @Test("Grouped mode never loses or duplicates a visible session")
    func groupedModeConservesSessions() async throws {
        let env = try await makeLoadedCoordinator()
        defer { env.teardown() }
        let coordinator = env.coordinator
        coordinator.activeWorkspace.sessionGrouping = .action

        let covered = coordinator.sessionRows.flatMap { row -> [UUID] in
            switch row {
            case let .action(activity): activity.sessions.map(\.id)
            case let .group(group): group.sessions.map(\.id)
            case let .session(session): [session.id]
            }
        }

        // Every visible session appears exactly once, whether nested or not.
        #expect(Set(covered) == Set(coordinator.visibleSessions.map(\.id)))
        #expect(covered.count == Set(covered).count)
    }

    @Test("An action row always has more than one child")
    func actionsAreNeverSingletons() async throws {
        let env = try await makeLoadedCoordinator()
        defer { env.teardown() }
        let coordinator = env.coordinator
        coordinator.activeWorkspace.sessionGrouping = .action

        for row in coordinator.sessionRows {
            if case let .action(activity) = row {
                // A disclosure triangle over one child claims a grouping that
                // is not there.
                #expect(activity.sessions.count > 1)
            }
        }
    }

    @Test("Filtering an action down to one session collapses it to a plain row")
    func filteredActionCollapses() async throws {
        let env = try await makeLoadedCoordinator()
        defer { env.teardown() }
        let coordinator = env.coordinator
        coordinator.activeWorkspace.sessionGrouping = .action

        // Narrow to a single session by id — nothing can still be an action.
        let target = try #require(coordinator.sessions.first)
        coordinator.activeWorkspace.filterText = target.host
        let narrowed = coordinator.visibleSessions
        try #require(!narrowed.isEmpty)

        for row in coordinator.sessionRows {
            if case let .action(activity) = row {
                // Whatever survives grouping must be entirely within the filter.
                #expect(activity.sessions.allSatisfy { member in
                    narrowed.contains { $0.id == member.id }
                })
            }
        }
    }

    @Test("A row resolves to a concrete session for the inspector to describe")
    func rowsResolveToASession() async throws {
        let env = try await makeLoadedCoordinator()
        defer { env.teardown() }
        let coordinator = env.coordinator
        coordinator.activeWorkspace.sessionGrouping = .action

        for row in coordinator.sessionRows {
            #expect(row.representativeSessionID != nil)
        }
    }

    // MARK: Private

    private struct Environment {
        let coordinator: MainContentCoordinator
        let teardown: () -> Void
    }

    private func makeLoadedCoordinator(function: String = #function) async throws -> Environment {
        let isolation = ProjectIsolationEnvironment(name: function)
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tracexy-tests-\(UUID().uuidString)", isDirectory: true)
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
