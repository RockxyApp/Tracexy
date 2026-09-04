import Foundation
import Testing
@testable import Tracexy

@MainActor
@Suite("Project workspace coordination")
struct ProjectCoordinationTests {
    // MARK: Internal

    @Test("Switching projects restores each workspace configuration")
    func switchingRestoresWorkspaceConfiguration() async throws {
        let environment = ProjectIsolationEnvironment(name: "coordination")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let firstProjectID = coordinator.projectStore.activeProjectID
        coordinator.workspaces.activeWorkspace.filterText = "api.example"
        coordinator.workspaces.activeWorkspace.sessionGrouping = .host
        coordinator.workspaces.activeWorkspace.sidebarSelection = .tls
        #expect(coordinator.flushProjectWorkspaceSnapshot())

        let secondProject = try #require(await Self.created(coordinator, named: "Authentication"))
        #expect(coordinator.workspaces.activeWorkspace.filterText.isEmpty)
        coordinator.workspaces.activeWorkspace.filterText = "handshake"
        coordinator.workspaces.activeWorkspace.sessionGrouping = .process
        #expect(coordinator.flushProjectWorkspaceSnapshot())

        #expect(await Self.switched(coordinator, to: firstProjectID))
        #expect(coordinator.workspaces.activeWorkspace.filterText == "api.example")
        #expect(coordinator.workspaces.activeWorkspace.sessionGrouping == .host)
        #expect(coordinator.workspaces.activeWorkspace.sidebarSelection == .tls)

        #expect(await Self.switched(coordinator, to: secondProject.id))
        #expect(coordinator.workspaces.activeWorkspace.filterText == "handshake")
        #expect(coordinator.workspaces.activeWorkspace.sessionGrouping == .process)
    }

    /// Selection is still excluded from the *portable* snapshot — a Project file
    /// must never carry a capture-local session id. It does, however, survive a
    /// switch inside one app session, because a parked Project keeps its real
    /// workspace instance rather than being rehydrated from that snapshot.
    @Test("Capture-local selection stays out of the portable snapshot but survives a switch")
    func transientSelectionIsExcludedFromTheSnapshot() async throws {
        let environment = ProjectIsolationEnvironment(name: "selection-snapshot")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let firstProjectID = coordinator.projectStore.activeProjectID
        let selectedID = UUID()
        coordinator.workspaces.activeWorkspace.selectedSessionID = selectedID
        #expect(coordinator.flushProjectWorkspaceSnapshot())

        let snapshot = try #require(coordinator.projectStore.activeProject.workspaces.first)
        let encoded = try JSONEncoder().encode(snapshot)
        let json = try #require(String(data: encoded, encoding: .utf8))
        #expect(!json.contains(selectedID.uuidString))

        _ = try #require(await Self.created(coordinator, named: "Second"))
        #expect(coordinator.workspaces.activeWorkspace.selectedSessionID == nil)

        #expect(await Self.switched(coordinator, to: firstProjectID))
        #expect(coordinator.workspaces.activeWorkspace.selectedSessionID == selectedID)
    }

    @Test("Deleting the active project falls back without deleting the final project")
    func activeDeletionFallsBack() async throws {
        let environment = ProjectIsolationEnvironment(name: "deletion")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let originalID = coordinator.projectStore.activeProjectID
        let project = try #require(await Self.created(coordinator, named: "Temporary"))
        #expect(coordinator.renameProject(id: project.id, to: "Renamed"))
        #expect(coordinator.projectStore.activeProject.name == "Renamed")

        #expect(coordinator.deleteProject(id: project.id))
        #expect(await coordinator.waitForProjectTransition())
        #expect(coordinator.projectStore.activeProjectID == originalID)
        #expect(coordinator.projectStore.projects.count == 1)
        #expect(!coordinator.deleteProject(id: originalID))
        #expect(coordinator.lastProjectOperationError == .cannotDeleteFinalProject)
    }

    // MARK: Private

    /// A Project change is durable-first and therefore asynchronous: starting one
    /// only means it was accepted and validated.
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
}
