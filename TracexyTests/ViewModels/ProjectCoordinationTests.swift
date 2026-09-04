import Foundation
import Testing
@testable import Tracexy

@MainActor
@Suite("Project workspace coordination")
struct ProjectCoordinationTests {
    @Test("Switching projects restores each workspace configuration")
    func switchingRestoresWorkspaceConfiguration() async throws {
        let coordinator = MainContentCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let firstProjectID = coordinator.projectStore.activeProjectID
        coordinator.workspaces.activeWorkspace.filterText = "api.example"
        coordinator.workspaces.activeWorkspace.sessionGrouping = .host
        coordinator.workspaces.activeWorkspace.sidebarSelection = .tls
        #expect(coordinator.flushProjectWorkspaceSnapshot())

        let secondProject = try #require(coordinator.createProject(named: "Authentication"))
        #expect(coordinator.workspaces.activeWorkspace.filterText.isEmpty)
        coordinator.workspaces.activeWorkspace.filterText = "handshake"
        coordinator.workspaces.activeWorkspace.sessionGrouping = .process
        #expect(coordinator.flushProjectWorkspaceSnapshot())

        #expect(coordinator.switchToProject(id: firstProjectID))
        #expect(coordinator.workspaces.activeWorkspace.filterText == "api.example")
        #expect(coordinator.workspaces.activeWorkspace.sessionGrouping == .host)
        #expect(coordinator.workspaces.activeWorkspace.sidebarSelection == .tls)

        #expect(coordinator.switchToProject(id: secondProject.id))
        #expect(coordinator.workspaces.activeWorkspace.filterText == "handshake")
        #expect(coordinator.workspaces.activeWorkspace.sessionGrouping == .process)
    }

    @Test("Capture-local selection is not persisted into a project")
    func transientSelectionIsExcluded() async throws {
        let coordinator = MainContentCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let firstProjectID = coordinator.projectStore.activeProjectID
        coordinator.workspaces.activeWorkspace.selectedSessionID = UUID()
        #expect(coordinator.flushProjectWorkspaceSnapshot())

        _ = try #require(coordinator.createProject(named: "Second"))
        #expect(coordinator.switchToProject(id: firstProjectID))
        #expect(coordinator.workspaces.activeWorkspace.selectedSessionID == nil)
    }

    @Test("Deleting the active project falls back without deleting the final project")
    func activeDeletionFallsBack() async throws {
        let coordinator = MainContentCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let originalID = coordinator.projectStore.activeProjectID
        let project = try #require(coordinator.createProject(named: "Temporary"))
        #expect(coordinator.renameProject(id: project.id, to: "Renamed"))
        #expect(coordinator.projectStore.activeProject.name == "Renamed")

        #expect(coordinator.deleteProject(id: project.id))
        #expect(coordinator.projectStore.activeProjectID == originalID)
        #expect(coordinator.projectStore.projects.count == 1)
        #expect(!coordinator.deleteProject(id: originalID))
        #expect(coordinator.lastProjectOperationError == .cannotDeleteFinalProject)
    }
}
