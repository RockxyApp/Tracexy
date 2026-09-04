import Foundation
import Testing
@testable import Tracexy

@Suite("ProjectStore")
@MainActor
struct ProjectStoreTests {
    // MARK: Internal

    @Test("Create, select, rename and delete keep one active bounded catalog")
    func mutations() throws {
        let store = ProjectStore(maxProjects: 3, maxWorkspacesPerProject: 2)
        let originalID = store.activeProjectID
        let created = try store.createProject(name: "  Research  ")
        #expect(store.activeProjectID == created.id)
        #expect(created.name == "Research")

        try store.renameProject(id: created.id, to: "Audit")
        #expect(store.activeProject.name == "Audit")
        try store.selectProject(id: originalID)
        try store.deleteProject(id: created.id)
        #expect(store.projects.count == 1)
        #expect(store.activeProjectID == originalID)
        #expect(throws: ProjectMutationError.cannotDeleteFinalProject) {
            try store.deleteProject(id: originalID)
        }
    }

    @Test("Folded duplicate names and project capacity fail typed")
    func duplicateAndCapacity() throws {
        let store = ProjectStore(maxProjects: 2, maxWorkspacesPerProject: 2)
        _ = try store.createProject(name: "Résumé")
        #expect(throws: ProjectMutationError.duplicateName) {
            try store.renameProject(id: store.projects[0].id, to: "RESUME")
        }
        #expect(throws: ProjectMutationError.capacityReached(limit: 2)) {
            try store.createProject(name: "Third")
        }
    }

    @Test("Workspace replacement enforces the injected and structural bounds")
    func workspaceBounds() throws {
        let store = ProjectStore(maxProjects: 2, maxWorkspacesPerProject: 2)
        let workspaces = (0 ..< 3).map { ProjectWorkspaceSnapshot(title: "Tab \($0)") }
        #expect(throws: ProjectMutationError.workspaceCapacityReached(limit: 2)) {
            try store.updateActiveProjectWorkspaces(workspaces, activeWorkspaceID: workspaces[0].id)
        }
    }

    @Test("Disk-backed mutations serialize and survive a reopen")
    func persistenceRoundTrip() async throws {
        let directory = Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let repository = JSONProjectCatalogRepository(directoryURL: directory)
        let store = ProjectStore(
            maxProjects: 4,
            maxWorkspacesPerProject: 4,
            repository: repository
        )
        await store.loadPersistedCatalog()
        let created = try store.createProject(name: "Persisted")
        await store.waitForPendingPersistence()
        #expect(store.persistenceState == .saved)

        let reopened = ProjectStore(
            maxProjects: 4,
            maxWorkspacesPerProject: 4,
            repository: JSONProjectCatalogRepository(directoryURL: directory)
        )
        await reopened.loadPersistedCatalog()
        #expect(reopened.projects.contains(where: { $0.id == created.id }))
        #expect(reopened.activeProjectID == created.id)
    }

    @Test("Import always regenerates identities and activates without overwriting")
    func importRegeneratesIdentities() throws {
        let store = ProjectStore(maxProjects: 4, maxWorkspacesPerProject: 4)
        let workspace = ProjectWorkspaceSnapshot(title: "Imported Tab")
        let source = Project(
            id: store.activeProjectID,
            name: "Imported",
            workspaces: [workspace],
            activeWorkspaceID: workspace.id
        )
        let imported = try store.importProject(source)
        #expect(imported.id != source.id)
        #expect(imported.workspaces[0].id != workspace.id)
        #expect(store.activeProjectID == imported.id)
        #expect(store.projects.count == 2)
    }

    // MARK: Private

    private static func temporaryDirectory() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("project-store-\(UUID().uuidString)", isDirectory: true)
    }
}
