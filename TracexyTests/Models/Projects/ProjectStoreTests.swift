import Foundation
import Testing
@testable import Tracexy

// MARK: - ProjectStoreTests

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

    @Test("A change that would not fit in the catalog file is refused; shrinking always goes through")
    func catalogCeilingRefusesGrowthOnly() throws {
        let initialBytes = ProjectCatalogCoding.encodedByteCount(of: ProjectCatalog.defaultCatalog(now: Date()))
        let store = ProjectStore(maxProjects: 8, maxWorkspacesPerProject: 32, maximumCatalogBytes: initialBytes + 600)
        let tabs = (0 ..< 8).map { ProjectWorkspaceSnapshot(title: "Tab \($0)") }
        #expect(throws: ProjectMutationError.catalogStorageFull) {
            try store.updateActiveProjectWorkspaces(tabs, activeWorkspaceID: tabs[0].id)
        }
        #expect(store.activeProject.workspaces.count == 1)
        #expect(store.isMutable)
        // A rename does not grow the catalog past what it holds, so it is kept.
        try store.renameProject(id: store.activeProjectID, to: "Renamed")
        #expect(store.activeProject.name == "Renamed")
    }

    @Test("The catalog's size is the sum of its Projects' sizes, exactly")
    func incrementalSizeIsExact() throws {
        var catalog = ProjectCatalog.defaultCatalog(now: Date(timeIntervalSince1970: 1_700_000_000))
        catalog.legacyDataOwnerProjectID = catalog.projects[0].id
        for index in 0 ..< 3 {
            let tabs = (0 ..< index + 2).map { tab in
                ProjectWorkspaceSnapshot(
                    title: "Tab \(tab)",
                    filterText: "dns and host contains \"é\(tab)\"",
                    hostFilter: tab == 0 ? "example.com" : nil,
                    filterRules: (0 ..< tab + 1).map { ProjectFilterRuleSnapshot(value: "value \($0) ✓") }
                )
            }
            catalog.projects.append(Project(name: "Project \(index)", workspaces: tabs, activeWorkspaceID: tabs[0].id))
        }
        let validated = try catalog.normalizedValidated()
        let parts = validated.projects.map { ProjectCatalogCoding.encodedByteCount(of: $0) }
        #expect(ProjectCatalogCoding.encodedByteCount(of: validated, projectBytes: parts)
            == ProjectCatalogCoding.encodedByteCount(of: validated))
    }

    @Test("Every published maximum fits: 128 Projects, 32 tabs each, 64 long rules a tab")
    func fullCapacityFits() throws {
        func fullProject(value: String) -> Project {
            let tabs = (0 ..< ProjectLimits.maximumWorkspacesPerProject).map { tab in
                ProjectWorkspaceSnapshot(
                    title: "Workspace \(tab + 1)",
                    filterText: value,
                    filterRules: (0 ..< ProjectLimits.maximumFilterRules).map { _ in
                        ProjectFilterRuleSnapshot(field: "destination", filterOperator: "notContains", value: value)
                    }
                )
            }
            return Project(name: "Project", workspaces: tabs, activeWorkspaceID: tabs[0].id)
        }
        // Every value at its longest, in every rule of every tab of every Project.
        let long = fullProject(value: String(repeating: "a", count: ProjectLimits.maximumStringLength))
        let longBytes = ProjectCatalogCoding.encodedByteCount(of: long)
        let catalogBytes = ProjectCatalogCoding.encodedByteCount(
            of: ProjectCatalog(projects: [long], activeProjectID: long.id),
            projectBytes: Array(repeating: longBytes, count: ProjectLimits.maximumProjects)
        )
        #expect(catalogBytes <= ProjectLimits.maximumCatalogBytes)
        // One Project at its longest — every value 512 four-byte characters — still
        // fits its own ceiling, and so exports as a `.tracexyproject`.
        let longest = fullProject(value: String(repeating: "🛰", count: ProjectLimits.maximumStringLength))
        #expect(ProjectCatalogCoding.encodedByteCount(of: longest) <= ProjectLimits.maximumProjectBytes)
        #expect(try PortableProjectCodec.encode(longest).count <= ProjectLimits.maximumPortableProjectBytes)
    }

    @Test("A Project past its own ceiling refuses growth only; other Projects are unaffected")
    func projectCeilingRefusesGrowthOnly() throws {
        let store = ProjectStore(maxProjects: 4, maxWorkspacesPerProject: 32, maximumProjectBytes: 4_000)
        let tabs = (0 ..< 12).map { ProjectWorkspaceSnapshot(title: "Tab \($0)") }
        #expect(throws: ProjectMutationError.catalogStorageFull) {
            try store.updateActiveProjectWorkspaces(tabs, activeWorkspaceID: tabs[0].id)
        }
        #expect(store.activeProject.workspaces.count == 1)
        let fewer = Array(tabs.prefix(2))
        try store.updateActiveProjectWorkspaces(fewer, activeWorkspaceID: fewer[0].id)
        #expect(store.activeProject.workspaces.count == 2)
        let other = try store.createProject(name: "Other")
        #expect(store.activeProjectID == other.id)
        try store.renameProject(id: other.id, to: "Other Renamed")
    }

    @Test("A failed save does not freeze Projects: the next change saves everything since")
    func failedSaveRecovers() async throws {
        let directory = Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let repository = FlakyCatalogRepository(JSONProjectCatalogRepository(directoryURL: directory))
        let store = ProjectStore(maxProjects: 4, maxWorkspacesPerProject: 4, repository: repository)
        await store.loadPersistedCatalog()

        await repository.failNextSave()
        let first = try store.createProject(name: "First")
        await store.waitForPendingPersistence()
        guard case .failed = store.persistenceState else {
            Issue.record("the save should have failed")
            return
        }
        #expect(store.isMutable)

        let second = try store.createProject(name: "Second")
        await store.waitForPendingPersistence()
        #expect(store.persistenceState == .saved)

        let reopened = ProjectStore(
            maxProjects: 4,
            maxWorkspacesPerProject: 4,
            repository: JSONProjectCatalogRepository(directoryURL: directory)
        )
        await reopened.loadPersistedCatalog()
        #expect(reopened.projects.map(\.id).contains(first.id))
        #expect(reopened.projects.map(\.id).contains(second.id))
    }

    // MARK: Private

    private static func temporaryDirectory() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("project-store-\(UUID().uuidString)", isDirectory: true)
    }
}

// MARK: - FlakyCatalogRepository

/// Fails the next save once, as a full disk or a locked file would.
private actor FlakyCatalogRepository: ProjectCatalogPersisting {
    // MARK: Lifecycle

    init(_ base: JSONProjectCatalogRepository) {
        self.base = base
    }

    // MARK: Internal

    func failNextSave() {
        failsNextSave = true
    }

    func load(seed: ProjectCatalog) async throws -> ProjectCatalog {
        try await base.load(seed: seed)
    }

    func save(_ catalog: ProjectCatalog, expectedRevision: UInt64) async throws {
        if failsNextSave {
            failsNextSave = false
            throw ProjectCatalogRepositoryError.fileSystem("simulated write failure")
        }
        try await base.save(catalog, expectedRevision: expectedRevision)
    }

    func reset(to catalog: ProjectCatalog) async throws -> ProjectCatalog {
        try await base.reset(to: catalog)
    }

    // MARK: Private

    private let base: JSONProjectCatalogRepository
    private var failsNextSave = false
}
