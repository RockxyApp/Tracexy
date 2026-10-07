import Foundation
import Testing
@testable import Tracexy

// MARK: - LimitPolicy

/// A policy each test states in full, so nothing depends on the shipping baseline.
private struct LimitPolicy: AppPolicy {
    var maxProjects = 3
    var maxWorkspaceTabs = 8
    var maxFocusSets = 5
    var maxPinnedHosts = 5
    var maxSessionFilterRules = 12
}

// MARK: - ProjectStoreGrowthLimitTests

/// Limits govern growth only. Content above the current limit is
/// never refused on load, never frozen, and never truncated.
@Suite("Project limits govern growth, not existing content")
@MainActor
struct ProjectStoreGrowthLimitTests {
    // MARK: Internal

    @Test("A catalog with more Projects than the limit loads, edits and only refuses creation")
    func overLimitCatalogLoads() async throws {
        let directory = Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let roomy = ProjectStore(
            maxProjects: 8,
            maxWorkspacesPerProject: 4,
            repository: JSONProjectCatalogRepository(directoryURL: directory)
        )
        await roomy.loadPersistedCatalog()
        for name in ["Alpha", "Bravo", "Charlie", "Delta"] {
            _ = try roomy.createProject(name: name)
        }
        await roomy.waitForPendingPersistence()
        #expect(roomy.projects.count == 5)

        let capped = ProjectStore(
            maxProjects: 3,
            maxWorkspacesPerProject: 4,
            repository: JSONProjectCatalogRepository(directoryURL: directory)
        )
        await capped.loadPersistedCatalog()
        #expect(capped.loadState == .ready)
        #expect(capped.projects.count == 5)
        #expect(capped.isOverProjectLimit)
        #expect(!capped.canCreateProject)

        let bravo = try #require(capped.projects.first { $0.name == "Bravo" })
        try capped.selectProject(id: bravo.id)
        try capped.renameProject(id: bravo.id, to: "Bravo Renamed")
        #expect(capped.activeProject.name == "Bravo Renamed")
        #expect(throws: ProjectMutationError.capacityReached(limit: 3)) {
            try capped.createProject(name: "Echo")
        }

        // Deleting one is not enough while still above the limit; reaching it is.
        try capped.deleteProject(id: #require(capped.projects.first { $0.name == "Alpha" }).id)
        #expect(!capped.canCreateProject)
        try capped.deleteProject(id: #require(capped.projects.first { $0.name == "Charlie" }).id)
        try capped.deleteProject(id: #require(capped.projects.first { $0.name == "Delta" }).id)
        #expect(capped.projects.count == 2)
        #expect(capped.canCreateProject)
        #expect(!capped.isOverProjectLimit)
    }

    @Test("Raising the limit at runtime allows creation; values stay within the storage ceiling")
    func updateLimitsRaisesAndClamps() throws {
        let store = ProjectStore(maxProjects: 1, maxWorkspacesPerProject: 1)
        #expect(!store.canCreateProject)
        store.updateLimits(maxProjects: 1_000_000, maxWorkspacesPerProject: 1_000_000)
        #expect(store.maxProjects == ProjectLimits.maximumProjects)
        #expect(store.maxWorkspacesPerProject == ProjectLimits.maximumWorkspacesPerProject)
        _ = try store.createProject(name: "Second")
        #expect(store.projects.count == 2)
    }

    @Test("Boundary: the ceiling is reachable and nothing past it can be created")
    func ceilingBoundary() throws {
        let store = ProjectStore(
            maxProjects: ProjectLimits.maximumProjects,
            maxWorkspacesPerProject: 1
        )
        for index in 1 ..< ProjectLimits.maximumProjects - 1 {
            _ = try store.createProject(name: "Project \(index)")
        }
        #expect(store.projects.count == ProjectLimits.maximumProjects - 1)
        #expect(store.canCreateProject)
        _ = try store.createProject(name: "Last")
        #expect(store.projects.count == ProjectLimits.maximumProjects)
        #expect(!store.canCreateProject)
        #expect(throws: ProjectMutationError.capacityReached(limit: ProjectLimits.maximumProjects)) {
            try store.createProject(name: "Past the ceiling")
        }

        // Lowering the limit keeps all of them.
        store.updateLimits(maxProjects: 3, maxWorkspacesPerProject: 1)
        #expect(store.projects.count == ProjectLimits.maximumProjects)
        #expect(store.isOverProjectLimit)
        try store.renameProject(id: store.projects[40].id, to: "Still Editable")
    }

    @Test("A Project with more tabs than the limit keeps saving, closing tabs, but cannot grow")
    func overLimitWorkspacesKeepSaving() throws {
        let store = ProjectStore(maxProjects: 2, maxWorkspacesPerProject: 8)
        let six = (0 ..< 6).map { ProjectWorkspaceSnapshot(title: "Tab \($0)") }
        try store.updateActiveProjectWorkspaces(six, activeWorkspaceID: six[0].id)

        store.updateLimits(maxProjects: 2, maxWorkspacesPerProject: 2)
        try store.updateActiveProjectWorkspaces(six, activeWorkspaceID: six[1].id)
        let five = Array(six.prefix(5))
        try store.updateActiveProjectWorkspaces(five, activeWorkspaceID: five[0].id)
        #expect(store.activeProject.workspaces.count == 5)

        let grown = five + [ProjectWorkspaceSnapshot(title: "New")]
        #expect(throws: ProjectMutationError.workspaceCapacityReached(limit: 2)) {
            try store.updateActiveProjectWorkspaces(grown, activeWorkspaceID: grown[0].id)
        }
    }

    @Test("Stored filter rows above the growth limit are restored intact")
    @MainActor
    func storedRulesAreNotTruncated() {
        let rules = (0 ..< 30).map { index in
            SessionFilterRule(field: .host, filterOperator: .contains, value: "host-\(index)")
        }
        let workspace = WorkspaceState(title: "Rules", isClosable: true)
        workspace.filterRules = rules
        let snapshot = ProjectWorkspaceSnapshot(capturing: workspace)
        let restored = snapshot.hydrateWorkspaceState(allowsAutomaticInspectorReveal: nil)
        #expect(restored.filterRules.map(\.value) == rules.map(\.value))
    }

    // MARK: Private

    private static func temporaryDirectory() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-growth-limits-\(UUID().uuidString)", isDirectory: true)
    }
}

// MARK: - CoordinatorApplyPolicyTests

@Suite("Limits can be replaced while the app runs")
@MainActor
struct CoordinatorApplyPolicyTests {
    @Test("applyPolicy reaches the store, the focus gate, every tab store and the rule limit")
    func applyPolicyReachesEveryOwner() {
        let coordinator = MainContentCoordinator(policy: LimitPolicy(
            maxProjects: 2,
            maxWorkspaceTabs: 2,
            maxFocusSets: 1,
            maxPinnedHosts: 1,
            maxSessionFilterRules: 3
        ))
        coordinator.applyPolicy(LimitPolicy(
            maxProjects: 20,
            maxWorkspaceTabs: 1_000_000,
            maxFocusSets: 40,
            maxPinnedHosts: 50,
            maxSessionFilterRules: 1_000_000
        ))
        #expect(coordinator.projectStore.maxProjects == 20)
        #expect(coordinator.workspaces.maxWorkspaces == ProjectLimits.maximumWorkspacesPerProject)
        #expect(coordinator.focusGate.maxFocusSets == 40)
        #expect(coordinator.focusGate.maxPinnedHosts == 50)
        #expect(coordinator.sessionFilterRuleLimit == ProjectLimits.maximumFilterRules)
    }

    @Test("Lowering the tab limit closes nothing and refuses only a new tab")
    func loweringTabsKeepsOpenTabs() throws {
        let coordinator = MainContentCoordinator(policy: LimitPolicy(maxWorkspaceTabs: 6))
        for _ in 1 ..< 5 {
            try coordinator.workspaces.addWorkspace()
        }
        #expect(coordinator.workspaces.workspaces.count == 5)

        coordinator.applyPolicy(LimitPolicy(maxWorkspaceTabs: 2))
        #expect(coordinator.workspaces.workspaces.count == 5)
        #expect(!coordinator.workspaces.canAddWorkspace)
        #expect(throws: AppPolicyViolation.workspaceTabLimitReached(limit: 2)) {
            try coordinator.workspaces.addWorkspace()
        }

        coordinator.applyPolicy(LimitPolicy(maxWorkspaceTabs: 8))
        #expect(coordinator.workspaces.canAddWorkspace)
    }

    @Test("Focus sets and pinned hosts above a lowered limit stay; only new ones are refused")
    func loweringFocusLimitsKeepsLibrary() async {
        let environment = ProjectIsolationEnvironment(name: "apply-policy-focus")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator(policy: LimitPolicy(maxFocusSets: 5, maxPinnedHosts: 5))
        await coordinator.hydrateProjectsOnLaunch()
        for index in 0 ..< 4 {
            coordinator.saveFocusSet(FocusSet(name: "set \(index)", rules: []))
            coordinator.togglePinHost("host-\(index).example")
        }
        #expect(coordinator.focusSets.count == 4)
        #expect(coordinator.pinnedHosts.count == 4)

        coordinator.applyPolicy(LimitPolicy(maxFocusSets: 2, maxPinnedHosts: 2))
        #expect(coordinator.focusSets.count == 4)
        #expect(coordinator.pinnedHosts.count == 4)
        #expect(!coordinator.canAddFocusSet)

        var edited = coordinator.focusSets[3]
        edited.name = "renamed"
        coordinator.saveFocusSet(edited)
        #expect(coordinator.focusSets[3].name == "renamed")
        #expect(coordinator.policyNotice == nil)

        coordinator.saveFocusSet(FocusSet(name: "refused", rules: []))
        #expect(coordinator.focusSets.count == 4)
        #expect(coordinator.policyNotice != nil)

        coordinator.togglePinHost("host-0.example")
        #expect(coordinator.pinnedHosts.count == 3)
    }

    @Test("Relaunching under a lower Project limit keeps every Project and refuses only creation")
    func relaunchUnderLowerLimit() async throws {
        let environment = ProjectIsolationEnvironment(name: "apply-policy-relaunch", persistsCatalog: true)
        defer { environment.tearDown() }
        let roomy = environment.makeCoordinator(policy: LimitPolicy(maxProjects: 8))
        await roomy.hydrateProjectsOnLaunch()
        for name in ["Alpha", "Bravo", "Charlie", "Delta"] {
            _ = try #require(roomy.createProject(named: name))
            #expect(await roomy.waitForProjectTransition())
        }
        #expect(roomy.projectStore.projects.count == 5)
        await roomy.flushProjectStateForTermination()

        let capped = environment.makeCoordinator(policy: LimitPolicy(maxProjects: 3))
        await capped.hydrateProjectsOnLaunch()
        #expect(capped.projectStore.loadState == .ready)
        #expect(capped.projectStore.projects.count == 5)
        #expect(capped.projectStore.isOverProjectLimit)

        let alpha = try #require(capped.projectStore.projects.first { $0.name == "Alpha" })
        #expect(capped.switchToProject(id: alpha.id))
        #expect(await capped.waitForProjectTransition())
        #expect(capped.projectStore.activeProjectID == alpha.id)

        #expect(capped.createProject(named: "Echo") == nil)
        #expect(capped.lastProjectOperationError == .capacityReached(limit: 3))

        capped.applyPolicy(LimitPolicy(maxProjects: 8))
        _ = try #require(capped.createProject(named: "Echo"))
        #expect(await capped.waitForProjectTransition())
        #expect(capped.projectStore.projects.count == 6)
    }
}
