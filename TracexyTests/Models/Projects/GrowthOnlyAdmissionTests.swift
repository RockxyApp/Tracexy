import Foundation
import Testing
@testable import Tracexy

// MARK: - GrowthOnlyAdmissionTests

/// Every route that adds to a bounded list goes through the same rule: growth is
/// refused past the limit, while edits, reorders and removals are always allowed,
/// even above it. These are the routes that previously went around it.
@Suite("Growth past a limit is refused on every route")
@MainActor
struct GrowthOnlyAdmissionTests {
    // MARK: Internal

    @Test("Importing a Project refuses a workspace with more filter rules than may be added")
    func importChecksRuleRows() throws {
        let store = ProjectStore(maxProjects: 4, maxWorkspacesPerProject: 4, maxFilterRulesPerWorkspace: 12)
        let crowded = Self.project(named: "Crowded", rules: 13)
        #expect(throws: ProjectMutationError.filterRuleCapacityReached(limit: 12)) {
            try store.importProject(crowded)
        }
        #expect(store.projects.count == 1)

        let fitting = try store.importProject(Self.project(named: "Fitting", rules: 12))
        #expect(fitting.workspaces[0].filterRules.count == 12)

        store.updateLimits(maxProjects: 4, maxWorkspacesPerProject: 4, maxFilterRulesPerWorkspace: 64)
        let raised = try store.importProject(Self.project(named: "Raised", rules: 13))
        #expect(raised.workspaces[0].filterRules.count == 13)
    }

    @Test("A prepared import is refused for its rule rows before anything is frozen")
    func preparedAdoptChecksRuleRows() throws {
        let store = ProjectStore(maxProjects: 4, maxWorkspacesPerProject: 4, maxFilterRulesPerWorkspace: 2)
        #expect(throws: ProjectMutationError.filterRuleCapacityReached(limit: 2)) {
            try store.prepareTransition(.adopt(Self.project(named: "Three", rules: 3)))
        }
        #expect(!store.isCatalogTransitionPrepared)
        #expect(store.isMutable)
    }

    @Test("A new Project prepared before the limit fell is refused when it would be committed")
    func commitRechecksProjectLimit() async throws {
        let store = ProjectStore(maxProjects: 2, maxWorkspacesPerProject: 4)
        let prepared = try store.prepareTransition(.create(name: "Second"))
        // The limit is lowered while the transition waits for a capture to drain.
        store.updateLimits(maxProjects: 1, maxWorkspacesPerProject: 4)
        await #expect(throws: ProjectMutationError.capacityReached(limit: 1)) {
            try await store.commitPreparedTransition(prepared)
        }
        #expect(store.projects.count == 1)
        #expect(!store.isCatalogTransitionPrepared)
        // Switching and editing still work; nothing was left frozen.
        try store.renameProject(id: store.activeProjectID, to: "Still Mine")
        #expect(store.activeProject.name == "Still Mine")
    }

    @Test("An import prepared before the limits fell is refused for its rule rows at commit")
    func commitRechecksImportedRuleRows() async throws {
        let store = ProjectStore(maxProjects: 4, maxWorkspacesPerProject: 4, maxFilterRulesPerWorkspace: 8)
        let prepared = try store.prepareTransition(.adopt(Self.project(named: "Eight", rules: 8)))
        store.updateLimits(maxProjects: 4, maxWorkspacesPerProject: 4, maxFilterRulesPerWorkspace: 2)
        await #expect(throws: ProjectMutationError.filterRuleCapacityReached(limit: 2)) {
            try await store.commitPreparedTransition(prepared)
        }
        #expect(store.projects.count == 1)
        #expect(!store.isCatalogTransitionPrepared)

        let fitting = try store.prepareTransition(.adopt(Self.project(named: "Two", rules: 2)))
        try await store.commitPreparedTransition(fitting)
        #expect(store.projects.count == 2)
    }

    @Test("Switching Projects is never refused by a lowered limit")
    func selectIsNotGrowth() async throws {
        let store = ProjectStore(maxProjects: 3, maxWorkspacesPerProject: 4)
        let second = try store.createProject(name: "Second")
        _ = try store.createProject(name: "Third")
        store.updateLimits(maxProjects: 1, maxWorkspacesPerProject: 4)
        let prepared = try store.prepareTransition(.select(second.id))
        try await store.commitPreparedTransition(prepared)
        #expect(store.activeProjectID == second.id)
        #expect(store.projects.count == 3)
    }

    @Test("A list over its limit may be edited, reordered and shrunk, but not refilled")
    func overLimitListsDoNotRefill() {
        let stored = (0 ..< 5).map { _ in UUID() }
        let limit = 3
        // Edit and reorder: the same entries.
        #expect(ExpressionLibraryController.admits(stored.reversed(), replacing: stored, limit: limit))
        // Remove two: still above the limit, still allowed.
        #expect(ExpressionLibraryController.admits(Array(stored.prefix(3)), replacing: stored, limit: limit))
        // Remove one and add one: the list would stay over the limit, so refused.
        #expect(!ExpressionLibraryController.admits(
            Array(stored.dropLast()) + [UUID()],
            replacing: stored,
            limit: limit
        ))
        // Remove three and add one: back within the limit, allowed.
        #expect(ExpressionLibraryController.admits(Array(stored.prefix(2)) + [UUID()], replacing: stored, limit: limit))
        // Under the limit, adding up to it is allowed and one past it is not.
        let few = [UUID()]
        #expect(ExpressionLibraryController.admits(few + [UUID(), UUID()], replacing: few, limit: limit))
        #expect(!ExpressionLibraryController.admits(few + [UUID(), UUID(), UUID()], replacing: few, limit: limit))
    }

    @Test("Saved Session Expressions stop at 40 new names; replacing an existing name still works")
    func savedExpressionsStopAtForty() {
        let (defaults, suite) = Self.defaults()
        defer { TestPreferences.remove(suite) }
        let library = SessionExpressionLibrary()
        library.bind(to: defaults)
        for index in 0 ..< SessionExpressionLibrary.maximumSaved {
            #expect(library.save("port == \(index + 1)", named: "Rule \(index)"))
        }
        #expect(SessionExpressionLibrary.maximumSaved == 40)
        #expect(!library.save("tcp", named: "One Too Many"))
        #expect(library.saved.count == 40)
        #expect(library.save("udp", named: "rule 7"))
        #expect(library.saved.first { $0.name == "Rule 7" }?.expression == "udp")
    }

    @Test("A stored library this build cannot fully read is set aside before it can be overwritten")
    func unreadableLibrariesAreSetAside() throws {
        let (defaults, suite) = Self.defaults()
        defer { TestPreferences.remove(suite) }
        let buttonsKey = ExpressionLibraryStore.buttonsKey
        let macrosKey = ExpressionLibraryStore.macrosKey

        let good = FilterButton(label: "DNS", expression: "dns")
        let bad = FilterButton(label: "", expression: "tcp")
        let stored = try JSONEncoder().encode([good, bad])
        defaults.set(stored, forKey: buttonsKey)
        #expect(ExpressionLibraryStore.loadButtons(from: defaults) == [good])
        #expect(defaults.data(forKey: ExpressionLibraryStore.setAsideKey(for: buttonsKey)) == stored)

        // Saving the list this build kept does not touch what was set aside.
        ExpressionLibraryStore.save([good], to: defaults)
        _ = ExpressionLibraryStore.loadButtons(from: defaults)
        #expect(defaults.data(forKey: ExpressionLibraryStore.setAsideKey(for: buttonsKey)) == stored)

        let future = Data("{\"version\":2}".utf8)
        defaults.set(future, forKey: macrosKey)
        #expect(ExpressionLibraryStore.loadMacros(from: defaults).isEmpty)
        #expect(defaults.data(forKey: ExpressionLibraryStore.setAsideKey(for: macrosKey)) == future)
    }

    @Test("A fully readable library sets nothing aside")
    func readableLibrariesSetNothingAside() {
        let (defaults, suite) = Self.defaults()
        defer { TestPreferences.remove(suite) }
        ExpressionLibraryStore.save([FilterButton(label: "DNS", expression: "dns")], to: defaults)
        ExpressionLibraryStore.save([ExpressionMacro(name: "web", text: "port == 443")], to: defaults)
        #expect(ExpressionLibraryStore.loadButtons(from: defaults).count == 1)
        #expect(ExpressionLibraryStore.loadMacros(from: defaults).count == 1)
        #expect(defaults
            .object(forKey: ExpressionLibraryStore.setAsideKey(for: ExpressionLibraryStore.buttonsKey)) == nil)
        #expect(defaults
            .object(forKey: ExpressionLibraryStore.setAsideKey(for: ExpressionLibraryStore.macrosKey)) == nil)
    }

    // MARK: Private

    private static func project(named name: String, rules: Int) -> Project {
        let workspace = ProjectWorkspaceSnapshot(
            title: "Rules",
            filterRules: (0 ..< rules).map { index in
                ProjectFilterRuleSnapshot(
                    connector: "and",
                    field: "host",
                    filterOperator: "contains",
                    value: "h\(index)"
                )
            }
        )
        return Project(name: name, workspaces: [workspace], activeWorkspaceID: workspace.id)
    }

    private static func defaults() -> (UserDefaults, String) {
        let suite = "growth-admission-\(UUID().uuidString)"
        return (UserDefaults(suiteName: suite) ?? .standard, suite)
    }
}
