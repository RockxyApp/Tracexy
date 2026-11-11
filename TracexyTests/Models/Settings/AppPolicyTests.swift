import Foundation
import Testing
@testable import Tracexy

// MARK: - TestPolicy

/// A policy built per-test, so a test states its own limits instead of
/// inheriting whatever the shipping baseline happens to be today.
private struct TestPolicy: AppPolicy {
    var maxProjects = 3
    var maxWorkspaceTabs = 8
    var maxFocusSets = 5
    var maxPinnedHosts = 5
    var maxSessionFilterRules = 12
}

// MARK: - AppPolicyDefaultsTests

@Suite("App policy defaults")
struct AppPolicyDefaultsTests {
    @Test("The shipping baseline caps local projects at three")
    func defaultProjectCap() {
        #expect(DefaultAppPolicy().maxProjects == 3)
    }

    @Test("The shipping baseline caps advanced filter rules at 12")
    func defaultSessionFilterRuleCap() {
        #expect(DefaultAppPolicy().maxSessionFilterRules == 12)
    }

    @Test("The protocol extension supplies the same rule cap when a policy omits it")
    func extensionSuppliesRuleCap() {
        struct Bare: AppPolicy {}
        #expect(Bare().maxSessionFilterRules == 12)
    }

    /// Every published Community number, stated here so none can be changed in
    /// silence.
    ///
    /// The licensed build's unlicensed state does not restate these numbers: it
    /// reads them from ``DefaultAppPolicy`` so the two can never disagree. That
    /// is the right dependency, but it means a quiet edit to a number here
    /// would raise or lower what an unlicensed licensed build allows, with no
    /// test anywhere failing. Only ``maxProjects`` and ``maxSessionFilterRules``
    /// were pinned before; the other six were free to drift.
    @Test("Every shipping limit is the published Community number")
    func everyDefaultIsPinned() {
        let policy = DefaultAppPolicy()
        #expect(policy.maxProjects == 3)
        #expect(policy.maxWorkspaceTabs == 8)
        #expect(policy.maxFocusSets == 5)
        #expect(policy.maxPinnedHosts == 5)
        #expect(policy.maxSessionFilterRules == 12)
        #expect(policy.maxFilterButtons == 10)
        #expect(policy.maxExpressionMacros == 10)
        #expect(policy.maxGeoIPDatabases == 1)
    }

    /// `DefaultAppPolicy` states every value itself rather than inheriting from
    /// the protocol extension. The two must agree, or which number applies would
    /// depend on whether a member happened to be written out — the drift that
    /// once silently gave a policy the Community cap of three Projects.
    @Test("The stated baseline and the protocol extension agree on every limit")
    func baselineMatchesExtension() {
        struct Bare: AppPolicy {}
        let stated = DefaultAppPolicy()
        let inherited = Bare()
        #expect(stated.maxProjects == inherited.maxProjects)
        #expect(stated.maxWorkspaceTabs == inherited.maxWorkspaceTabs)
        #expect(stated.maxFocusSets == inherited.maxFocusSets)
        #expect(stated.maxPinnedHosts == inherited.maxPinnedHosts)
        #expect(stated.maxSessionFilterRules == inherited.maxSessionFilterRules)
        #expect(stated.maxFilterButtons == inherited.maxFilterButtons)
        #expect(stated.maxExpressionMacros == inherited.maxExpressionMacros)
        #expect(stated.maxGeoIPDatabases == inherited.maxGeoIPDatabases)
    }
}

// MARK: - FocusPolicyGateTests

@Suite("Focus library capacity gate")
struct FocusPolicyGateTests {
    // MARK: Internal

    @Test("A new focus set is accepted below the cap")
    func acceptsBelowLimit() throws {
        let gate = FocusPolicyGate(maxFocusSets: 3, maxPinnedHosts: 3)
        let existing = makeSets(2)
        #expect(gate.canInsertFocusSet(into: existing))
        try gate.validateSavingFocusSet(makeSet("third"), into: existing)
    }

    @Test("A new focus set is rejected at the cap")
    func rejectsAtLimit() {
        let gate = FocusPolicyGate(maxFocusSets: 3, maxPinnedHosts: 3)
        let existing = makeSets(3)
        #expect(!gate.canInsertFocusSet(into: existing))
        #expect(throws: AppPolicyViolation.focusSetLimitReached(limit: 3)) {
            try gate.validateSavingFocusSet(makeSet("fourth"), into: existing)
        }
    }

    @Test("Editing a stored set stays allowed at the cap")
    func editingAtLimitIsAllowed() throws {
        let gate = FocusPolicyGate(maxFocusSets: 3, maxPinnedHosts: 3)
        var existing = makeSets(3)
        existing[1].name = "renamed"
        try gate.validateSavingFocusSet(existing[1], into: existing)
    }

    @Test("Pinning is capped, unpinning an already-pinned host is not")
    func pinningRespectsLimit() throws {
        let gate = FocusPolicyGate(maxFocusSets: 3, maxPinnedHosts: 2)
        try gate.validatePinningHost("b.example", into: ["a.example"])
        #expect(throws: AppPolicyViolation.pinnedHostLimitReached(limit: 2)) {
            try gate.validatePinningHost("c.example", into: ["a.example", "b.example"])
        }
        // Already pinned — the caller is toggling it off, which never grows the list.
        try gate.validatePinningHost("a.example", into: ["a.example", "b.example"])
    }

    // MARK: Private

    private func makeSet(_ name: String) -> FocusSet {
        FocusSet(name: name, rules: [])
    }

    private func makeSets(_ count: Int) -> [FocusSet] {
        (0 ..< count).map { makeSet("set \($0)") }
    }
}

// MARK: - WorkspaceStorePolicyTests

@MainActor
@Suite("Workspace tab capacity")
struct WorkspaceStorePolicyTests {
    @Test("Tabs are added up to the injected cap, then refused with a reason")
    func stopsAtInjectedCap() throws {
        let store = WorkspaceStore(maxWorkspaces: 3)
        // The store opens with one workspace already present.
        #expect(store.workspaces.count == 1)
        try store.addWorkspace()
        try store.addWorkspace()
        #expect(store.workspaces.count == 3)
        #expect(!store.canAddWorkspace)
        #expect(throws: AppPolicyViolation.workspaceTabLimitReached(limit: 3)) {
            try store.addWorkspace()
        }
    }

    @Test("A policy with the caps opened up accepts what the baseline refuses")
    func openPolicyAcceptsMore() throws {
        let baseline = DefaultAppPolicy()
        let opened = TestPolicy(maxWorkspaceTabs: baseline.maxWorkspaceTabs + 4)
        let store = WorkspaceStore(maxWorkspaces: opened.maxWorkspaceTabs)
        for _ in 1 ..< opened.maxWorkspaceTabs {
            try store.addWorkspace()
        }
        #expect(store.workspaces.count == opened.maxWorkspaceTabs)
        #expect(store.workspaces.count > baseline.maxWorkspaceTabs)
    }
}

// MARK: - CoordinatorPolicyTests

@MainActor
@Suite("Policy reaches the coordinator's state owners")
struct CoordinatorPolicyTests {
    @Test("The injected policy decides the tab cap and the focus gate's limits")
    func injectedPolicyIsPlumbedThrough() {
        let policy = TestPolicy(maxProjects: 2, maxWorkspaceTabs: 2, maxFocusSets: 1, maxPinnedHosts: 4)
        let coordinator = MainContentCoordinator(policy: policy)
        #expect(coordinator.projectStore.maxProjects == 2)
        #expect(coordinator.workspaces.maxWorkspaces == 2)
        #expect(coordinator.focusGate.maxFocusSets == 1)
        #expect(coordinator.focusGate.maxPinnedHosts == 4)
    }

    @Test("Saving past the focus-set cap changes nothing and says why")
    func refusedSaveIsExplained() async {
        let environment = ProjectIsolationEnvironment(name: "focus-cap")
        defer { environment.tearDown() }
        let capped = environment.makeCoordinator(policy: TestPolicy(maxFocusSets: 1))
        await capped.hydrateProjectsOnLaunch()

        let accepted = FocusSet(name: "accepted", rules: [])
        let refused = FocusSet(name: "refused", rules: [])

        capped.saveFocusSet(accepted)
        #expect(capped.focusSets.count == 1)
        #expect(capped.policyNotice == nil)

        capped.saveFocusSet(refused)
        #expect(capped.focusSets.count == 1)
        #expect(!capped.focusSets.contains { $0.id == refused.id })
        #expect(capped.policyNotice != nil)
        #expect(!capped.canAddFocusSet)
    }
}
