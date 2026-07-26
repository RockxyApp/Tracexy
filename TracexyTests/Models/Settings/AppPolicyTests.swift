import Foundation
import Testing
@testable import Tracexy

// MARK: - TestPolicy

/// A policy built per-test, so a test states its own limits instead of
/// inheriting whatever the shipping baseline happens to be today.
private struct TestPolicy: AppPolicy {
    var maxWorkspaceTabs = 8
    var maxFocusSets = 5
    var maxPinnedHosts = 5
    var maxSessionFilterRules = 12
}

// MARK: - AppPolicyDefaultsTests

@Suite("App policy defaults")
struct AppPolicyDefaultsTests {
    @Test("The shipping baseline caps advanced filter rules at 12")
    func defaultSessionFilterRuleCap() {
        #expect(DefaultAppPolicy().maxSessionFilterRules == 12)
    }

    @Test("The protocol extension supplies the same rule cap when a policy omits it")
    func extensionSuppliesRuleCap() {
        struct Bare: AppPolicy {}
        #expect(Bare().maxSessionFilterRules == 12)
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
        let policy = TestPolicy(maxWorkspaceTabs: 2, maxFocusSets: 1, maxPinnedHosts: 4)
        let coordinator = MainContentCoordinator(policy: policy)
        #expect(coordinator.workspaces.maxWorkspaces == 2)
        #expect(coordinator.focusGate.maxFocusSets == 1)
        #expect(coordinator.focusGate.maxPinnedHosts == 4)
    }

    @Test("Saving past the focus-set cap changes nothing and says why")
    func refusedSaveIsExplained() {
        // Focus sets persist to the app's shared defaults, so the cap is set
        // relative to whatever is already stored and the additions are undone
        // afterwards. Otherwise running the suite would leave sets behind.
        let coordinator = MainContentCoordinator(policy: TestPolicy())
        let stored = coordinator.focusSets.count
        let capped = MainContentCoordinator(policy: TestPolicy(maxFocusSets: stored + 1))

        let accepted = FocusSet(name: "accepted", rules: [])
        let refused = FocusSet(name: "refused", rules: [])
        defer { capped.deleteFocusSet(accepted) }

        capped.saveFocusSet(accepted)
        #expect(capped.focusSets.count == stored + 1)
        #expect(capped.policyNotice == nil)

        capped.saveFocusSet(refused)
        #expect(capped.focusSets.count == stored + 1)
        #expect(!capped.focusSets.contains { $0.id == refused.id })
        #expect(capped.policyNotice != nil)
        #expect(!capped.canAddFocusSet)
    }
}
