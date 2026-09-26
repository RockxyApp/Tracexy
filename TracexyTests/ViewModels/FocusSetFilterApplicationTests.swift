import Foundation
import Testing
@testable import Tracexy

// MARK: - CapPolicy

/// A policy that states its own advanced-rule cap so a test does not depend on
/// the shipping baseline.
private struct CapPolicy: AppPolicy {
    var maxWorkspaceTabs = 8
    var maxFocusSets = 5
    var maxPinnedHosts = 5
    var maxSessionFilterRules = 12
}

// MARK: - FocusSetFilterApplicationTests

@MainActor
@Suite("Applying a Focus Set into a workspace")
struct FocusSetFilterApplicationTests {
    // MARK: Internal

    @Test("A Focus Set above the row limit is applied intact; only adding rows is limited")
    func overLimitFocusSetIsPreserved() throws {
        let env = try makeCoordinator(maxRules: 12)
        defer { env.teardown() }
        let coordinator = env.coordinator

        let bigRules = (0 ..< 30).map { index in
            SessionFilterRule(field: .host, filterOperator: .contains, value: "host-\(index)")
        }
        coordinator.applyFocusSet(FocusSet(name: "oversized", rules: bigRules))

        #expect(coordinator.activeWorkspace.filterRules.map(\.value) == bigRules.map(\.value))
        #expect(coordinator.activeWorkspace.isAdvancedFilterVisible)
        #expect(coordinator.sessionFilterRuleLimit == 12)
    }

    @Test("A Focus Set past what a workspace can store is bounded by the storage ceiling")
    func focusSetIsBoundedByStorageCeiling() throws {
        let env = try makeCoordinator(maxRules: 12)
        defer { env.teardown() }
        let coordinator = env.coordinator

        let hostile = (0 ..< ProjectLimits.maximumFilterRules + 6).map { index in
            SessionFilterRule(field: .host, filterOperator: .contains, value: "host-\(index)")
        }
        coordinator.applyFocusSet(FocusSet(name: "hostile", rules: hostile))

        #expect(coordinator.activeWorkspace.filterRules.count == ProjectLimits.maximumFilterRules)
    }

    @Test("An empty Focus Set never leaves the builder with zero rows")
    func emptyFocusSetKeepsOneRow() throws {
        let env = try makeCoordinator(maxRules: 12)
        defer { env.teardown() }
        let coordinator = env.coordinator

        coordinator.applyFocusSet(FocusSet(name: "empty", rules: []))

        #expect(coordinator.activeWorkspace.filterRules.count == 1)
    }

    @Test("A within-cap Focus Set is applied verbatim")
    func withinCapIsVerbatim() throws {
        let env = try makeCoordinator(maxRules: 12)
        defer { env.teardown() }
        let coordinator = env.coordinator

        let rules = [
            SessionFilterRule(field: .proto, filterOperator: .contains, value: "TLS"),
            SessionFilterRule(connector: .or, field: .host, filterOperator: .contains, value: "example"),
        ]
        coordinator.applyFocusSet(FocusSet(name: "pair", rules: rules))

        #expect(coordinator.activeWorkspace.filterRules.count == 2)
    }

    @Test("A new Focus Set holds at most the rows a workspace may add; an existing one keeps its rows")
    func newFocusSetIsBoundedByTheLimit() async {
        let environment = ProjectIsolationEnvironment(name: "focus-set-rule-limit")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator(policy: CapPolicy(maxSessionFilterRules: 12))
        await coordinator.hydrateProjectsOnLaunch()
        let many = (0 ..< 30).map { index in
            SessionFilterRule(field: .host, filterOperator: .contains, value: "host-\(index)")
        }
        coordinator.activeWorkspace.filterRules = many
        #expect(coordinator.draftFocusSet().rules.count == 12)

        let fresh = FocusSet(name: "new", rules: many)
        coordinator.saveFocusSet(fresh)
        #expect(coordinator.focusSets.first { $0.id == fresh.id }?.rules.count == 12)

        // A set above the row limit keeps its rows when re-saved.
        let kept = FocusSet(name: "kept", rules: many)
        coordinator.focusSets.append(kept)
        var renamed = kept
        renamed.name = "renamed"
        coordinator.saveFocusSet(renamed)
        #expect(coordinator.focusSets.first { $0.id == kept.id }?.rules.count == 30)
    }

    // MARK: Private

    private struct Environment {
        let coordinator: MainContentCoordinator
        let teardown: () -> Void
    }

    private func makeCoordinator(maxRules: Int, function: String = #function) throws -> Environment {
        let suiteName = "com.amunx.tracexy.tests.\(function).\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        let coordinator = MainContentCoordinator(
            policy: CapPolicy(maxSessionFilterRules: maxRules),
            layoutPreferences: WorkspaceLayoutPreferences(defaults: defaults)
        )
        return Environment(coordinator: coordinator) {
            TestPreferences.remove(suiteName)
        }
    }
}
