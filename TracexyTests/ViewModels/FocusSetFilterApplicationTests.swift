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

    @Test("An oversized imported Focus Set is normalized down to the cap")
    func oversizedFocusSetIsClamped() throws {
        let env = try makeCoordinator(maxRules: 12)
        defer { env.teardown() }
        let coordinator = env.coordinator

        let bigRules = (0 ..< 30).map { index in
            SessionFilterRule(field: .host, filterOperator: .contains, value: "host-\(index)")
        }
        coordinator.applyFocusSet(FocusSet(name: "oversized", rules: bigRules))

        #expect(coordinator.activeWorkspace.filterRules.count == 12)
        #expect(coordinator.activeWorkspace.isAdvancedFilterVisible)
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
            defaults.removePersistentDomain(forName: suiteName)
        }
    }
}
