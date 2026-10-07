import Foundation

// MARK: - Capacity limits

@MainActor
extension MainContentCoordinator {
    /// Advanced Session Filter rows a workspace may grow to: the policy's number,
    /// never above what a workspace can persist. Views read this, not the raw
    /// policy, so a row the catalog would refuse to save is never offered.
    var sessionFilterRuleLimit: Int {
        min(max(1, policy.maxSessionFilterRules), ProjectLimits.maximumFilterRules)
    }

    /// Replace the limits in force without relaunching.
    ///
    /// Limits only ever govern *growth* — creating a Project, opening a tab,
    /// adding a filter row, saving a new focus set, pinning a host. Lowering one
    /// below what already exists removes, hides and truncates nothing: every
    /// Project, tab, rule, focus set and pinned host stays readable, editable and
    /// exportable, and only adding past the new limit is refused.
    func applyPolicy(_ newPolicy: any AppPolicy) {
        policy = newPolicy
        let gate = FocusPolicyGate(
            maxFocusSets: newPolicy.maxFocusSets,
            maxPinnedHosts: newPolicy.maxPinnedHosts
        )
        if gate.maxFocusSets != focusGate.maxFocusSets || gate.maxPinnedHosts != focusGate.maxPinnedHosts {
            focusGate = gate
        }
        projectStore.updateLimits(
            maxProjects: newPolicy.maxProjects,
            maxWorkspacesPerProject: newPolicy.maxWorkspaceTabs,
            maxFilterRulesPerWorkspace: newPolicy.maxSessionFilterRules
        )
        activeRuntime.workspaces.updateLimit(newPolicy.maxWorkspaceTabs)
        for runtime in projectRuntimes.values {
            runtime.workspaces.updateLimit(newPolicy.maxWorkspaceTabs)
        }
        // A notice about a limit that no longer applies would now be wrong.
        policyNotice = nil
    }
}
