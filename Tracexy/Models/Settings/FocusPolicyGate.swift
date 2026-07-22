import Foundation

// MARK: - FocusPolicyGate

/// Capacity gate for the saved-focus library: named focus sets and pinned
/// hosts.
///
/// The gate exists so the "may this be added?" decision lives in one testable
/// place instead of being spread across the coordinator and the views that
/// call it. It takes plain numbers, not an ``AppPolicy`` — whoever builds the
/// gate has already resolved the policy, and a type that never sees the policy
/// cannot accidentally start branching on it.
struct FocusPolicyGate: Sendable {
    let maxFocusSets: Int
    let maxPinnedHosts: Int

    /// Whether another *new* focus set fits alongside `existing`.
    func canInsertFocusSet(into existing: [FocusSet]) -> Bool {
        existing.count < maxFocusSets
    }

    /// Whether another host can be pinned alongside `existing`.
    func canPinHost(into existing: [String]) -> Bool {
        existing.count < maxPinnedHosts
    }

    /// Editing a set that is already stored is always allowed — the limit is on
    /// how many exist, not on how often they change.
    func validateSavingFocusSet(_ set: FocusSet, into existing: [FocusSet]) throws {
        guard !existing.contains(where: { $0.id == set.id }) else {
            return
        }
        guard canInsertFocusSet(into: existing) else {
            throw AppPolicyViolation.focusSetLimitReached(limit: maxFocusSets)
        }
    }

    /// Unpinning is always allowed; only growing the list is capped.
    func validatePinningHost(_ host: String, into existing: [String]) throws {
        guard !existing.contains(host) else {
            return
        }
        guard canPinHost(into: existing) else {
            throw AppPolicyViolation.pinnedHostLimitReached(limit: maxPinnedHosts)
        }
    }
}
