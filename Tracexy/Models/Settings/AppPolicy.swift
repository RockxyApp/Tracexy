import Foundation

// MARK: - AppPolicy

/// App-level capacity and capability limits.
///
/// Limits are *injected* at the composition root rather than read from a
/// global, so the types that own state never learn where their numbers came
/// from. `Core/` engines never see this protocol at all: capture, decode and
/// session building stay limit-neutral, and only app-layer state owners and
/// their gates are handed plain `Int`/`Bool` values through their own
/// initializers.
///
/// The shipping baseline is ``DefaultAppPolicy``.
protocol AppPolicy: Sendable {
    /// Maximum user-created workspace tabs, including the first one.
    var maxWorkspaceTabs: Int { get }
    /// Maximum saved focus sets in the sidebar's focus library.
    var maxFocusSets: Int { get }
    /// Maximum pinned favorite hosts.
    var maxPinnedHosts: Int { get }
    /// Maximum advanced session-filter rule rows in a single workspace.
    var maxSessionFilterRules: Int { get }
}

extension AppPolicy {
    var maxWorkspaceTabs: Int {
        8
    }

    var maxFocusSets: Int {
        5
    }

    var maxPinnedHosts: Int {
        5
    }

    var maxSessionFilterRules: Int {
        12
    }
}

// MARK: - DefaultAppPolicy

/// The baseline policy every build starts from. Values are stated explicitly
/// rather than inherited from the protocol extension so this file reads as the
/// single answer to "what are the limits?".
struct DefaultAppPolicy: AppPolicy {
    let maxWorkspaceTabs = 8
    let maxFocusSets = 5
    let maxPinnedHosts = 5
    let maxSessionFilterRules = 12
}
