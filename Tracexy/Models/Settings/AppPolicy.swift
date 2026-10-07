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
    /// Maximum local Projects, including the default Project.
    var maxProjects: Int { get }
    /// Maximum user-created workspace tabs, including the first one.
    var maxWorkspaceTabs: Int { get }
    /// Maximum saved focus sets in the sidebar's focus library.
    var maxFocusSets: Int { get }
    /// Maximum pinned favorite hosts.
    var maxPinnedHosts: Int { get }
    /// Maximum advanced session-filter rule rows in a single workspace.
    var maxSessionFilterRules: Int { get }
    /// Maximum one-click filter buttons a Project may grow to.
    var maxFilterButtons: Int { get }
    /// Maximum named expression macros a Project may grow to.
    var maxExpressionMacros: Int { get }
    /// Maximum local GeoIP/ASN database files a Project may refer to.
    var maxGeoIPDatabases: Int { get }
}

extension AppPolicy {
    var maxProjects: Int {
        3
    }

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

    var maxFilterButtons: Int {
        10
    }

    var maxExpressionMacros: Int {
        10
    }

    var maxGeoIPDatabases: Int {
        1
    }
}

// MARK: - DefaultAppPolicy

/// The baseline policy every build starts from. Values are stated explicitly
/// rather than inherited from the protocol extension so this file reads as the
/// single answer to "what are the limits?".
struct DefaultAppPolicy: AppPolicy {
    let maxProjects = 3
    let maxWorkspaceTabs = 8
    let maxFocusSets = 5
    let maxPinnedHosts = 5
    let maxSessionFilterRules = 12
    let maxFilterButtons = 10
    let maxExpressionMacros = 10
    let maxGeoIPDatabases = 1
}
