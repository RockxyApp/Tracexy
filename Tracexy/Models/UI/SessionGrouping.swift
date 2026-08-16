import Foundation

/// How the session list is grouped.
///
/// `none` — the raw observed sessions — is the default: a real high-volume
/// capture collapses into a handful of guessed rows under `action`, so the
/// honest starting point is every session, flat. The grouped modes are opt-in.
///
/// Grouping is inference, so it must be switchable off. Correlation can be
/// wrong — a shared CDN address, a resolver cache older than the causal window —
/// and a user who suspects it needs the raw sessions back without hunting for a
/// preference. `none` is that escape hatch, and it is one click away at all
/// times, not buried in Settings.
enum SessionGrouping: String, CaseIterable, Identifiable, Hashable {
    /// One row per correlated action, its sessions nested beneath. Inferred.
    case action
    /// One row per remote host. Observed, not inferred.
    case host
    /// One row per owning process. Observed, not inferred.
    case process
    /// One row per session, exactly as decoded. No grouping at all.
    case none

    // MARK: Internal

    nonisolated var id: String {
        rawValue
    }

    nonisolated var title: String {
        switch self {
        case .action: "Action"
        case .host: "Host"
        case .process: "Process"
        case .none: "None (flat)"
        }
    }

    nonisolated var systemImage: String {
        switch self {
        case .action: "list.bullet.indent"
        case .host: "globe"
        case .process: "app.badge"
        case .none: "list.bullet"
        }
    }

    /// Whether rows in this mode are a *claim* about causality (and therefore
    /// carry evidence and a confidence tier) or a plain observed attribute.
    ///
    /// Host and process grouping read a field that was on the wire; only `action`
    /// infers that separate conversations belong to one intent, so only `action`
    /// has to argue for itself.
    nonisolated var isInferred: Bool {
        self == .action
    }
}
