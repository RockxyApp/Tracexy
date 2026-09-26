import Foundation

// MARK: - AppPolicyViolation

/// Raised when an action would exceed an ``AppPolicy`` limit.
///
/// A violation is always surfaced to the user with an honest message — the
/// caller shows `errorDescription`. Never crash on one, and never swallow one
/// into a silent no-op: from the user's side a button that does nothing is
/// indistinguishable from a bug.
enum AppPolicyViolation: LocalizedError, Equatable {
    case workspaceTabLimitReached(limit: Int)
    case focusSetLimitReached(limit: Int)
    case pinnedHostLimitReached(limit: Int)

    // MARK: Internal

    var errorDescription: String? {
        switch self {
        case let .workspaceTabLimitReached(limit):
            String(localized: "New workspace tabs can be added up to \(limit) per Project. Open tabs stay available.")
        case let .focusSetLimitReached(limit):
            String(localized: "New focus sets can be saved up to \(limit). Saved focus sets stay available.")
        case let .pinnedHostLimitReached(limit):
            String(localized: "Hosts can be pinned up to \(limit). Pinned hosts stay pinned.")
        }
    }
}
