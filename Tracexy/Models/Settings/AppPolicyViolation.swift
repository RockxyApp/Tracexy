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
            String(localized: "This build keeps up to \(limit) workspace tabs open at once.")
        case let .focusSetLimitReached(limit):
            String(localized: "This build stores up to \(limit) focus sets.")
        case let .pinnedHostLimitReached(limit):
            String(localized: "This build pins up to \(limit) hosts.")
        }
    }
}
