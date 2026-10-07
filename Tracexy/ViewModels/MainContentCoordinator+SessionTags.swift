import Foundation

// MARK: - Session tags

/// Color tags on sessions, kept with the Project's notes (same capture scope, and
/// carried along when a live capture is saved).
@MainActor
extension MainContentCoordinator {
    /// Whether every one of `sessionIDs` carries `tag` — the menu's checkmark.
    func allSessions(_ sessionIDs: [UUID], carry tag: SessionTag) -> Bool {
        !sessionIDs.isEmpty && sessionIDs.allSatisfy { investigationNotes.tags(onSession: $0).contains(tag) }
    }

    /// Put `tag` on the sessions, or take it off when all of them already carry it.
    /// A query filtering by tag is re-run so the list reflects the change at once.
    func toggleTag(_ tag: SessionTag, on sessionIDs: [UUID]) {
        let enabled = !allSessions(sessionIDs, carry: tag)
        guard investigationNotes.setTag(tag, on: sessionIDs, enabled: enabled) else {
            if case let .projectFull(limit) = investigationNotes.lastRefusal {
                captureError = "This Project already tags \(limit.formatted()) sessions. Remove a tag to add another."
            }
            return
        }
        refreshActiveInvestigationQueries()
    }

    func clearTags(on sessionIDs: [UUID]) {
        for tag in SessionTag.allCases {
            investigationNotes.setTag(tag, on: sessionIDs, enabled: false)
        }
        refreshActiveInvestigationQueries()
    }
}
