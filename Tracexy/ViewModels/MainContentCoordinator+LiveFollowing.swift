import Foundation

// MARK: - Live session following

@MainActor
extension MainContentCoordinator {
    /// Enables or disables live following for the active workspace. Enabling has
    /// an immediate, visible result when rows already exist; an empty visible
    /// scope remains armed for a later matching session.
    func setFollowingLiveSessions(_ isEnabled: Bool) {
        let workspace = activeWorkspace
        workspace.isFollowingLiveSessions = isEnabled
        guard isEnabled else {
            return
        }
        reconcileLiveFollowing(in: workspace)
    }

    func toggleFollowingLiveSessions() {
        setFollowingLiveSessions(!activeWorkspace.isFollowingLiveSessions)
    }

    /// User-owned table navigation yields the persistent live tail for this tab.
    /// Coordinator-owned selection writes bypass this method.
    func userDidNavigateSessionHistory() {
        guard activeWorkspace.isFollowingLiveSessions else {
            return
        }
        activeWorkspace.isFollowingLiveSessions = false
    }

    /// Advances every armed workspace after a capture publication. When
    /// `acceptedSessionIDs` is present, only a session introduced by that
    /// publication can move selection; a non-matching batch leaves the mode
    /// armed and preserves the user's current visible row.
    func followLatestVisibleSession(acceptedSessionIDs: Set<UUID>? = nil) {
        for workspace in workspaces.workspaces {
            reconcileLiveFollowing(
                in: workspace,
                acceptedSessionIDs: acceptedSessionIDs
            )
        }
    }

    /// Reconciles Follow Live after filters, scopes or the mode itself change.
    /// Chronology is derived from capture timestamps and a stable id tie-break,
    /// never from a future presentation sort order.
    func reconcileLiveFollowing(
        in workspace: WorkspaceState,
        acceptedSessionIDs: Set<UUID>? = nil
    ) {
        guard workspace.isFollowingLiveSessions else {
            return
        }

        let candidates = visibleSessions(in: workspace).filter { session in
            acceptedSessionIDs?.contains(session.id) ?? true
        }
        guard let newest = Self.newestChronologicalSession(in: candidates) else {
            // A batch that simply had no visible match must not erase a valid
            // selection. A filter/scope reconcile, however, clears a stale row
            // while keeping Follow Live armed.
            if acceptedSessionIDs == nil {
                workspace.selectedSessionID = nil
            }
            return
        }
        workspace.selectedSessionID = newest.id
    }

    /// One-shot navigation to the last row in the current presentation order.
    /// It intentionally leaves Follow Live unchanged.
    func jumpToLatestVisibleSession() {
        guard let latest = visibleSessions.last else {
            return
        }
        activeWorkspace.selectedSessionID = latest.id
    }

    nonisolated static func newestChronologicalSession(
        in sessions: [SessionSummary]
    )
        -> SessionSummary?
    {
        sessions.max {
            ($0.startTime, $0.id.uuidString) < ($1.startTime, $1.id.uuidString)
        }
    }
}
