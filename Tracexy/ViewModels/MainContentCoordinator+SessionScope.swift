import Foundation

// MARK: - Effective session scope and its one reset route

/// Sessions, Overview and Flow each show a different projection of the same
/// filtered set, so the *description* of that filtering and the way out of it
/// live here rather than in any one surface. A second copy of either would be a
/// second chance to disagree with the list.
@MainActor
extension MainContentCoordinator {
    /// Everything currently narrowing what a session surface shows, ordered
    /// deterministically.
    ///
    /// `shownCount` lets a caller that has already filtered (the session table,
    /// the Overview rollups) pass its own count instead of making this re-filter
    /// the capture a second time for the notice above it.
    func sessionScope(
        in workspace: WorkspaceState? = nil,
        shownCount: Int? = nil
    )
        -> SessionScopeSummary
    {
        let workspace = workspace ?? activeWorkspace
        return SessionScopeSummary.make(
            workspace: workspace,
            shownCount: shownCount ?? visibleSessions(in: workspace).count,
            // The capture's own total, not the presented one: rows the user
            // removed are reported as their own scope rather than silently
            // shrinking the denominator.
            capturedCount: sessions.count,
            removedCount: removedSessionCount,
            noiseRuleCount: noiseRuleCount
        )
    }

    /// The single Reset Session Filters route, shared by the filter shelf, the
    /// scope notice and the empty-state recovery.
    ///
    /// It clears exactly one workspace's filtering: search text, categories, the
    /// host/client/IP drill-down, the Overview/Flow aggregate protocol
    /// intersection and destination scope, the advanced rules, the capture-local
    /// Investigation query (accepted *and* any evaluation still in flight), and
    /// the sidebar protocol lens.
    ///
    /// It deliberately does not touch:
    ///
    /// - the Overview/Flow/History location, so resetting from one of those
    ///   surfaces does not also navigate away from it — only a protocol lens,
    ///   which *is* a filter, returns to Sessions;
    /// - Project Noise Control or the rows removed from view, which are separate
    ///   persisted/privacy decisions with their own explicit recovery;
    /// - the search on/off switch, grouping, selection, or any other workspace.
    func resetSessionFilters(in workspace: WorkspaceState? = nil) {
        let workspace = workspace ?? activeWorkspace
        if workspace.sidebarSelection.protocolFilter != nil {
            workspace.sidebarSelection = .sessions
        }
        workspace.filterText = ""
        workspace.categoryFilters = []
        workspace.hostFilter = nil
        workspace.processFilter = nil
        workspace.ipFilter = nil
        workspace.aggregateProtocolFilters = []
        workspace.aggregateDestinationFilter = nil
        workspace.aggregateRequiresFindings = false
        workspace.filterRules = [SessionFilterRule()]
        workspace.isAdvancedFilterVisible = false
        // The reset *is* the widest scope, so there is nothing left to go back
        // to: keeping the drill-in history would offer a return that re-narrows
        // the list the user just cleared.
        workspace.sessionScopeReturnStack = []
        // Retires the accepted query, cancels any in-flight evaluation and bumps
        // the workspace's request ID, so a late result cannot re-narrow the list
        // the user just widened. The editable draft is capture-local user state
        // and stays available.
        clearInvestigationQuery(in: workspace)
    }

    // MARK: Bounded drill-in return

    /// Whether the active workspace has a Back to Previous Scope route right now.
    var canReturnToPreviousSessionScope: Bool {
        previousSessionScopeReturnPoint() != nil
    }

    /// The newest recorded scope still valid for the current capture generation,
    /// or `nil` when there is nothing to go back to.
    ///
    /// Pure by design: a view may read it while drawing, so it prunes nothing.
    /// Stale entries are dropped by the two mutating routes below.
    func previousSessionScopeReturnPoint(in workspace: WorkspaceState? = nil) -> SessionScopeReturnPoint? {
        let workspace = workspace ?? activeWorkspace
        return workspace.sessionScopeReturnStack.last { $0.startGeneration == startGeneration }
    }

    /// Records the scope an explicit drill-in is about to replace, applies the
    /// drill-in, and keeps the record only when the scope actually changed.
    ///
    /// This is the *only* push route, and only the explicit drill-ins use it:
    /// sidebar host/process/IP, Findings, and the Overview/Flow aggregate
    /// narrowing routes. Ordinary sidebar navigation, ⌘F,
    /// Follow Stream and filter editing deliberately record nothing: a history
    /// that logs every keystroke is a history no one can predict.
    func recordSessionScopeDrillIn(in workspace: WorkspaceState, _ drillIn: () -> Void) {
        let origin = SessionScopeReturnPoint(workspace: workspace, startGeneration: startGeneration)
        drillIn()
        guard !origin.matches(workspace) else {
            return
        }
        // Entries from an older generation describe a capture/source/Project that
        // is gone; they are dropped here rather than left to be reapplied.
        var stack = workspace.sessionScopeReturnStack.filter { $0.startGeneration == startGeneration }
        stack.append(origin)
        if stack.count > SessionScopeReturnPoint.maximumDepth {
            stack.removeFirst(stack.count - SessionScopeReturnPoint.maximumDepth)
        }
        workspace.sessionScopeReturnStack = stack
    }

    /// Back to Previous Scope: restores the newest still-valid recorded scope and
    /// consumes it. Returns `false` when nothing valid remains.
    ///
    /// It restores only the recorded fields plus the recorded selection. Search
    /// text, advanced rules, the Investigation query, Noise Control, removed rows
    /// and every other workspace are left exactly as they are.
    @discardableResult
    func returnToPreviousSessionScope(in workspace: WorkspaceState? = nil) -> Bool {
        let workspace = workspace ?? activeWorkspace
        let valid = workspace.sessionScopeReturnStack.filter { $0.startGeneration == startGeneration }
        guard let point = valid.last else {
            if valid.count != workspace.sessionScopeReturnStack.count {
                workspace.sessionScopeReturnStack = valid
            }
            return false
        }
        workspace.sessionScopeReturnStack = Array(valid.dropLast())
        workspace.sidebarSelection = point.sidebarSelection
        workspace.hostFilter = point.hostFilter
        workspace.processFilter = point.processFilter
        workspace.ipFilter = point.ipFilter
        workspace.aggregateProtocolFilters = point.aggregateProtocolFilters
        workspace.aggregateDestinationFilter = point.aggregateDestinationFilter
        workspace.aggregateRequiresFindings = point.aggregateRequiresFindings
        workspace.categoryFilters = point.categoryFilters
        workspace.isFilterBarVisible = point.isFilterBarVisible
        workspace.isSearchEnabled = point.isSearchEnabled
        restoreSessionScopeSelection(point.selectedSessionID, in: workspace)
        return true
    }

    // MARK: Private

    /// Re-establishes a recorded selection through the existing selection and
    /// evidence hooks, so the projection, cited frame and Follow Stream are
    /// retired and rebuilt exactly as a direct row selection would.
    ///
    /// A session that has left the capture, or that the user removed from view,
    /// clears the selection instead of being resurrected.
    private func restoreSessionScopeSelection(_ sessionID: UUID?, in workspace: WorkspaceState) {
        let isActive = workspace.id == activeWorkspace.id
        guard let sessionID, let session = presentedSessions.first(where: { $0.id == sessionID }) else {
            guard workspace.selectedSessionID != nil else {
                return
            }
            workspace.selectedSessionID = nil
            if isActive {
                cancelFollowStream(clearResult: true)
                evidenceNavigationDidChangeSelection()
            }
            return
        }
        guard workspace.selectedSessionID != session.id else {
            return
        }
        // A background workspace owns no coordinator pipeline, so it records the
        // selection and nothing else; the active one goes through `select`.
        guard isActive else {
            workspace.selectedSessionID = session.id
            return
        }
        select(session)
    }
}
