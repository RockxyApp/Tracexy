import Foundation

@MainActor
extension MainContentCoordinator {
    /// Sessions visible in the active workspace, after sidebar + pill + text filtering.
    var visibleSessions: [SessionSummary] {
        visibleSessions(in: activeWorkspace)
    }

    var selectedSession: SessionSummary? {
        guard let id = activeWorkspace.selectedSessionID else {
            return nil
        }
        return presentedSessions.first { $0.id == id }
    }

    // MARK: Correlation

    func select(_ session: SessionSummary) {
        cancelFollowStream(clearResult: true)
        activeWorkspace.selectedSessionID = session.id
        activeWorkspace.sessionRevealToken &+= 1
        loadSelectedSavedCaptureEvidence()
        evidenceNavigationDidChangeSelection()
        activeWorkspace.evidenceRetiredForSelection = session.id
        revealPanelsForSelection()
    }

    // MARK: Pinned sessions

    /// The pinned sessions still in this capture, in the order they were pinned. A
    /// pin outlives any filter — that is the point of it — but not removal from view.
    var pinnedSessions: [SessionSummary] {
        guard !pinnedSessionIDs.isEmpty else {
            return []
        }
        let wanted = Set(pinnedSessionIDs)
        let byID = Dictionary(
            presentedSessions.lazy.filter { wanted.contains($0.id) }.map { ($0.id, $0) },
            uniquingKeysWith: { first, _ in first }
        )
        return pinnedSessionIDs.compactMap { byID[$0] }
    }

    func isSessionPinned(_ id: UUID) -> Bool {
        pinnedSessionIDs.contains(id)
    }

    func togglePinSession(_ id: UUID) {
        if let index = pinnedSessionIDs.firstIndex(of: id) {
            pinnedSessionIDs.remove(at: index)
        } else {
            pinnedSessionIDs.append(id)
        }
    }

    func unpinAllSessions() {
        pinnedSessionIDs.removeAll()
    }

    /// Selects a pinned session as a click in the table would. The selection holds
    /// even when the current filter hides the row, so its evidence stays one click
    /// away without widening what the list shows.
    func showPinnedSession(_ session: SessionSummary) {
        userDidNavigateSessionHistory()
        select(session)
    }

    /// Capture boundary: rows removed from view and pins belong to the capture that
    /// is going away.
    func clearCaptureLocalSessionMarks() {
        removedSessionIDs.removeAll()
        pinnedSessionIDs.removeAll()
    }
}
