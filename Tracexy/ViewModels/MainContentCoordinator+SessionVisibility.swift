import Foundation

// MARK: - Session visibility

@MainActor
extension MainContentCoordinator {
    /// Capture sessions that remain available to presentation surfaces.
    /// `sessions` is the evidence-backed engine result; this reversible layer is
    /// the single privacy seam between that raw result and the UI.
    var presentedSessions: [SessionSummary] {
        guard !removedSessionIDs.isEmpty else {
            return sessions
        }
        return sessions.filter { !removedSessionIDs.contains($0.id) }
    }

    var removedSessionCount: Int {
        removedSessionIDs.intersection(Set(sessions.map(\.id))).count
    }

    /// Removes decoded sessions from every presentation surface without
    /// mutating the capture evidence that Save/Export relies on.
    func removeSessionsFromView(_ ids: Set<UUID>) {
        let validIDs = ids.intersection(Set(sessions.map(\.id)))
        guard !validIDs.isEmpty else {
            return
        }
        removedSessionIDs.formUnion(validIDs)
        if let selectedID = activeWorkspace.selectedSessionID,
           validIDs.contains(selectedID)
        {
            activeWorkspace.selectedSessionID = nil
        }
    }

    /// Restores every row removed from the current capture's presentation.
    func restoreRemovedSessions() {
        removedSessionIDs.removeAll()
    }
}
