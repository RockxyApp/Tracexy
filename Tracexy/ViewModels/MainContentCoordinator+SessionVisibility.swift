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

    /// Top talkers by total bytes, for the dashboard.
    func topHosts(limit: Int = 5) -> [(host: String, bytes: Int)] {
        var totals: [String: Int] = [:]
        for session in visibleSessions {
            totals[session.host, default: 0] += session.totalBytes
        }
        return totals.sorted { $0.value > $1.value }
            .prefix(limit)
            .map { (host: $0.key, bytes: $0.value) }
    }

    func count(for proto: ProtocolKind) -> Int {
        visibleSessions.filter { $0.protocolStack.contains(proto) }.count
    }

    /// Whether a session matches a single quick-filter chip. Finding membership
    /// comes from the already-published Core snapshots, not summary heuristics.
    func matches(_ session: SessionSummary, category: SessionFilterCategory) -> Bool {
        Self.categoryMatches(session, category: category, findingSessionIDs: findingSessionIDs)
    }

    /// Sessions visible in an arbitrary workspace. Live following uses this seam
    /// for inactive workspaces too, so a batch never applies the active tab's
    /// filters to another tab's selection.
    func visibleSessions(in workspace: WorkspaceState) -> [SessionSummary] {
        let protocolFilter = workspace.sidebarSelection.protocolFilter
        let categories = workspace.categoryFilters
        let query = workspace.isSearchActive
            ? workspace.filterText.trimmingCharacters(in: .whitespaces).lowercased()
            : ""
        let searchField = workspace.searchField
        let advancedRules = workspace.activeFilterRules
        let preparedRules = SessionFilterRuleEvaluator.prepared(advancedRules)
        let findingIDs = findingSessionIDs
        let investigationIDs = workspace.acceptedInvestigationDraft == nil
            ? nil
            : workspace.investigationMatchedSessionIDs

        return presentedSessions.filter { session in
            if mutedHosts.contains(session.host)
                || mutedProtocols.contains(session.primaryProtocol)
            {
                return false
            }
            if let proto = protocolFilter, !session.protocolStack.contains(proto) {
                return false
            }
            if !Self.categoryFilterMatches(
                session,
                categories: categories,
                findingSessionIDs: findingIDs
            ) {
                return false
            }
            if let host = workspace.hostFilter, session.host != host {
                return false
            }
            if let process = workspace.processFilter,
               (session.processName ?? "—") != process
            {
                return false
            }
            if let ip = workspace.ipFilter,
               !session.sourceEndpoint.contains(ip),
               !session.destinationEndpoint.contains(ip),
               !session.dnsAnswers.contains(ip)
            {
                return false
            }
            if !query.isEmpty, !searchField.haystack(in: session).contains(query) {
                return false
            }
            if let investigationIDs, !investigationIDs.contains(session.id) {
                return false
            }
            return advancedRules.isEmpty || preparedRules.matches(session)
        }
    }

    /// Removes decoded sessions from every presentation surface without
    /// mutating the capture evidence that Save/Export relies on.
    func removeSessionsFromView(_ ids: Set<UUID>) {
        let validIDs = ids.intersection(Set(sessions.map(\.id)))
        guard !validIDs.isEmpty else {
            return
        }
        removedSessionIDs.formUnion(validIDs)
        for workspace in workspaces.workspaces {
            if let selectedID = workspace.selectedSessionID,
               validIDs.contains(selectedID)
            {
                workspace.selectedSessionID = nil
            }
            reconcileLiveFollowing(in: workspace)
        }
    }

    /// Restores every row removed from the current capture's presentation.
    func restoreRemovedSessions() {
        removedSessionIDs.removeAll()
        followLatestVisibleSession()
    }
}
