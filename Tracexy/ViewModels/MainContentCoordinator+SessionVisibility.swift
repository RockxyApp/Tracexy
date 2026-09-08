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

    /// Distinct facts within the same visible scope as the surrounding rollups.
    var visibleSourceSummary: (apps: Int, domains: Int, addresses: Int) {
        let scoped = visibleSessions
        let apps = Set(scoped.compactMap(\.processName).filter { !$0.isEmpty && $0 != "—" })
        let domains = Set(scoped.map(\.host).filter(Self.isDomainName))
        var addresses = Set<IPAddressValue>()
        for session in scoped {
            let endpoints = [session.sourceEndpointValue, session.destinationEndpointValue].compactMap { $0?.ip }
            for text in endpoints + session.dnsAnswers {
                if let address = IPAddressValue(parsing: text) {
                    addresses.insert(address)
                }
            }
        }
        return (apps.count, domains.count, addresses.count)
    }

    /// Top talkers by total bytes, for the dashboard.
    ///
    /// Ties break on the host name ascending rather than on dictionary order, so
    /// two hosts with identical volume list the same way every render — a rollup
    /// that reshuffles under the cursor is a rollup nobody can click.
    func topHosts(limit: Int = 5) -> [(host: String, bytes: Int)] {
        var totals: [String: Int] = [:]
        for session in visibleSessions {
            totals[session.host, default: 0] += session.totalBytes
        }
        return totals.sorted { ($0.value, $1.key) > ($1.value, $0.key) }
            .prefix(limit)
            .map { (host: $0.key, bytes: $0.value) }
    }

    /// Sessions in view whose decoded stack contains `proto`.
    ///
    /// This counts **sessions, not packets or bytes**, and one session carries
    /// several layers, so these counts legitimately overlap and do not sum to the
    /// session total. Every surface presenting them has to say so.
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
        let scopedAddress = workspace.ipFilter.flatMap(IPAddressValue.init(parsing:))
        let scopedDestination = workspace.aggregateDestinationFilter.flatMap(IPAddressValue.init(parsing:))
        let aggregateProtocols = workspace.aggregateProtocolFilters
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
            if workspace.ipFilter != nil,
               !Self.session(session, matchesAddress: scopedAddress)
            {
                return false
            }
            // Conjunctive, unlike the OR-ed category group: an aggregate drill-in
            // may only ever narrow what was already on screen.
            if workspace.aggregateRequiresFindings, !findingIDs.contains(session.id) {
                return false
            }
            if !aggregateProtocols.isEmpty,
               !aggregateProtocols.isSubset(of: Set(session.protocolStack))
            {
                return false
            }
            if workspace.aggregateDestinationFilter != nil,
               !Self.session(session, matchesDestinationAddress: scopedDestination)
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

    /// A sidebar IP is one address, never a substring of a rendered endpoint.
    /// Typed endpoints and DNS answers share binary equality, including equivalent
    /// IPv6 spellings. Missing or invalid facts cannot establish a match.
    nonisolated static func session(_ session: SessionSummary, matchesAddress address: IPAddressValue?) -> Bool {
        guard let address else {
            return false
        }
        let endpoints = [session.sourceEndpointValue, session.destinationEndpointValue].compactMap { $0 }
        return endpoints.contains { IPAddressValue(parsing: $0.ip) == address }
            || session.dnsAnswers.contains { IPAddressValue(parsing: $0) == address }
    }

    /// A Flow destination scope is the **destination endpoint only** — not the
    /// source, and not a DNS answer.
    ///
    /// That narrowness is the whole point: `FlowEndpoint` groups its rows by this
    /// exact fact, so a row promising *n* sessions produces exactly those *n*.
    /// Widening to the sidebar IP semantics would pull in a session that merely
    /// resolved the address, or one that sent from it, and the row's count would
    /// stop being true. Binary equality, so equivalent IPv6 spellings match;
    /// a missing or invalid typed destination cannot establish a match.
    nonisolated static func session(
        _ session: SessionSummary,
        matchesDestinationAddress address: IPAddressValue?
    )
        -> Bool
    {
        guard let address, let destination = session.destinationEndpointValue else {
            return false
        }
        return IPAddressValue(parsing: destination.ip) == address
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
