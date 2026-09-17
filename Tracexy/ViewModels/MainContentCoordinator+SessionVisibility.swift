import Foundation

// MARK: - TrafficRankingEntry

/// One row of an Overview ranking: a named party and its bytes by session
/// direction. `sentBytes` is the client-side total (``SessionSummary/bytesUp``).
nonisolated struct TrafficRankingEntry: Identifiable, Equatable, Sendable {
    let name: String
    let sessionCount: Int
    let sentBytes: Int
    let receivedBytes: Int

    var id: String {
        name
    }

    var totalBytes: Int {
        sentBytes + receivedBytes
    }
}

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
        Self.sourceSummary(of: visibleSessions)
    }

    nonisolated static func sourceSummary(of scoped: [SessionSummary]) -> (apps: Int, domains: Int, addresses: Int) {
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

    /// Capture-wide bytes over time for the current capture — a projection of the
    /// adopted investigation snapshot, so it always describes the same accepted
    /// frames as the published sessions and evidence. Session filters do not
    /// narrow it; surfaces that show it beside scoped rollups must say so.
    var trafficTimeline: TrafficTimeline {
        investigationSnapshot.trafficTimeline
    }

    /// Byte share of the visible sessions by their innermost protocol — a true
    /// partition, unlike ``count(for:)``: each session's bytes land in exactly one
    /// row, so the rows sum to the scoped total. Sorted by bytes, then label, so
    /// the chart never reshuffles between renders. Rows past `limit` fold into a
    /// trailing `nil` "other" row rather than disappearing.
    func protocolByteShare(limit: Int = 5) -> [(kind: ProtocolKind?, bytes: Int)] {
        Self.protocolByteShare(of: visibleSessions, limit: limit)
    }

    nonisolated static func protocolByteShare(
        of sessions: [SessionSummary],
        limit: Int = 5
    )
        -> [(kind: ProtocolKind?, bytes: Int)]
    {
        var totals: [ProtocolKind: Int] = [:]
        for session in sessions {
            totals[session.primaryProtocol, default: 0] += session.totalBytes
        }
        let ranked = totals
            .filter { $0.value > 0 }
            .sorted { ($0.value, $1.key.label) > ($1.value, $0.key.label) }
        let leading = ranked.prefix(max(0, limit)).map { (kind: Optional($0.key), bytes: $0.value) }
        let rest = ranked.dropFirst(max(0, limit)).reduce(0) { $0 + $1.value }
        return rest > 0 ? leading + [(kind: nil, bytes: rest)] : leading
    }

    /// Top attributed local processes by total bytes, with the client/server
    /// split each row's bar draws. Sessions without attribution are excluded — a
    /// missing process is not an app named "—". Ties break on the name so the
    /// ranking is stable across renders.
    func topProcesses(limit: Int = 10) -> [TrafficRankingEntry] {
        Self.topProcesses(of: visibleSessions, limit: limit)
    }

    nonisolated static func topProcesses(of sessions: [SessionSummary], limit: Int = 10) -> [TrafficRankingEntry] {
        var totals: [String: RankingTotals] = [:]
        for session in sessions {
            guard let name = session.processName, !name.isEmpty, name != "—" else {
                continue
            }
            totals[name, default: RankingTotals()].add(session)
        }
        return Self.rank(totals, limit: limit)
    }

    /// Top hosts by total bytes with the same client/server split, over the same
    /// visible scope as ``topHosts(limit:)``.
    func topHostTraffic(limit: Int = 10) -> [TrafficRankingEntry] {
        Self.topHostTraffic(of: visibleSessions, limit: limit)
    }

    nonisolated static func topHostTraffic(of sessions: [SessionSummary], limit: Int = 10) -> [TrafficRankingEntry] {
        var totals: [String: RankingTotals] = [:]
        for session in sessions {
            totals[session.host, default: RankingTotals()].add(session)
        }
        return Self.rank(totals, limit: limit)
    }

    /// Sessions in view whose decoded stack contains `proto`.
    ///
    /// This counts **sessions, not packets or bytes**, and one session carries
    /// several layers, so these counts legitimately overlap and do not sum to the
    /// session total. Every surface presenting them has to say so.
    func count(for proto: ProtocolKind) -> Int {
        visibleSessions.filter { $0.protocolStack.contains(proto) }.count
    }

    nonisolated private struct RankingTotals {
        var sessions = 0
        var up = 0
        var down = 0

        mutating func add(_ session: SessionSummary) {
            sessions += 1
            up += session.bytesUp
            down += session.bytesDown
        }
    }

    nonisolated private static func rank(
        _ totals: [String: RankingTotals],
        limit: Int
    )
        -> [TrafficRankingEntry]
    {
        totals
            .map {
                TrafficRankingEntry(
                    name: $0.key, sessionCount: $0.value.sessions,
                    sentBytes: $0.value.up, receivedBytes: $0.value.down
                )
            }
            .filter { $0.totalBytes > 0 }
            .sorted { ($0.totalBytes, $1.name) > ($1.totalBytes, $0.name) }
            .prefix(max(0, limit))
            .map { $0 }
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
        // Projecting findings hashes every analysis tuple, so only pay for it
        // when a filter actually reads membership: the Security chip or an
        // aggregate Findings drill-in. Every other scope leaves it empty.
        let needsFindingMembership = workspace.aggregateRequiresFindings || categories.contains(.security)
        let findingIDs = needsFindingMembership ? findingSessionIDs : []
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
