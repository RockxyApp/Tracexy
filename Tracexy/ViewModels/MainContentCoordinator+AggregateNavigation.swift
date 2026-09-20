import Foundation

// MARK: - Aggregate drill-in from Overview and Flow

/// Clicking a number on a summary surface has to produce exactly the sessions
/// that number counted. That is a different job from the sidebar's
/// host/process/IP routes, which deliberately *replace* the scope with "show me
/// everything for this thing".
///
/// An Overview rollup and a Flow address row are already computed over the
/// currently visible session set — every complementary filter, the search text,
/// the Investigation query, Noise Control and the rows removed from view are
/// baked into them. So a drill-in from one may only ever add a constraint. If it
/// cleared a sibling filter the way ``MainContentCoordinator/selectHost(_:)``
/// does, the resulting list could be *larger* than the aggregate the user
/// clicked, and the surface would have lied about its own count.
///
/// Each route below therefore keeps every existing constraint, adds one, and
/// records the single bounded return point that U2 already provides.
@MainActor
extension MainContentCoordinator {
    /// Overview Top Talkers: narrow to one host without touching anything else.
    ///
    /// A stale click — the workspace is already scoped to a *different* host, so
    /// the row the user pressed no longer describes what is on screen — is a
    /// no-op rather than a replacement. Swapping the host there would widen past
    /// the aggregate and silently discard the scope the user is reading.
    func showSessionsForAggregateHost(_ host: String) {
        let workspace = activeWorkspace
        guard workspace.hostFilter == nil || workspace.hostFilter == host else {
            return
        }
        recordSessionScopeDrillIn(in: workspace) {
            carryProtocolLensIntoAggregate(in: workspace)
            workspace.sidebarSelection = .sessions
            workspace.hostFilter = host
        }
    }

    /// Overview Top Apps: narrow to one attributed process without touching
    /// anything else. Like the host route, a click under a *different* process
    /// scope is stale and does nothing rather than widening past the ranking.
    func showSessionsForAggregateProcess(_ process: String) {
        let workspace = activeWorkspace
        guard workspace.processFilter == nil || workspace.processFilter == process else {
            return
        }
        recordSessionScopeDrillIn(in: workspace) {
            carryProtocolLensIntoAggregate(in: workspace)
            workspace.sidebarSelection = .sessions
            workspace.processFilter = process
        }
    }

    /// Overview Protocol Mix: add one protocol to the conjunctive aggregate
    /// intersection.
    ///
    /// It writes to ``WorkspaceState/aggregateProtocolFilters`` rather than the
    /// category chips on purpose. The chips are OR-ed within their group, so
    /// inserting TCP beside an active TLS chip would *add* every plain-TCP
    /// session to a list that was showing TLS — the opposite of drilling in. It
    /// also never replaces a protocol already in the set: an earlier intersection
    /// is part of what the clicked row counted.
    ///
    /// Because the set is a finite `ProtocolKind` enum rather than a sidebar
    /// destination, rows with no sidebar lens of their own — UDP, HTTP/2 — drill
    /// in exactly like the rest.
    func showSessionsForAggregateProtocol(_ kind: ProtocolKind) {
        let workspace = activeWorkspace
        recordSessionScopeDrillIn(in: workspace) {
            carryProtocolLensIntoAggregate(in: workspace)
            workspace.sidebarSelection = .sessions
            workspace.aggregateProtocolFilters.insert(kind)
            workspace.isFilterBarVisible = true
        }
    }

    /// Flow address list: narrow to one remote destination address.
    ///
    /// This is the destination-only predicate the Flow rows are grouped by, not
    /// ``MainContentCoordinator/selectIP(_:)``'s source-or-destination-or-DNS-answer
    /// semantics — those would return sessions the clicked row never counted.
    /// Like the host route, a stale click under a different destination scope is
    /// a no-op.
    func showSessionsForAggregateDestination(_ address: String) {
        let workspace = activeWorkspace
        guard let parsed = IPAddressValue(parsing: address),
              workspace.aggregateDestinationFilter == nil
              || workspace.aggregateDestinationFilter.flatMap(IPAddressValue.init(parsing:)) == parsed else
        {
            return
        }
        recordSessionScopeDrillIn(in: workspace) {
            carryProtocolLensIntoAggregate(in: workspace)
            workspace.sidebarSelection = .sessions
            workspace.aggregateDestinationFilter = workspace.aggregateDestinationFilter ?? address
        }
    }

    /// The "Open Sessions" link on an aggregate surface: the same rows, in the
    /// full table.
    ///
    /// It opens a list, so it narrows nothing and records nothing — but it must
    /// not *widen* either, which is why it is not
    /// ``MainContentCoordinator/selectSidebarItem(_:)``: that route clears the
    /// host/process/IP and aggregate scope the surface just described.
    func openSessionsPreservingScope() {
        let workspace = activeWorkspace
        carryProtocolLensIntoAggregate(in: workspace)
        workspace.sidebarSelection = .sessions
    }

    /// Review only finding-bearing sessions within the current aggregate scope.
    func showAggregateFindingSessions() {
        let workspace = activeWorkspace
        recordSessionScopeDrillIn(in: workspace) {
            carryProtocolLensIntoAggregate(in: workspace)
            workspace.sidebarSelection = .sessions
            workspace.aggregateRequiresFindings = true
        }
    }

    func openFlowPreservingScope() {
        let workspace = activeWorkspace
        carryProtocolLensIntoAggregate(in: workspace)
        workspace.sidebarSelection = .flow
    }

    // MARK: Private

    /// Preserves a sidebar protocol lens across a move to Sessions.
    ///
    /// The lens is a filter (see ``WorkspaceState/hasActiveFilters``) that lives
    /// in the sidebar selection, so leaving the lens for `.sessions` would drop
    /// it and widen the list past the aggregate that was clicked. Folding it into
    /// the conjunctive set first keeps the same sessions, expressed as a scope
    /// the Sessions surface can name and Reset can clear.
    private func carryProtocolLensIntoAggregate(in workspace: WorkspaceState) {
        guard let lens = workspace.sidebarSelection.protocolFilter else {
            return
        }
        workspace.aggregateProtocolFilters.insert(lens)
    }
}
