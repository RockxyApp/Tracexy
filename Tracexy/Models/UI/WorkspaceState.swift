import Foundation
import Observation

@Observable
final class WorkspaceState: Identifiable {
    // MARK: Lifecycle

    init(
        id: UUID = UUID(),
        title: String,
        isClosable: Bool = true,
        sidebarSelection: SidebarItem = .sessions,
        inspectorLayout: InspectorLayout = .hidden,
        isContextDockVisible: Bool = false
    ) {
        self.id = id
        self.title = title
        self.isClosable = isClosable
        self.sidebarSelection = sidebarSelection
        self.inspectorLayout = inspectorLayout
        self.isContextDockVisible = isContextDockVisible
    }

    // MARK: Internal

    let id: UUID
    var title: String
    let isClosable: Bool

    /// Navigation
    var navigatorMode: SidebarNavigatorMode = .browse
    /// Whether the live-traffic chart above the session table is expanded.
    var isLiveChartExpanded = true
    var sidebarSelection: SidebarItem
    var inspectorTab: InspectorTab = .timeline

    /// Evidence inspector — bottom dock only. See `InspectorLayout`.
    var inspectorLayout: InspectorLayout

    /// Context Dock — the right-hand interpretation column. A separate object
    /// from the evidence inspector: separate visibility, separate tab, separate
    /// toggle. Both may be open at once.
    var isContextDockVisible: Bool
    var contextDockTab: ContextDockTab = .details

    /// Tri-state auto-reveal. `nil` means the user has never expressed a
    /// preference, so selecting a session may reveal the evidence inspector for
    /// them. Once they close it by hand this becomes `false` and the automatic
    /// reveal stops for good — a panel the user dismissed must not reappear.
    var allowsAutomaticInspectorReveal: Bool?

    /// How the session list groups rows. Defaults to the raw observed sessions
    /// exactly as decoded. Action grouping is inference layered on top and is
    /// opt-in — a real high-volume capture collapses into a handful of guessed
    /// rows, so the honest default is to show every session and let the user
    /// switch to Action/Host/Process when they want the interpretation.
    var sessionGrouping: SessionGrouping = .none

    /// Selection
    var selectedSessionID: UUID?

    /// Filtering
    var filterText: String = ""
    /// Which session attribute(s) the search box matches against. Defaults to
    /// spanning everything the list shows.
    var searchField: SessionSearchField = .allFields
    /// The search box has its own on/off switch, independent of whether it holds
    /// text. Turning it off keeps the typed query but stops it constraining the
    /// list — and a disabled search does not count as an active filter.
    var isSearchEnabled: Bool = true
    /// Active category tabs (protocol group + investigation group). Empty = "All".
    var categoryFilters: Set<SessionFilterCategory> = []
    /// Sidebar drill-down scopes (a single host / process / IP selected in the sidebar).
    var hostFilter: String?
    var processFilter: String?
    var ipFilter: String?

    /// Protocols added by an explicit aggregate drill-in (an Overview Protocol Mix
    /// row), as a finite set of recognized ``ProtocolKind`` values.
    ///
    /// These are **conjunctive**: a session must carry every kind in the set. That
    /// is deliberately not how ``categoryFilters`` behaves — the category group is
    /// OR-ed, so writing a drill-in into it could *widen* the list past the
    /// aggregate that was clicked. Keeping the two separate is what lets an
    /// aggregate promise the count it displayed, and lets a second drill-in
    /// intersect with the first instead of replacing it.
    var aggregateProtocolFilters: Set<ProtocolKind> = []

    /// One remote address chosen from the Flow address list.
    ///
    /// Matched against the **typed binary destination endpoint only** — never the
    /// source endpoint and never a DNS answer, which is what separates it from
    /// ``ipFilter``. Flow groups its rows by exactly this fact, so the row's
    /// session count and the resulting list are the same set.
    var aggregateDestinationFilter: String?
    /// Findings membership AND-ed with the existing category group.
    var aggregateRequiresFindings = false

    /// Bounded per-workspace history of the scopes explicit host/process/IP and
    /// Findings drill-ins replaced, oldest first and capped at
    /// ``SessionScopeReturnPoint/maximumDepth``.
    ///
    /// Ordinary sidebar navigation and ⌘F are not drill-ins and never push here.
    /// It holds view intent only — no rules, query, search text, noise, removal
    /// or raw evidence — and is capture-local: it is never persisted into a
    /// Project snapshot and never crosses into another workspace.
    var sessionScopeReturnStack: [SessionScopeReturnPoint] = []

    /// Advanced filter builder: the AND/OR rule rows (always at least one row).
    var filterRules: [SessionFilterRule] = [SessionFilterRule()]
    /// Whether the advanced rule builder is revealed below the category tabs.
    var isAdvancedFilterVisible: Bool = false

    /// Capture-local structured Investigation state. It is intentionally absent from
    /// every persisted FocusSet/settings path. A draft becomes accepted only after its
    /// typed query has compiled and evaluated successfully off-main.
    var investigationDraft = InvestigationQueryDraft()
    var acceptedInvestigationDraft: InvestigationQueryDraft?
    var investigationMatchedSessionIDs: Set<UUID> = []
    var investigationIndeterminateSessionIDs: Set<UUID> = []
    var investigationCoverageReasons: Set<QueryCoverageReason> = []
    var investigationQueryError: InvestigationQueryDraftError?
    var isEvaluatingInvestigationQuery = false
    var investigationQueryRequestID = 0

    /// Presentation toggles.
    var isFilterBarVisible: Bool = true

    /// Persistent live-tail intent for this workspace. The coordinator owns the
    /// selection transitions; keeping the mode here makes it independent across
    /// workspace tabs and lets an empty filtered view remain armed.
    var isFollowingLiveSessions: Bool = false

    /// Fresh identity issued every time something asks the session search field
    /// to take focus (⌘F). `SessionFilterBar` observes it via `.task(id:)`, so a
    /// repeat request re-focuses even when the command has just mounted the bar or
    /// switched between workspaces. `nil` keeps a fresh workspace from stealing
    /// focus unprompted.
    var searchFocusRequest: UUID?

    var hasActiveInvestigationQuery: Bool {
        acceptedInvestigationDraft != nil
    }

    /// The advanced rule rows that are enabled and carry a value (i.e. actually filter).
    var activeFilterRules: [SessionFilterRule] {
        SessionFilterRuleEvaluator.activeRules(in: filterRules)
    }

    /// Whether the search box is currently constraining the list: it must be
    /// switched on *and* hold text. A disabled search never counts as active.
    var isSearchActive: Bool {
        isSearchEnabled && !filterText.trimmingCharacters(in: .whitespaces).isEmpty
    }

    /// True when any user filter is active, including the sidebar protocol lens
    /// and the separate capture-local Investigation query. The query remains
    /// disjoint from persisted advanced rules.
    ///
    /// The sidebar lens counts because it constrains the list exactly like the
    /// category pills do (see ``MainContentCoordinator/visibleSessions(in:)``);
    /// omitting it left a user looking at a filtered list with no visible reason
    /// and no reset affordance.
    var hasActiveFilters: Bool {
        sidebarSelection.protocolFilter != nil
            || isSearchActive
            || !categoryFilters.isEmpty
            || hostFilter != nil
            || processFilter != nil
            || ipFilter != nil
            || !aggregateProtocolFilters.isEmpty
            || aggregateDestinationFilter != nil
            || aggregateRequiresFindings
            || !activeFilterRules.isEmpty
            || hasActiveInvestigationQuery
            || isEvaluatingInvestigationQuery
    }

    /// Drops both aggregate narrowing fields, for the global navigation routes
    /// that replace a scope rather than narrow one. Kept here so no caller can
    /// clear one and forget the other.
    func clearAggregateScope() {
        aggregateProtocolFilters = []
        aggregateDestinationFilter = nil
        aggregateRequiresFindings = false
    }
}
