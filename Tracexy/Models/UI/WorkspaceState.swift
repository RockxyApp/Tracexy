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

    /// How the session list groups rows. Defaults to correlated actions —
    /// that is the point of the product — with a one-click way back to raw
    /// sessions when the grouping looks wrong.
    var sessionGrouping: SessionGrouping = .action

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

    /// Advanced filter builder: the AND/OR rule rows (always at least one row).
    var filterRules: [SessionFilterRule] = [SessionFilterRule()]
    /// Whether the advanced rule builder is revealed below the category tabs.
    var isAdvancedFilterVisible: Bool = false

    /// Status-bar toggles.
    var isFilterBarVisible: Bool = true
    var autoSelectLatest: Bool = false

    /// The advanced rule rows that are enabled and carry a value (i.e. actually filter).
    var activeFilterRules: [SessionFilterRule] {
        SessionFilterRuleEvaluator.activeRules(in: filterRules)
    }

    /// Whether the search box is currently constraining the list: it must be
    /// switched on *and* hold text. A disabled search never counts as active.
    var isSearchActive: Bool {
        isSearchEnabled && !filterText.trimmingCharacters(in: .whitespaces).isEmpty
    }

    /// True when any user filter (search, category tabs, sidebar scope, advanced rules) is active.
    var hasActiveFilters: Bool {
        isSearchActive
            || !categoryFilters.isEmpty
            || hostFilter != nil
            || processFilter != nil
            || ipFilter != nil
            || !activeFilterRules.isEmpty
    }
}
