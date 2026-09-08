import Foundation

// MARK: - SessionScopeReturnPoint

/// One restorable session scope: exactly the fields an explicit drill-in
/// replaced, stamped with the capture generation they described.
///
/// It is deliberately narrow. Saved Focus Sets, advanced rules, the
/// capture-local Investigation query, the search text, Project Noise Control and
/// the rows removed from view are separate decisions with their own recovery, so
/// going back must never rewrite any of them. No bytes, locator, file identity,
/// evidence or finding is ever copied in here either — a return point is a view
/// intent, not a second copy of the capture.
struct SessionScopeReturnPoint: Equatable {
    // MARK: Lifecycle

    init(workspace: WorkspaceState, startGeneration: Int) {
        sidebarSelection = workspace.sidebarSelection
        hostFilter = workspace.hostFilter
        processFilter = workspace.processFilter
        ipFilter = workspace.ipFilter
        aggregateProtocolFilters = workspace.aggregateProtocolFilters
        aggregateDestinationFilter = workspace.aggregateDestinationFilter
        aggregateRequiresFindings = workspace.aggregateRequiresFindings
        categoryFilters = workspace.categoryFilters
        isFilterBarVisible = workspace.isFilterBarVisible
        isSearchEnabled = workspace.isSearchEnabled
        selectedSessionID = workspace.selectedSessionID
        self.startGeneration = startGeneration
    }

    // MARK: Internal

    /// How many drill-ins one workspace can retrace. Bounded like every other UI
    /// history here: a way back is a convenience, never a navigation log.
    static let maximumDepth = 8

    let sidebarSelection: SidebarItem
    let hostFilter: String?
    let processFilter: String?
    let ipFilter: String?
    /// The conjunctive aggregate protocol intersection and typed destination the
    /// drill-in added to. They are recorded like every other narrowing field, so
    /// going back removes exactly the intersection the drill-in introduced rather
    /// than leaving the list narrower than the scope it claims to have restored.
    let aggregateProtocolFilters: Set<ProtocolKind>
    let aggregateDestinationFilter: String?
    let aggregateRequiresFindings: Bool
    let categoryFilters: Set<SessionFilterCategory>
    let isFilterBarVisible: Bool
    let isSearchEnabled: Bool
    /// The session selected before the drill-in. Restored only when that session
    /// is still in the capture and has not been removed from view.
    let selectedSessionID: UUID?
    /// The coordinator capture generation this scope described. A newer
    /// generation means the capture, source or Project it named is gone, so the
    /// entry is dropped rather than reapplied — going back must never resurrect a
    /// source.
    let startGeneration: Int

    /// Whether `workspace` already stands in exactly this scope, so a repeated or
    /// no-op drill-in records nothing.
    func matches(_ workspace: WorkspaceState) -> Bool {
        sidebarSelection == workspace.sidebarSelection
            && hostFilter == workspace.hostFilter
            && processFilter == workspace.processFilter
            && ipFilter == workspace.ipFilter
            && aggregateProtocolFilters == workspace.aggregateProtocolFilters
            && aggregateDestinationFilter == workspace.aggregateDestinationFilter
            && aggregateRequiresFindings == workspace.aggregateRequiresFindings
            && categoryFilters == workspace.categoryFilters
            && isFilterBarVisible == workspace.isFilterBarVisible
            && isSearchEnabled == workspace.isSearchEnabled
            && selectedSessionID == workspace.selectedSessionID
    }
}

// MARK: - SessionScopeReturnAction

/// The one label/help pair for the single return route, so the shared scope
/// notice and the View menu can never describe the same action differently.
enum SessionScopeReturnAction {
    static let title = String(localized: "Back to Previous Scope")
    /// Used only where the full title genuinely cannot fit.
    static let shortTitle = String(localized: "Back")
    static let systemImage = "arrow.uturn.backward"
    static let help = String(
        localized: """
        Returns to the sidebar location, host/client/IP drill-down, Overview and Flow aggregate \
        narrowing, category filters and session selection that an explicit drill-in replaced. \
        Search text, advanced rules, the Investigation query, Noise Control and sessions removed \
        from view are not affected.
        """
    )
}
