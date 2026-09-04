import Foundation

extension ProjectWorkspaceSnapshot {
    @MainActor
    init(capturing workspace: WorkspaceState) {
        self.init(
            id: workspace.id,
            title: workspace.title,
            isClosable: workspace.isClosable,
            sidebarSelection: workspace.sidebarSelection.rawValue,
            navigatorMode: workspace.navigatorMode.rawValue,
            isLiveChartExpanded: workspace.isLiveChartExpanded,
            inspectorTab: workspace.inspectorTab.rawValue,
            inspectorLayout: workspace.inspectorLayout.rawValue,
            isContextDockVisible: workspace.isContextDockVisible,
            contextDockTab: workspace.contextDockTab.rawValue,
            allowsAutomaticInspectorReveal: workspace.allowsAutomaticInspectorReveal,
            sessionGrouping: workspace.sessionGrouping.rawValue,
            filterText: workspace.filterText,
            searchField: workspace.searchField.rawValue,
            isSearchEnabled: workspace.isSearchEnabled,
            categoryFilters: workspace.categoryFilters.map(\.rawValue).sorted(),
            hostFilter: workspace.hostFilter,
            processFilter: workspace.processFilter,
            ipFilter: workspace.ipFilter,
            filterRules: workspace.filterRules.map(ProjectFilterRuleSnapshot.init),
            isAdvancedFilterVisible: workspace.isAdvancedFilterVisible,
            isFilterBarVisible: workspace.isFilterBarVisible,
            isFollowingLiveSessions: workspace.isFollowingLiveSessions
        )
    }

    @MainActor
    func hydrateWorkspaceState(
        maxFilterRules: Int,
        allowsAutomaticInspectorReveal defaultAutomaticReveal: Bool?
    )
        -> WorkspaceState
    {
        let workspace = WorkspaceState(
            id: id,
            title: title,
            isClosable: isClosable,
            sidebarSelection: SidebarItem(rawValue: sidebarSelection) ?? .sessions,
            inspectorLayout: InspectorLayout(rawValue: inspectorLayout) ?? .hidden,
            isContextDockVisible: isContextDockVisible
        )
        workspace.navigatorMode = SidebarNavigatorMode(rawValue: navigatorMode) ?? .browse
        workspace.isLiveChartExpanded = isLiveChartExpanded
        workspace.inspectorTab = InspectorTab(rawValue: inspectorTab) ?? .timeline
        workspace.contextDockTab = ContextDockTab(rawValue: contextDockTab) ?? .details
        workspace.allowsAutomaticInspectorReveal = allowsAutomaticInspectorReveal ?? defaultAutomaticReveal
        workspace.sessionGrouping = SessionGrouping(rawValue: sessionGrouping) ?? .none
        workspace.filterText = filterText
        workspace.searchField = SessionSearchField(rawValue: searchField) ?? .allFields
        workspace.isSearchEnabled = isSearchEnabled
        workspace.categoryFilters = Set(categoryFilters.compactMap(SessionFilterCategory.init(rawValue:)))
        workspace.hostFilter = hostFilter
        workspace.processFilter = processFilter
        workspace.ipFilter = ipFilter
        workspace.filterRules = SessionFilterRule.normalized(
            filterRules.map(SessionFilterRule.init),
            limit: min(max(1, maxFilterRules), ProjectLimits.maximumFilterRules)
        )
        workspace.isAdvancedFilterVisible = isAdvancedFilterVisible
        workspace.isFilterBarVisible = isFilterBarVisible
        workspace.isFollowingLiveSessions = isFollowingLiveSessions
        return workspace
    }
}

private extension ProjectFilterRuleSnapshot {
    @MainActor
    init(_ rule: SessionFilterRule) {
        self.init(
            id: rule.id,
            isEnabled: rule.isEnabled,
            connector: rule.connector.rawValue,
            field: rule.field.rawValue,
            filterOperator: rule.filterOperator.rawValue,
            value: rule.value
        )
    }
}

private extension SessionFilterRule {
    nonisolated init(_ snapshot: ProjectFilterRuleSnapshot) {
        self.init(
            id: snapshot.id,
            isEnabled: snapshot.isEnabled,
            connector: FilterLogicConnector(rawValue: snapshot.connector) ?? .and,
            field: SessionFilterField(rawValue: snapshot.field) ?? .host,
            filterOperator: SessionFilterOperator(rawValue: snapshot.filterOperator) ?? .contains,
            value: snapshot.value
        )
    }
}
