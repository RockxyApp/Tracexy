import Foundation

// MARK: - Finding quick filtering

extension MainContentCoordinator {
    /// Whether a session matches a single quick-filter chip. The persisted
    /// `.security` discriminator is presented as Findings and matches only exact
    /// typed-finding membership; `Errors` remains the exact error-only subset.
    nonisolated static func categoryMatches(
        _ session: SessionSummary,
        category: SessionFilterCategory,
        findingSessionIDs: Set<UUID> = []
    )
        -> Bool
    {
        switch category {
        case .security:
            findingSessionIDs.contains(session.id)
        case .errors:
            session.status == .error
        default:
            if let kind = category.protocolKind {
                session.protocolStack.contains(kind)
            } else {
                true
            }
        }
    }

    /// Quick-category group semantics, in one testable place: selected protocol
    /// chips are OR-ed within their group, selected investigation chips are
    /// OR-ed within theirs, and the two groups combine with AND. An empty set
    /// ("All") is no constraint.
    nonisolated static func categoryFilterMatches(
        _ session: SessionSummary,
        categories: Set<SessionFilterCategory>,
        findingSessionIDs: Set<UUID> = []
    )
        -> Bool
    {
        let protocolCategories = categories.filter { !$0.isInvestigationFilter }
        let investigationCategories = categories.filter(\.isInvestigationFilter)
        if !protocolCategories.isEmpty,
           !protocolCategories.contains(where: {
               categoryMatches(session, category: $0, findingSessionIDs: findingSessionIDs)
           })
        {
            return false
        }
        if !investigationCategories.isEmpty,
           !investigationCategories.contains(where: {
               categoryMatches(session, category: $0, findingSessionIDs: findingSessionIDs)
           })
        {
            return false
        }
        return true
    }

    /// Findings is a session quick filter, not a separate destination. Reuse the
    /// full table/search/group/inspector workflow and retain any complementary
    /// protocol, text, or advanced filters the user already applied.
    func showFindingSessions() {
        let workspace = activeWorkspace
        workspace.sidebarSelection = .sessions
        workspace.hostFilter = nil
        workspace.processFilter = nil
        workspace.ipFilter = nil
        workspace.categoryFilters.insert(.security)
        workspace.isFilterBarVisible = true
    }
}
