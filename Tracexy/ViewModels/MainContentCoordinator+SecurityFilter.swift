import Foundation

// MARK: - Security quick filtering

extension MainContentCoordinator {
    /// Whether a session matches a single quick-filter chip: a protocol chip
    /// matches anywhere in the decoded stack; `Security` includes every session
    /// that can produce an evidence-backed finding; `Errors` remains the exact
    /// error-only subset.
    nonisolated static func categoryMatches(_ session: SessionSummary, category: SessionFilterCategory) -> Bool {
        switch category {
        case .security:
            securityCategoryMatches(session)
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

    /// The single source of truth for the Security quick filter. These are the
    /// same decoded facts that produce `Finding` values; no reputation service,
    /// threat score, or unobserved exposure is inferred here.
    nonisolated static func securityCategoryMatches(_ session: SessionSummary) -> Bool {
        if session.status != .ok {
            return true
        }
        if session.protocolStack.contains(.http), !session.protocolStack.contains(.tls) {
            return true
        }
        if let query = session.dnsQuery, !query.isEmpty, session.dnsAnswers.isEmpty {
            return true
        }
        if let latency = session.latencyMilliseconds, latency > 400 {
            return true
        }
        return false
    }

    /// Quick-category group semantics, in one testable place: selected protocol
    /// chips are OR-ed within their group, selected investigation chips are
    /// OR-ed within theirs, and the two groups combine with AND. An empty set
    /// ("All") is no constraint.
    nonisolated static func categoryFilterMatches(
        _ session: SessionSummary,
        categories: Set<SessionFilterCategory>
    )
        -> Bool
    {
        let protocolCategories = categories.filter { !$0.isInvestigationFilter }
        let investigationCategories = categories.filter(\.isInvestigationFilter)
        if !protocolCategories.isEmpty,
           !protocolCategories.contains(where: { categoryMatches(session, category: $0) })
        {
            return false
        }
        if !investigationCategories.isEmpty,
           !investigationCategories.contains(where: { categoryMatches(session, category: $0) })
        {
            return false
        }
        return true
    }

    /// Security is a session quick filter, not a separate destination. Reuse the
    /// full table/search/group/inspector workflow and retain any complementary
    /// protocol, text, or advanced filters the user already applied.
    func showSecuritySessions() {
        let workspace = activeWorkspace
        workspace.sidebarSelection = .sessions
        workspace.hostFilter = nil
        workspace.processFilter = nil
        workspace.ipFilter = nil
        workspace.categoryFilters.insert(.security)
        workspace.isFilterBarVisible = true
    }
}
