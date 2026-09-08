import Foundation

// MARK: - SessionScopeDescriptor

/// One thing that is currently narrowing what the session surfaces show.
///
/// Effective visibility is not one filter but several independent layers — the
/// sidebar protocol lens, the workspace's own filters, the capture-local
/// Investigation query, the Project's Noise Control and the rows the user removed
/// from view. A surface that names only some of them lets the user hunt for a
/// filter that is not there, so every layer gets a descriptor and they are always
/// listed in the same ``Kind`` order.
///
/// `label` is bounded for display; `fullLabel` is the untruncated value, so help
/// and accessibility can always spell out a scope the row had to shorten.
struct SessionScopeDescriptor: Identifiable, Hashable {
    /// Declaration order *is* presentation order, and is also what decides which
    /// descriptors ``MainContentCoordinator/resetSessionFilters(in:)`` clears.
    enum Kind: Int, CaseIterable, Comparable {
        case protocolLens
        case search
        case categories
        /// The conjunctive protocol intersection an Overview aggregate added. It
        /// is listed separately from `categories` because it is AND-ed, and a
        /// reader who saw it folded into the OR-ed category line would expect the
        /// wrong result set.
        case protocolIntersection
        case findingsIntersection
        case host
        case process
        case ip
        /// The typed destination address a Flow aggregate added — destination
        /// only, unlike the sidebar `ip` scope.
        case destination
        case rules
        case query
        case noise
        case removed

        // MARK: Internal

        /// Whether Reset Session Filters clears this layer. Noise Control is
        /// Project-wide persisted state and removed rows are an explicit privacy
        /// action, so neither is ever swept up by a filter reset.
        var isClearedByFilterReset: Bool {
            switch self {
            case .noise,
                 .removed: false
            default: true
            }
        }

        static func < (lhs: Kind, rhs: Kind) -> Bool {
            lhs.rawValue < rhs.rawValue
        }
    }

    let kind: Kind
    /// Bounded, single-line text for the compact notice.
    let label: String
    /// The same fact with nothing truncated, for `help` and accessibility.
    let fullLabel: String

    var id: Kind {
        kind
    }
}

// MARK: - SessionScopeEmptyClassification

/// Why a session surface has no rows to draw. Distinguishing *nothing captured*
/// from *everything hidden* is the whole point: an empty list under an active
/// scope must never read as "waiting for packets", even while a live capture runs.
enum SessionScopeEmptyClassification: Equatable {
    /// There are rows on screen; no empty state applies.
    case rowsVisible
    /// The capture genuinely holds no sessions.
    case noSessionsCaptured
    /// Every session in the capture was removed from view.
    case allSessionsRemoved
    /// Sessions exist and are not all removed, but the active scope hides them.
    case hiddenByScope
}

// MARK: - SessionScopeAction

/// The one label/help pair for the single reset route, so the filter shelf and an
/// empty state can never describe the same action differently.
enum SessionScopeAction {
    static let resetTitle = String(localized: "Reset Session Filters")
    /// Used only where the full title genuinely cannot fit.
    static let resetShortTitle = String(localized: "Reset Filters")
    static let resetSystemImage = "arrow.clockwise"
    static let resetHelp = String(
        localized: """
        Clears this workspace's search, categories, host/client/IP drill-down, Overview and Flow \
        aggregate narrowing, advanced rules, Investigation query and sidebar protocol lens. Noise \
        Control and sessions removed from view are not affected.
        """
    )
}

// MARK: - SessionScopeSummary

/// The complete, ordered description of what a session surface is showing and why.
///
/// It is a plain value built on demand from already-computed counts, so Sessions,
/// Overview and Flow all say the same thing without any of them re-deriving
/// visibility or holding duplicated presentation state.
struct SessionScopeSummary: Equatable {
    // MARK: Internal

    static let empty = SessionScopeSummary(
        shownCount: 0,
        capturedCount: 0,
        removedCount: 0,
        descriptors: []
    )

    /// Sessions currently visible on the surface asking.
    let shownCount: Int
    /// Sessions decoded from the current capture, before any presentation scope —
    /// the honest denominator, which is why removed rows are counted separately
    /// rather than quietly shrinking it.
    let capturedCount: Int
    let removedCount: Int
    /// Active scope layers, always ordered by ``SessionScopeDescriptor/Kind``.
    let descriptors: [SessionScopeDescriptor]

    /// True only when something is actually narrowing a non-empty capture. An
    /// empty capture has nothing to explain, so the notice stays silent there.
    var isConstrained: Bool {
        capturedCount > 0 && !descriptors.isEmpty
    }

    /// Whether Reset Session Filters would change anything.
    var hasClearableFilters: Bool {
        descriptors.contains { $0.kind.isClearedByFilterReset }
    }

    var countLine: String {
        "Showing \(shownCount.formatted()) of \(capturedCount.formatted()) sessions"
    }

    var scopeLine: String {
        descriptors.map(\.label).joined(separator: " · ")
    }

    var fullScopeLine: String {
        descriptors.map(\.fullLabel).joined(separator: " · ")
    }

    /// One untruncated sentence for `help` and accessibility.
    var accessibilityLabel: String {
        descriptors.isEmpty ? countLine : "\(countLine). Active scope: \(fullScopeLine)."
    }

    var emptyClassification: SessionScopeEmptyClassification {
        if shownCount > 0 {
            return .rowsVisible
        }
        if capturedCount == 0 {
            return .noSessionsCaptured
        }
        if removedCount >= capturedCount {
            return .allSessionsRemoved
        }
        return .hiddenByScope
    }

    /// Builds the summary from one workspace's filter state plus the capture-side
    /// counts only the coordinator can supply. Cost is proportional to the number
    /// of active scopes, never to the capture.
    static func make(
        workspace: WorkspaceState,
        shownCount: Int,
        capturedCount: Int,
        removedCount: Int,
        noiseRuleCount: Int
    )
        -> SessionScopeSummary
    {
        var descriptors: [SessionScopeDescriptor] = []

        if let proto = workspace.sidebarSelection.protocolFilter {
            descriptors.append(SessionScopeDescriptor(
                kind: .protocolLens,
                label: "\(proto.label) lens",
                fullLabel: "Sidebar protocol lens: \(proto.label)"
            ))
        }

        if workspace.isSearchActive {
            let query = workspace.filterText.trimmingCharacters(in: .whitespaces)
            let field = workspace.searchField.displayName
            descriptors.append(SessionScopeDescriptor(
                kind: .search,
                label: "Search “\(bounded(query))” in \(field)",
                fullLabel: "Search “\(query)” in \(field)"
            ))
        }

        if !workspace.categoryFilters.isEmpty {
            // Fixed enum order, never set-iteration order, so the same active
            // categories always read the same way.
            let names = SessionFilterCategory.allCases
                .filter { workspace.categoryFilters.contains($0) }
                .map(\.title)
            let shown = names.prefix(Self.maximumListedCategories)
            let overflow = names.count - shown.count
            let label = overflow > 0
                ? "\(shown.joined(separator: ", ")) +\(overflow)"
                : shown.joined(separator: ", ")
            descriptors.append(SessionScopeDescriptor(
                kind: .categories,
                label: "Categories: \(label)",
                fullLabel: "Categories: \(names.joined(separator: ", "))"
            ))
        }

        if workspace.aggregateRequiresFindings {
            descriptors.append(SessionScopeDescriptor(
                kind: .findingsIntersection,
                label: "With Findings",
                fullLabel: "Sessions with typed findings"
            ))
        }
        if !workspace.aggregateProtocolFilters.isEmpty {
            // Fixed enum order for the same reason the categories line uses one.
            let names = ProtocolKind.allCases
                .filter { workspace.aggregateProtocolFilters.contains($0) }
                .map(\.label)
            let joined = names.joined(separator: " + ")
            descriptors.append(SessionScopeDescriptor(
                kind: .protocolIntersection,
                label: "Also \(bounded(joined))",
                fullLabel: "Sessions that also carry \(joined)"
            ))
        }

        if let host = workspace.hostFilter {
            descriptors.append(drillDown(kind: .host, title: "Host", value: host))
        }
        if let process = workspace.processFilter {
            descriptors.append(drillDown(kind: .process, title: "Client", value: process))
        }
        if let ip = workspace.ipFilter {
            descriptors.append(drillDown(kind: .ip, title: "IP", value: ip))
        }
        if let destination = workspace.aggregateDestinationFilter {
            descriptors.append(drillDown(kind: .destination, title: "Destination", value: destination))
        }

        let ruleCount = workspace.activeFilterRules.count
        if ruleCount > 0 {
            let text = "\(ruleCount) advanced rule\(ruleCount == 1 ? "" : "s")"
            descriptors.append(SessionScopeDescriptor(kind: .rules, label: text, fullLabel: text))
        }

        if workspace.hasActiveInvestigationQuery || workspace.isEvaluatingInvestigationQuery {
            // An evaluation in flight has not constrained anything yet, and saying
            // otherwise would credit the query with a narrowing it has not done.
            let isAccepted = workspace.hasActiveInvestigationQuery
            let text = isAccepted && !workspace.isEvaluatingInvestigationQuery
                ? "Investigation query"
                : (isAccepted ? "Investigation query (updating)" : "Investigation query (evaluating)")
            descriptors.append(SessionScopeDescriptor(kind: .query, label: text, fullLabel: text))
        }

        if noiseRuleCount > 0 {
            let text = "Noise Control: \(noiseRuleCount) rule\(noiseRuleCount == 1 ? "" : "s")"
            descriptors.append(SessionScopeDescriptor(
                kind: .noise,
                label: text,
                fullLabel: "\(text) (Project-wide)"
            ))
        }

        if removedCount > 0 {
            let text = "\(removedCount.formatted()) session\(removedCount == 1 ? "" : "s") removed from view"
            descriptors.append(SessionScopeDescriptor(kind: .removed, label: text, fullLabel: text))
        }

        return SessionScopeSummary(
            shownCount: shownCount,
            capturedCount: capturedCount,
            removedCount: removedCount,
            descriptors: descriptors.sorted { $0.kind < $1.kind }
        )
    }

    // MARK: Private

    /// Longest value shown inline before it is elided. `fullLabel` keeps the rest.
    private static let maximumValueLength = 32
    private static let maximumListedCategories = 3

    private static func drillDown(
        kind: SessionScopeDescriptor.Kind,
        title: String,
        value: String
    )
        -> SessionScopeDescriptor
    {
        SessionScopeDescriptor(
            kind: kind,
            label: "\(title): \(bounded(value))",
            fullLabel: "\(title): \(value)"
        )
    }

    private static func bounded(_ value: String) -> String {
        guard value.count > maximumValueLength else {
            return value
        }
        return String(value.prefix(maximumValueLength - 1)) + "…"
    }
}
