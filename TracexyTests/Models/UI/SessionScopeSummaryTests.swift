import Foundation
import Testing
@testable import Tracexy

@MainActor
@Suite("Session scope summary")
struct SessionScopeSummaryTests {
    // MARK: Internal

    @Test("A sidebar protocol lens is an active filter like any other")
    func sidebarLensCountsAsActiveFilter() {
        let workspace = WorkspaceState(title: "Capture")
        #expect(!workspace.hasActiveFilters)

        workspace.sidebarSelection = .tcp
        #expect(workspace.hasActiveFilters)

        // Non-protocol destinations are places, not filters.
        for item in [SidebarItem.sessions, .overview, .flow, .history, .saved] {
            workspace.sidebarSelection = item
            #expect(!workspace.hasActiveFilters, "\(item.rawValue) must not read as a filter")
        }
    }

    @Test("An unfiltered non-empty capture reports no scope at all")
    func unconstrainedCaptureIsSilent() {
        let summary = SessionScopeSummary.make(
            workspace: WorkspaceState(title: "Capture"),
            shownCount: 12,
            capturedCount: 12,
            removedCount: 0,
            noiseRuleCount: 0
        )

        #expect(summary.descriptors.isEmpty)
        #expect(!summary.isConstrained)
        #expect(!summary.hasClearableFilters)
        #expect(summary.emptyClassification == .rowsVisible)
    }

    @Test("A disabled or whitespace-only search never enters the scope")
    func inertSearchIsNotScope() {
        let workspace = WorkspaceState(title: "Capture")
        workspace.filterText = "example"
        workspace.isSearchEnabled = false
        #expect(kinds(for: workspace).isEmpty)

        workspace.isSearchEnabled = true
        workspace.filterText = "   "
        #expect(kinds(for: workspace).isEmpty)

        workspace.filterText = "example"
        #expect(kinds(for: workspace) == [.search])
    }

    @Test("Every active layer is described exactly once, in a fixed order")
    func descriptorsAreDeterministicallyOrdered() {
        let workspace = WorkspaceState(title: "Capture")
        workspace.sidebarSelection = .dns
        workspace.filterText = "cdn"
        workspace.categoryFilters = [.tls, .dns, .errors]
        workspace.hostFilter = "example.com"
        workspace.processFilter = "Safari"
        workspace.ipFilter = "192.0.2.10"
        workspace.filterRules = [SessionFilterRule(field: .host, value: "cdn")]
        workspace.acceptedInvestigationDraft = InvestigationQueryDraft()

        let summary = SessionScopeSummary.make(
            workspace: workspace,
            shownCount: 2,
            capturedCount: 40,
            removedCount: 3,
            noiseRuleCount: 2
        )

        #expect(summary.descriptors.map(\.kind) == [
            .protocolLens, .search, .categories, .host, .process, .ip, .rules, .query, .noise, .removed,
        ])
        // Categories read in enum order, never in set-iteration order.
        #expect(summary.descriptors.first { $0.kind == .categories }?.fullLabel
            == "Categories: DNS, TLS, Errors")
        #expect(summary.countLine == "Showing 2 of 40 sessions")
        #expect(summary.isConstrained)
        #expect(summary.hasClearableFilters)
    }

    @Test("Noise Control and removed rows are scope, but not filter-reset scope")
    func projectScopeIsNotClearedByFilterReset() {
        let summary = SessionScopeSummary.make(
            workspace: WorkspaceState(title: "Capture"),
            shownCount: 4,
            capturedCount: 9,
            removedCount: 1,
            noiseRuleCount: 3
        )

        #expect(summary.descriptors.map(\.kind) == [.noise, .removed])
        #expect(summary.isConstrained)
        #expect(!summary.hasClearableFilters)
        #expect(summary.descriptors.first { $0.kind == .noise }?.fullLabel
            == "Noise Control: 3 rules (Project-wide)")
        #expect(summary.descriptors.first { $0.kind == .removed }?.label
            == "1 session removed from view")
    }

    @Test("Long values are elided for display and kept whole for accessibility")
    func longValuesAreBoundedButNeverLost() throws {
        let host = "extremely-long-subdomain-name.example.internal"
        let workspace = WorkspaceState(title: "Capture")
        workspace.hostFilter = host

        let summary = SessionScopeSummary.make(
            workspace: workspace,
            shownCount: 1,
            capturedCount: 5,
            removedCount: 0,
            noiseRuleCount: 0
        )
        let descriptor = try #require(summary.descriptors.first)

        #expect(descriptor.label.count < "Host: \(host)".count)
        #expect(descriptor.label.hasSuffix("…"))
        #expect(descriptor.fullLabel == "Host: \(host)")
        #expect(summary.accessibilityLabel.contains(host))
    }

    @Test("An in-flight query is described as evaluating, not as a result")
    func evaluatingQueryIsDistinctFromAcceptedQuery() {
        let workspace = WorkspaceState(title: "Capture")
        workspace.isEvaluatingInvestigationQuery = true
        #expect(workspace.hasActiveFilters)
        #expect(label(for: workspace, kind: .query) == "Investigation query (evaluating)")

        workspace.acceptedInvestigationDraft = InvestigationQueryDraft()
        #expect(label(for: workspace, kind: .query) == "Investigation query (updating)")

        workspace.isEvaluatingInvestigationQuery = false
        #expect(label(for: workspace, kind: .query) == "Investigation query")
    }

    @Test("An empty list names why it is empty instead of guessing")
    func emptyClassificationDistinguishesTheReasons() {
        #expect(classification(shown: 3, captured: 9, removed: 0) == .rowsVisible)
        #expect(classification(shown: 0, captured: 0, removed: 0) == .noSessionsCaptured)
        #expect(classification(shown: 0, captured: 6, removed: 6) == .allSessionsRemoved)
        // Sessions exist and are not all removed: something in the scope hides them,
        // even while a capture is running.
        #expect(classification(shown: 0, captured: 6, removed: 2) == .hiddenByScope)
    }

    @Test("An empty capture has nothing to explain")
    func emptyCaptureShowsNoNotice() {
        let workspace = WorkspaceState(title: "Capture")
        workspace.filterText = "cdn"

        let summary = SessionScopeSummary.make(
            workspace: workspace,
            shownCount: 0,
            capturedCount: 0,
            removedCount: 0,
            noiseRuleCount: 0
        )

        #expect(!summary.descriptors.isEmpty)
        #expect(!summary.isConstrained)
        #expect(summary.emptyClassification == .noSessionsCaptured)
    }

    // MARK: Private

    private func kinds(for workspace: WorkspaceState) -> [SessionScopeDescriptor.Kind] {
        SessionScopeSummary.make(
            workspace: workspace,
            shownCount: 1,
            capturedCount: 4,
            removedCount: 0,
            noiseRuleCount: 0
        )
        .descriptors.map(\.kind)
    }

    private func label(
        for workspace: WorkspaceState,
        kind: SessionScopeDescriptor.Kind
    )
        -> String?
    {
        SessionScopeSummary.make(
            workspace: workspace,
            shownCount: 1,
            capturedCount: 4,
            removedCount: 0,
            noiseRuleCount: 0
        )
        .descriptors.first { $0.kind == kind }?.label
    }

    private func classification(
        shown: Int,
        captured: Int,
        removed: Int
    )
        -> SessionScopeEmptyClassification
    {
        SessionScopeSummary(
            shownCount: shown,
            capturedCount: captured,
            removedCount: removed,
            descriptors: []
        )
        .emptyClassification
    }
}
