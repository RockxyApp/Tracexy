import Testing
@testable import Tracexy

/// Pure, deterministic coverage for the footer presentation package: the session
/// footer's action descriptors and status text, and the right Details footer
/// summary. These are the parts that were made pure precisely so they could be
/// asserted without a running AppKit window.
struct WorkspaceFooterModelTests {
    // MARK: - Session footer action descriptors

    @Test("Footer actions are always ordered Clear → Filter → Auto Select")
    func actionOrderingIsStable() {
        let actions = SessionStatusBarModel.actions(
            activeFilterRuleCount: 0,
            isAdvancedFilterVisible: false,
            autoSelectLatest: false,
            hasSessions: true
        )
        #expect(actions.map(\.kind) == [.clear, .filter, .autoSelect])
        // Identity is the kind, so the overflow menu and inline rows agree.
        #expect(actions.map(\.id) == [.clear, .filter, .autoSelect])
    }

    @Test("There are exactly the three real actions — no invented controls")
    func onlyRealActionsExist() {
        let actions = SessionStatusBarModel.actions(
            activeFilterRuleCount: 0,
            isAdvancedFilterVisible: false,
            autoSelectLatest: false,
            hasSessions: true
        )
        #expect(actions.count == 3)
        #expect(Set(actions.map(\.kind)) == Set(SessionFooterAction.Kind.allCases))
    }

    @Test("Clear is disabled on an empty capture and enabled once sessions exist")
    func clearReflectsSessionPresence() {
        func clear(hasSessions: Bool) -> SessionFooterAction? {
            SessionStatusBarModel.actions(
                activeFilterRuleCount: 0,
                isAdvancedFilterVisible: false,
                autoSelectLatest: false,
                hasSessions: hasSessions
            ).first { $0.kind == .clear }
        }
        #expect(clear(hasSessions: false)?.isEnabled == false)
        #expect(clear(hasSessions: true)?.isEnabled == true)
        // Clear is never a toggle, so it is never "active".
        #expect(clear(hasSessions: true)?.isActive == false)
    }

    @Test("Filter is active when the builder is open or any rule is live")
    func filterActiveStateAndTitle() {
        func filter(rules: Int, visible: Bool) -> SessionFooterAction? {
            SessionStatusBarModel.actions(
                activeFilterRuleCount: rules,
                isAdvancedFilterVisible: visible,
                autoSelectLatest: false,
                hasSessions: true
            ).first { $0.kind == .filter }
        }

        let idle = filter(rules: 0, visible: false)
        #expect(idle?.isActive == false)
        #expect(idle?.title == "Filter")

        // Revealed builder counts as active even with no live rules yet.
        #expect(filter(rules: 0, visible: true)?.isActive == true)
        #expect(filter(rules: 0, visible: true)?.title == "Filter")

        // Live rules count as active and relabel, even while the builder is hidden.
        let withRules = filter(rules: 2, visible: false)
        #expect(withRules?.isActive == true)
        #expect(withRules?.title == "Filter (on)")
    }

    @Test("Auto Select's active state mirrors the toggle")
    func autoSelectReflectsToggle() {
        func autoSelect(_ on: Bool) -> SessionFooterAction? {
            SessionStatusBarModel.actions(
                activeFilterRuleCount: 0,
                isAdvancedFilterVisible: false,
                autoSelectLatest: on,
                hasSessions: true
            ).first { $0.kind == .autoSelect }
        }
        #expect(autoSelect(false)?.isActive == false)
        #expect(autoSelect(true)?.isActive == true)
    }

    // MARK: - Session footer status text

    @Test("Session-list status text tracks totals, filtering and selection")
    func statusTextSessionList() {
        #expect(SessionStatusBarModel.statusText(
            surface: .sessionList, totalSessions: 0, visibleCount: 0, hasSelection: false, findingCount: 0
        ) == "No sessions")

        #expect(SessionStatusBarModel.statusText(
            surface: .sessionList, totalSessions: 5, visibleCount: 5, hasSelection: false, findingCount: 0
        ) == "5 sessions")

        #expect(SessionStatusBarModel.statusText(
            surface: .sessionList, totalSessions: 5, visibleCount: 3, hasSelection: false, findingCount: 0
        ) == "3 of 5 sessions")

        #expect(SessionStatusBarModel.statusText(
            surface: .sessionList, totalSessions: 5, visibleCount: 3, hasSelection: true, findingCount: 0
        ) == "3 shown · 1 selected")
    }

    @Test("Intelligence surfaces get their own quiet summaries")
    func statusTextIntelligenceSurfaces() {
        #expect(SessionStatusBarModel.statusText(
            surface: .overview, totalSessions: 0, visibleCount: 0, hasSelection: false, findingCount: 0
        ) == "Capture overview · No sessions")

        #expect(SessionStatusBarModel.statusText(
            surface: .overview, totalSessions: 4, visibleCount: 4, hasSelection: false, findingCount: 0
        ) == "Capture overview · 4 sessions")

        #expect(SessionStatusBarModel.statusText(
            surface: .flow, totalSessions: 2, visibleCount: 2, hasSelection: false, findingCount: 0
        ) == "Flow map · 2 sessions")

        #expect(SessionStatusBarModel.statusText(
            surface: .security, totalSessions: 9, visibleCount: 9, hasSelection: false, findingCount: 0
        ) == "No findings")

        #expect(SessionStatusBarModel.statusText(
            surface: .security, totalSessions: 9, visibleCount: 9, hasSelection: false, findingCount: 1
        ) == "1 finding")

        #expect(SessionStatusBarModel.statusText(
            surface: .security, totalSessions: 9, visibleCount: 9, hasSelection: false, findingCount: 3
        ) == "3 findings")
    }

    @Test("Only the session list surfaces the Clear / Filter / Auto Select controls")
    func onlySessionListShowsControls() {
        #expect(StatusSurface.sessionList.showsSessionControls)
        #expect(!StatusSurface.overview.showsSessionControls)
        #expect(!StatusSurface.flow.showsSessionControls)
        #expect(!StatusSurface.security.showsSessionControls)
    }

    // MARK: - Details footer summary

    @Test("The Details footer says so honestly when nothing is selected")
    func detailsFooterNoSelection() {
        #expect(ContextDockDetailsFooter.summary(
            hasSelection: false, sessionCount: 0, primaryProtocol: nil, formattedBytes: nil
        ) == "No selection")
    }

    @Test("A single selection reads count · protocol · bytes")
    func detailsFooterSingleSession() {
        #expect(ContextDockDetailsFooter.summary(
            hasSelection: true, sessionCount: 1, primaryProtocol: "TLS", formattedBytes: "36 KB"
        ) == "1 session · TLS · 36 KB")
    }

    @Test("The summary omits figures it does not have")
    func detailsFooterOmitsMissingValues() {
        // Empty derived strings are dropped rather than rendered as stray separators.
        #expect(ContextDockDetailsFooter.summary(
            hasSelection: true, sessionCount: 1, primaryProtocol: "", formattedBytes: ""
        ) == "1 session")
    }
}
