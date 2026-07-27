import Testing
@testable import Tracexy

/// Pure, deterministic coverage for the footer presentation package: the session
/// footer's action descriptors, its telemetry chips, the center status text, and
/// the right Details footer summary. These are the parts that were made pure
/// precisely so they could be asserted without a running AppKit window.
struct WorkspaceFooterModelTests {
    // MARK: Internal

    // MARK: - Session footer action descriptors

    @Test("Primary launchers are ordered Save Capture → New Focus Set → Noise Control")
    func primaryOrderingIsStable() {
        let primary = makeActions().filter { $0.placement == .primary }
        #expect(primary.map(\.kind) == [.saveCapture, .newFocusSet, .noiseControl])
    }

    @Test("Descriptors split into primary launchers and List Options with stable unique ids")
    func placementAndIdentity() {
        let actions = makeActions()

        // Exactly the six real effects — no invented controls.
        #expect(actions.count == 6)
        #expect(Set(actions.map(\.kind)) == Set(FooterActionDescriptor.Kind.allCases))

        // Identity is the kind, so every surface variant agrees, and ids are unique.
        #expect(actions.map(\.id) == actions.map(\.kind))
        #expect(Set(actions.map(\.id)).count == actions.count)

        // Clear / Advanced Filters / Auto Select are List Options, never inline.
        let listOptions = actions.filter { $0.placement == .listOptions }
        #expect(listOptions.map(\.kind) == [.clearSessions, .advancedFilters, .autoSelectLatest])

        // Priority is monotonic across the whole catalog, primaries first.
        #expect(actions.map(\.priority) == [0, 1, 2, 3, 4, 5])
    }

    @Test("Every descriptor carries a distinct, non-empty title and help")
    func titlesAndHelpAreDistinct() {
        let actions = makeActions()
        #expect(actions.allSatisfy { !$0.title.isEmpty && !$0.help.isEmpty })
        #expect(Set(actions.map(\.title)).count == actions.count)
        #expect(Set(actions.map(\.help)).count == actions.count)
    }

    @Test("Save Capture is enabled only from canSaveCapture")
    func saveCaptureEnabled() {
        #expect(action(.saveCapture, in: makeActions(canSaveCapture: false))?.isEnabled == false)
        #expect(action(.saveCapture, in: makeActions(canSaveCapture: true))?.isEnabled == true)
    }

    @Test("New Focus Set is enabled only from canAddFocusSet")
    func newFocusSetEnabled() {
        #expect(action(.newFocusSet, in: makeActions(canAddFocusSet: false))?.isEnabled == false)
        #expect(action(.newFocusSet, in: makeActions(canAddFocusSet: true))?.isEnabled == true)
    }

    @Test("Noise Control is always enabled and active only when muting")
    func noiseControlMetadata() {
        let inactive = action(.noiseControl, in: makeActions(isNoiseControlActive: false))
        #expect(inactive?.isEnabled == true)
        #expect(inactive?.isActive == false)

        let active = action(.noiseControl, in: makeActions(isNoiseControlActive: true))
        #expect(active?.isEnabled == true)
        #expect(active?.isActive == true)
    }

    @Test("Clear Current Sessions is destructive and disabled with no sessions")
    func clearMetadata() {
        let empty = action(.clearSessions, in: makeActions(hasSessions: false))
        #expect(empty?.isDestructive == true)
        #expect(empty?.isEnabled == false)
        #expect(empty?.title == "Clear Capture Data…")
        #expect(empty?.help.contains("retained packets") == true)
        // Clear is never a toggle, so it is never "active".
        #expect(empty?.isActive == false)

        #expect(action(.clearSessions, in: makeActions(hasSessions: true))?.isEnabled == true)

        // Only Clear is destructive.
        #expect(makeActions().filter(\.isDestructive).map(\.kind) == [.clearSessions])
    }

    @Test("Advanced Filters shows active/check state from the builder or live rules")
    func advancedFiltersActiveState() {
        let idle = action(.advancedFilters, in: makeActions(activeFilterRuleCount: 0, isAdvancedFilterVisible: false))
        #expect(idle?.isActive == false)
        #expect(idle?.title == "Advanced Filters")

        // Revealed builder counts as active even with no live rules yet.
        #expect(action(
            .advancedFilters,
            in: makeActions(activeFilterRuleCount: 0, isAdvancedFilterVisible: true)
        )?.isActive == true)

        // Live rules count as active and relabel, even while the builder is hidden.
        let withRules = action(
            .advancedFilters,
            in: makeActions(activeFilterRuleCount: 2, isAdvancedFilterVisible: false)
        )
        #expect(withRules?.isActive == true)
        #expect(withRules?.title == "Advanced Filters (on)")
    }

    @Test("Auto Select Latest's active state mirrors the toggle")
    func autoSelectActiveState() {
        #expect(action(.autoSelectLatest, in: makeActions(autoSelectLatest: false))?.isActive == false)
        #expect(action(.autoSelectLatest, in: makeActions(autoSelectLatest: true))?.isActive == true)
    }

    // MARK: - Session footer status text

    @Test("Session-list status text follows the selected/visible/total hierarchy")
    func statusTextSessionList() {
        #expect(status(total: 0, visible: 0, selected: false) == "No sessions")
        #expect(status(total: 5, visible: 5, selected: false) == "5 sessions")
        #expect(status(total: 5, visible: 3, selected: false) == "3 of 5 sessions")
        #expect(status(total: 5, visible: 5, selected: true) == "1 selected · 5 sessions")
        // Selected + filtered retains selected, visible and total.
        #expect(status(total: 5, visible: 3, selected: true) == "1 selected · 3 of 5 shown")
    }

    @Test("Intelligence surfaces keep their own quiet summaries")
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

    @Test("Non-session surfaces expose no controls but retain their summaries")
    func onlySessionListShowsControls() {
        // The view gates descriptors on this flag, so only the session list gets
        // the feature launchers / List Options; the rest keep status + telemetry.
        #expect(StatusSurface.sessionList.showsSessionControls)
        #expect(!StatusSurface.overview.showsSessionControls)
        #expect(!StatusSurface.flow.showsSessionControls)
        #expect(!StatusSurface.security.showsSessionControls)
    }

    // MARK: - Telemetry chips

    @Test("Packet drops are absent without statistics or when nothing was dropped")
    func packetDropsAbsent() {
        #expect(telemetry(hasCaptureStatistics: false, totalDropped: 0, kind: .packetDrops) == nil)
        #expect(telemetry(hasCaptureStatistics: false, totalDropped: 42, kind: .packetDrops) == nil)
        #expect(telemetry(hasCaptureStatistics: true, totalDropped: 0, kind: .packetDrops) == nil)
    }

    @Test("Packet drops warn only for material loss, otherwise stay neutral")
    func packetDropsRole() {
        let minor = telemetry(hasCaptureStatistics: true, totalDropped: 3, isMaterialLoss: false, kind: .packetDrops)
        #expect(minor?.role == .neutral)

        let material = telemetry(hasCaptureStatistics: true, totalDropped: 3, isMaterialLoss: true, kind: .packetDrops)
        #expect(material?.role == .warning)
    }

    @Test("Session errors are labelled \"session errors\" with the error role")
    func sessionErrorsLabel() {
        #expect(telemetry(errorCount: 0, kind: .sessionErrors) == nil)

        let errors = telemetry(errorCount: 3, kind: .sessionErrors)
        #expect(errors?.role == .error)
        #expect(errors?.text.contains("session error") == true)
    }

    @Test("Combined live rate appears only while capturing with a sample, and is never directional")
    func liveRatePresence() {
        // Not capturing → no live rate, even with a sample value.
        #expect(telemetry(isCapturing: false, liveBytesPerSecond: 2_048, kind: .liveRate) == nil)
        // Capturing but no sample yet → no live rate.
        #expect(telemetry(isCapturing: true, liveBytesPerSecond: nil, kind: .liveRate) == nil)

        // Capturing with a sample → a single combined live-role chip.
        let items = makeTelemetry(
            isCapturing: true,
            liveBytesPerSecond: 2_048,
            bytesUp: 60,
            bytesDown: 40
        )
        let liveKinds = items.filter { $0.role == .live }.map(\.kind)
        #expect(liveKinds == [.liveRate])

        // Directional totals exist but are neutral — no invented directional speed.
        let up = items.first { $0.kind == .bytesUp }
        let down = items.first { $0.kind == .bytesDown }
        #expect(up?.role == .neutral)
        #expect(down?.role == .neutral)
    }

    @Test("Capture duration chip appears only when a capture is running")
    func captureDurationPresence() {
        #expect(telemetry(hasCaptureDuration: false, kind: .captureDuration) == nil)
        #expect(telemetry(hasCaptureDuration: true, kind: .captureDuration) != nil)
    }

    @Test("Byte totals are omitted when zero")
    func byteTotalsOmitted() {
        let empty = makeTelemetry(totalBytes: 0, bytesUp: 0, bytesDown: 0)
        #expect(!empty.contains { $0.kind == .totalBytes })
        #expect(!empty.contains { $0.kind == .bytesUp })
        #expect(!empty.contains { $0.kind == .bytesDown })

        let present = makeTelemetry(totalBytes: 100, bytesUp: 60, bytesDown: 40)
        #expect(present.first { $0.kind == .totalBytes }?.role == .neutral)
        #expect(present.first { $0.kind == .bytesUp }?.role == .neutral)
        #expect(present.first { $0.kind == .bytesDown }?.role == .neutral)
    }

    @Test("Total help names session-attributed bytes, not payload")
    func totalHelpWording() {
        let total = telemetry(totalBytes: 100, kind: .totalBytes)
        #expect(total?.help.contains("Session-attributed") == true)
        #expect(total?.help.contains("not raw payload") == true)
    }

    @Test("Telemetry is ordered by importance when everything is present")
    func telemetryOrdering() {
        let items = makeTelemetry(
            isCapturing: true,
            hasCaptureStatistics: true,
            totalDropped: 5,
            isMaterialLoss: true,
            errorCount: 2,
            hasCaptureDuration: true,
            liveBytesPerSecond: 4_096,
            totalBytes: 100,
            bytesUp: 60,
            bytesDown: 40
        )
        #expect(items.map(\.kind) == [
            .packetDrops, .sessionErrors, .captureDuration, .liveRate, .totalBytes, .bytesUp, .bytesDown,
        ])
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

    // MARK: Private

    /// Build the footer action catalog with sensible defaults so each test varies
    /// only the input it is about.
    private func makeActions(
        canSaveCapture: Bool = true,
        canAddFocusSet: Bool = true,
        isNoiseControlActive: Bool = false,
        hasSessions: Bool = true,
        activeFilterRuleCount: Int = 0,
        isAdvancedFilterVisible: Bool = false,
        autoSelectLatest: Bool = false
    )
        -> [FooterActionDescriptor]
    {
        SessionStatusBarModel.actions(
            canSaveCapture: canSaveCapture,
            canAddFocusSet: canAddFocusSet,
            isNoiseControlActive: isNoiseControlActive,
            hasSessions: hasSessions,
            activeFilterRuleCount: activeFilterRuleCount,
            isAdvancedFilterVisible: isAdvancedFilterVisible,
            autoSelectLatest: autoSelectLatest
        )
    }

    private func action(
        _ kind: FooterActionDescriptor.Kind,
        in actions: [FooterActionDescriptor]
    )
        -> FooterActionDescriptor?
    {
        actions.first { $0.kind == kind }
    }

    /// Build the telemetry list with defaults that suppress every chip, so a test
    /// enables exactly the ones it asserts on.
    private func makeTelemetry(
        isCapturing: Bool = false,
        hasCaptureStatistics: Bool = false,
        totalDropped: Int = 0,
        isMaterialLoss: Bool = false,
        errorCount: Int = 0,
        hasCaptureDuration: Bool = false,
        liveBytesPerSecond: Double? = nil,
        totalBytes: Int = 0,
        bytesUp: Int = 0,
        bytesDown: Int = 0
    )
        -> [FooterTelemetry]
    {
        SessionStatusBarModel.telemetry(
            isCapturing: isCapturing,
            hasCaptureStatistics: hasCaptureStatistics,
            totalDropped: totalDropped,
            isMaterialLoss: isMaterialLoss,
            errorCount: errorCount,
            hasCaptureDuration: hasCaptureDuration,
            liveBytesPerSecond: liveBytesPerSecond,
            totalBytes: totalBytes,
            bytesUp: bytesUp,
            bytesDown: bytesDown
        )
    }

    /// Fetch a single telemetry chip by kind from a defaulted build.
    private func telemetry(
        isCapturing: Bool = false,
        hasCaptureStatistics: Bool = false,
        totalDropped: Int = 0,
        isMaterialLoss: Bool = false,
        errorCount: Int = 0,
        hasCaptureDuration: Bool = false,
        liveBytesPerSecond: Double? = nil,
        totalBytes: Int = 0,
        bytesUp: Int = 0,
        bytesDown: Int = 0,
        kind: FooterTelemetry.Kind
    )
        -> FooterTelemetry?
    {
        makeTelemetry(
            isCapturing: isCapturing,
            hasCaptureStatistics: hasCaptureStatistics,
            totalDropped: totalDropped,
            isMaterialLoss: isMaterialLoss,
            errorCount: errorCount,
            hasCaptureDuration: hasCaptureDuration,
            liveBytesPerSecond: liveBytesPerSecond,
            totalBytes: totalBytes,
            bytesUp: bytesUp,
            bytesDown: bytesDown
        ).first { $0.kind == kind }
    }

    private func status(total: Int, visible: Int, selected: Bool) -> String {
        SessionStatusBarModel.statusText(
            surface: .sessionList,
            totalSessions: total,
            visibleCount: visible,
            hasSelection: selected,
            findingCount: 0
        )
    }
}
