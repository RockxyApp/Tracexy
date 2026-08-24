import Testing
@testable import Tracexy

@Suite("Live investigation chrome")
struct LiveInvestigationChromeTests {
    // MARK: Internal

    @Test("command catalog has stable ownership and order")
    func commandOwnership() {
        let commands = makeCommands()

        #expect(commands.map(\.id) == [
            .followLive,
            .jumpToLatest,
            .investigate,
            .clearCapture,
            .saveCapture,
            .newFocusSet,
            .noiseControl,
            .restoreRemovedSessions,
            .advancedFilters,
        ])
        #expect(Set(commands.map(\.id)) == Set(SessionCommandKind.allCases))
        #expect(commands.map(\.priority) == Array(0 ... 8))
        #expect(commands.filter(\.isDestructive).map(\.id) == [.clearCapture])
        #expect(commands.filter { $0.placement == .overflow }.map(\.id) == [
            .restoreRemovedSessions,
            .advancedFilters,
        ])
    }

    @Test("Follow Live and Jump to Latest expose distinct state")
    func followingAndJumpAreDistinct() {
        let stopped = makeCommands(isFollowingLive: false, hasVisibleSessions: false)
        #expect(command(.followLive, in: stopped)?.isEnabled == true)
        #expect(command(.followLive, in: stopped)?.isActive == false)
        #expect(command(.jumpToLatest, in: stopped)?.isEnabled == false)

        let following = makeCommands(isFollowingLive: true, hasVisibleSessions: true)
        #expect(command(.followLive, in: following)?.isActive == true)
        #expect(command(.followLive, in: following)?.help.contains("scroll") == true)
        #expect(command(.jumpToLatest, in: following)?.isEnabled == true)
        #expect(command(.jumpToLatest, in: following)?.isActive == false)
    }

    @Test("capture mutations use truthful availability")
    func captureMutationAvailability() {
        let empty = makeCommands(
            hasCaptureData: false,
            canSaveCapture: false,
            canAddFocusSet: false,
            removedSessionCount: 0
        )
        #expect(command(.clearCapture, in: empty)?.isEnabled == false)
        #expect(command(.investigate, in: empty)?.isEnabled == false)
        #expect(command(.saveCapture, in: empty)?.isEnabled == false)
        #expect(command(.newFocusSet, in: empty)?.isEnabled == false)
        #expect(command(.restoreRemovedSessions, in: empty)?.isEnabled == false)

        let available = makeCommands(
            hasCaptureData: true,
            canSaveCapture: true,
            canAddFocusSet: true,
            removedSessionCount: 2
        )
        #expect(command(.clearCapture, in: available)?.isEnabled == true)
        #expect(command(.investigate, in: available)?.isEnabled == true)
        #expect(command(.saveCapture, in: available)?.isEnabled == true)
        #expect(command(.newFocusSet, in: available)?.isEnabled == true)
        #expect(command(.restoreRemovedSessions, in: available)?.isEnabled == true)
    }

    @Test("Investigation chip distinguishes evaluation, matches, and incomplete evidence")
    func investigationChipTruth() {
        #expect(InvestigationQueryChipModel.label(
            isEvaluating: true,
            hasActiveQuery: false,
            matchedCount: 0,
            incompleteCount: 0
        ) == "Investigation · evaluating")
        #expect(InvestigationQueryChipModel.label(
            isEvaluating: true,
            hasActiveQuery: true,
            matchedCount: 4,
            incompleteCount: 2
        ) == "Investigation · updating")
        #expect(InvestigationQueryChipModel.label(
            isEvaluating: false,
            hasActiveQuery: true,
            matchedCount: 4,
            incompleteCount: 2
        ) == "Investigation · 4 matched · 2 incomplete")
        #expect(InvestigationQueryChipModel.showsCoverage(incompleteCount: 0, coverageReasonCount: 1))
        #expect(!InvestigationQueryChipModel.showsCoverage(incompleteCount: 0, coverageReasonCount: 0))
    }

    @Test("stopped readiness exposes the source and unknown accounting")
    func stoppedReadiness() {
        let presentation = makeReadiness(
            displayState: .stopped,
            helperStatus: .installedIncompatible
        )

        #expect(presentation.title == "Stopped")
        #expect(item("Interface", in: presentation)?.value.contains("Wi-Fi (en0) · up") == true)
        #expect(item("Capture helper", in: presentation)?.value == "Incompatible · update needed")
        #expect(item("Capture helper", in: presentation)?.level == .attention)
        #expect(item("Capture filter", in: presentation)?.value == "All traffic")
        #expect(item("Interface drops", in: presentation)?.value == "Unknown while stopped")
        #expect(item("Helper drops", in: presentation)?.value == "Not active")
    }

    @Test("missing interface is attention, never fabricated as ready")
    func missingInterface() {
        let presentation = makeReadiness(interface: nil)
        let interface = item("Interface", in: presentation)

        #expect(interface?.value == "en0 · unavailable")
        #expect(interface?.level == .attention)
    }

    @Test("live readiness keeps loss stages separate")
    func liveLossStages() {
        let presentation = makeReadiness(
            displayState: .capturing,
            helperStatus: .installedCompatible,
            statistics: CaptureStatistics(
                received: 100,
                droppedByKernel: 2,
                droppedByInterface: 1
            ),
            helperDrops: 4,
            retentionEvictions: 5
        )

        #expect(item("Interface drops", in: presentation)?.value == "3 reported")
        #expect(item("Helper drops", in: presentation)?.value == "4 reported")
        #expect(item("Outside memory window", in: presentation)?.value == "5 frames")
        #expect(item("Helper drops", in: presentation)?.level == .attention)
        #expect(item("Outside memory window", in: presentation)?.level == .neutral)
    }

    // MARK: Private

    private func makeCommands(
        isFollowingLive: Bool = false,
        hasVisibleSessions: Bool = true,
        hasCaptureData: Bool = true,
        canSaveCapture: Bool = true,
        canAddFocusSet: Bool = true,
        isNoiseControlActive: Bool = false,
        removedSessionCount: Int = 0,
        activeFilterRuleCount: Int = 0,
        isAdvancedFilterVisible: Bool = false
    )
        -> [SessionCommandDescriptor]
    {
        SessionCommandBarModel.commands(
            isFollowingLive: isFollowingLive,
            hasVisibleSessions: hasVisibleSessions,
            hasCaptureData: hasCaptureData,
            canSaveCapture: canSaveCapture,
            canAddFocusSet: canAddFocusSet,
            isNoiseControlActive: isNoiseControlActive,
            removedSessionCount: removedSessionCount,
            activeFilterRuleCount: activeFilterRuleCount,
            isAdvancedFilterVisible: isAdvancedFilterVisible,
            isInvestigationActive: false
        )
    }

    private func command(
        _ kind: SessionCommandKind,
        in commands: [SessionCommandDescriptor]
    )
        -> SessionCommandDescriptor?
    {
        commands.first { $0.id == kind }
    }

    private func makeReadiness(
        displayState: CaptureDisplayState = .stopped,
        interface: NetworkInterface? = NetworkInterface(
            id: "en0",
            displayName: "Wi-Fi",
            category: .wifi,
            ipv4: "192.0.2.10",
            isUp: true,
            isLoopback: false
        ),
        helperStatus: HelperClient.Status = .installedCompatible,
        statistics: CaptureStatistics? = nil,
        helperDrops: UInt64 = 0,
        retentionEvictions: UInt64 = 0
    )
        -> CaptureReadinessPresentation
    {
        CaptureReadinessPresentation(
            displayState: displayState,
            captureError: displayState == .error ? "Capture failed." : nil,
            interfaceID: "en0",
            interface: interface,
            configuration: CaptureConfiguration(
                interface: "en0",
                snapLength: 65_536,
                promiscuous: false,
                bpf: nil
            ),
            retentionCapacity: 8_000,
            helperStatus: helperStatus,
            isDirectCapture: false,
            captureStatistics: statistics,
            helperDropCount: helperDrops,
            retentionEvictionCount: retentionEvictions
        )
    }

    private func item(
        _ label: String,
        in presentation: CaptureReadinessPresentation
    )
        -> CaptureReadinessItem?
    {
        presentation.items.first { $0.label == label }
    }
}
