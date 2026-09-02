import AppKit
import SwiftUI

// MARK: - RootView

struct RootView: View {
    // MARK: Internal

    /// Autosave name for the root workspace split (sidebar ‖ workspace ‖ inspector).
    /// Identity-scoped so the divider frames never collide with another layout namespace or
    /// with the bottom evidence split below.
    static let workspaceSplitAutosaveName = TracexyIdentity.current.defaultsKey(
        "nativeWorkspaceSplit.v1"
    )

    /// Autosave name for the bottom evidence split (session table over inspector).
    /// Kept distinct from the workspace split so the two divider positions persist
    /// independently.
    static let bottomInspectorSplitAutosaveName = TracexyIdentity.current.defaultsKey(
        "nativeBottomInspectorSplit.v1"
    )

    /// The single app-level coordinator, shared with the editor/manager windows.
    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        NativeWorkspaceSplitView(
            isSidebarPresented: $isSidebarPresented,
            isInspectorPresented: contextDockVisibility,
            autosaveName: Self.workspaceSplitAutosaveName,
            sidebarMinimumWidth: Theme.Metrics.sidebarMinWidth,
            sidebarIdealWidth: Theme.Metrics.sidebarIdealWidth,
            sidebarMaximumWidth: Theme.Metrics.sidebarMaxWidth,
            workspaceMinimumWidth: Theme.Metrics.sessionTableMinWidth,
            inspectorMinimumWidth: Theme.Metrics.contextDockMinWidth,
            inspectorIdealWidth: Theme.Metrics.contextDockIdealWidth,
            inspectorMaximumWidth: Theme.Metrics.contextDockMaxWidth,
            toolbarConfiguration: NativeWorkspaceToolbarConfiguration(coordinator: coordinator)
        ) {
            SidebarView(coordinator: coordinator)
        } workspace: {
            MainDetailView(
                coordinator: coordinator,
                bottomInspectorAutosaveName: Self.bottomInspectorSplitAutosaveName
            )
        } inspector: {
            ContextDockView(coordinator: coordinator)
        }
        .ignoresSafeArea(.container, edges: .top)
        .onChange(of: coordinator.workspaces.activeWorkspaceID) {
            coordinator.evidenceNavigationDidChangeSelection()
        }
        // The unified window toolbar — sidebar toggle, interface picker, capture
        // status, and the capture/inspector actions — is installed natively by
        // `NativeWorkspaceWindowChrome`, so the sidebar toggle can sit above the
        // source list with a tracking separator. No SwiftUI `.toolbar` here.
        .task { await launchSetup() }
        .sheet(isPresented: $showHelperInstall) {
            HelperInstallPromptView(coordinator: coordinator)
        }
        // A capacity limit is worth one sentence and a dismiss, not a banner
        // that lingers over the traffic the user came here to read.
        .alert(
            "Limit Reached",
            isPresented: Binding(
                get: { coordinator.policyNotice != nil },
                set: {
                    if !$0 {
                        coordinator.policyNotice = nil
                    }
                }
            )
        ) {
            Button("OK", role: .cancel) { coordinator.policyNotice = nil }
        } message: {
            Text(coordinator.policyNotice ?? "")
        }
    }

    // MARK: Private

    @State private var showHelperInstall = false
    /// Sidebar presentation is view-local: the source list is chrome, not workspace
    /// state, so it is not persisted with the capture/filter/selection model. The
    /// native toolbar toggle and `View ▸ Show Sidebar` both drive the split, which
    /// resynchronizes this value through the collapse KVO.
    @State private var isSidebarPresented = true

    /// Bridges the native inspector split's presentation to workspace state. Routing the
    /// setter through `toggleContextDock()` keeps the existing persistence and animation
    /// semantics, and the equality guard means a native collapse publishes back exactly once.
    private var contextDockVisibility: Binding<Bool> {
        Binding(
            get: {
                coordinator.activeWorkspace.sidebarSelection == .history
                    ? false
                    : coordinator.isContextDockVisible
            },
            set: { newValue in
                guard coordinator.activeWorkspace.sidebarSelection != .history else {
                    return
                }
                if coordinator.isContextDockVisible != newValue {
                    coordinator.toggleContextDock()
                }
            }
        )
    }

    /// On launch, direct-capture mode selects the unprivileged libpcap backend but
    /// does not itself imply consent to start capturing. The persisted Capture
    /// setting is the single source of truth for auto-start in both development
    /// and normal launches.
    private func launchSetup() async {
        if coordinator.isHistoryDemoMode {
            await coordinator.prepareHistoryDemo()
            return
        }

        let shouldAutoStart = UserDefaults.standard.bool(
            forKey: SettingsKeys.autoStartCapture
        )
        if MainContentCoordinator.forceDirectCapture {
            if shouldAutoStart {
                coordinator.startCapture()
            }
            return
        }
        await coordinator.helper.checkStatus()
        if coordinator.helper.status == .notInstalled {
            showHelperInstall = true
        } else if shouldAutoStart {
            coordinator.startCapture()
        }
    }
}

// MARK: - MainDetailView

/// The workspace column hosted in the centre of the native root split.
///
/// Owns the active surface and its own full-width `SessionStatusBar` footer. The right
/// inspector is a separate root split item, so this footer spans only the centre column
/// and never runs underneath the dock.
struct MainDetailView: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    let bottomInspectorAutosaveName: String

    var body: some View {
        let workspace = coordinator.activeWorkspace
        let footerSurface = statusSurface(for: workspace.sidebarSelection)
        surface(workspace)
            .tracexySafeAreaBar(edge: .bottom) {
                SessionStatusBar(snapshot: footerSnapshot(workspace, surface: footerSurface))
            }
            // Selection is the trigger for revealing the panels, and it has two
            // sources: `coordinator.select(_:)` (the dock's related cards) and the
            // tables, which write `selectedSessionID` straight through their own
            // binding. Watching the state itself catches both — hooking only the
            // method left clicking a row unable to bring the inspector back, which
            // is the most ordinary thing a user does here.
            .onChange(of: workspace.selectedSessionID) { _, newValue in
                // Raw Follow Stream bytes are explicitly selection-scoped. Table
                // bindings bypass `coordinator.select(_:)`, so this root observer is
                // the authoritative retirement boundary for both selection paths.
                coordinator.cancelFollowStream(clearResult: true)
                coordinator.evidenceNavigationDidChangeSelection()
                if newValue != nil {
                    coordinator.revealPanelsForSelection()
                }
            }
            .confirmationDialog(
                "Clear all capture data?",
                isPresented: $showsClearConfirmation,
                titleVisibility: .visible
            ) {
                Button("Clear Capture Data", role: .destructive) {
                    coordinator.clearSessions()
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text(
                    "This removes decoded sessions, retained packets, capture statistics, "
                        + "and throughput history. Save the capture first if you need it later."
                )
            }
    }

    // MARK: Private

    /// Opens the Focus Set editor and Noise Control auxiliary windows in response
    /// to footer launchers. Held here, at the footer's owner, rather than inside
    /// the presentation-only status bar.
    @Environment(\.openWindow) private var openWindow
    @State private var showsClearConfirmation = false
    @State private var showsInvestigationEditor = false

    /// Bridges the native evidence split's presentation to the workspace's inspector
    /// layout. Routing the setter through `toggleInspectorBottom()` preserves the
    /// auto-reveal and persistence rules, and the equality guard means a native collapse
    /// publishes back exactly once.
    private var bottomInspectorPresented: Binding<Bool> {
        Binding(
            get: { coordinator.inspectorLayout == .bottom },
            set: { newValue in
                if (coordinator.inspectorLayout == .bottom) != newValue {
                    coordinator.toggleInspectorBottom()
                }
            }
        )
    }

    /// The session list with its evidence inspector docked below in a native horizontal
    /// split. The inspector item collapses and expands in place rather than swapping the
    /// whole subtree, so table selection and scroll position survive every toggle.
    private var sessionArea: some View {
        let workspace = coordinator.activeWorkspace
        return NativeBottomInspectorSplitView(
            isInspectorPresented: bottomInspectorPresented,
            autosaveName: bottomInspectorAutosaveName,
            primaryMinimumHeight: Theme.Metrics.sessionTableMinHeight,
            inspectorMinimumHeight: Theme.Metrics.bottomInspectorMinHeight
        ) {
            SessionCenterView(
                coordinator: coordinator,
                commandDescriptors: sessionCommandDescriptors(workspace),
                onCommandAction: { performSessionCommand($0, workspace) }
            )
            .popover(isPresented: $showsInvestigationEditor, arrowEdge: .bottom) {
                InvestigationQueryEditorView(
                    coordinator: coordinator,
                    workspace: workspace
                )
            }
        } inspector: {
            InspectorView(coordinator: coordinator)
        }
        .tracexyDenseScrollEdge()
    }

    @ViewBuilder
    private func surface(_ workspace: WorkspaceState) -> some View {
        switch workspace.sidebarSelection {
        // The earned intelligence surface (fidelity · findings · rollups).
        case .overview: OverviewView(coordinator: coordinator)
        // Where traffic is going, geographically.
        case .flow: FlowMapView(coordinator: coordinator)
        // Terminal local summaries, independent from the active capture table.
        case .history: HistoryView(coordinator: coordinator)
        default: sessionArea
        }
    }

    /// Maps the active sidebar selection to the status-bar surface, so the footer
    /// mirrors `surface`: the intelligence surfaces get a quiet summary, and only
    /// the session list surfaces the feature launchers and List Options.
    private func statusSurface(for selection: SidebarItem) -> StatusSurface {
        switch selection {
        case .overview: .overview
        case .flow: .flow
        case .history: .history
        default: .sessionList
        }
    }

    /// The pure presentation snapshot handed to the footer: the summary string and
    /// the ordered telemetry. The combined live rate is read directly from the
    /// latest throughput sample and only while capturing — the coordinator is not
    /// edited to derive it.
    private func footerSnapshot(_ workspace: WorkspaceState, surface: StatusSurface) -> FooterSnapshot {
        if case .history = surface {
            let sessionCount = coordinator.historyCaptures.reduce(0) { partial, capture in
                partial + capture.sessionCount
            }
            return FooterSnapshot(
                summary: HistoryFooterModel.statusText(
                    captureCount: coordinator.historyCaptures.count,
                    sessionCount: sessionCount,
                    hasMore: coordinator.historyCaptureCursor != nil
                ),
                telemetry: [],
                hasSelection: false,
                captureStartedAt: nil
            )
        }
        let stats = coordinator.captureStatistics
        // The first sample uses a startup-clamped interval and is intentionally
        // not presented as a trustworthy live rate. The second sample has a
        // real preceding timestamp.
        let liveBytesPerSecond = coordinator.isCapturing && coordinator.throughputSamples.count > 1
            ? coordinator.throughputSamples.last?.bytesPerSecond
            : nil
        let summary = SessionStatusBarModel.statusText(
            surface: surface,
            totalSessions: coordinator.presentedSessions.count,
            visibleCount: coordinator.visibleSessions.count,
            hasSelection: workspace.selectedSessionID != nil
        )
        let loss = CaptureLoss(
            hasStatistics: stats != nil,
            totalDropped: stats?.totalDropped ?? 0,
            isMaterialLoss: stats?.isLossy ?? false,
            helperDropCount: coordinator.helperBufferDropCount,
            retentionEvictionCount: coordinator.retainedFrameEvictionCount
        )
        let telemetry = SessionStatusBarModel.telemetry(
            isCapturing: coordinator.isCapturing,
            loss: loss,
            errorCount: coordinator.errorCount,
            hasCaptureDuration: coordinator.captureStartedAt != nil,
            liveBytesPerSecond: liveBytesPerSecond,
            totalBytes: coordinator.totalBytes,
            bytesUp: coordinator.totalBytesUp,
            bytesDown: coordinator.totalBytesDown
        )
        return FooterSnapshot(
            summary: summary,
            telemetry: telemetry,
            hasSelection: workspace.selectedSessionID != nil,
            captureStartedAt: coordinator.captureStartedAt
        )
    }

    private func sessionCommandDescriptors(_ workspace: WorkspaceState) -> [SessionCommandDescriptor] {
        SessionCommandBarModel.commands(
            isFollowingLive: workspace.isFollowingLiveSessions,
            hasVisibleSessions: !coordinator.visibleSessions.isEmpty,
            hasCaptureData: !coordinator.sessions.isEmpty,
            canSaveCapture: coordinator.canSaveCapture,
            canAddFocusSet: coordinator.canAddFocusSet,
            isNoiseControlActive: coordinator.isNoiseControlActive,
            removedSessionCount: coordinator.removedSessionCount,
            activeFilterRuleCount: workspace.activeFilterRules.count,
            isAdvancedFilterVisible: workspace.isAdvancedFilterVisible,
            isInvestigationActive: workspace.hasActiveInvestigationQuery
        )
    }

    private func performSessionCommand(_ kind: SessionCommandKind, _ workspace: WorkspaceState) {
        switch kind {
        case .followLive:
            coordinator.toggleFollowingLiveSessions()
        case .jumpToLatest:
            coordinator.jumpToLatestVisibleSession()
        case .investigate:
            showsInvestigationEditor = true
        case .clearCapture:
            showsClearConfirmation = true
        case .saveCapture:
            coordinator.saveCurrentCapture()
        case .newFocusSet:
            coordinator.editingFocusSet = coordinator.draftFocusSet()
            openWindow(id: TracexyApp.focusSetEditorWindowID)
        case .noiseControl:
            openWindow(id: TracexyApp.noiseControlWindowID)
        case .restoreRemovedSessions:
            coordinator.restoreRemovedSessions()
        case .advancedFilters:
            // Keep the category tabs visible and reveal/hide the advanced rule
            // builder directly beneath them.
            workspace.isFilterBarVisible = true
            workspace.isAdvancedFilterVisible.toggle()
        }
    }
}

// MARK: - CaptureStatusView

/// The center toolbar capsule.
/// Reads `Tracexy | <interface> | <State>` with a state-colored dot.
struct CaptureStatusView: View {
    // MARK: Internal

    var coordinator: MainContentCoordinator

    var body: some View {
        HStack(spacing: 0) {
            Button {
                showsReadiness.toggle()
            } label: {
                HStack(spacing: 7) {
                    Circle()
                        .fill(statusColor)
                        .frame(width: 8, height: 8)
                        .shadow(color: statusShadowColor, radius: 4)
                    Text(statusText)
                        .font(Theme.Typography.bodyMedium)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    Image(systemName: "chevron.down")
                        .font(Theme.Typography.micro)
                        .foregroundStyle(.tertiary)
                    if updater.updateStatusSummary != nil {
                        Text("|")
                            .font(Theme.Typography.badge)
                            .foregroundStyle(.tertiary)
                    }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .padding(.leading, 14)
            .padding(.trailing, updater.updateStatusSummary == nil ? 14 : 7)
            .frame(height: Theme.Metrics.toolbarControlHeight)
            .help(statusHelp)
            .accessibilityLabel("Capture Readiness")
            .accessibilityValue(statusText)
            .popover(isPresented: $showsReadiness, arrowEdge: .bottom) {
                CaptureReadinessPopover(
                    coordinator: coordinator,
                    isPresented: $showsReadiness
                )
            }

            if let summary = updater.updateStatusSummary {
                Button {
                    updater.showUpdatesFromStatusBadge()
                } label: {
                    ViewThatFits(in: .horizontal) {
                        updateBadge(summary.badgeTitle)
                        updateBadge("Update")
                    }
                }
                .buttonStyle(.plain)
                .help(updateHelp(summary))
                .accessibilityLabel(summary.badgeTitle)
                .accessibilityHint("Open software update")
                .padding(.trailing, 14)
                .frame(height: Theme.Metrics.toolbarControlHeight)
            }
        }
        .frame(height: Theme.Metrics.toolbarControlHeight)
        // The unified NSToolbar owns the environmental material and elevation.
        // Keep only the capsule hit geometry here so the hosted SwiftUI content
        // never draws a second translucent surface over the native toolbar.
        .contentShape(Capsule(style: .continuous))
    }

    // MARK: Private

    @ObservedObject private var updater = AppUpdater.shared
    @State private var showsReadiness = false

    private var statusText: String {
        "\(TracexyIdentity.productName) | \(coordinator.captureInterface) | \(coordinator.captureDisplayState.title)"
    }

    private var statusHelp: String {
        guard let summary = updater.updateStatusSummary else {
            return coordinator.captureStatusLine
        }
        return [
            coordinator.captureStatusLine,
            summary.title,
            summary.versionLine,
            summary.countLine,
        ]
        .compactMap { $0 }
        .joined(separator: "\n")
    }

    private var statusColor: Color {
        switch coordinator.captureDisplayState {
        case .stopped: Color(nsColor: .tertiaryLabelColor)
        case .starting: Color.accentColor
        case .capturing: Color(nsColor: .systemGreen)
        case .error: Color(nsColor: .systemRed)
        }
    }

    private var statusShadowColor: Color {
        switch coordinator.captureDisplayState {
        case .capturing: Color(nsColor: .systemGreen).opacity(0.45)
        case .starting: Color.accentColor.opacity(0.35)
        default: Color.clear
        }
    }

    private func updateBadge(_ title: String) -> some View {
        Text(title)
            .font(Theme.Typography.toolbarBadge)
            .lineLimit(1)
            .padding(.horizontal, Theme.Metrics.updateBadgeHorizontalPadding)
            .frame(height: Theme.Metrics.updateBadgeHeight)
            .tracexyChipStyle(tint: .accentColor, isActive: true)
    }

    private func updateHelp(_ summary: AppUpdater.UpdateStatusSummary) -> String {
        [summary.title, summary.versionLine, summary.countLine]
            .compactMap { $0 }
            .joined(separator: "\n")
    }
}

#Preview {
    RootView(coordinator: MainContentCoordinator())
        .frame(width: 1_200, height: 760)
}
