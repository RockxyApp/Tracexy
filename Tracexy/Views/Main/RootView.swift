import AppKit
import SwiftUI

// MARK: - RootView

struct RootView: View {
    // MARK: Internal

    /// The single app-level coordinator, shared with the editor/manager windows.
    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        NavigationSplitView {
            SidebarView(coordinator: coordinator)
                .navigationSplitViewColumnWidth(
                    min: Theme.Metrics.sidebarMinWidth,
                    ideal: Theme.Metrics.sidebarIdealWidth
                )
        } detail: {
            MainDetailView(coordinator: coordinator)
        }
        .navigationTitle(coordinator.activeWorkspace.sidebarSelection.title)
        .navigationSubtitle(TracexyIdentity.tagline)
        // Keep the toolbar opaque so the inspector split divider doesn't bleed
        // up through it (hidden title bar makes the chrome otherwise translucent).
        .toolbarBackground(.visible, for: .windowToolbar)
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

    /// On launch: in direct-capture dev mode (`scripts/run.sh`), just start
    /// capturing so `./scripts/run.sh` lands straight on live traffic — no click,
    /// no helper, no approval. Otherwise, check the helper and offer to install it.
    private func launchSetup() async {
        if MainContentCoordinator.forceDirectCapture {
            coordinator.startCapture()
            return
        }
        await coordinator.helper.checkStatus()
        if coordinator.helper.status == .notInstalled {
            showHelperInstall = true
        }
    }
}

// MARK: - MainDetailView

/// Routes the active sidebar selection to its surface, and owns the toolbar.
struct MainDetailView: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let workspace = coordinator.activeWorkspace
        // The status bar is a fixed full-width footer below every surface,
        // like the sibling app — pinned across Sessions and Overview alike.
        VStack(spacing: 0) {
            surface(workspace)
            SessionStatusBar(coordinator: coordinator, visibleCount: coordinator.visibleSessions.count)
        }
        .toolbar { toolbarContent() }
        // Selection is the trigger for revealing the panels, and it has two
        // sources: `coordinator.select(_:)` (the dock's related cards) and the
        // tables, which write `selectedSessionID` straight through their own
        // binding. Watching the state itself catches both — hooking only the
        // method left clicking a row unable to bring the inspector back, which
        // is the most ordinary thing a user does here.
        .onChange(of: workspace.selectedSessionID) { _, newValue in
            if newValue != nil {
                coordinator.revealPanelsForSelection()
            }
        }
    }

    // MARK: Private

    @State private var interfaceGroups: [InterfaceGroup] = []

    private var currentInterface: NetworkInterface? {
        interfaceGroups.flatMap(\.interfaces).first { $0.id == coordinator.captureInterface }
    }

    private var currentInterfaceSymbol: String {
        currentInterface?.symbol ?? "network"
    }

    /// Friendly label for the toolbar button, e.g. "Wi-Fi (en0)".
    private var currentInterfaceLabel: String {
        currentInterface?.menuLabel ?? coordinator.captureInterface
    }

    /// Bottom-dock layout: a native `VSplitView` (the approved inspector split)
    /// with a draggable divider. Session table on top, inspector docked below.
    private var bottomSplit: some View {
        VSplitView {
            SessionCenterView(coordinator: coordinator)
                .frame(minHeight: Theme.Metrics.sessionTableMinHeight, maxHeight: .infinity)
            InspectorView(coordinator: coordinator)
                .frame(
                    minHeight: Theme.Metrics.bottomInspectorMinHeight,
                    idealHeight: Theme.Metrics.bottomInspectorIdealHeight
                )
        }
        .id("tracexy-bottom-inspector-split")
    }

    /// Interface dropdown grouped by family (Wi-Fi, Ethernet, Thunderbolt, …),
    /// with macOS's friendly names and a checkmark on the active one.
    private var interfacePicker: some View {
        Menu {
            Picker(
                selection: Binding(
                    get: { coordinator.captureInterface },
                    set: { coordinator.captureInterface = $0 }
                )
            ) {
                ForEach(interfaceGroups) { group in
                    Section(group.category.title) {
                        ForEach(group.interfaces) { iface in
                            Text(iface.menuLabel).tag(iface.id)
                        }
                    }
                }
            } label: {
                EmptyView()
            }
            .pickerStyle(.inline)
        } label: {
            HStack(spacing: 5) {
                Image(systemName: currentInterfaceSymbol)
                Text(currentInterfaceLabel).lineLimit(1).truncationMode(.tail)
            }
            .frame(width: 188, alignment: .leading)
        }
        .menuStyle(.button)
        .help("Capture interface")
        .onAppear {
            interfaceGroups = NetworkInterfaces.grouped()
            // Make sure a real interface is selected by default.
            if currentInterface == nil, let first = interfaceGroups.flatMap(\.interfaces).first {
                coordinator.captureInterface = first.id
            }
        }
    }

    /// Containment: `centre column ‖ context dock`, where the evidence inspector
    /// is nested *inside* the centre column rather than spanning the window.
    ///
    /// That nesting is what keeps the two panels independent: the dock costs
    /// width, the evidence inspector costs height, so they never compete. A
    /// bottom pane stretched under the dock would stop being detail-of-the-
    /// selection and become a second dock.
    private func surface(_ workspace: WorkspaceState) -> some View {
        HSplitView {
            centreColumn(workspace)
                .frame(
                    minWidth: Theme.Metrics.sessionTableMinWidth,
                    maxWidth: .infinity,
                    maxHeight: .infinity
                )
            if workspace.isContextDockVisible {
                ContextDockView(coordinator: coordinator)
                    .frame(
                        minWidth: Theme.Metrics.contextDockMinWidth,
                        idealWidth: Theme.Metrics.contextDockIdealWidth,
                        maxWidth: Theme.Metrics.contextDockMaxWidth,
                        maxHeight: .infinity
                    )
            }
        }
        .id("tracexy-context-dock-split")
    }

    @ViewBuilder
    private func centreColumn(_ workspace: WorkspaceState) -> some View {
        switch workspace.sidebarSelection {
        // The earned intelligence surface (fidelity · findings · rollups).
        case .overview: OverviewView(coordinator: coordinator)
        // Where traffic is going, geographically.
        case .flow: FlowMapView(coordinator: coordinator)
        // The cross-cutting findings lens (Wireshark "Expert Information") — a
        // severity-ranked problem list, distinct from the raw session stream.
        case .security: SecurityFindingsView(coordinator: coordinator)
        default: sessionArea(layout: workspace.inspectorLayout)
        }
    }

    @ViewBuilder
    private func sessionArea(layout: InspectorLayout) -> some View {
        switch layout {
        case .bottom:
            // Docked inspector below the table (native VSplitView, draggable);
            // shows an empty state until a row is selected.
            bottomSplit
        case .hidden:
            SessionCenterView(coordinator: coordinator)
        }
    }

    @ToolbarContentBuilder
    private func toolbarContent() -> some ToolbarContent {
        ToolbarItem(placement: .navigation) {
            interfacePicker
        }

        ToolbarItem(placement: .principal) {
            CaptureStatusView(coordinator: coordinator)
        }

        ToolbarItemGroup {
            Button {
                coordinator.toggleCapture()
            } label: {
                Label(
                    coordinator.isCapturing ? "Stop" : "Start",
                    systemImage: coordinator.isCapturing ? "stop.fill" : "play.fill"
                )
            }
            .tint(coordinator.isCapturing ? .red : .green)
            .help(coordinator.isCapturing ? "Stop capture" : "Start capture")

            Divider()

            Button {
                coordinator.toggleInspectorBottom()
            } label: {
                Label("Bottom Inspector", systemImage: "rectangle.split.1x2")
                    .symbolVariant(coordinator.activeWorkspace.inspectorLayout == .bottom ? .fill : .none)
            }
            .tint(coordinator.activeWorkspace.inspectorLayout == .bottom ? Color.accentColor : nil)
            .help("Show or hide the bottom inspector panel")

            Button {
                coordinator.toggleContextDock()
            } label: {
                Label("Context Dock", systemImage: "sidebar.trailing")
                    .symbolVariant(coordinator.activeWorkspace.isContextDockVisible ? .fill : .none)
            }
            .tint(coordinator.activeWorkspace.isContextDockVisible ? Color.accentColor : nil)
            .help("Show or hide the Context Dock")
        }
    }
}

// MARK: - CaptureStatusView

/// The center toolbar capsule (Tracexy's analog of the sibling app's `ProxyStatusIndicator`).
/// Reads `Tracexy | <interface> | <State>` with a state-colored dot, mirroring
/// the sibling app's `<name> | <address> | <state>` capsule.
struct CaptureStatusView: View {
    // MARK: Internal

    var coordinator: MainContentCoordinator

    var body: some View {
        HStack(spacing: 7) {
            Circle()
                .fill(statusColor)
                .frame(width: 8, height: 8)
                .shadow(color: statusShadowColor, radius: 4)
            Text(statusText)
                .font(Theme.Typography.bodyMedium)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 5)
        .background(.quaternary, in: Capsule())
        .help(statusText)
    }

    // MARK: Private

    private var statusText: String {
        "\(TracexyIdentity.productName) | \(coordinator.captureInterface) | \(coordinator.captureDisplayState.title)"
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
}

#Preview {
    RootView(coordinator: MainContentCoordinator())
        .frame(width: 1_200, height: 760)
}
