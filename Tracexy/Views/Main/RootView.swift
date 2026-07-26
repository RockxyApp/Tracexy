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
            inspectorMaximumWidth: Theme.Metrics.contextDockMaxWidth
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
        .navigationTitle(coordinator.activeWorkspace.sidebarSelection.title)
        .navigationSubtitle(TracexyIdentity.tagline)
        // Keep the toolbar opaque so the inspector split divider doesn't bleed
        // up through it (hidden title bar makes the chrome otherwise translucent).
        .toolbarBackground(.visible, for: .windowToolbar)
        .toolbar { toolbarContent() }
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
    /// state, so it is not persisted with the capture/filter/selection model.
    @State private var isSidebarPresented = true
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

    /// Bridges the native inspector split's presentation to workspace state. Routing the
    /// setter through `toggleContextDock()` keeps the existing persistence and animation
    /// semantics, and the equality guard means a native collapse publishes back exactly once.
    private var contextDockVisibility: Binding<Bool> {
        Binding(
            get: { coordinator.isContextDockVisible },
            set: { newValue in
                if coordinator.isContextDockVisible != newValue {
                    coordinator.toggleContextDock()
                }
            }
        )
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

    @ToolbarContentBuilder
    private func toolbarContent() -> some ToolbarContent {
        ToolbarItem(placement: .navigation) {
            Button {
                withAnimation(.smooth(duration: 0.18)) {
                    isSidebarPresented.toggle()
                }
            } label: {
                Label("Sidebar", systemImage: "sidebar.leading")
            }
            .help("Show or hide the sidebar")
        }

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
                Label("Inspector", systemImage: "sidebar.trailing")
                    .symbolVariant(coordinator.isContextDockVisible ? .fill : .none)
            }
            .tint(coordinator.isContextDockVisible ? Color.accentColor : nil)
            .help("Show or hide the inspector (Details · AI Assistant).")
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
        // The status bar is a fixed full-width footer below every surface,
        // pinned across Sessions and Overview alike.
        VStack(spacing: 0) {
            surface(workspace)
            SessionStatusBar(
                coordinator: coordinator,
                visibleCount: coordinator.visibleSessions.count,
                surface: statusSurface(for: workspace.sidebarSelection)
            )
        }
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
        NativeBottomInspectorSplitView(
            isInspectorPresented: bottomInspectorPresented,
            autosaveName: bottomInspectorAutosaveName,
            primaryMinimumHeight: Theme.Metrics.sessionTableMinHeight,
            inspectorMinimumHeight: Theme.Metrics.bottomInspectorMinHeight
        ) {
            SessionCenterView(coordinator: coordinator)
        } inspector: {
            InspectorView(coordinator: coordinator)
        }
    }

    @ViewBuilder
    private func surface(_ workspace: WorkspaceState) -> some View {
        switch workspace.sidebarSelection {
        // The earned intelligence surface (fidelity · findings · rollups).
        case .overview: OverviewView(coordinator: coordinator)
        // Where traffic is going, geographically.
        case .flow: FlowMapView(coordinator: coordinator)
        // The cross-cutting findings lens (Wireshark "Expert Information") — a
        // severity-ranked problem list, distinct from the raw session stream.
        case .security: SecurityFindingsView(coordinator: coordinator)
        default: sessionArea
        }
    }

    /// Maps the active sidebar selection to the status-bar surface, so the footer
    /// mirrors `surface`: the intelligence surfaces get a quiet summary, and
    /// only the session list surfaces the Clear / Filter / Auto Select controls.
    private func statusSurface(for selection: SidebarItem) -> StatusSurface {
        switch selection {
        case .overview: .overview
        case .flow: .flow
        case .security: .security
        default: .sessionList
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
