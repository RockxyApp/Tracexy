import SwiftUI

// MARK: - SettingsView

/// Native Settings split: a semantic sidebar provides stable navigation while
/// the selected pane remains a dense, opaque content layer.
struct SettingsView: View {
    // MARK: Lifecycle

    init(
        updater: AppUpdater,
        applicationDefaults: UserDefaults = .standard,
        activeProjectName: String? = nil,
        isProjectReady: Bool = true,
        historyRetentionError: String? = nil,
        isHistoryDemoMode: Bool = false,
        onAutoClearChange: @escaping (AutoClear) -> Void = { _ in }
    ) {
        self.updater = updater
        self.applicationDefaults = applicationDefaults
        _selectedTab = AppStorage(
            wrappedValue: SettingsTab.general.rawValue,
            SettingsKeys.selectedSettingsTab,
            store: applicationDefaults
        )
        self.activeProjectName = activeProjectName
        self.isProjectReady = isProjectReady
        self.historyRetentionError = historyRetentionError
        self.isHistoryDemoMode = isHistoryDemoMode
        self.onAutoClearChange = onAutoClearChange
    }

    // MARK: Internal

    var body: some View {
        NavigationSplitView {
            List(SettingsTab.allCases, selection: selection) { tab in
                Label(tab.title, systemImage: tab.systemImage)
                    .font(metrics.font(
                        weight: selection.wrappedValue == tab ? .semibold : .regular
                    ))
                    .tag(tab)
            }
            .listStyle(.sidebar)
            .tracexySoftScrollEdge()
            .navigationSplitViewColumnWidth(
                min: metrics.sidebarMinWidth,
                ideal: metrics.sidebarIdealWidth,
                max: metrics.sidebarMaxWidth
            )
            .navigationTitle("Settings")
        } detail: {
            selectedPane
                .disabled(isProjectScopedPane && !isProjectReady)
                .font(metrics.font())
                .navigationTitle(selection.wrappedValue.title)
                .navigationSubtitle(paneSubtitle)
        }
        .frame(
            minWidth: metrics.windowMinWidth,
            idealWidth: metrics.windowIdealWidth,
            maxWidth: .infinity,
            minHeight: metrics.windowMinHeight,
            idealHeight: metrics.windowIdealHeight,
            maxHeight: .infinity
        )
    }

    // MARK: Private

    /// Which pane is open is an application preference, not a Project one, so it
    /// names `.standard` explicitly and is unaffected by the per-Project store.
    @AppStorage(SettingsKeys.selectedSettingsTab, store: .standard)
    private var selectedTab = SettingsTab.general.rawValue

    private let updater: AppUpdater
    private let applicationDefaults: UserDefaults
    private let activeProjectName: String?
    private let isProjectReady: Bool
    private let historyRetentionError: String?
    private let isHistoryDemoMode: Bool
    private let onAutoClearChange: (AutoClear) -> Void
    private let metrics = SettingsDisplayMetrics.standard

    private var selection: Binding<SettingsTab> {
        Binding(
            get: { SettingsTab(rawValue: selectedTab) ?? .general },
            set: { selectedTab = $0.rawValue }
        )
    }

    /// Name the Project whose preferences the pane is editing, so a per-Project
    /// setting is never mistaken for an app-wide one.
    private var paneSubtitle: String {
        guard let activeProjectName, isProjectScopedPane else {
            return ""
        }
        return String(localized: "Project: \(activeProjectName)")
    }

    private var isProjectScopedPane: Bool {
        switch selection.wrappedValue {
        case .capture,
             .general,
             .privacy: true
        case .helper,
             .mcp,
             .updates: false
        }
    }

    @ViewBuilder private var selectedPane: some View {
        switch selection.wrappedValue {
        case .general: GeneralSettingsView(applicationDefaults: applicationDefaults)
        case .capture: CaptureSettingsView()
        case .helper: HelperSettingsView()
        case .privacy: PrivacySettingsView(
                applicationDefaults: applicationDefaults,
                historyRetentionError: historyRetentionError,
                isHistoryDemoMode: isHistoryDemoMode,
                onAutoClearChange: onAutoClearChange
            )
        case .mcp: MCPSettingsView()
        case .updates: UpdatesSettingsView(updater: updater)
        }
    }
}

#Preview {
    SettingsView(
        updater: AppUpdater(
            configuration: TracexyUpdateConfiguration(infoDictionary: [:])
        )
    )
}
