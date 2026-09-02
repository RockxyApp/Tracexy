import SwiftUI

// MARK: - SettingsView

/// Native Settings split: a semantic sidebar provides stable navigation while
/// the selected pane remains a dense, opaque content layer.
struct SettingsView: View {
    // MARK: Lifecycle

    init(
        updater: AppUpdater,
        historyRetentionError: String? = nil,
        isHistoryDemoMode: Bool = false,
        onAutoClearChange: @escaping (AutoClear) -> Void = { _ in }
    ) {
        self.updater = updater
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
                .font(metrics.font())
                .navigationTitle(selection.wrappedValue.title)
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

    @AppStorage(SettingsKeys.selectedSettingsTab) private var selectedTab = SettingsTab.general.rawValue

    private let updater: AppUpdater
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

    @ViewBuilder private var selectedPane: some View {
        switch selection.wrappedValue {
        case .general: GeneralSettingsView()
        case .capture: CaptureSettingsView()
        case .helper: HelperSettingsView()
        case .privacy: PrivacySettingsView(
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
