import SwiftUI

// MARK: - SettingsView

/// The app's Settings window (⌘,). A native `TabView` whose `.tabItem`s render as
/// the standard macOS Settings toolbar — SF Pro type + real SF Symbols throughout.
/// Each pane uses `SettingsPane` / `SettingsCard` and shared
/// `SettingsDisplayMetrics` for a consistent native layout.
struct SettingsView: View {
    // MARK: Lifecycle

    init(updater: AppUpdater) {
        self.updater = updater
    }

    // MARK: Internal

    var body: some View {
        TabView(selection: selection) {
            GeneralSettingsView()
                .tabItem { Label("General", systemImage: "gearshape") }
                .tag(SettingsTab.general)
            CaptureSettingsView()
                .tabItem { Label("Capture", systemImage: "antenna.radiowaves.left.and.right") }
                .tag(SettingsTab.capture)
            HelperSettingsView()
                .tabItem { Label("Helper", systemImage: "shield.lefthalf.filled") }
                .tag(SettingsTab.helper)
            PrivacySettingsView()
                .tabItem { Label("Privacy", systemImage: "hand.raised") }
                .tag(SettingsTab.privacy)
            MCPSettingsView()
                .tabItem { Label("MCP & AI", systemImage: "sparkles") }
                .tag(SettingsTab.mcp)
            UpdatesSettingsView(updater: updater)
                .tabItem { Label("Updates", systemImage: "arrow.down.circle") }
                .tag(SettingsTab.updates)
        }
        .font(metrics.font())
        .frame(width: metrics.windowWidth, height: metrics.windowHeight)
    }

    // MARK: Private

    @AppStorage(SettingsKeys.selectedSettingsTab) private var selectedTab = SettingsTab.general.rawValue

    private let updater: AppUpdater
    private let metrics = SettingsDisplayMetrics.standard

    private var selection: Binding<SettingsTab> {
        Binding(
            get: { SettingsTab(rawValue: selectedTab) ?? .general },
            set: { selectedTab = $0.rawValue }
        )
    }
}

#Preview {
    SettingsView(
        updater: AppUpdater(
            configuration: TracexyUpdateConfiguration(infoDictionary: [:])
        )
    )
}
