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
        TabView {
            GeneralSettingsView()
                .tabItem { Label("General", systemImage: "gearshape") }
            CaptureSettingsView()
                .tabItem { Label("Capture", systemImage: "antenna.radiowaves.left.and.right") }
            HelperSettingsView()
                .tabItem { Label("Helper", systemImage: "shield.lefthalf.filled") }
            PrivacySettingsView()
                .tabItem { Label("Privacy", systemImage: "hand.raised") }
            MCPSettingsView()
                .tabItem { Label("MCP & AI", systemImage: "sparkles") }
            UpdatesSettingsView(updater: updater)
                .tabItem { Label("Updates", systemImage: "arrow.down.circle") }
        }
        .font(metrics.font())
        .frame(width: metrics.windowWidth, height: metrics.windowHeight)
    }

    // MARK: Private

    private let updater: AppUpdater
    private let metrics = SettingsDisplayMetrics.standard
}

#Preview {
    SettingsView(
        updater: AppUpdater(
            configuration: TracexyUpdateConfiguration(infoDictionary: [:])
        )
    )
}
