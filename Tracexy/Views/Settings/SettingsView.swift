import SwiftUI

// MARK: - SettingsView

/// The app's Settings window (⌘,). A native `TabView` whose `.tabItem`s render as
/// the standard macOS Settings toolbar — SF Pro type + real SF Symbols throughout.
/// Each pane is styled after the sibling app's classic System-Preferences look via
/// `SettingsPane` / `SettingsCard`, sized from `SettingsDisplayMetrics`.
struct SettingsView: View {
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
            UpdatesSettingsView()
                .tabItem { Label("Updates", systemImage: "arrow.down.circle") }
        }
        .font(metrics.font())
        .frame(width: metrics.windowWidth, height: metrics.windowHeight)
    }

    // MARK: Private

    private let metrics = SettingsDisplayMetrics.standard
}

#Preview {
    SettingsView()
}
