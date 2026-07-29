import SwiftUI

// MARK: - GeneralSettingsView

/// Appearance, default landing view, byte units, and launch behavior.
/// Appearance and Default view take effect immediately; the rest persist.
struct GeneralSettingsView: View {
    // MARK: Internal

    var body: some View {
        SettingsPane {
            SettingsSection("Appearance") {
                SettingsThemeCard(selection: $appearance)

                SettingsDivider()

                SettingsRow(label: "Default view:") {
                    Picker("", selection: $defaultView) {
                        ForEach(DefaultView.allCases) { Text($0.title).tag($0.rawValue) }
                    }
                    .labelsHidden()
                    .frame(width: metrics.menuWidth(180))
                    .frame(minHeight: metrics.controlHeight)
                }
            }

            SettingsSection("Units") {
                SettingsRow(label: "Byte units:") {
                    Picker("", selection: $byteUnits) {
                        ForEach(ByteUnits.allCases) { Text($0.title).tag($0.rawValue) }
                    }
                    .labelsHidden()
                    .frame(width: metrics.menuWidth(200))
                    .frame(minHeight: metrics.controlHeight)
                }
            }

            SettingsSection("Behavior") {
                SettingsCheckbox(
                    isOn: $confirmQuit,
                    title: "Confirm before quitting while capturing",
                    description: "Ask for confirmation before quitting while a live capture is running."
                )

                SettingsDivider()

                SettingsCheckbox(
                    isOn: $restoreWorkspace,
                    title: "Restore last workspace on launch",
                    description: "Reopen your last workspace, tabs, filters, and selection when Tracexy starts."
                )
            }
        }
    }

    // MARK: Private

    @AppStorage(SettingsKeys.appearance) private var appearance = AppAppearance.system.rawValue
    @AppStorage(SettingsKeys.defaultView) private var defaultView = DefaultView.sessions.rawValue
    @AppStorage(SettingsKeys.byteUnits) private var byteUnits = ByteUnits.binary.rawValue
    @AppStorage(SettingsKeys.confirmQuitWhileCapturing) private var confirmQuit = true
    @AppStorage(SettingsKeys.restoreWorkspace) private var restoreWorkspace = true

    private let metrics = SettingsDisplayMetrics.standard
}

#Preview {
    GeneralSettingsView()
}
