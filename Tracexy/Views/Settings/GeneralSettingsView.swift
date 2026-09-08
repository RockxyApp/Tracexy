import SwiftUI

// MARK: - GeneralSettingsView

/// Appearance, default landing view, byte units, and launch behavior.
/// Appearance and Default view take effect immediately; the rest persist.
struct GeneralSettingsView: View {
    // MARK: Lifecycle

    init(applicationDefaults: UserDefaults = .standard) {
        _appearance = AppStorage(
            wrappedValue: AppAppearance.system.rawValue,
            SettingsKeys.appearance,
            store: applicationDefaults
        )
        _byteUnits = AppStorage(
            wrappedValue: ByteUnits.binary.rawValue,
            SettingsKeys.byteUnits,
            store: applicationDefaults
        )
        _confirmQuit = AppStorage(
            wrappedValue: true,
            SettingsKeys.confirmQuitWhileCapturing,
            store: applicationDefaults
        )
        _restoreWorkspace = AppStorage(wrappedValue: true, SettingsKeys.restoreWorkspace, store: applicationDefaults)
    }

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

    /// Appearance, byte units, quit confirmation and workspace restoration describe
    /// the application, so they stay in the shared domain explicitly. "Default
    /// view" is a per-Project layout preference and follows the injected store.
    @AppStorage(SettingsKeys.appearance, store: .standard) private var appearance = AppAppearance.system.rawValue
    @AppStorage(SettingsKeys.byteUnits, store: .standard) private var byteUnits = ByteUnits.binary.rawValue
    @AppStorage(SettingsKeys.confirmQuitWhileCapturing, store: .standard) private var confirmQuit = true
    @AppStorage(SettingsKeys.restoreWorkspace, store: .standard) private var restoreWorkspace = true

    @AppStorage(SettingsKeys.defaultView) private var defaultView = DefaultView.sessions.rawValue

    private let metrics = SettingsDisplayMetrics.standard
}

#Preview {
    GeneralSettingsView()
}
