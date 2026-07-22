import SwiftUI

// MARK: - UpdatesSettingsView

/// Software-update preferences. The version is read from the bundle (real); the
/// updater itself (auto-check / channel / "Check Now") is not yet wired, so those
/// controls persist intent and the button is a no-op placeholder for now.
struct UpdatesSettingsView: View {
    // MARK: Internal

    var body: some View {
        SettingsPane {
            SettingsSectionTitle("Software Update")
            SettingsCard {
                SettingsCheckbox(
                    isOn: $autoCheck,
                    title: "Automatically check for updates",
                    description: "Check for new Tracexy releases in the background on your chosen channel."
                )
                SettingsRow(label: "Update channel:") {
                    Picker("", selection: $channel) {
                        ForEach(UpdateChannel.allCases) { Text($0.title).tag($0.rawValue) }
                    }
                    .labelsHidden()
                    .frame(width: metrics.menuWidth(160))
                    .frame(minHeight: metrics.controlHeight)
                }
                SettingsRow(label: "Current version:") {
                    Text(AppInfo.versionString)
                        .font(metrics.font())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }

            SettingsSectionTitle("Manual Check")
            SettingsCard {
                HStack {
                    Button("Check for Updates Now") {
                        // TODO: wire to the updater when it lands (Sparkle-style feed).
                    }
                    Spacer(minLength: 0)
                }
                Text("Tracexy is up to date.")
                    .font(metrics.secondaryFont())
                    .foregroundStyle(.secondary)
            }
        }
    }

    // MARK: Private

    @AppStorage(SettingsKeys.autoCheckUpdates) private var autoCheck = true
    @AppStorage(SettingsKeys.updateChannel) private var channel = UpdateChannel.stable.rawValue

    private let metrics = SettingsDisplayMetrics.standard
}

#Preview {
    UpdatesSettingsView()
}
