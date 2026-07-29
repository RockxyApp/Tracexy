import SwiftUI

// MARK: - UpdatesSettingsView

/// Software-update preferences backed directly by Sparkle. Sparkle owns
/// persistence for these settings; this view never creates duplicate defaults.
struct UpdatesSettingsView: View {
    // MARK: Lifecycle

    init(updater: AppUpdater) {
        self.updater = updater
    }

    // MARK: Internal

    var body: some View {
        SettingsPane {
            SettingsSection("Software Update") {
                SettingsCheckbox(
                    isOn: Binding(
                        get: { updater.automaticallyChecksForUpdates },
                        set: { updater.setAutomaticallyChecksForUpdates($0) }
                    ),
                    title: "Automatically check for updates",
                    description: "Check the signed Tracexy release feed on a schedule."
                )
                .disabled(!updater.supportsAutomaticChecks)

                SettingsDivider()

                SettingsCheckbox(
                    isOn: Binding(
                        get: { updater.automaticallyDownloadsUpdates },
                        set: { updater.setAutomaticallyDownloadsUpdates($0) }
                    ),
                    title: "Automatically download updates",
                    description: "Download verified updates in the background so they are ready to install."
                )
                .disabled(
                    !updater.supportsAutomaticChecks
                        || !updater.automaticallyChecksForUpdates
                        || !updater.allowsAutomaticUpdates
                )

                SettingsDivider()

                SettingsRow(label: "Check frequency:") {
                    Picker(
                        "",
                        selection: Binding(
                            get: {
                                UpdateCheckIntervalOption.closest(
                                    to: updater.updateCheckInterval
                                )
                            },
                            set: { updater.setUpdateCheckInterval($0.rawValue) }
                        )
                    ) {
                        ForEach(UpdateCheckIntervalOption.allCases) { option in
                            Text(option.title).tag(option)
                        }
                    }
                    .labelsHidden()
                    .frame(width: metrics.menuWidth(160))
                    .frame(minHeight: metrics.controlHeight)
                    .disabled(
                        !updater.supportsAutomaticChecks
                            || !updater.automaticallyChecksForUpdates
                    )
                }

                SettingsDivider()

                SettingsRow(label: "Current version:") {
                    Text(updater.currentVersionSummary)
                        .font(metrics.font())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }

                SettingsDivider()

                SettingsRow(label: "Last checked:") {
                    Text(updater.lastCheckedDescription)
                        .font(metrics.font())
                        .foregroundStyle(.secondary)
                }
            }

            SettingsSection("Manual Check") {
                HStack(spacing: 10) {
                    Button("Check for Updates Now") {
                        updater.checkForUpdates()
                    }
                    .disabled(!updater.canInitiateUpdateCheck)

                    Button("Change Logs…") {
                        updater.openChangelog()
                    }

                    if updater.sessionInProgress {
                        ProgressView()
                            .controlSize(.small)
                    }
                }
                Text(updater.updateAvailabilitySummary)
                    .font(metrics.secondaryFont())
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            SettingsSection("Privacy") {
                SettingsCheckbox(
                    isOn: Binding(
                        get: { updater.sendsSystemProfile },
                        set: { updater.setSendsSystemProfile($0) }
                    ),
                    title: "Send anonymous compatibility profile",
                    description: """
                    Share basic macOS and hardware compatibility details with the update feed. Captured traffic is never included.
                    """
                )
                .disabled(!updater.supportsAutomaticChecks)
            }
        }
    }

    // MARK: Private

    @ObservedObject private var updater: AppUpdater

    private let metrics = SettingsDisplayMetrics.standard
}

#Preview {
    UpdatesSettingsView(
        updater: AppUpdater(
            configuration: TracexyUpdateConfiguration(infoDictionary: [:])
        )
    )
}
