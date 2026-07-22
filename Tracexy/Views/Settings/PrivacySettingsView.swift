import SwiftUI

// MARK: - PrivacySettingsView

/// Privacy preferences. These persist the user's choices; the redaction / masking
/// pipeline and retention timer that consume them are not yet implemented (they
/// arrive with the export & analysis engines). Local-first is the default posture.
struct PrivacySettingsView: View {
    // MARK: Internal

    var body: some View {
        SettingsPane {
            SettingsSectionTitle("On Export & Share")
            SettingsCard {
                SettingsCheckbox(
                    isOn: $redactBodies,
                    title: "Redact payload bodies",
                    description: "Replace request and response bodies with placeholders in exported captures."
                )
                SettingsCheckbox(
                    isOn: $stripCredentials,
                    title: "Strip credentials & tokens",
                    description: "Remove Authorization headers, cookies, and API keys before sharing."
                )
                SettingsCheckbox(
                    isOn: $maskIPs,
                    title: "Mask IP addresses",
                    description: "Anonymize source and destination addresses in exports and shared sessions."
                )
            }

            SettingsSectionTitle("Data")
            SettingsCard {
                SettingsCheckbox(
                    isOn: $localOnly,
                    title: "Keep all data on this Mac (never upload)",
                    description: "Captured traffic stays on this device and is never sent to any server."
                )
                SettingsRow(label: "Auto-clear:") {
                    Picker("", selection: $autoClear) {
                        ForEach(AutoClear.allCases) { Text($0.title).tag($0.rawValue) }
                    }
                    .labelsHidden()
                    .frame(width: metrics.menuWidth(200))
                    .frame(minHeight: metrics.controlHeight)
                }
            }

            SettingsSectionTitle("Diagnostics")
            SettingsCard {
                SettingsCheckbox(
                    isOn: $shareAnalytics,
                    title: "Share anonymous usage analytics",
                    description: "Send aggregate, non-identifying usage metrics to help improve Tracexy."
                )
            }
        }
    }

    // MARK: Private

    @AppStorage(SettingsKeys.redactBodies) private var redactBodies = true
    @AppStorage(SettingsKeys.stripCredentials) private var stripCredentials = true
    @AppStorage(SettingsKeys.maskIPs) private var maskIPs = false
    @AppStorage(SettingsKeys.localOnly) private var localOnly = true
    @AppStorage(SettingsKeys.autoClear) private var autoClear = AutoClear.never.rawValue
    @AppStorage(SettingsKeys.shareAnalytics) private var shareAnalytics = false

    private let metrics = SettingsDisplayMetrics.standard
}

#Preview {
    PrivacySettingsView()
}
