import SwiftUI

// MARK: - PrivacySettingsView

/// Privacy preferences for protected native session exports. Raw capture formats
/// preserve packet evidence and therefore require explicit acknowledgement when
/// any protection is active. Local-first remains the default posture.
struct PrivacySettingsView: View {
    // MARK: Internal

    var body: some View {
        SettingsPane {
            SettingsSection("Protected Session Export") {
                SettingsCheckbox(
                    isOn: $redactBodies,
                    title: "Redact payload bodies",
                    description: "Exclude captured packet bytes from protected Tracexy session documents."
                )

                SettingsDivider()

                SettingsCheckbox(
                    isOn: $stripCredentials,
                    title: "Strip credentials & tokens",
                    description: "Remove DNS-derived and free-form decoded metadata that may carry secrets."
                )

                SettingsDivider()

                SettingsCheckbox(
                    isOn: $maskIPs,
                    title: "Mask IP addresses",
                    description: "Replace literal addresses in protected session summaries with a fixed placeholder."
                )

                SettingsDivider()

                SettingsIndented {
                    SettingsFootnote(
                        """
                        These protections apply to .tracexysession documents. Raw pcap and pcapng exports preserve \
                        captured bytes and always require confirmation while a protection is enabled.
                        """
                    )
                }
            }

            SettingsSection("Data") {
                SettingsCheckbox(
                    isOn: $localOnly,
                    title: "Keep all data on this Mac (never upload)",
                    description: "Captured traffic stays on this device and is never sent to any server."
                )

                SettingsDivider()

                SettingsRow(label: "Auto-clear:") {
                    Picker("", selection: $autoClear) {
                        ForEach(AutoClear.allCases) { Text($0.title).tag($0.rawValue) }
                    }
                    .labelsHidden()
                    .frame(width: metrics.menuWidth(200))
                    .frame(minHeight: metrics.controlHeight)
                }
            }

            SettingsSection("Diagnostics") {
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
