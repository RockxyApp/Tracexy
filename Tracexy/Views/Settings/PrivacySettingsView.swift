import SwiftUI

// MARK: - PrivacySettingsView

/// Privacy preferences for protected native session exports. Raw capture formats
/// preserve packet evidence and therefore require explicit acknowledgement when
/// any protection is active. Local-first remains the default posture.
struct PrivacySettingsView: View {
    // MARK: Lifecycle

    init(
        historyRetentionError: String? = nil,
        isHistoryDemoMode: Bool = false,
        onAutoClearChange: @escaping (AutoClear) -> Void = { _ in }
    ) {
        self.historyRetentionError = historyRetentionError
        self.isHistoryDemoMode = isHistoryDemoMode
        self.onAutoClearChange = onAutoClearChange
    }

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
                    Picker("", selection: autoClearSelection) {
                        ForEach(AutoClear.allCases) { Text($0.title).tag($0.rawValue) }
                    }
                    .labelsHidden()
                    .frame(width: metrics.menuWidth(200))
                    .frame(minHeight: metrics.controlHeight)
                }

                SettingsIndented {
                    SettingsFootnote(
                        "Removes only local History summaries at launch, after a capture is added, "
                            + "and when this setting changes. Current capture data and saved files stay untouched."
                    )
                }

                if isHistoryDemoMode {
                    SettingsIndented {
                        SettingsInlineMessage(
                            "Demo mode uses isolated synthetic History. Re-launch with --dum-data to restore all four age tiers.",
                            tone: .info
                        )
                    }
                }

                if let historyRetentionError {
                    SettingsIndented {
                        SettingsInlineMessage(historyRetentionError, tone: .failure)
                    }
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

    private let historyRetentionError: String?
    private let isHistoryDemoMode: Bool
    private let onAutoClearChange: (AutoClear) -> Void
    private let metrics = SettingsDisplayMetrics.standard

    private var autoClearSelection: Binding<String> {
        Binding(
            get: {
                AutoClear(rawValue: autoClear)?.rawValue ?? AutoClear.never.rawValue
            },
            set: { rawValue in
                let selection = AutoClear(rawValue: rawValue) ?? .never
                autoClear = selection.rawValue
                onAutoClearChange(selection)
            }
        )
    }
}

#Preview {
    PrivacySettingsView()
}
