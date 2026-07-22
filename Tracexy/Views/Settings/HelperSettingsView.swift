import ServiceManagement
import SwiftUI

// MARK: - HelperSettingsView

/// Install / update / uninstall / recover the privileged capture helper, with
/// live version + compatibility status. Mirrors the sibling app's helper settings.
struct HelperSettingsView: View {
    // MARK: Internal

    var body: some View {
        SettingsPane {
            SettingsSectionTitle("Capture Helper")
            SettingsCard {
                SettingsRow(label: "Status:") { statusBadge }

                if let issue = helper.signingIssue {
                    helperNote(signingIssueText(issue))
                }

                if let info = helper.installedInfo {
                    SettingsRow(label: "Installed:") {
                        versionText(
                            "v\(info.binaryVersion) · build \(info.buildNumber) · protocol \(info.protocolVersion)"
                        )
                    }
                }

                SettingsRow(label: "Bundled:") {
                    versionText(
                        "v\(helper.bundledHelperVersion) · build \(helper.bundledHelperBuild) · protocol \(helper.expectedProtocolVersion)"
                    )
                }
            }

            SettingsSectionTitle("Actions")
            SettingsCard {
                HStack(spacing: 12) {
                    primaryAction
                    Button("Check Status") { Task { await helper.checkStatus() } }
                    Button("Uninstall", role: .destructive) { Task { await helper.uninstall() } }
                        .disabled(helper.status == .notInstalled)
                    Spacer(minLength: 0)
                }
            }

            SettingsSectionTitle("Recovery")
            SettingsCard {
                Toggle("Also reset macOS Login & Background Items", isOn: $resetBackgroundItems)
                    .toggleStyle(.checkbox)
                HStack {
                    Button("Force Reset & Reinstall…", role: .destructive) {
                        Task { await forceReset() }
                    }
                    Spacer(minLength: 0)
                }
                helperNote(
                    "Use this only if the helper is stuck and Install/Update don't recover it. Requires an administrator password."
                )
            }

            if let message {
                SettingsSectionTitle("Result")
                SettingsCard {
                    Text(message)
                        .font(metrics.secondaryFont())
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .disabled(helper.isBusy || isWorking)
        .overlay(alignment: .topTrailing) {
            if helper.isBusy || isWorking {
                ProgressView().controlSize(.small).padding(12)
            }
        }
        .task { await helper.checkStatus() }
    }

    // MARK: Private

    @State private var helper = HelperClient.shared
    @State private var resetBackgroundItems = false
    @State private var isWorking = false
    @State private var message: String?

    private let metrics = SettingsDisplayMetrics.standard

    private var statusAppearance: (String, Color, String) {
        switch helper.status {
        case .installedCompatible: ("Installed & up to date", .green, "checkmark.seal.fill")
        case .installedOutdated: ("Installed — update available", .orange, "arrow.up.circle.fill")
        case .installedIncompatible: ("Installed — incompatible protocol", .red, "exclamationmark.triangle.fill")
        case .requiresApproval: ("Awaiting approval in Login Items", .orange, "hourglass")
        case .notInstalled: ("Not installed", .secondary, "xmark.seal")
        case .unreachable: ("Registered but unreachable", .red, "bolt.horizontal.circle")
        case .signingMismatch: ("Signing mismatch", .red, "xmark.shield.fill")
        case let .failed(reason): (reason, .red, "exclamationmark.triangle.fill")
        }
    }

    @ViewBuilder private var statusBadge: some View {
        let (text, color, symbol) = statusAppearance
        Label(text, systemImage: symbol)
            .font(metrics.font())
            .foregroundStyle(color)
    }

    @ViewBuilder private var primaryAction: some View {
        switch helper.status {
        case .installedCompatible:
            Label("No action needed", systemImage: "checkmark").foregroundStyle(.secondary)
        case .notInstalled:
            Button("Install Helper") { Task { await helper.install() } }
        case .requiresApproval:
            Button("Open Login Items") { SMAppService.openSystemSettingsLoginItems() }
        case .installedOutdated,
             .installedIncompatible:
            Button("Update Helper") { Task { await helper.update() } }
        case .unreachable:
            Button("Retry") { Task { await helper.checkStatus() } }
        case .signingMismatch:
            if case .appSignatureInvalid = helper.signingIssue {
                Label("Clean build & rebuild the app", systemImage: "hammer").foregroundStyle(.secondary)
            } else {
                Button("Reinstall Helper") { Task { await helper.update() } }
            }
        case .failed:
            Button("Reinstall Helper") { Task { await helper.update() } }
        }
    }

    private func versionText(_ text: String) -> some View {
        Text(text)
            .font(metrics.secondaryFont())
            .foregroundStyle(.secondary)
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func helperNote(_ text: String) -> some View {
        Text(text)
            .font(metrics.secondaryFont())
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func signingIssueText(_ issue: HelperClient.SigningIssue) -> String {
        switch issue {
        case let .appSignatureInvalid(detail):
            "This app build has an invalid code signature (\(detail)). Clean the build folder and rebuild."
        case let .identityMismatch(appSigner, helperSigner):
            "The app is signed by “\(appSigner)” but the installed helper was signed by “\(helperSigner)”. Reinstall the helper from this build."
        }
    }

    private func forceReset() async {
        isWorking = true
        defer { isWorking = false }
        message = await helper.forceResetAndReinstall(resetBackgroundItems: resetBackgroundItems)
    }
}
