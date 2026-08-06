import ServiceManagement
import SwiftUI

// MARK: - HelperSettingsView

/// Install / update / uninstall / recover the privileged capture helper, with
/// live version + compatibility status.
struct HelperSettingsView: View {
    // MARK: Internal

    var body: some View {
        SettingsPane {
            SettingsSection("Capture Helper") {
                SettingsRow(label: "Status:") { statusBadge }

                if let issue = helper.signingIssue {
                    SettingsDivider()
                    helperNote(signingIssueText(issue))
                }

                if helper.status == .unreachable, let detail = helper.probeFailureDetail {
                    SettingsDivider()
                    helperNote(detail)
                }

                if let info = helper.installedInfo {
                    SettingsDivider()
                    SettingsRow(label: "Installed:") {
                        versionText(
                            "v\(info.binaryVersion) · build \(info.buildNumber) · protocol \(info.protocolVersion)"
                        )
                    }
                }

                SettingsDivider()

                SettingsRow(label: "Bundled:") {
                    versionText(
                        "v\(helper.bundledHelperVersion) · build \(helper.bundledHelperBuild) · protocol \(helper.expectedProtocolVersion)"
                    )
                }
            }

            SettingsSection("Actions") {
                HStack(spacing: 12) {
                    primaryAction
                    Button("Check Status") { Task { await helper.checkStatus() } }
                    Button("Uninstall", role: .destructive) { Task { await helper.uninstall() } }
                        .disabled(helper.status == .notInstalled)
                    Spacer(minLength: 0)
                }
            }

            recoverySection

            if let summary = recovery.summary {
                resultSection(summary)
            }
        }
        .disabled(helper.isBusy || recovery.isWorking)
        .overlay(alignment: .topTrailing) {
            if helper.isBusy || recovery.isWorking {
                ProgressView().controlSize(.small).padding(12)
            }
        }
        .task { await helper.checkStatus() }
    }

    // MARK: Private

    @State private var helper = HelperClient.shared
    @State private var recovery = HelperRecoveryPresenter()
    @State private var showForceResetConfirm = false
    @State private var showBackgroundItemsConfirm = false

    private let metrics = SettingsDisplayMetrics.standard

    // MARK: Status

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

    // MARK: Recovery

    private var recoverySection: some View {
        SettingsSection("Recovery") {
            helperNote(
                "Use this only if the helper is stuck and Install / Update don’t recover it. It stops any active "
                    + "capture, removes the privileged helper with administrator rights, and reinstalls it from this app. "
                    + "Requires an administrator password."
            )

            HStack {
                Button("Force Reset & Reinstall…", role: .destructive) {
                    showForceResetConfirm = true
                }
                Spacer(minLength: 0)
            }
            .confirmationDialog(
                "Force reset the capture helper?",
                isPresented: $showForceResetConfirm,
                titleVisibility: .visible
            ) {
                Button("Force Reset & Reinstall", role: .destructive) {
                    Task { await recovery.runNormalReset() }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text(
                    "This stops any active capture, removes the privileged helper with administrator rights, and "
                        + "reinstalls it. You’ll be asked for an administrator password."
                )
            }

            if recovery.offersBackgroundItemsReset {
                SettingsDivider()
                helperNote(
                    "Normal recovery didn’t fully clear the helper. As a last resort you can also reset macOS Login & "
                        + "Background Items. This runs “sfltool resetbtm”, which can affect Background Items for other "
                        + "apps too — they may need re-approval. You must restart your Mac before installing the helper "
                        + "again."
                )
                HStack {
                    Button("Reset Background Items…", role: .destructive) {
                        showBackgroundItemsConfirm = true
                    }
                    Spacer(minLength: 0)
                }
                .confirmationDialog(
                    "Also reset macOS Background Items?",
                    isPresented: $showBackgroundItemsConfirm,
                    titleVisibility: .visible
                ) {
                    Button("Reset Background Items", role: .destructive) {
                        Task { await recovery.runBackgroundItemsReset() }
                    }
                    Button("Cancel", role: .cancel) {}
                } message: {
                    Text(
                        "This runs “sfltool resetbtm” and can affect Login & Background Items for other apps, which may "
                            + "need re-approval. Tracexy will remove the helper but will not reinstall it immediately; "
                            + "restart your Mac, then install it from Settings. Only continue if normal recovery didn’t work."
                    )
                }
            }
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
            // After a Background Items reset the helper is removed but a restart is
            // required before it can be installed again. Suppress the Install button
            // while that summary is active so the user restarts first instead of
            // hitting an install that cannot succeed yet.
            if recovery.summary?.requiresRestart == true {
                Label("Restart your Mac before installing", systemImage: "arrow.clockwise.circle.fill")
                    .foregroundStyle(.secondary)
            } else {
                Button("Install Helper") { Task { await helper.install() } }
            }
        case .requiresApproval:
            Button("Open Login Items") { SMAppService.openSystemSettingsLoginItems() }
        case .installedOutdated,
             .installedIncompatible:
            Button("Update Helper") { Task { await helper.update() } }
        case .unreachable:
            // First-line, non-destructive repair for a registered-but-unreachable
            // helper (BTM/launchd drift after an in-place update): re-submit the
            // registration from this bundle and re-probe, before the privileged
            // hard reset in the Recovery section below.
            if HelperClient.offersRegistrationRepair(for: helper.status) {
                Button("Repair Registration") { Task { await helper.repairRegistration() } }
            } else {
                Button("Retry") { Task { await helper.checkStatus() } }
            }
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

    private func resultSection(_ summary: ForceResetSummary) -> some View {
        let (symbol, tint): (String, Color) = if summary.succeeded {
            ("checkmark.seal.fill", .green)
        } else if summary.requiresRestart {
            ("arrow.clockwise.circle.fill", .blue)
        } else {
            ("exclamationmark.triangle.fill", .orange)
        }
        return SettingsSection("Result") {
            Label(summary.title, systemImage: symbol)
                .font(metrics.font())
                .foregroundStyle(tint)

            Text(summary.details)
                .font(metrics.secondaryFont())
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)

            HStack {
                Button("Copy Details") { recovery.copyDetails() }
                Spacer(minLength: 0)
            }
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
}
