import SwiftUI

/// First-run prompt that explains and installs the privileged capture helper.
/// Shown automatically when the helper isn't installed yet.
struct HelperInstallPromptView: View {
    // MARK: Internal

    var coordinator: MainContentCoordinator

    var body: some View {
        ScrollView {
            reasons
        }
        .tracexySoftScrollEdge()
        .tracexySafeAreaBar(edge: .top) { header }
        .tracexySafeAreaBar(edge: .bottom) { footer }
        .frame(width: 580)
    }

    // MARK: Private

    @Environment(\.dismiss) private var dismiss
    @State private var isInstalling = false
    @State private var installError: String?

    private var header: some View {
        HStack(alignment: .top, spacing: 18) {
            icon
            VStack(alignment: .leading, spacing: 8) {
                Text("Install Helper Tool")
                    .font(Theme.Typography.title)
                Text("Tracexy uses a small privileged helper so macOS can grant packet-capture access securely.")
                    .font(Theme.Typography.body)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(24)
    }

    private var icon: some View {
        Image(systemName: "lock.shield.fill")
            .font(.system(size: Theme.Icon.heroLarge, weight: .medium))
            .foregroundStyle(Color.accentColor)
            .frame(width: 84, height: 84)
            .tracexyGlassEffect(
                tint: .accentColor,
                in: RoundedRectangle(cornerRadius: 18, style: .continuous)
            )
    }

    private var reasons: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Why install it?")
                .font(Theme.Typography.surfaceTitle)
            reasonRow("Capture live traffic without running Tracexy as root.")
            reasonRow("Keep /dev/bpf* capture permissions repaired automatically.")
            reasonRow("Stay local: the helper never inspects, stores, or uploads traffic.")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(24)
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let installError {
                Label(installError, systemImage: "exclamationmark.triangle.fill")
                    .font(Theme.Typography.surfaceTitle)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .tracexyGlassButtonStyle()
                Spacer()
                Button {
                    Task {
                        isInstalling = true
                        installError = nil
                        await coordinator.helper.install()
                        isInstalling = false

                        switch coordinator.helper.status {
                        case .installedCompatible,
                             .installedOutdated,
                             .requiresApproval:
                            dismiss()
                        case let .failed(reason):
                            installError = reason
                        case .unreachable:
                            installError = coordinator.helper.probeFailureDetail
                                ?? "The helper was registered but did not respond."
                        case .installedIncompatible:
                            installError = "The installed helper is incompatible with this app build."
                        case .signingMismatch:
                            installError = "The app and helper signing identities do not match."
                        case .notInstalled:
                            installError = "The helper could not be installed."
                        }
                    }
                } label: {
                    if isInstalling {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Install Helper Tool", systemImage: "arrow.down.circle.fill")
                    }
                }
                .keyboardShortcut(.defaultAction)
                .tracexyGlassButtonStyle(prominent: true)
                .disabled(isInstalling)
            }
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 16)
    }

    private func reasonRow(_ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 11) {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .font(Theme.Typography.title)
            Text(text).font(Theme.Typography.body)
            Spacer(minLength: 0)
        }
    }
}

#Preview {
    HelperInstallPromptView(coordinator: MainContentCoordinator())
}
