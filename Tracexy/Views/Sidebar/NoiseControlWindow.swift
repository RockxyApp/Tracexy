import SwiftUI

// MARK: - NoiseControlWindow

/// Native window that mutes chatty hosts and protocols so a busy capture (mDNS,
/// ARP, ICMPv6…) stops flooding the session list. Muting is global and persisted;
/// the session list, counts, and stats all respect it. Opened via `openWindow`
/// from the Focus sidebar.
struct NoiseControlWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Label("Noise Control", systemImage: "speaker.slash").font(Theme.Typography.surfaceTitle)
                Spacer()
                Button("Clear All") { coordinator.clearNoiseControl() }
                    .controlSize(.small)
                    .disabled(!coordinator.isNoiseControlActive)
            }
            .padding(16)
            Divider()

            List {
                Section("Protocols") {
                    if coordinator.presentProtocols.isEmpty {
                        Text("No traffic yet").font(Theme.Typography.caption).foregroundStyle(.tertiary)
                    } else {
                        ForEach(coordinator.presentProtocols) { proto in
                            muteRow(
                                title: proto.label,
                                isMuted: coordinator.isProtocolMuted(proto)
                            ) { coordinator.toggleMuteProtocol(proto) }
                        }
                    }
                }

                Section("Hosts") {
                    if topHosts.isEmpty {
                        Text("No hosts yet").font(Theme.Typography.caption).foregroundStyle(.tertiary)
                    } else {
                        ForEach(topHosts, id: \.host) { entry in
                            muteRow(
                                title: entry.host,
                                subtitle: entry.hits > 0 ? "\(entry.hits)" : nil,
                                isMuted: coordinator.isHostMuted(entry.host)
                            ) { coordinator.toggleMuteHost(entry.host) }
                        }
                    }
                }
            }

            Divider()
            HStack {
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            .padding(16)
        }
        .frame(minWidth: 420, minHeight: 420)
    }

    // MARK: Private

    @Environment(\.dismiss) private var dismiss

    /// Distinct hosts by session count (desc), plus any already-muted host so it
    /// can be un-muted even after its traffic scrolled off.
    private var topHosts: [(host: String, hits: Int)] {
        var counts: [String: Int] = [:]
        for session in coordinator.sessions {
            counts[session.host, default: 0] += 1
        }
        for host in coordinator.mutedHosts where counts[host] == nil {
            counts[host] = 0
        }
        return counts
            .sorted { lhs, rhs in
                lhs.value != rhs.value ? lhs.value > rhs.value : lhs.key < rhs.key
            }
            .prefix(40)
            .map { (host: $0.key, hits: $0.value) }
    }

    private func muteRow(
        title: String,
        subtitle: String? = nil,
        isMuted: Bool,
        toggle: @escaping () -> Void
    )
        -> some View
    {
        Button(action: toggle) {
            HStack(spacing: 8) {
                Image(systemName: isMuted ? "speaker.slash.fill" : "speaker.wave.2")
                    .foregroundStyle(isMuted ? Color.accentColor : .secondary)
                    .frame(width: 16)
                Text(title).lineLimit(1).foregroundStyle(isMuted ? .secondary : .primary)
                Spacer()
                if let subtitle {
                    Text(subtitle).font(Theme.Typography.caption.monospacedDigit()).foregroundStyle(.tertiary)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}
