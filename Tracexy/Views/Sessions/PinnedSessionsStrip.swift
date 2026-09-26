import SwiftUI

// MARK: - PinnedSessionsStrip

/// The sessions pinned for this capture, above the Sessions table (Wireshark's
/// pinned packets). Filters never hide a pin: a pinned session the current scope
/// leaves out of the list is still here, marked, and a click still inspects it.
struct PinnedSessionsStrip: View {
    // MARK: Internal

    var coordinator: MainContentCoordinator
    let pinned: [SessionSummary]
    /// The ids the list currently shows, to mark the pins it does not.
    let shownIDs: Set<UUID>

    var body: some View {
        HStack(spacing: Theme.Metrics.spacingS) {
            Label("Pinned", systemImage: "pin.fill")
                .labelStyle(.iconOnly)
                .foregroundStyle(.secondary)
                .help("Pinned sessions stay here whatever the filter shows.")
                .accessibilityLabel("Pinned sessions")
            ScrollView(.horizontal) {
                HStack(spacing: Theme.Metrics.spacingS) {
                    ForEach(pinned) { session in
                        chip(session)
                    }
                }
            }
            .scrollIndicators(.never)
            Button("Unpin All") { coordinator.unpinAllSessions() }
                .buttonStyle(.borderless)
                .font(Theme.Typography.chromeAction)
                .help("Removes every pin from this capture.")
        }
        .font(Theme.Typography.caption)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Pinned sessions")
    }

    /// The name a pin goes by: the session's host, or its destination when the
    /// host is unknown.
    nonisolated static func title(for session: SessionSummary) -> String {
        session.host.isEmpty || session.host == "—" ? session.destinationEndpoint : session.host
    }

    // MARK: Private

    private func chip(_ session: SessionSummary) -> some View {
        let isSelected = coordinator.activeWorkspace.selectedSessionID == session.id
        let isShown = shownIDs.contains(session.id)
        let title = Self.title(for: session)
        return Button {
            coordinator.showPinnedSession(session)
        } label: {
            HStack(spacing: 4) {
                if !isShown {
                    Image(systemName: "eye.slash")
                        .imageScale(.small)
                        .foregroundStyle(.secondary)
                }
                Text(title)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(maxWidth: 220)
                    .fixedSize(horizontal: true, vertical: false)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .tracexyChipStyle(tint: Theme.color(for: session.primaryProtocol), isActive: isSelected)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(isShown
            ? "\(session.primaryProtocol.label) from \(session.sourceEndpoint) to \(session.destinationEndpoint)"
            :
            "\(session.primaryProtocol.label) from \(session.sourceEndpoint) to \(session.destinationEndpoint). The current filter hides it from the list.")
        .accessibilityLabel(isShown ? Text(verbatim: title) : Text("\(title), hidden by the current filter"))
        .accessibilityAddTraits(isSelected ? .isSelected : [])
        .contextMenu {
            Button("Inspect Session", systemImage: "sidebar.right") { coordinator.showPinnedSession(session) }
            Button("Unpin Session", systemImage: "pin.slash") { coordinator.togglePinSession(session.id) }
            Divider()
            Button("Unpin All Sessions") { coordinator.unpinAllSessions() }
        }
    }
}
