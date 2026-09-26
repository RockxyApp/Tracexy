import SwiftUI

// MARK: - EnabledProtocolsPane

/// Capture ▸ Enabled Protocols…: switch a protocol's recognition off, as Wireshark's
/// Enabled Protocols dialog does, so its traffic stays plain TCP or UDP data — for a
/// port another program uses for something else. Belongs to the Project and applies to
/// captures decoded from then on; Decode Again re-reads the open one. Shown in the
/// Decode As window, beside the rules.
struct EnabledProtocolsPane: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let settings = coordinator.decodeAs
        let reads = Dictionary(uniqueKeysWithValues: SupportedProtocols.rows.map { ($0.kind, $0) })
        let needle = search.trimmingCharacters(in: .whitespacesAndNewlines)
        let shown = DecodeAsProtocol.allCases.filter { proto in
            needle.isEmpty || proto.title.localizedCaseInsensitiveContains(needle)
                || (reads[proto.kind]?.name.localizedCaseInsensitiveContains(needle) ?? false)
        }
        List {
            ForEach(shown) { proto in
                Toggle(isOn: Binding(
                    get: { !settings.disabledProtocols.contains(proto.kind) },
                    set: { settings.setEnabled($0, proto.kind) }
                )) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(proto.title)
                        if let row = reads[proto.kind] {
                            Text(row.name).font(Theme.Typography.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                .toggleStyle(.checkbox)
            }
        }
        .listStyle(.inset)
        .searchable(text: $search, placement: .toolbar, prompt: "Protocol")
        .tracexySafeAreaBar(edge: .bottom) { footer(settings) }
    }

    // MARK: Private

    @State private var search = ""

    private func footer(_ settings: DecodeAsSettings) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Button("Enable All") { settings.setDisabled([]) }
                .disabled(settings.disabledProtocols.isEmpty)
            Spacer()
            if settings.needsRedecode {
                Text("Changes apply to captures decoded from now on.")
                    .foregroundStyle(.secondary)
                Button("Decode Again") {
                    coordinator.redecodeActiveSavedCapture()
                }
                .disabled(!coordinator.canRedecodeActiveSavedCapture)
                .help("Read the open capture file again with these protocols, like Wireshark's Redissect")
            }
        }
        .font(Theme.Typography.caption)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }
}
