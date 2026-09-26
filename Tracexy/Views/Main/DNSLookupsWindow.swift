import SwiftUI

// MARK: - DNSLookupsWindow

/// Statistics ▸ DNS Lookups: every name the sessions in view looked up, what came back,
/// and how long it took; each row leads to that name's sessions.
struct DNSLookupsWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let all = DNSLookups.rows(
            sessions: coordinator.visibleSessions,
            findings: coordinator.datagramAnalysisSnapshot.findings,
            responseTimes: coordinator.timingSnapshot.measurements
        )
        let rows = all.filter { filter.isEmpty || $0.name.localizedCaseInsensitiveContains(filter) }
        Group {
            if mode == .encrypted {
                encryptedDNS
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if all.isEmpty {
                ContentUnavailableView(
                    "No DNS Lookups in View",
                    systemImage: "network",
                    description: Text("No unicast DNS query is among the sessions in view.")
                )
            } else {
                Table(rows, selection: $selection) {
                    TableColumn("Name") { row in
                        HStack(spacing: Theme.Metrics.spacingS) {
                            if row.problemCount > 0 {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundStyle(Color(nsColor: .systemOrange))
                                    .accessibilityLabel("Had problems")
                            }
                            Text(row.name).lineLimit(1).truncationMode(.middle).help(row.name)
                        }
                    }
                    .width(min: 150, ideal: 200)
                    TableColumn("Lookups") { row in
                        Text(row.lookupCount.formatted()).monospacedDigit()
                    }
                    .width(min: 52, ideal: 60)
                    TableColumn("Outcome") { row in
                        Text(row.outcome).foregroundStyle(row.problemCount > 0 ? Color.primary : Color.secondary)
                            .lineLimit(1)
                            .help(row.outcome)
                    }
                    .width(min: 150, ideal: 250)
                    TableColumn("Response") { row in
                        Text(row.medianResponseTime.map { "\(SessionResponseTimes.durationLabel($0)) median" } ?? "—")
                            .monospacedDigit()
                            .foregroundStyle(.secondary)
                    }
                    .width(min: 80, ideal: 100)
                }
                .contextMenu(forSelectionType: DNSLookupRow.ID.self) { ids in
                    if let name = ids.first {
                        Button("Show Sessions for \(name)") {
                            coordinator.selectHost(name)
                        }
                    }
                } primaryAction: { ids in
                    if let name = ids.first {
                        coordinator.selectHost(name)
                    }
                }
            }
        }
        .searchable(text: $filter, placement: .toolbar, prompt: "Name")
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Picker("Show", selection: $mode) {
                    Text("Lookups").tag(Mode.lookups)
                    Text("Encrypted DNS").tag(Mode.encrypted)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .help("Show the names looked up in the clear, or the sessions that carried DNS encrypted")
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) {
            if mode == .encrypted {
                encryptedFooter
            } else {
                footer(visibleSelection: rows.first { $0.id == selection }?.name, shown: rows.count, total: all.count)
            }
        }
        .frame(minWidth: 560, minHeight: 320)
    }

    // MARK: Private

    private enum Mode: Hashable {
        case lookups
        case encrypted
    }

    @State private var mode: Mode = .lookups
    @State private var encryptedSelection: EncryptedDNSRow.ID?
    @State private var filter = ""

    @State private var selection: DNSLookupRow.ID?

    @ViewBuilder private var encryptedDNS: some View {
        let rows = EncryptedDNS.rows(of: coordinator.visibleSessions)
            .filter { filter.isEmpty || $0.server.localizedCaseInsensitiveContains(filter) }
        if rows.isEmpty {
            ContentUnavailableView(
                "No Encrypted DNS Recognized",
                systemImage: "lock.shield",
                description: Text(
                    "DNS over TLS and QUIC are recognized by port 853, DNS over HTTPS by a well-known resolver's name."
                )
            )
        } else {
            Table(rows, selection: $encryptedSelection) {
                TableColumn("Server") { row in
                    Text(row.server).lineLimit(1).truncationMode(.middle).help(row.server)
                }
                .width(min: 150, ideal: 220)
                TableColumn("Transport") { row in
                    Text(row.transport.title)
                }
                .width(min: 110, ideal: 130)
                TableColumn("Recognized by") { row in
                    Text(row.basis).foregroundStyle(.secondary)
                }
                .width(min: 90, ideal: 110)
                TableColumn("Sessions") { row in
                    Text(row.sessionCount.formatted()).monospacedDigit()
                }
                .width(min: 56, ideal: 64)
                TableColumn("Bytes") { row in
                    Text(ByteUnits.string(Int64(row.byteCount))).monospacedDigit().foregroundStyle(.secondary)
                }
                .width(min: 64, ideal: 80)
            }
            .contextMenu(forSelectionType: EncryptedDNSRow.ID.self) { ids in
                if let row = rows.first(where: { $0.id == ids.first }) {
                    Button("Show Sessions with \(row.server)") {
                        coordinator.selectHost(row.server)
                    }
                }
            } primaryAction: { ids in
                if let row = rows.first(where: { $0.id == ids.first }) {
                    coordinator.selectHost(row.server)
                }
            }
        }
    }

    private var encryptedFooter: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Text(EncryptedDNS.summary(of: coordinator.visibleSessions))
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .help("Encrypted DNS hides the names looked up; only the resolver is visible.")
            Spacer()
        }
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    /// `visibleSelection` is the selected row only while the search still shows it.
    private func footer(visibleSelection: String?, shown: Int, total: Int) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Text(shown == total ? "\(total.formatted()) names" : "\(shown.formatted()) of \(total.formatted()) names")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
            Spacer()
            Button("Show Sessions") {
                if let visibleSelection {
                    coordinator.selectHost(visibleSelection)
                }
            }
            .disabled(visibleSelection == nil)
            .keyboardShortcut(.defaultAction)
            .help("Show the lookups of this name and the sessions to it in the main window")
        }
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }
}
