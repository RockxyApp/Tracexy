import AppKit
import SwiftUI

// MARK: - EndpointsWindow

/// View ▸ Endpoints: every address (or address:port) in the sessions in view, with the
/// frames and bytes it sent (Tx) and received (Rx) and the name the capture or the
/// Project gave it. Each row leads back to its sessions through a Session Expression.
struct EndpointsWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let sessions = coordinator.visibleSessions
        let names = nameByAddress(sessions)
        let subnets = coordinator.addressNames.subnets
        let all = TrafficStatistics.endpoints(
            of: sessions, kind: kind, subnets: groupsBySubnet ? subnets : []
        )
        let rows = all.filter { matches($0, names: names) }.sorted(using: sortOrder)
        let origin = coordinator.trafficTimeline.firstTimedFrame
        Group {
            if all.isEmpty {
                ContentUnavailableView(
                    "No \(kind.title) Endpoints in View",
                    systemImage: "point.3.connected.trianglepath.dotted",
                    description: Text("None of the sessions in view is carried over \(kind.title).")
                )
            } else {
                table(rows, names: names, origin: origin)
            }
        }
        .searchable(text: $filter, placement: .toolbar, prompt: "Address, port or name")
        .toolbar {
            ToolbarItem(placement: .navigation) {
                TrafficKindPicker(kind: $kind, counts: TrafficStatistics.endpointCounts(of: sessions))
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) {
            footer(rows: rows, total: all.count, sessions: sessions.count, canGroup: kind == .ipv4 && !subnets.isEmpty)
        }
        .frame(minWidth: 680, minHeight: 320)
    }

    // MARK: Private

    @State private var kind: TrafficAddressKind = .ipv4
    @State private var groupsBySubnet = false
    @State private var filter = ""
    @State private var notice: String?
    @State private var selection: TrafficEndpointRow.ID?
    @State private var sortOrder = [KeyPathComparator(\TrafficEndpointRow.bytes, order: .reverse)]

    /// The table, with location columns when a locator is installed and has
    /// answers (never for Ethernet endpoints, which have no IP address).
    @ViewBuilder
    private func table(_ rows: [TrafficEndpointRow], names: [String: String], origin: Date?) -> some View {
        if let locator = AddressLocators.installed, locator.isLocating, kind != .ethernet {
            Table(rows, selection: $selection, sortOrder: $sortOrder) {
                columns(names: names, origin: origin)
                locationColumns(locator)
            }
            .contextMenu(forSelectionType: TrafficEndpointRow.ID.self) { ids in
                menu(ids, rows: rows, locator: locator)
            } primaryAction: { ids in
                showSessions(ids, rows: rows)
            }
        } else {
            Table(rows, selection: $selection, sortOrder: $sortOrder) {
                columns(names: names, origin: origin)
            }
            .contextMenu(forSelectionType: TrafficEndpointRow.ID.self) { ids in
                menu(ids, rows: rows, locator: nil)
            } primaryAction: { ids in
                showSessions(ids, rows: rows)
            }
        }
    }

    @ViewBuilder
    private func menu(
        _ ids: Set<TrafficEndpointRow.ID>,
        rows: [TrafficEndpointRow],
        locator: (any AddressLocating)?
    )
        -> some View
    {
        if let row = rows.first(where: { $0.id == ids.first }) {
            Button("Show Sessions (\(row.term))") {
                coordinator.showSessions(narrowingWith: row.term)
            }
            if let locator {
                ForEach(locator.menuItems(for: row.address)) { item in
                    Button(item.title) {
                        coordinator.showSessions(narrowingWith: item.expression)
                    }
                }
            }
            Button("Copy as Session Expression") {
                copy(row.term)
            }
            Divider()
            Button("Copy Row as CSV") {
                copy(TrafficStatistics.csv([row]))
            }
        }
        Button("Copy All as CSV") {
            copy(TrafficStatistics.csv(rows))
        }
    }

    private func footer(rows: [TrafficEndpointRow], total: Int, sessions: Int, canGroup: Bool) -> some View {
        let selected = rows.first { $0.id == selection }
        return HStack(spacing: Theme.Metrics.spacingM) {
            Text(rows.count == total
                ? "\(total.formatted()) endpoints from \(sessions.formatted()) sessions in view"
                : "Showing \(rows.count.formatted()) of \(total.formatted()) endpoints")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            Spacer()
            if canGroup {
                Toggle("Group by Named Subnet", isOn: $groupsBySubnet)
                    .toggleStyle(.checkbox)
                    .help("Add the addresses in each subnet named in Resolved Addresses into one row")
            }
            if let accessory = AddressLocators.installed?.endpointsAccessory() {
                accessory
            }
            if let notice {
                Text(notice).font(Theme.Typography.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Button("Save as CSV…") {
                notice = StatisticsExport.saveText(TrafficStatistics.csv(rows), suggestedName: "Endpoints.csv")
            }
            .disabled(rows.isEmpty)
            .help("Save the rows shown as comma-separated values")
            Button("Show Sessions") {
                if let selected {
                    coordinator.showSessions(narrowingWith: selected.term)
                }
            }
            .disabled(selected == nil)
            .keyboardShortcut(.defaultAction)
            .help("Narrow the Session Expression in the main window to the selected endpoint")
        }
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    @TableColumnBuilder<TrafficEndpointRow, KeyPathComparator<TrafficEndpointRow>>
    private func columns(
        names: [String: String],
        origin: Date?
    )
        -> some TableColumnContent<TrafficEndpointRow, KeyPathComparator<TrafficEndpointRow>>
    {
        TableColumn("Address", value: \.label) { row in
            Text(row.label).font(Theme.Typography.mono).lineLimit(1).truncationMode(.middle).help(row.label)
        }
        .width(min: 120, ideal: 180)
        TableColumn("Name") { row in
            Text(names[row.address] ?? "—")
                .lineLimit(1)
                .truncationMode(.middle)
                .foregroundStyle(names[row.address] == nil ? .tertiary : .secondary)
                .help(names[row.address] ?? "No name was learned or given for this address")
        }
        .width(min: 100, ideal: 170)
        TableColumn("Sessions", value: \.sessionCount) { row in
            TrafficCells.number(row.sessionCount)
        }
        .width(min: 52, ideal: 60)
        TableColumn("Packets", value: \.packets) { row in
            TrafficCells.number(row.packets)
        }
        .width(min: 52, ideal: 64)
        TableColumn("Bytes", value: \.bytes) { row in
            TrafficCells.bytes(row.bytes)
        }
        .width(min: 60, ideal: 72)
        TableColumn("Tx Packets", value: \.txPackets) { row in
            TrafficCells.number(row.txPackets)
        }
        .width(min: 60, ideal: 72)
        TableColumn("Tx Bytes", value: \.txBytes) { row in
            TrafficCells.bytes(row.txBytes)
        }
        .width(min: 60, ideal: 72)
        TableColumn("Rx Packets", value: \.rxPackets) { row in
            TrafficCells.number(row.rxPackets)
        }
        .width(min: 60, ideal: 72)
        TableColumn("Rx Bytes", value: \.rxBytes) { row in
            TrafficCells.bytes(row.rxBytes)
        }
        .width(min: 60, ideal: 72)
        TableColumn("First Seen") { row in
            Text(TrafficCells.relativeStart(row.firstSeen, origin: origin))
                .monospacedDigit().foregroundStyle(.secondary)
        }
        .width(min: 64, ideal: 76)
    }

    @TableColumnBuilder<TrafficEndpointRow, KeyPathComparator<TrafficEndpointRow>>
    private func locationColumns(
        _ locator: any AddressLocating
    )
        -> some TableColumnContent<TrafficEndpointRow, KeyPathComparator<TrafficEndpointRow>>
    {
        TableColumn(locator.columnTitle(.country)) { row in
            locator.cell(.country, for: row.address)
        }
        .width(min: 70, ideal: 120)
        TableColumn(locator.columnTitle(.city)) { row in
            locator.cell(.city, for: row.address)
        }
        .width(min: 60, ideal: 110)
        TableColumn(locator.columnTitle(.asNumber)) { row in
            locator.cell(.asNumber, for: row.address)
        }
        .width(min: 60, ideal: 76)
        TableColumn(locator.columnTitle(.asOrganization)) { row in
            locator.cell(.asOrganization, for: row.address)
        }
        .width(min: 90, ideal: 180)
    }

    private func showSessions(_ ids: Set<TrafficEndpointRow.ID>, rows: [TrafficEndpointRow]) {
        if let row = rows.first(where: { $0.id == ids.first }) {
            coordinator.showSessions(narrowingWith: row.term)
        }
    }

    /// The first name each address has — one the user gave first, then one a DNS or
    /// mDNS answer in this capture carried.
    private func nameByAddress(_ sessions: [SessionSummary]) -> [String: String] {
        var names: [String: String] = [:]
        for row in ResolvedAddresses.rows(
            sessions: coordinator.presentedSessions, namedAddresses: coordinator.addressNames.names,
            namedSubnets: coordinator.addressNames.subnetNames
        ) where names[row.address] == nil {
            names[row.address] = row.name
        }
        // Addresses with no name of their own show their named subnet's form.
        for session in sessions {
            for address in [session.sourceEndpointValue?.ip, session.destinationEndpointValue?.ip].compactMap(\.self)
                where names[address] == nil
            {
                names[address] = coordinator.addressNames.displayName(for: address)
            }
        }
        return names
    }

    private func matches(_ row: TrafficEndpointRow, names: [String: String]) -> Bool {
        filter.isEmpty || row.label.localizedCaseInsensitiveContains(filter)
            || (names[row.address]?.localizedCaseInsensitiveContains(filter) ?? false)
            || (AddressLocators.installed.map { $0.isLocating && $0.matches(row.address, filter: filter) } ?? false)
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
