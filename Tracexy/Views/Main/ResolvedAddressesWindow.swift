import SwiftUI

// MARK: - ResolvedAddressesWindow

/// Statistics ▸ Resolved Addresses: the names this capture's DNS and mDNS answers gave each
/// address, and the names given in this Project, with a route from every row back
/// to the sessions it explains.
struct ResolvedAddressesWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let all = coordinator.resolvedAddressRows
        let rows = all.filter { ResolvedAddresses.matches($0, filter: filter) }
        Group {
            if all.isEmpty {
                ContentUnavailableView(
                    "No Resolved Addresses",
                    systemImage: "character.book.closed",
                    description: Text("No DNS or mDNS answer in this capture named an address.")
                )
            } else {
                table(rows)
            }
        }
        .searchable(text: $filter, placement: .toolbar, prompt: "Address or name")
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) { footer(rows: rows, total: all.count) }
        .frame(minWidth: 520, minHeight: 360)
        .sheet(item: $subnetDraft) { draft in
            SubnetNameSheet(draft: draft) { block, name in
                if draft.block != block, !draft.block.isEmpty {
                    coordinator.addressNames.setSubnetName("", for: draft.block)
                }
                return coordinator.addressNames.setSubnetName(name, for: block)
            }
        }
    }

    // MARK: Private

    @State private var filter = ""
    @State private var selection: ResolvedAddressRow.ID?
    @State private var subnetDraft: SubnetNameDraft?

    private func table(_ rows: [ResolvedAddressRow]) -> some View {
        Table(rows, selection: $selection) {
            TableColumn("Address") { row in
                Text(row.address)
                    .font(Theme.Typography.mono)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(row.address)
            }
            .width(min: 110, ideal: 150)
            TableColumn("Name") { row in
                HStack(spacing: Theme.Metrics.spacingS) {
                    Text(row.name)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                    if row.hasOtherNames {
                        Image(systemName: "exclamationmark.circle")
                            .foregroundStyle(.secondary)
                            .help("Answers in this capture gave this address more than one name")
                            .accessibilityLabel("Also has other names")
                    }
                }
            }
            .width(min: 150, ideal: 210)
            TableColumn("Learned From") { row in
                Text(row.answerCount > 1 ? "\(row.source.label), \(row.answerCount) answers" : row.source.label)
                    .foregroundStyle(.secondary)
            }
            .width(min: 130, ideal: 170)
        }
        .onDeleteCommand {
            // Edit ▸ Delete removes a subnet name; learned names are the capture's own.
            if let row = rows.first(where: { $0.id == selection }), row.source == .namedSubnet {
                coordinator.addressNames.setSubnetName("", for: row.address)
            }
        }
        .contextMenu(forSelectionType: ResolvedAddressRow.ID.self) { ids in
            if let row = rows.first(where: { ids.contains($0.id) }) {
                Button("Show Sessions for \(row.address)") {
                    show(row)
                }
                if let sessionID = row.sessionID {
                    Button("Show Answering Session") {
                        coordinator.showSessionThatResolved(sessionID)
                    }
                }
                if row.source == .namedSubnet {
                    Divider()
                    Button("Rename Subnet…") {
                        subnetDraft = SubnetNameDraft(block: row.address, name: row.name)
                    }
                    Button("Remove Subnet Name") {
                        coordinator.addressNames.setSubnetName("", for: row.address)
                    }
                }
            }
        } primaryAction: { ids in
            if let row = rows.first(where: { ids.contains($0.id) }) {
                show(row)
            }
        }
    }

    private func footer(rows: [ResolvedAddressRow], total: Int) -> some View {
        let selected = rows.first { $0.id == selection }
        return HStack(spacing: Theme.Metrics.spacingM) {
            Text(rows
                .count == total ? "\(total.formatted()) names" :
                "\(rows.count.formatted()) of \(total.formatted()) names")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
            Spacer()
            Button("Name Subnet…") {
                subnetDraft = SubnetNameDraft(block: "", name: "")
            }
            .help("Name an IPv4 block, so its addresses show as name.host")
            Button("Show Answering Session") {
                if let sessionID = selected?.sessionID {
                    coordinator.showSessionThatResolved(sessionID)
                }
            }
            .disabled(selected?.sessionID == nil)
            .help("Select the DNS or mDNS session whose answer gave this name")
            Button("Show Sessions") {
                if let selected {
                    show(selected)
                }
            }
            .disabled(selected == nil)
            .keyboardShortcut(.defaultAction)
            .help("Show the sessions to or from this address in the main window")
        }
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    /// An address row selects its sessions; a subnet row narrows to its block.
    private func show(_ row: ResolvedAddressRow) {
        if row.source == .namedSubnet {
            coordinator.showSessions(narrowingWith: ResolvedAddresses.term(row))
        } else {
            coordinator.selectIP(row.address)
        }
    }
}

// MARK: - SubnetNameDraft

struct SubnetNameDraft: Identifiable {
    let block: String
    let name: String

    var id: String {
        block
    }
}

// MARK: - SubnetNameSheet

/// Names an IPv4 block for this Project, as Wireshark's `subnets` file does.
private struct SubnetNameSheet: View {
    // MARK: Lifecycle

    init(draft: SubnetNameDraft, save: @escaping (_ block: String, _ name: String) -> Bool) {
        self.draft = draft
        self.save = save
        _block = State(initialValue: draft.block)
        _name = State(initialValue: draft.name)
    }

    // MARK: Internal

    let draft: SubnetNameDraft
    let save: (_ block: String, _ name: String) -> Bool

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            Text(draft.block.isEmpty ? "Name Subnet" : "Rename Subnet")
                .font(Theme.Typography.surfaceTitle)
            Form {
                TextField("Subnet:", text: $block, prompt: Text("192.168.1.0/24"))
                    .font(Theme.Typography.mono)
                TextField("Name:", text: $name, prompt: Text("office"))
            }
            Text(message)
                .font(Theme.Typography.caption)
                .foregroundStyle(isValid || block.isEmpty ? Color.secondary : Color.orange)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save") {
                    if save(block, name) {
                        dismiss()
                    } else {
                        isFull = true
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!isValid)
            }
        }
        .padding(Theme.Metrics.spacingL * 2)
        .frame(width: 380)
    }

    // MARK: Private

    @Environment(\.dismiss) private var dismiss
    @State private var block: String
    @State private var name: String
    @State private var isFull = false

    private var parsed: CIDRValue? {
        SubnetNames.block(block)
    }

    private var isValid: Bool {
        parsed != nil && !name.trimmingCharacters(in: .whitespaces).isEmpty
    }

    private var message: String {
        if isFull {
            return String(localized: "This Project already names \(AddressNameBook.maximumSubnets) subnets.")
        }
        guard let parsed else {
            return String(localized: "Enter an IPv4 block such as 192.168.1.0/24.")
        }
        let example = SubnetName(block: parsed, name: name.trimmingCharacters(in: .whitespaces).isEmpty ? "name" : name)
        // The block's first host (the network address itself for a /31 or /32).
        var first = parsed.network.bytes
        if parsed.prefixLength < 31 {
            first[3] &+= 1
        }
        let sample = SubnetNames.label(first.map(String.init).joined(separator: "."), in: example)
        return String(localized: "Addresses in \(SubnetNames.text(of: parsed)) show as \(sample) and so on.")
    }
}
