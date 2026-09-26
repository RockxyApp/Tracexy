import SwiftUI

// MARK: - ManageInterfacesWindow

/// Capture ▸ Manage Interfaces: which of this Mac's interfaces the capture menus
/// list, the name each is shown by and a note, as Wireshark's Manage Interfaces.
/// A Mac lists many system interfaces (awdl, llw, utun, bridge…) most people never
/// capture on; hiding them keeps the menus short. The interface in use stays listed.
struct ManageInterfacesWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        Group {
            switch tab {
            case .local: localInterfaces
            case .pipes: ManagePipesView()
            }
        }
        .toolbar {
            ToolbarItem(placement: .principal) {
                Picker("Interfaces", selection: $tab) {
                    Text("Local Interfaces").tag(Tab.local)
                    Text("Pipes").tag(Tab.pipes)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
            }
        }
        .frame(minWidth: 620, minHeight: 320)
    }

    // MARK: Private

    private enum Tab: Hashable {
        case local
        case pipes
    }

    private struct Row: Identifiable {
        let interface: NetworkInterface

        var id: String {
            interface.id
        }
    }

    @State private var tab = Tab.local

    @State private var interfaces: [NetworkInterface] = []

    private var preferences: InterfacePreferences {
        InterfacePreferences.shared
    }

    /// In the capture menus' order: by type, then as the system lists them.
    private var rows: [Row] {
        InterfaceCategory.allCases.flatMap { category in
            interfaces.filter { $0.category == category }.map(Row.init)
        }
    }

    private var localInterfaces: some View {
        let rows = rows
        return Table(rows) {
            TableColumn("Show") { row in
                Toggle("Show \(row.interface.id)", isOn: Binding(
                    get: { !preferences.settings.hidden.contains(row.id) },
                    set: { preferences.setShown($0, for: row.id) }
                ))
                .toggleStyle(.checkbox)
                .labelsHidden()
            }
            .width(40)
            TableColumn("Interface") { row in
                Text(row.id).font(Theme.Typography.mono)
            }
            .width(min: 60, ideal: 80)
            TableColumn("Type") { row in
                Text(row.interface.category.title).foregroundStyle(.secondary)
            }
            .width(min: 60, ideal: 90)
            TableColumn("Name") { row in
                InterfaceTextField(
                    label: "Name for \(row.id)", prompt: row.interface.displayName,
                    value: preferences.settings.friendlyNames[row.id]
                ) { preferences.setFriendlyName($0, for: row.id) }
            }
            .width(min: 120, ideal: 160)
            TableColumn("Comment") { row in
                InterfaceTextField(
                    label: "Comment for \(row.id)", prompt: "",
                    value: preferences.settings.comments[row.id]
                ) { preferences.setComment($0, for: row.id) }
            }
            .width(min: 100, ideal: 150)
            TableColumn("Status") { row in
                Text(status(row.interface))
                    .foregroundStyle(row.interface.isUp ? .primary : .secondary)
                    .lineLimit(1)
            }
            .width(min: 100, ideal: 110)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) {
            footer(rows)
        }
        .onAppear { interfaces = NetworkInterfaces.available() }
        .onChange(of: coordinator.interfaceListToken) {
            interfaces = NetworkInterfaces.available()
        }
    }

    private func footer(_ rows: [Row]) -> some View {
        let shown = rows.count { !preferences.settings.hidden.contains($0.id) }
        return HStack(spacing: Theme.Metrics.spacingM) {
            Text("\(shown.formatted()) of \(rows.count.formatted()) shown in the capture menus")
            Spacer()
            Button("Show All") { preferences.showAll() }
                .disabled(preferences.settings.hidden.isEmpty)
            Button("Refresh") { coordinator.refreshInterfaces() }
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    private func status(_ interface: NetworkInterface) -> String {
        guard interface.isUp else {
            return String(localized: "Not connected")
        }
        return interface.ipv4 ?? String(localized: "Connected")
    }
}

// MARK: - ManagePipesView

/// Manage Interfaces ▸ Pipes: named pipes the capture menus list as sources, as
/// Wireshark's Pipes tab. A pipe carries a pcap or pcapng stream from another
/// program, such as `ssh host "tcpdump -U -w -" > /tmp/remote.fifo`.
private struct ManagePipesView: View {
    // MARK: Internal

    var body: some View {
        let pipes = NetworkInterfaces.pipes(preferences.settings)
        Group {
            if pipes.isEmpty {
                ContentUnavailableView(
                    "No Pipes",
                    systemImage: "pipe.and.drop",
                    description: Text("Make a named pipe with mkfifo, add its path below, then send a capture into it.")
                )
            } else {
                Table(pipes, selection: $selection) {
                    TableColumn("Path") { pipe in
                        Text(pipe.id).font(Theme.Typography.mono).lineLimit(1).truncationMode(.middle)
                            .help(pipe.id)
                    }
                    .width(min: 200, ideal: 360)
                    TableColumn("Status") { pipe in
                        Text(pipe.isUp ? "Named pipe" : "Missing")
                            .foregroundStyle(pipe.isUp ? .primary : .secondary)
                    }
                    .width(min: 80, ideal: 100)
                }
                .onDeleteCommand { remove() }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) { footer }
    }

    // MARK: Private

    @State private var draft = ""
    @State private var selection = Set<String>()
    @State private var notice: String?

    private var preferences: InterfacePreferences {
        InterfacePreferences.shared
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            HStack(spacing: Theme.Metrics.spacingM) {
                TextField("Pipe path", text: $draft, prompt: Text(verbatim: "/tmp/remote.fifo"))
                    .labelsHidden()
                    .font(Theme.Typography.mono)
                    .onSubmit(add)
                Button("Add", action: add)
                    .disabled(draft.trimmingCharacters(in: .whitespaces).isEmpty)
                Button("Remove", action: remove)
                    .disabled(selection.isEmpty)
            }
            Text(notice ??
                String(localized: "The capture filter does not apply to a pipe; filter where the capture is taken."))
                .foregroundStyle(notice == nil ? .secondary : Color.orange)
                .lineLimit(2)
        }
        .font(Theme.Typography.caption)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    private func add() {
        notice = preferences.addPipe(draft)
        if notice == nil {
            draft = ""
        }
    }

    private func remove() {
        preferences.removePipes(selection)
        selection = []
    }
}

// MARK: - InterfaceTextField

/// An editable table cell. Each edit is saved cleaned as it is typed, while the
/// field keeps the raw text until editing ends, so trimming never fights the typing.
private struct InterfaceTextField: View {
    // MARK: Internal

    let label: String
    let prompt: String
    let value: String?
    let commit: (String) -> Void

    var body: some View {
        TextField(label, text: $draft, prompt: Text(prompt))
            .labelsHidden()
            .textFieldStyle(.plain)
            .focused($isFocused)
            .onChange(of: draft) { commit(draft) }
            .onAppear { draft = value ?? "" }
            .onChange(of: value) {
                if !isFocused {
                    draft = value ?? ""
                }
            }
    }

    // MARK: Private

    @State private var draft = ""
    @FocusState private var isFocused: Bool
}
