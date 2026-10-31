import SwiftUI

// MARK: - FrameAddressNaming

/// The distinct, canonical IP endpoints that can be named from one frame row.
nonisolated enum FrameAddressNaming {
    static func addresses(source: String, destination: String) -> [String] {
        Set([source, destination].compactMap { IPAddressValue(parsing: $0)?.compressedText }).sorted()
    }
}

// MARK: - FrameAddressNameTarget

struct FrameAddressNameTarget: Identifiable {
    let id: String
    let projectID: UUID
}

// MARK: - FrameAddressNameMenu

struct FrameAddressNameMenu: View {
    let row: CaptureFrameRow

    @Bindable var addressNames: AddressNameBook
    @Binding var target: FrameAddressNameTarget?
    @Bindable var projectStore: ProjectStore

    var body: some View {
        let addresses = FrameAddressNaming.addresses(source: row.source, destination: row.destination)
        if !addresses.isEmpty {
            Menu {
                ForEach(addresses, id: \.self) { address in
                    Button(
                        addressNames.name(for: address).map { "\(address) (\($0))…" } ?? "\(address)…"
                    ) {
                        target = FrameAddressNameTarget(id: address, projectID: projectStore.activeProjectID)
                    }
                }
            } label: {
                Label("Name Address", systemImage: "character.cursor.ibeam")
            }
        }
    }
}

// MARK: - FrameAddressNameSheet

struct FrameAddressNameSheet: View {
    // MARK: Lifecycle

    init(
        address: String,
        addressNames: AddressNameBook,
        projectStore: ProjectStore,
        expectedProjectID: UUID,
        onDone: @escaping () -> Void
    ) {
        self.address = address
        self.addressNames = addressNames
        self.projectStore = projectStore
        self.expectedProjectID = expectedProjectID
        self.onDone = onDone
        _name = State(initialValue: addressNames.name(for: address) ?? "")
    }

    // MARK: Internal

    @Bindable var addressNames: AddressNameBook
    @Bindable var projectStore: ProjectStore

    let address: String
    let expectedProjectID: UUID
    let onDone: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            Text("Name Address")
                .font(Theme.Typography.bodyEmphasis)
            Text(address)
                .font(Theme.Typography.mono)
                .textSelection(.enabled)
            let conflicts = addressNames.conflictingNames(for: address)
            if !conflicts.isEmpty {
                Text(
                    "Saved names conflict for this address: \(conflicts.joined(separator: ", ")). Saving a new name or removing it will resolve this conflict."
                )
                .font(Theme.Typography.caption)
                .foregroundStyle(.orange)
            }
            if !addressNames.canEditNames {
                Text(
                    "The saved address-name data could not be read. It has been preserved; editing is unavailable until it is restored."
                )
                .font(Theme.Typography.caption)
                .foregroundStyle(.red)
            }
            TextField("Name, for example NAS", text: $name)
                .textFieldStyle(.roundedBorder)
                .disabled(!addressNames.canEditNames)
            Text("This name is local to the active Project and appears where the address is the session's only name.")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
            if let saveError {
                Text(saveError)
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.red)
            }
            HStack {
                if addressNames.name(for: address) != nil {
                    Button("Remove Name", role: .destructive) {
                        guard projectStore.activeProjectID == expectedProjectID else {
                            onDone()
                            return
                        }
                        addressNames.setName("", for: address)
                        onDone()
                    }
                    .disabled(!addressNames.canEditNames)
                }
                Spacer()
                Button("Cancel", role: .cancel, action: onDone)
                Button("Save") {
                    guard projectStore.activeProjectID == expectedProjectID else {
                        onDone()
                        return
                    }
                    if addressNames.setName(name, for: address) {
                        onDone()
                    } else {
                        saveError = "The Project address book is full. Remove a name before adding another."
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!addressNames.canEditNames)
            }
        }
        .padding(Theme.Metrics.spacingL)
        .frame(minWidth: 420)
        .onChange(of: projectStore.activeProjectID) { _, _ in onDone() }
    }

    // MARK: Private

    @State private var name: String
    @State private var saveError: String?
}
