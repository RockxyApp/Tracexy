import SwiftUI

// MARK: - FrameFilterPresetManagerSheet

/// Transactional editor for one Project's saved packet-level filters.
struct FrameFilterPresetManagerSheet: View {
    // MARK: Lifecycle

    init(library: FrameFilterPresetLibrary, expectedProjectID: UUID?) {
        self.library = library
        self.expectedProjectID = expectedProjectID
        _filters = State(initialValue: library.filters)
    }

    // MARK: Internal

    let library: FrameFilterPresetLibrary
    let expectedProjectID: UUID?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Saved Frame Filters")
                .font(Theme.Typography.surfaceTitle)
            Text(
                "These Tracexy Frame Expressions belong to this Project. Choosing one edits the draft; Apply still runs it."
            )
            .foregroundStyle(.secondary)
            List {
                ForEach($filters) { $filter in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            TextField("Name", text: $filter.name)
                                .frame(width: 190)
                                .focused($focusedFilterName, equals: filter.id)
                                .accessibilityIdentifier("frameFilterPreset.name.\(filter.id.uuidString)")
                            Spacer()
                            Button("Remove", systemImage: "minus.circle", role: .destructive) {
                                remove(filter.id)
                            }
                            .labelStyle(.iconOnly)
                            .accessibilityLabel("Remove \(filter.name)")
                        }
                        TextField("Frame Expression", text: $filter.expression)
                            .textFieldStyle(.roundedBorder)
                            .accessibilityIdentifier("frameFilterPreset.expression.\(filter.id.uuidString)")
                        if !FrameFilterPresetLibrary.isValid(filter) || !isNameUnique(filter) {
                            Text("Enter a unique name and a valid Tracexy Frame Expression.")
                                .font(Theme.Typography.micro)
                                .foregroundStyle(.orange)
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
            .listStyle(.inset)
            if let message {
                Text(message).foregroundStyle(.red)
            }
            HStack {
                Button("Add Filter", systemImage: "plus") { add() }
                    .disabled(filters.count >= FrameFilterPresetLibrary.maximumFilters)
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save") { save() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!isValid)
                    .accessibilityIdentifier("frameFilterPresets.save")
            }
        }
        .padding(20)
        .frame(minWidth: 680, minHeight: 460)
        // Typing starts in the first filter's name rather than nowhere.
        .task { focusedFilterName = filters.first?.id }
    }

    // MARK: Private

    @Environment(\.dismiss) private var dismiss
    @State private var filters: [SavedFrameFilter]
    @State private var message: String?
    @FocusState private var focusedFilterName: UUID?

    private var isValid: Bool {
        filters.count <= FrameFilterPresetLibrary.maximumFilters
            && filters.allSatisfy(FrameFilterPresetLibrary.isValid)
            && Set(filters.map { $0.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() })
            .count == filters.count
    }

    private func add() {
        let names = Set(filters.map { $0.name.lowercased() })
        var suffix = 1
        var name = "New Filter"
        while names.contains(name.lowercased()) {
            suffix += 1
            name = "New Filter \(suffix)"
        }
        filters.append(SavedFrameFilter(name: name, expression: "tcp.rst"))
    }

    private func isNameUnique(_ filter: SavedFrameFilter) -> Bool {
        filters.filter { $0.id != filter.id }
            .allSatisfy { $0.name.caseInsensitiveCompare(filter.name) != .orderedSame }
    }

    private func remove(_ id: UUID) {
        filters.removeAll { $0.id == id }
    }

    private func save() {
        let cleaned = filters.map {
            SavedFrameFilter(
                id: $0.id,
                name: $0.name.trimmingCharacters(in: .whitespacesAndNewlines),
                expression: $0.expression.trimmingCharacters(in: .whitespacesAndNewlines)
            )
        }
        guard library.replaceAll(cleaned, expectedProjectID: expectedProjectID) else {
            message = "This Project changed or the filter list could not be saved."
            return
        }
        dismiss()
    }
}
