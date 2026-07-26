import SwiftUI

// MARK: - FocusSetEditorWindow

/// Native window that edits the focus set currently held in
/// `coordinator.editingFocusSet`. Opened via `openWindow(id:)` from the Focus
/// sidebar. Replaces the old in-sidebar sheet.
struct FocusSetEditorWindow: View {
    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        Group {
            if let editing = coordinator.editingFocusSet {
                FocusSetEditorForm(coordinator: coordinator, draft: editing)
                    .id(editing.id)
            } else {
                ContentUnavailableView(
                    "No Focus Set",
                    systemImage: "scope",
                    description: Text("Choose “New Focus Set” in the Focus sidebar.")
                )
            }
        }
        .frame(minWidth: 560, minHeight: 340)
    }
}

// MARK: - FocusSetEditorForm

/// Names and edits a focus set's filter rules. Reuses the field/operator/value
/// model of the advanced filter builder.
private struct FocusSetEditorForm: View {
    // MARK: Lifecycle

    init(coordinator: MainContentCoordinator, draft: FocusSet) {
        self.coordinator = coordinator
        _draft = State(initialValue: draft)
    }

    // MARK: Internal

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach($draft.rules) { $rule in
                        ruleRow($rule, isFirst: rule.id == draft.rules.first?.id)
                    }
                    Button {
                        draft.rules.append(SessionFilterRule())
                    } label: {
                        Label("Add Rule", systemImage: "plus")
                    }
                    .buttonStyle(.borderless)
                    .controlSize(.small)
                    .disabled(draft.rules.count >= coordinator.policy.maxSessionFilterRules)
                    .help(draft.rules.count >= coordinator.policy.maxSessionFilterRules
                        ? "Filter limit reached — this build allows \(coordinator.policy.maxSessionFilterRules) rules"
                        : "Add a filter rule")
                    .padding(.top, 2)
                }
                .padding(16)
            }
            Divider()
            footer
        }
    }

    // MARK: Private

    @Environment(\.dismiss) private var dismiss

    @State private var draft: FocusSet

    private let coordinator: MainContentCoordinator

    private var trimmedName: String {
        draft.name.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// True when saving would create a set the focus library has no room for.
    /// Editing one that already exists is never blocked.
    private var wouldExceedFocusSetLimit: Bool {
        !coordinator.focusSets.contains { $0.id == draft.id } && !coordinator.canAddFocusSet
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: "scope").font(.system(size: Theme.Icon.xlarge)).foregroundStyle(Color.accentColor)
            TextField("Focus set name", text: $draft.name)
                .textFieldStyle(.roundedBorder)
                .font(Theme.Typography.surfaceTitle)
        }
        .padding(16)
    }

    private var footer: some View {
        HStack {
            if wouldExceedFocusSetLimit {
                Text("\(coordinator.focusSets.count) of \(coordinator.focusGate.maxFocusSets) focus sets used")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Cancel") { close() }
                .keyboardShortcut(.cancelAction)
            Button("Save") {
                var toSave = draft
                if toSave.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    toSave.name = String(localized: "Untitled Focus Set")
                }
                coordinator.saveFocusSet(toSave)
                close()
            }
            .keyboardShortcut(.defaultAction)
            .disabled(trimmedName.isEmpty || wouldExceedFocusSetLimit)
        }
        .padding(16)
    }

    private func ruleRow(_ rule: Binding<SessionFilterRule>, isFirst: Bool) -> some View {
        HStack(spacing: 8) {
            Toggle("", isOn: rule.isEnabled).toggleStyle(.checkbox).labelsHidden()

            if isFirst {
                Text("Where").font(Theme.Typography.bodyMedium)
                    .foregroundStyle(.secondary).frame(width: 74, alignment: .leading)
            } else {
                Picker("", selection: rule.connector) {
                    ForEach(FilterLogicConnector.allCases, id: \.self) { Text($0.displayName).tag($0) }
                }
                .pickerStyle(.segmented).controlSize(.small).labelsHidden().frame(width: 74)
            }

            Picker("", selection: rule.field) {
                ForEach(SessionFilterField.allCases, id: \.self) { Text($0.displayName).tag($0) }
            }
            .labelsHidden().frame(width: 120)

            Picker("", selection: rule.filterOperator) {
                ForEach(SessionFilterOperator.allCases, id: \.self) { Text($0.displayName).tag($0) }
            }
            .labelsHidden().frame(width: 130)

            TextField("Value", text: rule.value).textFieldStyle(.roundedBorder).font(Theme.Typography.body)

            Button {
                draft.rules.removeAll { $0.id == rule.wrappedValue.id }
                if draft.rules.isEmpty {
                    draft.rules = [SessionFilterRule()]
                }
            } label: {
                Image(systemName: "minus").font(.system(size: Theme.Icon.small))
            }
            .buttonStyle(.bordered).controlSize(.small)
            .disabled(draft.rules.count <= 1)
        }
        .opacity(rule.wrappedValue.isEnabled ? 1 : 0.5)
    }

    private func close() {
        coordinator.editingFocusSet = nil
        dismiss()
    }
}
