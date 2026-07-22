import SwiftUI

// MARK: - StructuredFilterBar

/// Multi-rule advanced filter builder shown below the category tabs when the footer
/// "Filter" button is toggled. Each row is an independently-toggleable predicate
/// (field · operator · value) joined to its neighbour by an AND/OR connector. The
/// first row reads "Where" and carries the Presets menu. Ported from the sibling app's
/// `AdvancedFilterBar`, retargeted to capture sessions.
///
/// Rows are iterated as `ForEach($rules)` so each row owns a *stable* element
/// binding tracked by id — adding/removing a row never leaves a view bound to a
/// stale index (which would trap on the array subscript).
struct StructuredFilterBar: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let workspace = coordinator.activeWorkspace
        let rules = Binding(
            get: { workspace.filterRules },
            set: { workspace.filterRules = $0 }
        )
        VStack(spacing: 0) {
            ForEach(rules) { $rule in
                filterRow(rule: $rule, isFirst: rule.id == workspace.filterRules.first?.id, workspace: workspace)
            }
            shortcutsHint
        }
        .padding(.bottom, 2)
        .background(Color(nsColor: .windowBackgroundColor))
        .overlay(alignment: .bottom) { Divider() }
        .fixedSize(horizontal: false, vertical: true)
    }

    // MARK: Private

    private static let enableToggleWidth: CGFloat = 22
    private static let connectorWidth: CGFloat = 78

    private var shortcutsHint: some View {
        HStack(spacing: 12) {
            Text("New: ⌘N")
            Text("Remove: ⌥⌘N")
            Text("On/Off: ⌘B")
            Text("Hide: ESC")
        }
        .font(Theme.Typography.micro)
        .foregroundStyle(Color(nsColor: .tertiaryLabelColor))
        .padding(.horizontal, 12)
        .padding(.top, 4)
        .padding(.bottom, 6)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func filterRow(rule: Binding<SessionFilterRule>, isFirst: Bool, workspace: WorkspaceState) -> some View {
        HStack(spacing: 10) {
            Toggle("", isOn: rule.isEnabled)
                .toggleStyle(.checkbox)
                .labelsHidden()
                .frame(width: Self.enableToggleWidth, alignment: .center)

            if isFirst {
                Text("Where")
                    .font(Theme.Typography.bodyMedium)
                    .foregroundStyle(.secondary)
                    .frame(width: Self.connectorWidth, alignment: .leading)
            } else {
                Picker("", selection: rule.connector) {
                    ForEach(FilterLogicConnector.allCases, id: \.self) { connector in
                        Text(connector.displayName).tag(connector)
                    }
                }
                .pickerStyle(.segmented)
                .controlSize(.small)
                .labelsHidden()
                .frame(width: Self.connectorWidth)
            }

            Picker("", selection: rule.field) {
                ForEach(SessionFilterField.allCases, id: \.self) { field in
                    Text(field.displayName).tag(field)
                }
            }
            .labelsHidden()
            .frame(width: 130)

            Picker("", selection: rule.filterOperator) {
                ForEach(SessionFilterOperator.allCases, id: \.self) { op in
                    Text(op.displayName).tag(op)
                }
            }
            .labelsHidden()
            .frame(width: 138)

            TextField("Text", text: rule.value)
                .textFieldStyle(.roundedBorder)
                .font(Theme.Typography.body)

            Button {
                removeRule(workspace, id: rule.wrappedValue.id)
            } label: {
                Image(systemName: "minus").font(.system(size: Theme.Icon.small))
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .disabled(workspace.filterRules.count <= 1)

            Button {
                addRule(workspace, afterID: rule.wrappedValue.id)
            } label: {
                Image(systemName: "plus").font(.system(size: Theme.Icon.small))
            }
            .buttonStyle(.bordered)
            .controlSize(.small)

            if isFirst {
                presetMenu(workspace)
            }
        }
        .padding(.horizontal, 12)
        .padding(.top, isFirst ? 8 : 4)
        .frame(minHeight: 30)
        .opacity(rule.wrappedValue.isEnabled ? 1.0 : 0.5)
    }

    private func presetMenu(_ workspace: WorkspaceState) -> some View {
        Menu {
            ForEach(StructuredFilterPreset.builtIns) { preset in
                Button {
                    workspace.filterRules = preset.rules
                } label: {
                    Label(preset.name, systemImage: preset.symbol)
                }
            }
            Divider()
            Button(role: .destructive) {
                workspace.filterRules = [SessionFilterRule()]
            } label: {
                Label("Clear Rules", systemImage: "trash")
            }
        } label: {
            Label("Presets", systemImage: "chevron.down").labelStyle(.titleAndIcon)
        }
        .menuStyle(.borderlessButton)
        .controlSize(.small)
        .fixedSize()
    }

    private func addRule(_ workspace: WorkspaceState, afterID id: UUID) {
        guard let index = workspace.filterRules.firstIndex(where: { $0.id == id }) else {
            workspace.filterRules.append(SessionFilterRule())
            return
        }
        workspace.filterRules.insert(SessionFilterRule(), at: index + 1)
    }

    private func removeRule(_ workspace: WorkspaceState, id: UUID) {
        guard workspace.filterRules.count > 1 else {
            return
        }
        workspace.filterRules.removeAll { $0.id == id }
        // Never leave the builder empty — keep one editable row.
        if workspace.filterRules.isEmpty {
            workspace.filterRules = [SessionFilterRule()]
        }
    }
}

// MARK: - StructuredFilterPreset

/// A named, ready-made set of filter rows offered in the Presets menu.
struct StructuredFilterPreset: Identifiable {
    static let builtIns: [StructuredFilterPreset] = [
        StructuredFilterPreset(
            name: String(localized: "Errors Only"),
            symbol: "exclamationmark.triangle",
            rules: [SessionFilterRule(field: .status, filterOperator: .is, value: "Error")]
        ),
        StructuredFilterPreset(
            name: String(localized: "Secure (TLS)"),
            symbol: "lock",
            rules: [SessionFilterRule(field: .proto, filterOperator: .contains, value: "TLS")]
        ),
        StructuredFilterPreset(
            name: String(localized: "DNS Lookups"),
            symbol: "magnifyingglass",
            rules: [SessionFilterRule(field: .proto, filterOperator: .contains, value: "DNS")]
        ),
    ]

    let id = UUID()
    let name: String
    let symbol: String
    let rules: [SessionFilterRule]
}
