import SwiftUI

// MARK: - StructuredFilterBar

/// Multi-rule advanced filter builder shown below the category/search rows when
/// the "Add Filter" / disclosure control reveals it. Each row is an
/// independently-toggleable predicate (field · operator · value) joined to its
/// neighbour by an AND/OR connector, evaluated strictly left-to-right. The first
/// row reads "Where" and carries the Presets menu.
///
/// Rows are iterated as `ForEach($rules)` so each row owns a *stable* element
/// binding tracked by id — adding/removing a row never leaves a view bound to a
/// stale index (which would trap on the array subscript).
///
/// The row builds itself two ways via `ViewThatFits`: a single line when the
/// center pane is wide, and a two-line compact layout when it is narrow (~420pt),
/// so every control stays operable without horizontal clipping. Once several
/// rows accumulate the list scrolls rather than growing without bound.
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
            rowsViewport(rules: rules, workspace: workspace)
        }
        .padding(.bottom, 6)
        .background(Color(nsColor: .windowBackgroundColor))
        .overlay(alignment: .bottom) { Divider() }
    }

    // MARK: Private

    private static let enableToggleWidth: CGFloat = 22
    private static let connectorWidth: CGFloat = 78
    private static let fieldWidth: CGFloat = 130
    private static let operatorWidth: CGFloat = 138
    /// Above this many rows the builder scrolls instead of growing taller.
    private static let visibleRowCap = 5
    private static let viewportMaxHeight: CGFloat = 240

    private var maxRules: Int {
        coordinator.policy.maxSessionFilterRules
    }

    /// The rows, wrapped in a bounded scroll viewport once they pass the cap so
    /// the builder never pushes the session table off-screen.
    @ViewBuilder
    private func rowsViewport(rules: Binding<[SessionFilterRule]>, workspace: WorkspaceState) -> some View {
        let rows = VStack(spacing: 0) {
            ForEach(rules) { $rule in
                filterRow(rule: $rule, isFirst: rule.id == workspace.filterRules.first?.id, workspace: workspace)
            }
        }
        if workspace.filterRules.count > Self.visibleRowCap {
            ScrollView(.vertical, showsIndicators: true) {
                rows
            }
            .frame(maxHeight: Self.viewportMaxHeight)
        } else {
            rows
        }
    }

    private func filterRow(rule: Binding<SessionFilterRule>, isFirst: Bool, workspace: WorkspaceState) -> some View {
        ViewThatFits(in: .horizontal) {
            singleLineRow(rule: rule, isFirst: isFirst, workspace: workspace)
            compactRow(rule: rule, isFirst: isFirst, workspace: workspace)
        }
        .padding(.horizontal, 12)
        .padding(.top, isFirst ? 8 : 4)
        .frame(minHeight: 30)
        .opacity(rule.wrappedValue.isEnabled ? 1.0 : 0.5)
    }

    // MARK: Row layouts

    private func singleLineRow(rule: Binding<SessionFilterRule>, isFirst: Bool, workspace: WorkspaceState)
        -> some View
    {
        HStack(spacing: 10) {
            enableToggle(rule)
            connector(rule, isFirst: isFirst)
            fieldPicker(rule)
            operatorPicker(rule)
            valueField(rule)
            removeButton(rule, workspace: workspace)
            addButton(rule, workspace: workspace)
            if isFirst {
                presetMenu(workspace)
            }
        }
    }

    /// Two-line fallback for a narrow center pane: the predicate structure sits
    /// on the first line, the value + row actions on the second.
    private func compactRow(rule: Binding<SessionFilterRule>, isFirst: Bool, workspace: WorkspaceState)
        -> some View
    {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                enableToggle(rule)
                connector(rule, isFirst: isFirst)
                fieldPicker(rule)
                operatorPicker(rule)
            }
            HStack(spacing: 8) {
                valueField(rule)
                removeButton(rule, workspace: workspace)
                addButton(rule, workspace: workspace)
                if isFirst {
                    presetMenu(workspace)
                }
            }
        }
    }

    // MARK: Row controls

    private func enableToggle(_ rule: Binding<SessionFilterRule>) -> some View {
        Toggle("", isOn: rule.isEnabled)
            .toggleStyle(.checkbox)
            .labelsHidden()
            .frame(width: Self.enableToggleWidth, alignment: .center)
            .help(rule.wrappedValue.isEnabled ? "Rule is on" : "Rule is off")
            .accessibilityLabel("Enable rule")
    }

    @ViewBuilder
    private func connector(_ rule: Binding<SessionFilterRule>, isFirst: Bool) -> some View {
        if isFirst {
            Text("Where")
                .font(Theme.Typography.bodyMedium)
                .foregroundStyle(.secondary)
                .frame(width: Self.connectorWidth, alignment: .leading)
                .accessibilityHidden(true)
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
            .accessibilityLabel("Row connector")
        }
    }

    private func fieldPicker(_ rule: Binding<SessionFilterRule>) -> some View {
        Picker("", selection: rule.field) {
            ForEach(SessionFilterField.allCases, id: \.self) { field in
                Text(field.displayName).tag(field)
            }
        }
        .labelsHidden()
        .frame(width: Self.fieldWidth)
        .accessibilityLabel("Filter field")
    }

    private func operatorPicker(_ rule: Binding<SessionFilterRule>) -> some View {
        Picker("", selection: rule.filterOperator) {
            ForEach(SessionFilterOperator.allCases, id: \.self) { op in
                Text(op.displayName).tag(op)
            }
        }
        .labelsHidden()
        .frame(width: Self.operatorWidth)
        .accessibilityLabel("Filter operator")
    }

    private func valueField(_ rule: Binding<SessionFilterRule>) -> some View {
        TextField("Text", text: rule.value)
            .textFieldStyle(.roundedBorder)
            .font(Theme.Typography.body)
            .accessibilityLabel("Filter value")
    }

    private func removeButton(_ rule: Binding<SessionFilterRule>, workspace: WorkspaceState) -> some View {
        Button {
            removeRule(workspace, id: rule.wrappedValue.id)
        } label: {
            Image(systemName: "minus").font(.system(size: Theme.Icon.small))
        }
        .buttonStyle(.bordered)
        .controlSize(.small)
        .disabled(workspace.filterRules.count <= 1)
        .help("Remove this rule")
        .accessibilityLabel("Remove rule")
    }

    private func addButton(_ rule: Binding<SessionFilterRule>, workspace: WorkspaceState) -> some View {
        let atCap = workspace.filterRules.count >= maxRules
        return Button {
            addRule(workspace, afterID: rule.wrappedValue.id)
        } label: {
            Image(systemName: "plus").font(.system(size: Theme.Icon.small))
        }
        .buttonStyle(.bordered)
        .controlSize(.small)
        .disabled(atCap)
        .help(atCap
            ? "Filter limit reached — this build allows \(maxRules) rules"
            : "Add a rule below this one")
        .accessibilityLabel("Add rule")
    }

    private func presetMenu(_ workspace: WorkspaceState) -> some View {
        Menu {
            ForEach(StructuredFilterPreset.builtIns) { preset in
                Button {
                    workspace.filterRules = SessionFilterRule.normalized(preset.rules, limit: maxRules)
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
        .help("Load a ready-made set of filter rules")
        .accessibilityLabel("Filter presets")
    }

    /// Inserts a blank rule after `id`, unless the capacity cap is already met.
    private func addRule(_ workspace: WorkspaceState, afterID id: UUID) {
        guard workspace.filterRules.count < maxRules else {
            return
        }
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
