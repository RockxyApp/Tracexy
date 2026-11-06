import SwiftUI

// MARK: - DecodeAsWindow

/// Capture ▸ Decode As…: rules that make a TCP or UDP port's payload decode as a chosen
/// protocol, as Wireshark's Decode As dialog does. Rules belong to the Project and
/// apply to every capture decoded after the change; the open capture is re-read with
/// Reload Capture.
struct DecodeAsWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        @Bindable var settings = coordinator.decodeAs
        Group {
            if settings.showsEnabledProtocols {
                EnabledProtocolsPane(coordinator: coordinator)
            } else {
                rules(settings)
            }
        }
        .tracexyDenseScrollEdge()
        .tracexySafeAreaBar(edge: .top) {
            HStack {
                Picker("Pane", selection: $settings.showsEnabledProtocols) {
                    Text("Decode As").tag(false)
                    Text("Enabled Protocols").tag(true)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
                Spacer(minLength: 0)
            }
            .controlSize(.small)
            .padding(.horizontal, Theme.Metrics.spacingL)
            .padding(.vertical, Theme.Metrics.spacingS)
        }
        .navigationTitle(settings.showsEnabledProtocols ? "Enabled Protocols" : "Decode As")
        .frame(minWidth: 520, minHeight: 320)
    }

    // MARK: Private

    private func rules(_ settings: DecodeAsSettings) -> some View {
        VStack(spacing: 0) {
            if settings.rules.isEmpty, settings.ruleDraft == nil {
                ContentUnavailableView {
                    Label("No Decode As Rules", systemImage: "arrow.triangle.branch")
                } description: {
                    Text(
                        "Add a rule to read a port's traffic as a protocol Tracexy would not recognize there on its own, such as DNS on UDP 5300."
                    )
                } actions: {
                    Button("Add Rule") { addRule() }
                }
            } else {
                List {
                    if let draft = settings.ruleDraft {
                        Section(settings.ruleDraftReplacesExisting ? "Review Replacement Rule" : "Review New Rule") {
                            draftRuleRow(draft)
                        }
                    }
                    if !settings.rules.isEmpty {
                        Section("Project Rules") {
                            ForEach(settings.rules) { rule in
                                ruleRow(rule)
                            }
                        }
                    }
                }
                .listStyle(.inset)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) {
            footer(settings)
        }
    }

    private func ruleRow(_ rule: DecodeAsRule) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Picker("Transport", selection: binding(rule, \.transport)) {
                ForEach(DecodeAsRule.Transport.allCases, id: \.self) { transport in
                    Text(transport.title).tag(transport)
                }
            }
            .labelsHidden()
            .fixedSize()
            Text("port")
                .foregroundStyle(.secondary)
            TextField("Port", value: binding(rule, \.port), format: .number.grouping(.never))
                .textFieldStyle(.roundedBorder)
                .frame(width: 80)
                .accessibilityLabel("Port")
            Text("decodes as")
                .foregroundStyle(.secondary)
            Picker("Protocol", selection: binding(rule, \.decode)) {
                ForEach(DecodeAsProtocol.allCases.filter { $0.transports.contains(rule.transport) }) { proto in
                    Text(proto.title).tag(proto)
                }
            }
            .labelsHidden()
            .fixedSize()
            Spacer()
            if !rule.isValid {
                Image(systemName: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                    .help(
                        "This rule is not applied: choose a port above 0 and a protocol that runs on \(rule.transport.title)."
                    )
                    .accessibilityLabel("Rule not applied")
            }
            Button {
                coordinator.decodeAs.setRules(coordinator.decodeAs.rules.filter { $0.id != rule.id })
            } label: {
                Image(systemName: "minus.circle")
            }
            .buttonStyle(.borderless)
            // HIG Accessibility's macOS default hit target is 28x28pt; the bare
            // symbol alone was under it.
            .frame(width: 28, height: 28)
            .contentShape(Rectangle())
            .help("Remove this rule")
            .accessibilityLabel("Remove rule")
        }
    }

    private func draftRuleRow(_ rule: DecodeAsRule) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Text(rule.transport.title)
                .frame(width: 42, alignment: .leading)
            Text("port")
                .foregroundStyle(.secondary)
            TextField(
                "Port", value: draftBinding(\.port, draftID: rule.id, fallback: rule.port),
                format: .number.grouping(.never)
            )
            .textFieldStyle(.roundedBorder)
            .frame(width: 80)
            .accessibilityLabel("Port")
            Text("decodes as")
                .foregroundStyle(.secondary)
            Picker("Protocol", selection: draftBinding(\.decode, draftID: rule.id, fallback: rule.decode)) {
                ForEach(DecodeAsProtocol.allCases.filter { $0.transports.contains(rule.transport) }) { proto in
                    Text(proto.title).tag(proto)
                }
            }
            .labelsHidden()
            .fixedSize()
            Spacer(minLength: 0)
            if !rule.isValid {
                Image(systemName: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                    .help("Choose a nonzero port and a supported protocol for this transport.")
                    .accessibilityLabel("Rule not valid")
            }
        }
        .help("This proposal is not saved or used until you apply it.")
    }

    private func footer(_ settings: DecodeAsSettings) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            if settings.ruleDraft != nil {
                Button("Discard") { settings.discardRuleDraft() }
                Button("Apply Rule") { settings.applyRuleDraft() }
                    .disabled(!settings.canApplyRuleDraft)
                    .help("Save this rule to the active Project and request Decode Again for an open capture.")
                if settings.ruleDraftCapacityReached {
                    Text("This Project has reached its 64-rule limit. Remove a rule before applying this proposal.")
                        .foregroundStyle(.secondary)
                        .accessibilityLabel("Decode As rule limit reached. Remove a rule before applying.")
                }
            }
            if !settings.rules.isEmpty {
                Button("Add Rule") { addRule() }
                    .disabled(settings.rules.count >= DecodeAsSettings.maximumRules)
                    .help("A Project can have at most 64 Decode As rules.")
            }
            Spacer()
            if settings.needsRedecode {
                Text("Rules apply to captures decoded from now on.")
                    .foregroundStyle(.secondary)
                Button("Decode Again") {
                    coordinator.redecodeActiveSavedCapture()
                }
                .disabled(!coordinator.canRedecodeActiveSavedCapture)
                .help("Read the open capture file again with these rules, like Wireshark's Redissect")
            }
        }
        .font(Theme.Typography.caption)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    private func draftBinding<Value>(
        _ keyPath: WritableKeyPath<DecodeAsRule, Value>, draftID: UUID, fallback: Value
    )
        -> Binding<Value>
    {
        Binding(
            get: {
                guard let draft = coordinator.decodeAs.ruleDraft, draft.id == draftID else {
                    return fallback
                }
                return draft[keyPath: keyPath]
            },
            set: { coordinator.decodeAs.updateRuleDraft($0, at: keyPath, draftID: draftID) }
        )
    }

    private func addRule() {
        coordinator.decodeAs.setRules(
            coordinator.decodeAs.rules + [DecodeAsRule(transport: .udp, port: 5_300, decode: .dns)]
        )
    }

    private func binding<Value>(
        _ rule: DecodeAsRule,
        _ keyPath: WritableKeyPath<DecodeAsRule, Value>
    )
        -> Binding<Value>
    {
        Binding(
            get: { coordinator.decodeAs.rules.first { $0.id == rule.id }?[keyPath: keyPath] ?? rule[keyPath: keyPath] },
            set: { newValue in
                var rules = coordinator.decodeAs.rules
                guard let index = rules.firstIndex(where: { $0.id == rule.id }) else {
                    return
                }
                rules[index][keyPath: keyPath] = newValue
                if !rules[index].decode.transports.contains(rules[index].transport) {
                    rules[index].decode = DecodeAsProtocol.allCases
                        .first { $0.transports.contains(rules[index].transport) }
                        ?? rules[index].decode
                }
                coordinator.decodeAs.setRules(rules)
            }
        )
    }
}
