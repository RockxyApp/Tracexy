import Foundation
import Observation

// MARK: - DecodeAsSettings

/// Capture ▸ Decode As…: the active Project's port → protocol rules, persisted in its
/// settings suite and pushed to the decoder's process-wide table whenever they change
/// or the Project changes.
@MainActor
@Observable
final class DecodeAsSettings {
    // MARK: Internal

    static let maximumRules = 64

    private(set) var rules: [DecodeAsRule] = []
    /// A packet-derived Decode As proposal. It is intentionally not persisted or
    /// published to the decoder until the user applies it.
    private(set) var ruleDraft: DecodeAsRule?
    /// Analyze ▸ Enabled Protocols: the protocols the decoder leaves unrecognized.
    private(set) var disabledProtocols: Set<ProtocolKind> = []

    /// Whether changes reach the process-wide decoder; off for a test's own instance,
    /// which must not change what parallel tests decode.
    @ObservationIgnored var publishesToDecoder = true

    /// Which of the window's two panes shows: Decode As rules or Enabled Protocols.
    var showsEnabledProtocols = false

    /// Whether the rules changed since the open capture was decoded, so the window can
    /// offer to reload it (Wireshark's Redissect).
    var needsRedecode = false

    var canApplyRuleDraft: Bool {
        guard let ruleDraft, ruleDraft.isValid else {
            return false
        }
        let replacesExisting = rules.contains {
            $0.transport == ruleDraft.transport && $0.port == ruleDraft.port
        }
        return replacesExisting || rules.count < Self.maximumRules
    }

    var ruleDraftCapacityReached: Bool {
        guard ruleDraft?.isValid == true, !ruleDraftReplacesExisting else {
            return false
        }
        return rules.count >= Self.maximumRules
    }

    var ruleDraftReplacesExisting: Bool {
        guard let ruleDraft else {
            return false
        }
        return rules.contains { $0.transport == ruleDraft.transport && $0.port == ruleDraft.port }
    }

    func prepareRuleDraft(transport: DecodeAsRule.Transport, port: UInt16) {
        guard let initialProtocol = DecodeAsProtocol.allCases.first(where: { $0.transports.contains(transport) }) else {
            return
        }
        ruleDraft = DecodeAsRule(transport: transport, port: port, decode: initialProtocol)
        showsEnabledProtocols = false
    }

    func updateRuleDraft<Value>(
        _ value: Value,
        at keyPath: WritableKeyPath<DecodeAsRule, Value>,
        draftID: UUID
    ) {
        guard var draft = ruleDraft, draft.id == draftID else {
            return
        }
        draft[keyPath: keyPath] = value
        ruleDraft = draft
    }

    func discardRuleDraft() {
        ruleDraft = nil
    }

    func applyRuleDraft() {
        guard let ruleDraft, canApplyRuleDraft else {
            return
        }
        var updatedRules = rules
        if let index = updatedRules.firstIndex(where: {
            $0.transport == ruleDraft.transport && $0.port == ruleDraft.port
        }) {
            updatedRules[index] = ruleDraft
        } else {
            updatedRules.append(ruleDraft)
        }
        setRules(updatedRules)
        self.ruleDraft = nil
    }

    func bind(to defaults: UserDefaults) {
        self.defaults = nil
        ruleDraft = nil
        let stored = defaults.data(forKey: ProjectScopedSettingsKeys.decodeAsRules)
            .flatMap { try? JSONDecoder().decode([DecodeAsRule].self, from: $0) } ?? []
        rules = Array(stored.prefix(Self.maximumRules))
        if publishesToDecoder {
            DecodeAs.setRules(rules)
        }
        disabledProtocols = Set((defaults.stringArray(forKey: ProjectScopedSettingsKeys.disabledProtocols) ?? [])
            .compactMap(ProtocolKind.init(rawValue:)))
        if publishesToDecoder {
            DecodeAs.setDisabled(disabledProtocols)
        }
        needsRedecode = false
        self.defaults = defaults
    }

    func setRules(_ newRules: [DecodeAsRule]) {
        rules = Array(newRules.prefix(Self.maximumRules))
        if publishesToDecoder {
            DecodeAs.setRules(rules)
        }
        needsRedecode = true
        if let data = try? JSONEncoder().encode(rules) {
            defaults?.set(data, forKey: ProjectScopedSettingsKeys.decodeAsRules)
        }
    }

    func setEnabled(_ enabled: Bool, _ kind: ProtocolKind) {
        var next = disabledProtocols
        if enabled {
            next.remove(kind)
        } else {
            next.insert(kind)
        }
        setDisabled(next)
    }

    func setDisabled(_ kinds: Set<ProtocolKind>) {
        guard kinds != disabledProtocols else {
            return
        }
        disabledProtocols = kinds
        if publishesToDecoder {
            DecodeAs.setDisabled(kinds)
        }
        needsRedecode = true
        defaults?.set(kinds.map(\.rawValue).sorted(), forKey: ProjectScopedSettingsKeys.disabledProtocols)
    }

    // MARK: Private

    @ObservationIgnored private var defaults: UserDefaults?
}
