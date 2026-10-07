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

    private(set) var rules: [DecodeAsRule] = []
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

    func bind(to defaults: UserDefaults) {
        self.defaults = nil
        let stored = defaults.data(forKey: ProjectScopedSettingsKeys.decodeAsRules)
            .flatMap { try? JSONDecoder().decode([DecodeAsRule].self, from: $0) } ?? []
        rules = Array(stored.prefix(Self.maximumRules))
        DecodeAs.setRules(rules)
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
        DecodeAs.setRules(rules)
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

    private static let maximumRules = 64

    @ObservationIgnored private var defaults: UserDefaults?
}
