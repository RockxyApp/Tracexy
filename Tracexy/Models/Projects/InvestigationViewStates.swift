import Foundation

// MARK: - InvestigationViewState

/// Where the investigator left a capture: the selected session and the applied
/// session expression. Restored when the same capture file is opened again.
nonisolated struct InvestigationViewState: Hashable, Codable, Sendable {
    var selectedSessionID: UUID?
    var expression: String?
    var updatedAt: Date

    var isEmpty: Bool {
        selectedSessionID == nil && (expression?.isEmpty ?? true)
    }
}

// MARK: - InvestigationViewStates

/// Per-Project memory of where each capture was left, keyed by the same content
/// identity notes use, so a moved or renamed file is recognised. Bounded to the most
/// recently touched captures and written through to the Project's own suite. Live
/// runs are not remembered: a live capture is never reopened as itself.
@MainActor
final class InvestigationViewStates {
    // MARK: Internal

    static let maximumCaptures = 100

    private(set) var states: [String: InvestigationViewState] = [:]

    func bind(to defaults: UserDefaults) {
        self.defaults = defaults
        let data = defaults.data(forKey: ProjectScopedSettingsKeys.investigationViewStates) ?? Data()
        states = (try? JSONDecoder().decode([String: InvestigationViewState].self, from: data)) ?? [:]
    }

    func state(for scope: InvestigationNoteScope) -> InvestigationViewState? {
        scope.isLiveRun ? nil : states[scope.rawValue]
    }

    /// Record `state` for `scope`; an empty state forgets the capture. Writes only on
    /// change, so a selection that did not move costs nothing.
    func remember(_ state: InvestigationViewState, for scope: InvestigationNoteScope) {
        guard !scope.isLiveRun else {
            return
        }
        if state.isEmpty {
            guard states.removeValue(forKey: scope.rawValue) != nil else {
                return
            }
        } else {
            let previous = states[scope.rawValue]
            guard previous?.selectedSessionID != state.selectedSessionID || previous?.expression != state.expression else {
                return
            }
            states[scope.rawValue] = state
            if states.count > Self.maximumCaptures,
               let oldest = states.min(by: { $0.value.updatedAt < $1.value.updatedAt })?.key
            {
                states.removeValue(forKey: oldest)
            }
        }
        persist()
    }

    // MARK: Private

    private var defaults: UserDefaults?

    private func persist() {
        guard let data = try? JSONEncoder().encode(states) else {
            return
        }
        defaults?.set(data, forKey: ProjectScopedSettingsKeys.investigationViewStates)
    }
}
