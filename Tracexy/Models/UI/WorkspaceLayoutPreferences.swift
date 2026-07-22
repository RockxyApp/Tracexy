import Foundation

/// Persists the user's explicit panel choices across launches. A missing value
/// means "never chosen", so a new workspace starts with both panels closed and
/// may reveal the evidence inspector automatically on first selection. Once the
/// user toggles a panel by hand that choice becomes the default for later
/// workspaces and launches. Mirrors the sibling app's `WorkspaceLayoutPreferences`.
struct WorkspaceLayoutPreferences {
    // MARK: Lifecycle

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    // MARK: Internal

    /// The remembered evidence-inspector dock, or `nil` if never toggled.
    var preferredInspectorLayout: InspectorLayout? {
        guard let raw = defaults.string(forKey: Self.inspectorLayoutKey) else {
            return nil
        }
        return InspectorLayout(rawValue: raw)
    }

    /// The remembered Context Dock visibility, or `nil` if never toggled.
    var preferredContextDockVisible: Bool? {
        defaults.object(forKey: Self.contextDockKey) as? Bool
    }

    /// Whether selecting a session may reveal the evidence inspector. `nil`
    /// until the user first hides it by hand.
    var allowsAutomaticInspectorReveal: Bool? {
        defaults.object(forKey: Self.automaticRevealKey) as? Bool
    }

    func rememberInspectorLayout(_ layout: InspectorLayout) {
        defaults.set(layout.rawValue, forKey: Self.inspectorLayoutKey)
    }

    func rememberContextDockVisible(_ isVisible: Bool) {
        defaults.set(isVisible, forKey: Self.contextDockKey)
    }

    func rememberAutomaticInspectorReveal(_ allows: Bool) {
        defaults.set(allows, forKey: Self.automaticRevealKey)
    }

    // MARK: Private

    private static let inspectorLayoutKey = TracexyIdentity.current
        .defaultsKey("workspace.inspectorLayout")
    private static let contextDockKey = TracexyIdentity.current
        .defaultsKey("workspace.contextDockVisible")
    private static let automaticRevealKey = TracexyIdentity.current
        .defaultsKey("workspace.allowsAutomaticInspectorReveal")

    private let defaults: UserDefaults
}
