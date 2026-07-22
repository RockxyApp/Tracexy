import Foundation

/// A saved, named collection of advanced filter rules — Tracexy's analog of
/// the sibling app's Focus Sets. Applying one loads its rules into the active workspace's
/// advanced filter. Persisted as JSON in `UserDefaults`.
struct FocusSet: Identifiable, Codable, Hashable {
    var id = UUID()
    var name: String
    var symbol: String = "scope"
    var rules: [SessionFilterRule]

    /// The rules that actually constrain results (enabled + non-empty value).
    var activeRuleCount: Int {
        SessionFilterRuleEvaluator.activeRules(in: rules).count
    }

    /// A one-line subtitle summarizing the first meaningful rule, e.g.
    /// "Client contains Chrome" — mirrors the sibling app's focus-set subtitles.
    var subtitle: String {
        guard let rule = SessionFilterRuleEvaluator.activeRules(in: rules).first else {
            return String(localized: "No active rules")
        }
        return "\(rule.field.displayName) \(rule.filterOperator.displayName.lowercased()) \(rule.value)"
    }
}
