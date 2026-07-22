import Foundation

// MARK: - FilterLogicConnector

/// AND/OR connector between adjacent rows in the advanced filter builder.
/// Ported from the sibling app's `FilterLogicConnector`.
enum FilterLogicConnector: String, CaseIterable, Codable, Hashable {
    case and
    case or

    // MARK: Internal

    var displayName: String {
        switch self {
        case .and: "AND"
        case .or: "OR"
        }
    }
}

// MARK: - SessionFilterField

/// The session attribute a `SessionFilterRule` matches against. The Tracexy analog
/// of the sibling app's `FilterField`, retargeted from HTTP transactions to capture sessions.
enum SessionFilterField: String, CaseIterable, Codable, Hashable {
    case host
    case source
    case destination
    case process
    case proto
    case status
    case summary

    // MARK: Internal

    var displayName: String {
        switch self {
        case .host: String(localized: "Host")
        case .source: String(localized: "Source")
        case .destination: String(localized: "Destination")
        case .process: String(localized: "Client")
        case .proto: String(localized: "Protocol")
        case .status: String(localized: "Status")
        case .summary: String(localized: "Summary")
        }
    }

    /// The string drawn from a session for this field, used by the operator.
    func value(in session: SessionSummary) -> String {
        switch self {
        case .host: session.host
        case .source: session.sourceEndpoint
        case .destination: session.destinationEndpoint
        case .process: session.processName ?? ""
        case .proto: session.protocolStack.map(\.label).joined(separator: " ")
        case .status: session.status.label
        case .summary: session.infoSummary
        }
    }
}

// MARK: - SessionFilterOperator

/// Case-insensitive string comparison operators for `SessionFilterRule`.
/// Ported verbatim from the sibling app's `FilterOperator`.
enum SessionFilterOperator: String, CaseIterable, Codable, Hashable {
    case contains
    case `is`
    case startsWith
    case endsWith
    case doesNotContain
    case notEqual
    case regex

    // MARK: Internal

    var displayName: String {
        switch self {
        case .contains: String(localized: "Contains")
        case .is: String(localized: "Is")
        case .startsWith: String(localized: "Starts With")
        case .endsWith: String(localized: "Ends With")
        case .doesNotContain: String(localized: "Does Not Contain")
        case .notEqual: String(localized: "Is Not")
        case .regex: String(localized: "Regex")
        }
    }

    func matches(_ fieldValue: String, against text: String) -> Bool {
        guard !text.isEmpty else {
            return true
        }
        let lowerField = fieldValue.lowercased()
        let lowerText = text.lowercased()
        switch self {
        case .contains: return lowerField.contains(lowerText)
        case .is: return lowerField == lowerText
        case .startsWith: return lowerField.hasPrefix(lowerText)
        case .endsWith: return lowerField.hasSuffix(lowerText)
        case .doesNotContain: return !lowerField.contains(lowerText)
        case .notEqual: return lowerField != lowerText
        case .regex:
            guard let pattern = try? NSRegularExpression(pattern: text, options: .caseInsensitive) else {
                return false
            }
            let range = NSRange(fieldValue.startIndex..., in: fieldValue)
            return pattern.firstMatch(in: fieldValue, range: range) != nil
        }
    }
}

// MARK: - SessionFilterRule

/// A single row in the advanced filter builder: a toggleable predicate combining a
/// target field, comparison operator, match value, and a connector to the prior row.
struct SessionFilterRule: Identifiable, Codable, Hashable {
    var id = UUID()
    var isEnabled: Bool = true
    var connector: FilterLogicConnector = .and
    var field: SessionFilterField = .host
    var filterOperator: SessionFilterOperator = .contains
    var value: String = ""
}

// MARK: - SessionFilterRuleEvaluator

/// Evaluates a list of `SessionFilterRule`s against a session, applying each row's
/// AND/OR connector left-to-right. Ported from the sibling app's `FilterRuleEvaluator`.
enum SessionFilterRuleEvaluator {
    /// The enabled rules with a non-empty value — the only rows that constrain results.
    static func activeRules(in rules: [SessionFilterRule]) -> [SessionFilterRule] {
        rules.filter { $0.isEnabled && !$0.value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
    }

    static func matches(_ session: SessionSummary, rules: [SessionFilterRule]) -> Bool {
        guard let first = rules.first else {
            return true
        }
        var result = matches(session, rule: first)
        for rule in rules.dropFirst() {
            let ruleMatches = matches(session, rule: rule)
            switch rule.connector {
            case .and: result = result && ruleMatches
            case .or: result = result || ruleMatches
            }
        }
        return result
    }

    static func matches(_ session: SessionSummary, rule: SessionFilterRule) -> Bool {
        rule.filterOperator.matches(rule.field.value(in: session), against: rule.value)
    }
}
