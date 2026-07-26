import Foundation

// MARK: - FilterLogicConnector

/// AND/OR connector between adjacent rows in the advanced filter builder.
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

/// The session attribute a `SessionFilterRule` matches against, targeting capture sessions.
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
    nonisolated func value(in session: SessionSummary) -> String {
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

// MARK: - SessionSearchField

/// The scope of the main session search box. Distinct from ``SessionFilterField``
/// because it adds an "All Fields" default that spans several session attributes
/// at once. These are strictly Tracexy fields — there is no URL, method, status
/// code, header, body, or proxy concept here.
enum SessionSearchField: String, CaseIterable, Identifiable, Codable, Hashable {
    case allFields
    case host
    case client
    case proto
    case source
    case destination
    case summary

    // MARK: Internal

    nonisolated var id: String {
        rawValue
    }

    var displayName: String {
        switch self {
        case .allFields: String(localized: "All Fields")
        case .host: String(localized: "Host")
        case .client: String(localized: "Client")
        case .proto: String(localized: "Protocol")
        case .source: String(localized: "Source")
        case .destination: String(localized: "Destination")
        case .summary: String(localized: "Summary")
        }
    }

    /// The lowercased text a free-text query is matched against for this scope.
    /// "All Fields" spans host, process, protocol labels, both endpoints, the
    /// info summary, and DNS answers — the same breadth the list already shows.
    nonisolated func haystack(in session: SessionSummary) -> String {
        switch self {
        case .allFields:
            ([
                session.host,
                session.processName ?? "",
                session.sourceEndpoint,
                session.destinationEndpoint,
                session.infoSummary,
            ]
                + session.protocolStack.map(\.label)
                + session.dnsAnswers)
                .joined(separator: " ")
                .lowercased()
        case .host: session.host.lowercased()
        case .client: (session.processName ?? "").lowercased()
        case .proto: session.protocolStack.map(\.label).joined(separator: " ").lowercased()
        case .source: session.sourceEndpoint.lowercased()
        case .destination: session.destinationEndpoint.lowercased()
        case .summary: session.infoSummary.lowercased()
        }
    }
}

// MARK: - SessionFilterOperator

/// Case-insensitive string comparison operators for `SessionFilterRule`.
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

    nonisolated func matches(_ fieldValue: String, against text: String) -> Bool {
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
    // MARK: Lifecycle

    nonisolated init(
        id: UUID = UUID(),
        isEnabled: Bool = true,
        connector: FilterLogicConnector = .and,
        field: SessionFilterField = .host,
        filterOperator: SessionFilterOperator = .contains,
        value: String = ""
    ) {
        self.id = id
        self.isEnabled = isEnabled
        self.connector = connector
        self.field = field
        self.filterOperator = filterOperator
        self.value = value
    }

    // MARK: Internal

    var id = UUID()
    var isEnabled: Bool = true
    var connector: FilterLogicConnector = .and
    var field: SessionFilterField = .host
    var filterOperator: SessionFilterOperator = .contains
    var value: String = ""

    /// Clamps a rule list to `limit` rows and guarantees at least one editable
    /// row remains. Used whenever an external source (a Focus Set, a preset)
    /// loads rules into a workspace: an imported list must never exceed the
    /// build's capacity, and the builder must never be left with zero rows.
    nonisolated static func normalized(_ rules: [SessionFilterRule], limit: Int) -> [SessionFilterRule] {
        let bounded = Array(rules.prefix(max(1, limit)))
        return bounded.isEmpty ? [SessionFilterRule()] : bounded
    }
}

// MARK: - SessionFilterRuleEvaluator

/// Evaluates a list of `SessionFilterRule`s against a session, applying each row's
/// AND/OR connector left-to-right.
///
/// Two entry points, on purpose:
///   * ``matches(_:rules:)`` is the convenient one-shot API the tests and any
///     one-off caller use.
///   * ``prepared(_:)`` compiles each regex rule exactly once, up front, and is
///     what filtering a whole `visibleSessions` pass uses so a pattern is not
///     recompiled per session.
enum SessionFilterRuleEvaluator {
    /// The enabled rules with a non-empty value — the only rows that constrain results.
    nonisolated static func activeRules(in rules: [SessionFilterRule]) -> [SessionFilterRule] {
        rules.filter { $0.isEnabled && !$0.value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
    }

    /// Compiles `rules` once so a batch of sessions can be tested without
    /// re-parsing any regex pattern per session.
    nonisolated static func prepared(_ rules: [SessionFilterRule]) -> PreparedRules {
        PreparedRules(rules: rules)
    }

    nonisolated static func matches(_ session: SessionSummary, rules: [SessionFilterRule]) -> Bool {
        prepared(rules).matches(session)
    }

    nonisolated static func matches(_ session: SessionSummary, rule: SessionFilterRule) -> Bool {
        prepared([rule]).matches(session)
    }
}

// MARK: - PreparedRules

/// A rule list with its regex patterns already compiled, applying each row's
/// AND/OR connector left-to-right. Left-to-right evaluation (no operator
/// precedence) is a saved-Focus-Set compatibility guarantee — do not reorder it.
struct PreparedRules {
    // MARK: Lifecycle

    nonisolated init(rules: [SessionFilterRule]) {
        compiled = SessionFilterRuleEvaluator.activeRules(in: rules).map(CompiledRule.init)
    }

    // MARK: Internal

    nonisolated func matches(_ session: SessionSummary) -> Bool {
        guard let first = compiled.first else {
            return true
        }
        var result = first.matches(session)
        for rule in compiled.dropFirst() {
            let ruleMatches = rule.matches(session)
            switch rule.connector {
            case .and: result = result && ruleMatches
            case .or: result = result || ruleMatches
            }
        }
        return result
    }

    // MARK: Private

    /// One rule with its regex pre-compiled. An invalid regex compiles to `nil`
    /// and is remembered as invalid so it safely matches *no* session rather than
    /// trapping or being treated as an unconstrained match.
    private struct CompiledRule {
        // MARK: Lifecycle

        nonisolated init(_ rule: SessionFilterRule) {
            connector = rule.connector
            field = rule.field
            filterOperator = rule.filterOperator
            value = rule.value
            if rule.filterOperator == .regex,
               !rule.value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            {
                if let expression = try? NSRegularExpression(pattern: rule.value, options: .caseInsensitive) {
                    regex = expression
                    isInvalidRegex = false
                } else {
                    regex = nil
                    isInvalidRegex = true
                }
            } else {
                regex = nil
                isInvalidRegex = false
            }
        }

        // MARK: Internal

        let connector: FilterLogicConnector

        nonisolated func matches(_ session: SessionSummary) -> Bool {
            let fieldValue = field.value(in: session)
            guard filterOperator == .regex else {
                return filterOperator.matches(fieldValue, against: value)
            }
            if isInvalidRegex {
                return false
            }
            guard let regex else {
                // Empty pattern — mirrors the operator's "empty text = no constraint" rule.
                return true
            }
            let range = NSRange(fieldValue.startIndex..., in: fieldValue)
            return regex.firstMatch(in: fieldValue, range: range) != nil
        }

        // MARK: Private

        private let field: SessionFilterField
        private let filterOperator: SessionFilterOperator
        private let value: String
        private let regex: NSRegularExpression?
        private let isInvalidRegex: Bool
    }

    private let compiled: [CompiledRule]
}
