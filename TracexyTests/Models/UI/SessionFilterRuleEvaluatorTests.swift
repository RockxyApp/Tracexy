import Foundation
import Testing
@testable import Tracexy

// MARK: - Fixtures

private func makeSession(
    host: String = "api.example.com",
    process: String? = "Safari",
    source: String = "192.168.1.10:52344",
    destination: String = "93.184.216.34:443",
    protocols: [ProtocolKind] = [.tcp, .tls],
    status: SessionStatus = .ok,
    dnsQuery: String? = nil,
    dnsAnswers: [String] = []
)
    -> SessionSummary
{
    SessionSummary(
        id: UUID(),
        startTime: Date(timeIntervalSince1970: 0),
        duration: 0.1,
        processName: process,
        host: host,
        sourceEndpoint: source,
        destinationEndpoint: destination,
        protocolStack: protocols,
        status: status,
        latencyMilliseconds: nil,
        bytesUp: 100,
        bytesDown: 200,
        sni: nil,
        dnsQuery: dnsQuery,
        dnsAnswers: dnsAnswers
    )
}

private func rule(
    _ field: SessionFilterField,
    _ op: SessionFilterOperator,
    _ value: String,
    connector: FilterLogicConnector = .and,
    enabled: Bool = true
)
    -> SessionFilterRule
{
    SessionFilterRule(isEnabled: enabled, connector: connector, field: field, filterOperator: op, value: value)
}

// MARK: - SessionFilterOperatorTests

@Suite("The seven filter operators")
struct SessionFilterOperatorTests {
    // MARK: Internal

    @Test("Contains matches a substring, case-insensitively")
    func contains() {
        #expect(SessionFilterRuleEvaluator.matches(session, rules: [rule(.host, .contains, "EXAMPLE")]))
        #expect(!SessionFilterRuleEvaluator.matches(session, rules: [rule(.host, .contains, "google")]))
    }

    @Test("Is requires exact equality")
    func isExact() {
        #expect(SessionFilterRuleEvaluator.matches(session, rules: [rule(.host, .is, "API.EXAMPLE.COM")]))
        #expect(!SessionFilterRuleEvaluator.matches(session, rules: [rule(.host, .is, "example.com")]))
    }

    @Test("Starts With and Ends With anchor at the edges")
    func edges() {
        #expect(SessionFilterRuleEvaluator.matches(session, rules: [rule(.host, .startsWith, "api.")]))
        #expect(SessionFilterRuleEvaluator.matches(session, rules: [rule(.host, .endsWith, ".com")]))
        #expect(!SessionFilterRuleEvaluator.matches(session, rules: [rule(.host, .startsWith, "com")]))
    }

    @Test("Does Not Contain and Is Not are the negations")
    func negations() {
        #expect(SessionFilterRuleEvaluator.matches(session, rules: [rule(.host, .doesNotContain, "google")]))
        #expect(!SessionFilterRuleEvaluator.matches(session, rules: [rule(.host, .doesNotContain, "example")]))
        #expect(SessionFilterRuleEvaluator.matches(session, rules: [rule(.host, .notEqual, "other.host")]))
        #expect(!SessionFilterRuleEvaluator.matches(session, rules: [rule(.host, .notEqual, "api.example.com")]))
    }

    @Test("Regex matches a valid pattern")
    func regexValid() {
        #expect(SessionFilterRuleEvaluator.matches(session, rules: [rule(.host, .regex, "^api\\.")]))
        #expect(!SessionFilterRuleEvaluator.matches(session, rules: [rule(.host, .regex, "^www\\.")]))
    }

    // MARK: Private

    private let session = makeSession(host: "api.example.com")
}

// MARK: - SessionFilterActiveRuleTests

@Suite("Active-rule selection")
struct SessionFilterActiveRuleTests {
    // MARK: Internal

    @Test("A blank-value rule imposes no constraint and is not active")
    func blankRuleIsInert() {
        let blank = rule(.host, .contains, "   ")
        #expect(SessionFilterRuleEvaluator.activeRules(in: [blank]).isEmpty)
        // Evaluated on its own, an empty value is an unconstrained match.
        #expect(SessionFilterRuleEvaluator.matches(session, rules: [blank]))
    }

    @Test("A disabled rule is excluded from the active set")
    func disabledRuleIsInert() {
        let disabled = rule(.host, .contains, "nope", enabled: false)
        #expect(SessionFilterRuleEvaluator.activeRules(in: [disabled]).isEmpty)
        #expect(SessionFilterRuleEvaluator.matches(session, rules: [disabled]))
    }

    @Test("Only enabled, non-empty rules are active")
    func mixedActiveSet() {
        let rules = [
            rule(.host, .contains, "example"),
            rule(.host, .contains, "", enabled: true),
            rule(.process, .contains, "safari", enabled: false),
        ]
        #expect(SessionFilterRuleEvaluator.activeRules(in: rules).count == 1)
    }

    // MARK: Private

    private let session = makeSession()
}

// MARK: - SessionFilterRegexSafetyTests

@Suite("Regex safety")
struct SessionFilterRegexSafetyTests {
    // MARK: Internal

    @Test("An invalid regex safely matches no session instead of trapping")
    func invalidRegexMatchesNothing() {
        // "[" is an unterminated character class — not a valid pattern.
        #expect(!SessionFilterRuleEvaluator.matches(session, rules: [rule(.host, .regex, "[")]))
    }

    @Test("A prepared rule set applies a compiled regex correctly")
    func preparedRegexApplies() {
        let prepared = SessionFilterRuleEvaluator.prepared([rule(.host, .regex, "example")])
        #expect(prepared.matches(session))
        let invalid = SessionFilterRuleEvaluator.prepared([rule(.host, .regex, "(")])
        #expect(!invalid.matches(session))
    }

    // MARK: Private

    private let session = makeSession(host: "api.example.com")
}

// MARK: - SessionFilterConnectorTests

@Suite("Left-to-right AND/OR evaluation")
struct SessionFilterConnectorTests {
    // MARK: Internal

    @Test("Connectors evaluate strictly left-to-right, with no AND-over-OR precedence")
    func leftToRightNoPrecedence() {
        // true OR false AND false:
        //   precedence (AND first) would give: true OR (false AND false) = true
        //   left-to-right gives:               (true OR false) AND false = false
        let rules = [
            rule(.host, .contains, "abc"), // true
            rule(.host, .contains, "zzz", connector: .or), // false
            rule(.host, .contains, "yyy", connector: .and), // false
        ]
        #expect(!SessionFilterRuleEvaluator.matches(session, rules: rules))
    }

    @Test("The mirrored ordering pins the same left-to-right rule")
    func leftToRightMirror() {
        // false OR true AND true:
        //   left-to-right: ((false OR true) AND true) = true
        let rules = [
            rule(.host, .contains, "zzz"), // false
            rule(.host, .contains, "abc", connector: .or), // true
            rule(.host, .contains, "abc", connector: .and), // true
        ]
        #expect(SessionFilterRuleEvaluator.matches(session, rules: rules))
    }

    @Test("The first row's connector is ignored")
    func firstConnectorIgnored() {
        // A lone OR row behaves like the single predicate it is.
        #expect(SessionFilterRuleEvaluator.matches(session, rules: [rule(.host, .contains, "abc", connector: .or)]))
    }

    // MARK: Private

    /// Host is "abc"; hitTrue matches it, hitFalse does not.
    private let session = makeSession(host: "abc")
}

// MARK: - SessionFilterRuleNormalizationTests

@Suite("Rule-list normalization to the capacity cap")
struct SessionFilterRuleNormalizationTests {
    @Test("An oversized list is clamped to the limit")
    func clampsToLimit() {
        let many = Array(repeating: rule(.host, .contains, "x"), count: 30)
        #expect(SessionFilterRule.normalized(many, limit: 12).count == 12)
    }

    @Test("A list within the limit is preserved")
    func preservesWithinLimit() {
        let few = Array(repeating: rule(.host, .contains, "x"), count: 3)
        #expect(SessionFilterRule.normalized(few, limit: 12).count == 3)
    }

    @Test("Normalization never leaves zero rows")
    func neverEmpty() {
        #expect(SessionFilterRule.normalized([], limit: 12).count == 1)
        #expect(SessionFilterRule.normalized([], limit: 0).count == 1)
    }

    @Test("At the cap the list is full, which is the disable condition for the plus buttons")
    func atCapIsFull() {
        let capped = SessionFilterRule.normalized(Array(repeating: rule(.host, .contains, "x"), count: 40), limit: 12)
        #expect(capped.count == 12)
        // The UI disables "add" when count >= limit; assert that state is reachable.
        #expect(capped.count >= 12)
    }
}
