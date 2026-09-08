import Foundation
import Testing
@testable import Tracexy

@Suite("Investigation session-expression draft")
struct InvestigationQueryExpressionDraftTests {
    // MARK: Internal

    @Test("A fresh draft still defaults to the structured row editor")
    func defaultsToRows() {
        let draft = InvestigationQueryDraft()
        #expect(draft.mode == .rows)
        #expect(draft.expression.isEmpty)
        #expect(draft.rows.count == 1)
        // The pre-existing memberwise spellings keep compiling unchanged.
        #expect(InvestigationQueryDraft(rows: [InvestigationQueryDraftRow()]).mode == .rows)
        #expect(InvestigationQueryDraft(combination: .any, rows: []).mode == .rows)
    }

    @Test("Expression mode compiles the parsed AST through the same engine validation")
    func expressionModeCompiles() throws {
        let draft = InvestigationQueryDraft(
            mode: .expression,
            expression: "tcp and destination.port == 443"
        )

        let result = try compiler.compile(draft)

        #expect(result.query == .all([
            .leaf(.protocolStackContains(.tcp)),
            .leaf(.portInRange(lower: 443, upper: 443, scope: .destination)),
        ]))
        #expect(try result.compiled == InvestigationQueryEngine().compile(result.query))
    }

    @Test("Only the selected mode is compiled, and the other draft is retained")
    func modeSelectsWhichDraftCompiles() throws {
        var draft = InvestigationQueryDraft(
            rows: [InvestigationQueryDraftRow(predicate: .protocolStackContains(.udp))],
            mode: .rows,
            expression: "tcp"
        )

        // Rows mode ignores the retained (and here contradictory) expression text.
        #expect(try compiler.compile(draft).query == .all([.leaf(.protocolStackContains(.udp))]))

        // Switching mode compiles the other representation without losing either.
        draft.mode = .expression
        #expect(try compiler.compile(draft).query == .leaf(.protocolStackContains(.tcp)))
        #expect(draft.rows.count == 1)
        #expect(draft.expression == "tcp")
    }

    @Test("A malformed expression is a draft-level typed error carrying its position")
    func parseFailuresAreDraftLevel() {
        let cases: [(String, SessionQueryParseError)] = [
            ("", SessionQueryParseError(position: 1, reason: .emptyExpression)),
            ("ip.addr == 192.0.2.1", SessionQueryParseError(position: 1, reason: .unknownName("ip.addr"))),
            ("port != 443", SessionQueryParseError(position: 6, reason: .unsupportedOperator("!="))),
            ("tcp and", SessionQueryParseError(position: 8, reason: .expectedExpression)),
            ("tcp udp", SessionQueryParseError(position: 5, reason: .unexpectedTrailingInput)),
        ]

        for (expression, expected) in cases {
            let draft = InvestigationQueryDraft(mode: .expression, expression: expression)
            #expect(throws: InvestigationQueryDraftError(rowID: nil, reason: .expression(expected))) {
                try compiler.compile(draft)
            }
        }
    }

    @Test("An engine bound rejected after parsing stays a draft-level core error")
    func engineFailuresStayDraftLevel() {
        let wide = (0 ..< 17).map { _ in "tcp" }.joined(separator: " and ")
        let draft = InvestigationQueryDraft(mode: .expression, expression: wide)

        #expect(throws: InvestigationQueryDraftError(
            rowID: nil,
            reason: .core(.childCountExceeded(
                limit: InvestigationQueryEngine.Configuration.productionMaxChildrenPerGroup
            ))
        )) {
            try compiler.compile(draft)
        }
    }

    // MARK: Private

    private let compiler = InvestigationQueryDraftCompiler()
}
