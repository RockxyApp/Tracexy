import Foundation
import Testing
@testable import Tracexy

@Suite("Investigation query draft")
struct InvestigationQueryDraftTests {
    // MARK: Internal

    @Test("Every structured row compiles to the exact typed predicate")
    func everyRowCompiles() throws {
        let now = Date(timeIntervalSince1970: 100)
        let later = Date(timeIntervalSince1970: 200)
        let cases: [(InvestigationPredicateDraft, QueryPredicate)] = try [
            (.processContains(" Safari "), .processContains(" Safari ")),
            (.hostContains(" example.test "), .hostContains(" example.test ")),
            (
                .ipEquals(" 192.0.2.1 ", scope: .source),
                .ipEquals(#require(IPAddressValue(parsing: "192.0.2.1")), scope: .source)
            ),
            (
                .cidrContains(" 2001:db8::1/64 ", scope: .destination),
                .cidrContains(#require(CIDRValue(parsing: "2001:db8::1/64")), scope: .destination)
            ),
            (
                .portInRange(lower: " 443 ", upper: "8443", scope: .either),
                .portInRange(lower: 443, upper: 8_443, scope: .either)
            ),
            (.protocolStackContains(.tls), .protocolStackContains(.tls)),
            (.statusEquals(.warning), .statusEquals(.warning)),
            (.findingKind(.retransmission), .findingKind(.retransmission)),
            (.startDateInRange(lower: now, upper: later), .startDateInRange(lower: now, upper: later)),
            (.totalBytesInRange(lower: "0", upper: " 4096 "), .totalBytesInRange(lower: 0, upper: 4_096)),
            (.hasEvidence(.serverNameIndication), .hasEvidence(.serverNameIndication)),
        ]

        for (draftPredicate, expected) in cases {
            let row = InvestigationQueryDraftRow(predicate: draftPredicate)
            let result = try compiler.compile(InvestigationQueryDraft(rows: [row]))
            #expect(result.query == .all([.leaf(expected)]))
        }
    }

    @Test("Any and negate compile to a bounded nested AST")
    func combinationAndNegation() throws {
        let first = InvestigationQueryDraftRow(predicate: .hostContains("example"))
        let second = InvestigationQueryDraftRow(
            isNegated: true,
            predicate: .statusEquals(.error)
        )

        let result = try compiler.compile(InvestigationQueryDraft(
            combination: .any,
            rows: [first, second]
        ))

        #expect(result.query == .any([
            .leaf(.hostContains("example")),
            .not(.leaf(.statusEquals(.error))),
        ]))
    }

    @Test("Invalid editable values report the exact row")
    func invalidValuesReportRow() {
        let cases: [(InvestigationPredicateDraft, InvestigationQueryDraftError.Reason)] = [
            (.ipEquals("host.test", scope: .either), .invalidIPAddress),
            (.cidrContains("192.0.2.1/99", scope: .either), .invalidCIDR),
            (.portInRange(lower: "-1", upper: "443", scope: .either), .invalidPort),
            (.portInRange(lower: "1", upper: "65536", scope: .either), .invalidPort),
            (.totalBytesInRange(lower: "+1", upper: "2"), .invalidByteCount),
            (.hostContains("\u{0000}"), .core(.controlCharacterInText)),
        ]

        for (predicate, reason) in cases {
            let row = InvestigationQueryDraftRow(predicate: predicate)
            #expect(throws: InvestigationQueryDraftError(rowID: row.id, reason: reason)) {
                try compiler.compile(InvestigationQueryDraft(rows: [row]))
            }
        }
    }

    @Test("Empty and oversized drafts fail before Core compilation")
    func draftBounds() {
        #expect(throws: InvestigationQueryDraftError(rowID: nil, reason: .emptyDraft)) {
            try compiler.compile(InvestigationQueryDraft(rows: []))
        }

        let rows = (0 ... InvestigationQueryDraftCompiler.maximumRows).map { index in
            InvestigationQueryDraftRow(predicate: .hostContains("host-\(index)"))
        }
        #expect(throws: InvestigationQueryDraftError(
            rowID: nil,
            reason: .tooManyRows(limit: InvestigationQueryDraftCompiler.maximumRows)
        )) {
            try compiler.compile(InvestigationQueryDraft(rows: rows))
        }
    }

    @Test("Field changes receive safe typed defaults")
    func fieldDefaults() {
        let date = Date(timeIntervalSince1970: 42)
        #expect(InvestigationPredicateDraft.initialValue(for: .process, now: date) == .processContains(""))
        #expect(InvestigationPredicateDraft.initialValue(for: .ip, now: date) == .ipEquals("", scope: .either))
        #expect(InvestigationPredicateDraft.initialValue(for: .port, now: date) == .portInRange(
            lower: "",
            upper: "",
            scope: .either
        ))
        #expect(InvestigationPredicateDraft.initialValue(for: .protocol, now: date) == .protocolStackContains(.tcp))
        #expect(InvestigationPredicateDraft.initialValue(for: .startTime, now: date) == .startDateInRange(
            lower: date,
            upper: date
        ))
        #expect(InvestigationPredicateDraft.initialValue(for: .evidence, now: date) == .hasEvidence(.anyFinding))
    }

    // MARK: Private

    private let compiler = InvestigationQueryDraftCompiler()
}
