import Foundation
import Testing
@testable import Tracexy

/// Arithmetic in session expressions (`+ - * / %`, `{}` grouping) over the
/// session measures `bytes`, `bytes.sent`, `bytes.received`, `frames`,
/// `frames.sent` and `frames.received`, as a Wireshark display filter computes.
struct QueryArithmeticTests {
    // MARK: Internal

    @Test
    func parsesPrecedenceAndGrouping() throws {
        let product = QueryArithmetic.binary(.multiply, .number(2), .field(.bytesSent))
        #expect(try parser.parse("bytes.received >= 2 * bytes.sent")
            == .leaf(.numericCompare(.init(field: .bytesReceived, relation: .greaterOrEqual, value: product))))
        // `*` binds tighter than `+`; braces group.
        #expect(try parser.parse("frames == 1 + 2 * frames.sent") == .leaf(.numericCompare(.init(
            field: .frames, relation: .equal,
            value: .binary(.add, .number(1), .binary(.multiply, .number(2), .field(.framesSent)))
        ))))
        #expect(try parser.parse("frames == {1 + 2} * frames.sent") == .leaf(.numericCompare(.init(
            field: .frames, relation: .equal,
            value: .binary(.multiply, .binary(.add, .number(1), .number(2)), .field(.framesSent))
        ))))
        #expect(try parser.parse("bytes.sent <= bytes.received / 4 % 3") == .leaf(.numericCompare(.init(
            field: .bytesSent, relation: .lessOrEqual,
            value: .binary(.remainder, .binary(.divide, .field(.bytesReceived), .number(4)), .number(3))
        ))))
    }

    /// A constant `bytes` value folds into the existing closed range, so older
    /// expressions compile exactly as before.
    @Test
    func constantBytesKeepsTheTotalRange() throws {
        #expect(try parser.parse("bytes >= {64 * 1024}") == .leaf(.totalBytesInRange(lower: 65_536, upper: .max)))
        #expect(try parser.parse("bytes == 1 + 2") == .leaf(.totalBytesInRange(lower: 3, upper: 3)))
        #expect(try parser.parse("bytes <= 500") == .leaf(.totalBytesInRange(lower: 0, upper: 500)))
    }

    @Test
    func strayArithmeticStaysRejected() {
        expectFailure("port == -1", .unsupportedOperator("-"))
        expectFailure("host contains \"a\" + 1", .unsupportedOperator("+"))
        expectFailure("tcp * udp", .unsupportedOperator("*"))
        expectFailure("bytes.sent == -1", .unsupportedOperator("-"))
        expectFailure("bytes.sent == bytes.received +", .expectedValue)
        expectFailure("bytes.sent == {1 + 2", .unbalancedBrace)
        expectFailure("frames >= host", .invalidNumber)
        expectFailure("bytes >= host", .invalidByteCount)
        expectFailure("bytes == 1 - 2", .invalidByteCount)
        expectFailure("frames == 9223372036854775807 + 1", .invalidNumber)
        expectFailure(
            "frames > 2",
            .unsupportedOperator(">")
        )
    }

    @Test
    func evaluatesAgainstSessions() throws {
        let upload = session("upload", up: 90_000, down: 1_000, framesUp: 70, framesDown: 20)
        let download = session("download", up: 1_000, down: 90_000, framesUp: 20, framesDown: 70)
        let legacy = session("legacy", up: 500, down: 500, framesUp: 0, framesDown: 0)
        let all = [upload, download, legacy]

        #expect(try matched("bytes.sent >= {10 * bytes.received}", all) == ["upload"])
        #expect(try matched("bytes.received >= 10 * bytes.sent", all) == ["download"])
        #expect(try matched("frames == frames.sent + frames.received", all) == ["upload", "download"])
        #expect(try matched("frames.sent == 70", all) == ["upload"])
        // Frame counts a summary does not carry are undecidable, never a silent no-match.
        #expect(try evaluate("frames >= 0", all).indeterminate == [legacy.id])
        #expect(try evaluate("not frames >= 0", all).indeterminate == [legacy.id])
        // A zero divisor is no match, as a failed computation is in Wireshark.
        #expect(try matched("bytes.sent >= bytes.received / {frames.sent - 70}", all) == ["download"])
    }

    @Test
    func compilerBoundsTheArithmetic() {
        var value = QueryArithmetic.number(1)
        for _ in 0 ..< 40 {
            value = .binary(.add, value, .number(1))
        }
        let query = InvestigationQuery.leaf(.numericCompare(.init(field: .bytes, relation: .equal, value: value)))
        #expect(throws: QueryValidationError.arithmeticTooLarge(limit: QueryNumericComparison.maximumNodes)) {
            try InvestigationQueryEngine().compile(query)
        }
    }

    @Test
    func completionOffersTheMeasures() {
        #expect(SessionExpressionCompletion.suggestions(for: "bytes.s").candidates == ["bytes.sent"])
        #expect(SessionExpressionCompletion.suggestions(for: "frames.sent ").candidates == ["==", ">=", "<="])
    }

    // MARK: Private

    private let parser = SessionQueryParser()

    private func expectFailure(
        _ text: String,
        _ reason: SessionQueryParseError.Reason,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        do {
            _ = try parser.parse(text)
            Issue.record("\(text) parsed", sourceLocation: sourceLocation)
        } catch let error as SessionQueryParseError {
            #expect(error.reason == reason, "\(text)", sourceLocation: sourceLocation)
        } catch {
            Issue.record("\(error)", sourceLocation: sourceLocation)
        }
    }

    private func matched(_ text: String, _ sessions: [SessionSummary]) throws -> [String] {
        let ids = try Set(evaluate(text, sessions).matched.map(\.id))
        return sessions.filter { ids.contains($0.id) }.map(\.host)
    }

    private func evaluate(_ text: String, _ sessions: [SessionSummary]) throws -> InvestigationQueryResult {
        let engine = InvestigationQueryEngine()
        let snapshot = InvestigationSnapshot(
            fold: SessionFoldSnapshot(
                sessions: sessions,
                connections: .empty,
                datagramEvidence: .empty,
                tlsEvidence: .empty,
                segmentSeries: .empty
            ),
            connectionAssessor: ConnectionAssessor(),
            datagramAssessor: DatagramAssessor()
        )
        return try engine.evaluate(engine.compile(parser.parse(text)), over: snapshot)
    }

    private func session(_ host: String, up: Int, down: Int, framesUp: Int, framesDown: Int) -> SessionSummary {
        let source = IPEndpoint(ip: "192.0.2.10", port: 51_000)
        let destination = IPEndpoint(ip: "198.51.100.5", port: 443)
        var summary = SessionSummary(
            id: SessionBuilder.stableID("arithmetic-\(host)"),
            startTime: Date(timeIntervalSince1970: 1_000),
            duration: 0,
            processName: nil,
            host: host,
            sourceEndpoint: source.display,
            destinationEndpoint: destination.display,
            sourceEndpointValue: source,
            destinationEndpointValue: destination,
            protocolStack: [.tcp],
            status: .ok,
            latencyMilliseconds: nil,
            bytesUp: up,
            bytesDown: down,
            sni: nil,
            dnsQuery: nil,
            dnsAnswers: []
        )
        summary.packetsUp = framesUp
        summary.packetsDown = framesDown
        return summary
    }
}
