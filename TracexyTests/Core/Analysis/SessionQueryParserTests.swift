import Foundation
import Testing
@testable import Tracexy

@Suite("Session expression parser")
struct SessionQueryParserTests {
    // MARK: Internal

    // MARK: Precedence, grouping, negation

    @Test("not binds tighter than and, which binds tighter than or")
    func precedence() throws {
        #expect(try parser.parse("tcp or udp and tls") == .any([
            .leaf(.protocolStackContains(.tcp)),
            .all([.leaf(.protocolStackContains(.udp)), .leaf(.protocolStackContains(.tls))]),
        ]))
        #expect(try parser.parse("not tcp and udp") == .all([
            .not(.leaf(.protocolStackContains(.tcp))),
            .leaf(.protocolStackContains(.udp)),
        ]))
        // The symbol spellings are the same operators, not a second dialect.
        #expect(try parser.parse("!tcp && udp || tls") == parser.parse("not tcp and udp or tls"))
    }

    @Test("Parentheses override precedence and a long run stays one flat group")
    func groupingIsFlat() throws {
        #expect(try parser.parse("(tcp or udp) and tls") == .all([
            .any([.leaf(.protocolStackContains(.tcp)), .leaf(.protocolStackContains(.udp))]),
            .leaf(.protocolStackContains(.tls)),
        ]))
        // Four conjuncts produce one four-child group, never a left-nested chain.
        #expect(try parser.parse("tcp and udp and tls and dns") == .all([
            .leaf(.protocolStackContains(.tcp)),
            .leaf(.protocolStackContains(.udp)),
            .leaf(.protocolStackContains(.tls)),
            .leaf(.protocolStackContains(.dns)),
        ]))
    }

    @Test("Repeated negation nests the existing three-valued AST not")
    func repeatedNegation() throws {
        #expect(try parser.parse("not not tcp") == .not(.not(.leaf(.protocolStackContains(.tcp)))))
    }

    @Test("Every protocol keyword maps to its existing typed kind")
    func protocolKeywords() throws {
        let expected: [String: ProtocolKind] = [
            "ipv4": .ipv4, "ipv6": .ipv6, "arp": .arp, "icmp": .icmp, "icmpv6": .icmpv6,
            "tcp": .tcp, "udp": .udp, "dns": .dns, "tls": .tls, "http": .http,
            "http2": .http2, "quic": .quic, "websocket": .websocket, "stun": .stun,
        ]
        for (keyword, kind) in expected {
            #expect(try parser.parse(keyword) == .leaf(.protocolStackContains(kind)))
        }
        // Outer framing and the catch-all are deliberately absent from the grammar.
        for keyword in ["ethernet", "linuxCooked", "other"] {
            expectFailure(keyword, .unknownName(keyword), at: 1)
        }
    }

    // MARK: Address, CIDR and port operands

    @Test("Address comparisons validate exact IPv4/IPv6 values per endpoint scope")
    func addressComparisons() throws {
        let v4 = try #require(IPAddressValue(parsing: "192.0.2.1"))
        let v6 = try #require(IPAddressValue(parsing: "2001:db8::1"))
        #expect(try parser.parse("ip == 192.0.2.1") == .leaf(.ipEquals(v4, scope: .either)))
        #expect(try parser.parse("source.ip == 2001:db8::1") == .leaf(.ipEquals(v6, scope: .source)))
        #expect(try parser.parse("destination.ip==192.0.2.1") == .leaf(.ipEquals(v4, scope: .destination)))

        expectFailure("ip == 192.0.2.256", .invalidIPAddress, at: 7)
        expectFailure("ip == 192.0.2.1/32", .invalidIPAddress, at: 7)
        expectFailure("ip == host.example", .invalidIPAddress, at: 7)
    }

    @Test("CIDR containment requires a valid block in the operand's own family")
    func cidrComparisons() throws {
        let v4 = try #require(CIDRValue(parsing: "192.0.2.0/24"))
        let v6 = try #require(CIDRValue(parsing: "2001:db8::/32"))
        #expect(try parser.parse("ip in 192.0.2.0/24") == .leaf(.cidrContains(v4, scope: .either)))
        #expect(try parser.parse("destination.ip in 2001:db8::/32") == .leaf(.cidrContains(v6, scope: .destination)))

        expectFailure("ip in 192.0.2.0/33", .invalidCIDR, at: 7)
        expectFailure("ip in 192.0.2.0", .invalidCIDR, at: 7)
    }

    @Test("Ports accept both closed bounds and reject overflow or a signed value")
    func portComparisons() throws {
        #expect(try parser.parse("port == 0") == .leaf(.portInRange(lower: 0, upper: 0, scope: .either)))
        #expect(try parser.parse("source.port == 65535") == .leaf(
            .portInRange(lower: 65_535, upper: 65_535, scope: .source)
        ))
        #expect(try parser.parse("destination.port == 443") == .leaf(
            .portInRange(lower: 443, upper: 443, scope: .destination)
        ))

        expectFailure("port == 65536", .invalidPort, at: 9)
        expectFailure("port == 99999999999999999999999", .invalidPort, at: 9)
        expectFailure("port == 0x50", .invalidPort, at: 9)
        // A sign is arithmetic punctuation, rejected before it can become a value.
        expectFailure("port == -1", .unsupportedOperator("-"), at: 9)
    }

    @Test("Byte comparisons map to the engine's closed non-negative range")
    func byteComparisons() throws {
        #expect(try parser.parse("bytes == 0") == .leaf(.totalBytesInRange(lower: 0, upper: 0)))
        #expect(try parser.parse("bytes >= 4096") == .leaf(.totalBytesInRange(lower: 4_096, upper: Int.max)))
        #expect(try parser.parse("bytes <= 4096") == .leaf(.totalBytesInRange(lower: 0, upper: 4_096)))

        // Beyond Int is an explicit rejection, never a wrapped or clamped bound.
        expectFailure("bytes >= 99999999999999999999999", .invalidByteCount, at: 10)
        expectFailure("bytes > 10", .unsupportedOperator(">"), at: 7)
    }

    @Test("Finding values map to the existing typed projection and reject unknown names")
    func findingValues() throws {
        let expected: [String: QueryFindingKind] = [
            "reset": .reset,
            "retransmission": .retransmission,
            "overlap": .overlap,
            "outOfOrder": .outOfOrder,
            "dnsTruncation": .dnsTruncation,
        ]
        for (name, kind) in expected {
            #expect(try parser.parse("finding == \(name)") == .leaf(.findingKind(kind)))
        }
        expectFailure("finding == resetobserved", .unknownName("resetobserved"), at: 12)
        expectFailure("finding == \"reset\"", .expectedValue, at: 12)
    }

    // MARK: Text operands

    @Test("Quoted text carries Unicode through and supports only quote/backslash escapes")
    func quotedText() throws {
        #expect(try parser.parse("host contains \"Ünïcode.example\"") == .leaf(
            .hostContains("Ünïcode.example")
        ))
        #expect(try parser.parse("process contains \"a\\\"b\\\\c\"") == .leaf(
            .processContains("a\"b\\c")
        ))

        expectFailure("host contains \"unterminated", .unterminatedString, at: 15)
        expectFailure("host contains \"bad\\nescape\"", .unsupportedEscape, at: 19)
        expectFailure("host contains \"tab\there\"", .controlCharacterInText, at: 19)
        expectFailure("host contains example", .expectedValue, at: 15)
        expectFailure("host == \"example\"", .operatorNotSupportedForField(field: "host", operatorText: "=="), at: 6)
    }

    // MARK: Rejections that must never be guessed

    @Test("Packet-field spellings and unknown names are rejected by name")
    func packetFieldsRejected() {
        expectFailure("ip.addr == 192.0.2.1", .unknownName("ip.addr"), at: 1)
        expectFailure("tcp.port == 443", .unknownName("tcp.port"), at: 1)
        expectFailure("http.host contains \"x\"", .unknownName("http.host"), at: 1)
        expectFailure("frame.len >= 100", .unknownName("frame.len"), at: 1)
        expectFailure("tcp and eth.src == 192.0.2.1", .unknownName("eth.src"), at: 9)
    }

    @Test("Inequality, regular expressions and arithmetic are refused explicitly")
    func unsupportedOperatorsRejected() {
        expectFailure("port != 443", .unsupportedOperator("!="), at: 6)
        expectFailure(
            "host matches \"a.*\"",
            .operatorNotSupportedForField(field: "host", operatorText: "matches"),
            at: 6
        )
        expectFailure("host ~ \"a.*\"", .unsupportedOperator("~"), at: 6)
        expectFailure("bytes == 1 + 2", .unsupportedOperator("+"), at: 12)
        expectFailure("port = 443", .unsupportedOperator("="), at: 6)
        expectFailure("tcp & udp", .unsupportedOperator("&"), at: 5)
        expectFailure("tcp | udp", .unsupportedOperator("|"), at: 5)
    }

    @Test("Incomplete, trailing and unbalanced input is never partially accepted")
    func incompleteInputRejected() {
        expectFailure("", .emptyExpression, at: 1)
        expectFailure("   ", .emptyExpression, at: 1)
        expectFailure("tcp and", .expectedExpression, at: 8)
        expectFailure("and tcp", .expectedExpression, at: 1)
        expectFailure("tcp udp", .unexpectedTrailingInput, at: 5)
        expectFailure("(tcp or udp", .unbalancedParenthesis, at: 12)
        expectFailure("tcp)", .unexpectedTrailingInput, at: 4)
        expectFailure("()", .expectedExpression, at: 2)
        expectFailure("port ==", .expectedValue, at: 8)
        expectFailure("ip", .expectedValue, at: 3)
        // A non-ASCII scalar outside quotes cannot begin a term.
        expectFailure("tcp and ✓", .unexpectedCharacter, at: 9)
    }

    // MARK: Bounds

    @Test("Input byte, token and recursion ceilings reject before producing an AST")
    func boundsAreEnforced() {
        let tinyInput = SessionQueryParser(configuration: .init(maxUTF8Bytes: 4))
        #expect(throws: SessionQueryParseError(position: 1, reason: .inputTooLong(limit: 4))) {
            try tinyInput.parse("tcp and udp")
        }
        // The production ceiling rejects an oversized paste without evaluating it.
        let ceiling = SessionQueryParser.Configuration.productionMaxUTF8Bytes
        #expect(throws: SessionQueryParseError(position: 1, reason: .inputTooLong(limit: ceiling))) {
            try parser.parse(String(repeating: "t", count: ceiling + 1))
        }

        let fewTokens = SessionQueryParser(configuration: .init(maxTokens: 2))
        #expect(throws: SessionQueryParseError(position: 9, reason: .tokenLimitExceeded(limit: 2))) {
            try fewTokens.parse("tcp and udp")
        }

        let shallow = SessionQueryParser(configuration: .init(maxDepth: 2))
        #expect(throws: SessionQueryParseError(position: 2, reason: .depthLimitExceeded(limit: 2))) {
            try shallow.parse("((tcp))")
        }
        #expect(throws: SessionQueryParseError(position: 5, reason: .depthLimitExceeded(limit: 2))) {
            try shallow.parse("not not tcp")
        }
    }

    @Test("Configuration can only lower a ceiling, never raise it")
    func configurationClampsDownwardOnly() {
        let raised = SessionQueryParser.Configuration(
            maxUTF8Bytes: .max,
            maxTokens: .max,
            maxDepth: .max
        )
        #expect(raised.maxUTF8Bytes == SessionQueryParser.Configuration.productionMaxUTF8Bytes)
        #expect(raised.maxTokens == SessionQueryParser.Configuration.productionMaxTokens)
        #expect(raised.maxDepth == SessionQueryParser.Configuration.productionMaxDepth)

        let floored = SessionQueryParser.Configuration(maxUTF8Bytes: 0, maxTokens: -5, maxDepth: 0)
        #expect(floored.maxUTF8Bytes == 1)
        #expect(floored.maxTokens == 1)
        #expect(floored.maxDepth == 1)
    }

    @Test("Engine node, group and text ceilings still own the parsed AST")
    func engineBoundsStillApply() throws {
        // 17 conjuncts exceed the engine's 16-children-per-group ceiling.
        let wide = (0 ..< 17).map { _ in "tcp" }.joined(separator: " and ")
        let wideQuery = try parser.parse(wide)
        #expect(throws: QueryValidationError.childCountExceeded(
            limit: InvestigationQueryEngine.Configuration.productionMaxChildrenPerGroup
        )) {
            try engine.compile(wideQuery)
        }

        // Text longer than the engine's operand ceiling is rejected at compile, not parse.
        let longText = String(repeating: "a", count: 300)
        let longQuery = try parser.parse("host contains \"\(longText)\"")
        #expect(throws: QueryValidationError.textTooLong(
            limit: InvestigationQueryEngine.Configuration.productionMaxTextUTF8Bytes
        )) {
            try engine.compile(longQuery)
        }

        // Empty quoted text is an engine-level empty operand, not a silent match-all.
        let emptyQuery = try parser.parse("host contains \"\"")
        #expect(throws: QueryValidationError.emptyText) {
            try engine.compile(emptyQuery)
        }
    }

    // MARK: Equivalence with the structured path

    @Test("A parsed expression compiles and evaluates identically to the structured AST")
    func matchesStructuredEquivalent() throws {
        let structured = InvestigationQuery.all([
            .leaf(.protocolStackContains(.tcp)),
            .leaf(.portInRange(lower: 443, upper: 443, scope: .destination)),
        ])
        let parsed = try parser.parse("tcp and destination.port == 443")
        #expect(parsed == structured)
        #expect(try engine.compile(parsed) == engine.compile(structured))

        let snapshot = snapshot(sessions: [matchingSession, otherSession])
        let parsedResult = try evaluate(parsed, over: snapshot)
        let structuredResult = try evaluate(structured, over: snapshot)
        #expect(parsedResult == structuredResult)
        #expect(parsedResult.matched.map(\.id) == [matchingSession.id])
    }

    @Test("An absent finding stays indeterminate under negation")
    func absentFindingStaysIndeterminateUnderNot() throws {
        // The TCP session retains no finding, so the kind applies but cannot be decided.
        let snapshot = snapshot(sessions: [matchingSession])
        let positive = try evaluate(parser.parse("finding == reset"), over: snapshot)
        #expect(positive.matched.isEmpty)
        #expect(positive.indeterminate == [matchingSession.id])

        // Negation propagates indeterminate rather than turning absence into a match.
        let negated = try evaluate(parser.parse("not finding == reset"), over: snapshot)
        #expect(negated.matched.isEmpty)
        #expect(negated.indeterminate == [matchingSession.id])

        // A kind that cannot apply to this stack is a known no-match, so `not` matches.
        let inapplicable = try evaluate(parser.parse("not finding == dnsTruncation"), over: snapshot)
        #expect(inapplicable.matched.map(\.id) == [matchingSession.id])
        #expect(inapplicable.indeterminate.isEmpty)
    }

    // MARK: Private

    private let parser = SessionQueryParser()
    private let engine = InvestigationQueryEngine()

    private var matchingSession: SessionSummary {
        session(
            index: 1,
            source: IPEndpoint(ip: "192.0.2.10", port: 51_000),
            destination: IPEndpoint(ip: "198.51.100.5", port: 443),
            protocolStack: [.ipv4, .tcp]
        )
    }

    private var otherSession: SessionSummary {
        session(
            index: 2,
            source: IPEndpoint(ip: "192.0.2.11", port: 51_001),
            destination: IPEndpoint(ip: "198.51.100.6", port: 80),
            protocolStack: [.ipv4, .tcp]
        )
    }

    /// Assert one expression fails with an exact typed reason at an exact position.
    private func expectFailure(
        _ text: String,
        _ reason: SessionQueryParseError.Reason,
        at position: Int,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        #expect(
            throws: SessionQueryParseError(position: position, reason: reason),
            sourceLocation: sourceLocation
        ) {
            try parser.parse(text)
        }
    }

    private func evaluate(
        _ query: InvestigationQuery,
        over snapshot: InvestigationSnapshot
    )
        throws -> InvestigationQueryResult
    {
        try engine.evaluate(engine.compile(query), over: snapshot)
    }

    private func snapshot(sessions: [SessionSummary]) -> InvestigationSnapshot {
        InvestigationSnapshot(
            fold: SessionFoldSnapshot(
                sessions: sessions,
                connections: .empty,
                datagramEvidence: .empty,
                tlsEvidence: .empty
            ),
            connectionAssessor: ConnectionAssessor(),
            datagramAssessor: DatagramAssessor()
        )
    }

    private func session(
        index: Int,
        source: IPEndpoint,
        destination: IPEndpoint,
        protocolStack: [ProtocolKind]
    )
        -> SessionSummary
    {
        SessionSummary(
            id: SessionBuilder.stableID("session-query-parser-test-\(index)"),
            startTime: Date(timeIntervalSince1970: 1_000),
            duration: 0,
            processName: nil,
            host: "host.example",
            sourceEndpoint: source.display,
            destinationEndpoint: destination.display,
            sourceEndpointValue: source,
            destinationEndpointValue: destination,
            protocolStack: protocolStack,
            status: .ok,
            latencyMilliseconds: nil,
            bytesUp: 0,
            bytesDown: 0,
            sni: nil,
            dnsQuery: nil,
            dnsAnswers: []
        )
    }
}
