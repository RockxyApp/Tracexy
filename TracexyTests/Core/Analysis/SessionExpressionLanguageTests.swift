import Foundation
import Testing
@testable import Tracexy

// MARK: - SessionExpressionLanguageTests

/// The thirteenth slice's additions to the session-expression language: a linear-time
/// wildcard `matches` (never a regular expression), value sets that are sugar for an
/// `or` of existing predicates, port ranges, completion that only suggests names the
/// parser accepts, and terms built from a session's own facts.
struct SessionExpressionLanguageTests {
    // MARK: Internal

    // MARK: Wildcard

    @Test
    func wildcardSemantics() {
        let pattern = WildcardPattern(normalized: "*.example.com")
        #expect(pattern.matches("api.example.com"))
        #expect(pattern.matches("a.b.example.com"))
        #expect(!pattern.matches("example.com"))
        #expect(!pattern.matches("api.example.com.evil"))
        #expect(WildcardPattern(normalized: "a?c").matches("abc"))
        #expect(!WildcardPattern(normalized: "a?c").matches("ac"))
        #expect(WildcardPattern(normalized: "*").matches("anything"))
        #expect(WildcardPattern(normalized: "exact").matches("exact"))
        #expect(!WildcardPattern(normalized: "exact").matches("exactly"))
        #expect(WildcardPattern(normalized: "**a**").matches("xxaxx"))
    }

    /// The pattern that makes a backtracking regex engine explode must stay cheap.
    @Test
    func pathologicalPatternStaysLinearish() {
        let value = String(repeating: "a", count: 250)
        let pattern = WildcardPattern(normalized: String(repeating: "*a", count: 60) + "b")
        let clock = ContinuousClock()
        let elapsed = clock.measure {
            for _ in 0 ..< 50 {
                #expect(!pattern.matches(value))
            }
        }
        #expect(elapsed < .seconds(1))
    }

    @Test
    func matchesIsCaseInsensitiveAndWholeValue() throws {
        let hit = session(host: "API.Example.COM", process: "com.apple.Safari")
        #expect(try matches("host matches \"*.example.com\"", hit))
        #expect(try !matches("host matches \"example\"", hit))
        #expect(try matches("process matches \"com.apple.*\"", hit))
        #expect(try !matches("process matches \"*chrome*\"", hit))
        // An absent value never matches, exactly as for `contains`.
        #expect(try !matches("process matches \"*\"", session(host: "h", process: nil)))
    }

    // MARK: Sets and ranges

    @Test
    func setsAreSugarForOr() throws {
        #expect(try parser.parse("port in {80, 443}") == .any([
            .leaf(.portInRange(lower: 80, upper: 80, scope: .either)),
            .leaf(.portInRange(lower: 443, upper: 443, scope: .either)),
        ]))
        #expect(try parser.parse("finding in {reset, retransmission}") == .any([
            .leaf(.findingKind(.reset)),
            .leaf(.findingKind(.retransmission)),
        ]))
        let address = try #require(IPAddressValue(parsing: "192.0.2.1"))
        let block = try #require(CIDRValue(parsing: "198.51.100.0/24"))
        #expect(try parser.parse("destination.ip in {192.0.2.1, 198.51.100.0/24}") == .any([
            .leaf(.ipEquals(address, scope: .destination)),
            .leaf(.cidrContains(block, scope: .destination)),
        ]))
        // A one-value set is just that comparison.
        #expect(try parser.parse("port in {53}") == .leaf(.portInRange(lower: 53, upper: 53, scope: .either)))
    }

    @Test
    func portRanges() throws {
        #expect(try parser.parse("destination.port in 8000..8080")
            == .leaf(.portInRange(lower: 8_000, upper: 8_080, scope: .destination)))
        #expect(try parser.parse("port in {22, 8000..8080}") == .any([
            .leaf(.portInRange(lower: 22, upper: 22, scope: .either)),
            .leaf(.portInRange(lower: 8_000, upper: 8_080, scope: .either)),
        ]))
        // `==` takes a single port; a range there is not a port.
        expectFailure("port == 1..2", .invalidPort)
        expectFailure("port in 1..2..3", .invalidPort)
        // A reversed range is the engine's typed error, not a parse guess.
        let reversed = try parser.parse("port in 90..80")
        #expect(throws: QueryValidationError.reversedRange) {
            _ = try InvestigationQueryEngine().compile(reversed)
        }
    }

    @Test
    func malformedSetsFailClosed() {
        expectFailure("port in {}", .expectedValue)
        expectFailure("port in {80,}", .expectedValue)
        expectFailure("port in {80 443}", .unbalancedBrace)
        expectFailure("finding in {reset, nonsense}", .unknownName("nonsense"))
        expectFailure("ip in {not-an-address}", .unsupportedOperator("-"))
        let tooMany = "port in {" + (1 ... 33).map(String.init).joined(separator: ", ") + "}"
        expectFailure(tooMany, .setTooLarge(limit: SessionQueryParser.maximumSetValues))
        expectFailure("host matches", .expectedValue)
        expectFailure("bytes matches \"1\"", .operatorNotSupportedForField(field: "bytes", operatorText: "matches"))
    }

    @Test
    func setEvaluatesLikeTheOrItStandsFor() throws {
        let web = session(host: "a", process: nil, destinationPort: 443)
        let dns = session(host: "b", process: nil, destinationPort: 53)
        let ssh = session(host: "c", process: nil, destinationPort: 22)
        let result = try evaluate("destination.port in {443, 53}", over: [web, dns, ssh])
        #expect(Set(result.matched.map(\.id)) == [web.id, dns.id])
    }

    // MARK: Completion

    @Test
    func completionOffersOnlyWhatCanFollow() {
        #expect(SessionExpressionCompletion.suggestions(for: "").candidates.contains("host"))
        #expect(SessionExpressionCompletion.suggestions(for: "ho").candidates == ["host"])
        #expect(SessionExpressionCompletion.suggestions(for: "host ").candidates == ["contains", "matches"])
        #expect(SessionExpressionCompletion.suggestions(for: "port ").candidates == ["==", "in"])
        #expect(SessionExpressionCompletion.suggestions(for: "bytes ").candidates == ["==", ">=", "<="])
        #expect(SessionExpressionCompletion.suggestions(for: "tcp ").candidates == ["and", "or"])
        #expect(SessionExpressionCompletion.suggestions(for: "finding == ret").candidates == ["retransmission"])
        #expect(SessionExpressionCompletion.suggestions(for: "finding in {reset, dnsN").candidates == ["dnsNameError"])
        #expect(SessionExpressionCompletion.suggestions(for: "port == 4").candidates.isEmpty)
        #expect(SessionExpressionCompletion.applying("host", to: "tcp and ho") == "tcp and host ")
    }

    /// Every term completion can produce must parse once its value is filled in.
    @Test
    func everySuggestedTermNameParses() throws {
        let values: [String: String] = [
            "ip": "== 192.0.2.1", "source.ip": "== 192.0.2.1", "destination.ip": "in 192.0.2.0/24",
            "port": "== 1", "source.port": "== 1", "destination.port": "in 1..2",
            "host": "matches \"*\"", "process": "contains \"x\"", "bytes": ">= 1",
            "finding": "== reset", "not": "tcp",
            "http.method": "== GET", "http.status": "in 400..499", "dhcp.message": "== Discover",
            "duration": ">= 5s", "latency": "in 50ms..1s", "start": ">= \"2027-01-15T08:00:00Z\"",
            "tag": "== red", "tcp.completeness": "== complete", "sni": "", "dns.query": "", "dns.answer": "",
            "mac": "== 0a:00:27:00:00:01", "source.mac": "in {0a:00:27:00:00:01}",
            "destination.mac": "== 0A:00:27:00:00:FE",
            "bytes.sent": ">= 2 * bytes.received", "bytes.received": "<= {bytes.sent + 1}", "frames": "== 3",
            "frames.sent": ">= frames.received % 2", "frames.received": "<= frames / 2",
        ]
        for name in SessionExpressionCompletion.termNames {
            let text = "\(name) \(values[name] ?? "")"
            #expect(throws: Never.self, "\(text)") { _ = try parser.parse(text) }
        }
    }

    // MARK: Time

    @Test
    func durationLatencyAndStartPredicates() throws {
        #expect(try parser.parse("duration >= 5s") == .leaf(.durationInRange(
            lower: 5,
            upper: .greatestFiniteMagnitude
        )))
        #expect(try parser.parse("duration <= 1.5m") == .leaf(.durationInRange(lower: 0, upper: 90)))
        #expect(try parser.parse("latency >= 200ms") == .leaf(.latencyInRange(
            lower: 200,
            upper: .greatestFiniteMagnitude
        )))
        #expect(try parser.parse("latency in 50ms..1s") == .leaf(.latencyInRange(lower: 50, upper: 1_000)))
        #expect(try parser.parse("start >= \"2027-01-15T08:00:00Z\"")
            == .leaf(.startDateInRange(lower: Date(timeIntervalSince1970: 1_800_000_000), upper: .distantFuture)))
        expectFailure("duration >= 5", .expectedValue)
        expectFailure("latency == 5ms", .operatorNotSupportedForField(field: "latency", operatorText: "=="))
        expectFailure("start >= \"yesterday\"", .expectedValue)

        var slow = session(host: "slow", process: nil)
        slow.duration = 12
        slow.latencyMilliseconds = 450
        var quick = session(host: "quick", process: nil, destinationPort: 80)
        quick.duration = 1
        quick.latencyMilliseconds = 20
        var unknown = session(host: "unknown", process: nil, destinationPort: 22)
        unknown.duration = nil
        let result = try evaluate("duration >= 5s or latency >= 200ms", over: [slow, quick, unknown])
        #expect(result.matched.map(\.host) == ["slow"])
        // An unknown duration and an unmeasured latency are undecidable, not "fast".
        #expect(result.indeterminate == [unknown.id])
    }

    // MARK: Terms from a session

    @Test
    func termsFromASessionParseAndMatchIt() throws {
        let subject = session(host: "api.example.com", process: "curl \"quoted\"", destinationPort: 8_443)
        let terms = [
            SessionExpressionTerm.sameHost(subject.host),
            SessionExpressionTerm.sameProcess(subject.processName),
            SessionExpressionTerm.sameDestinationIP(subject.destinationEndpointValue),
            SessionExpressionTerm.sameDestinationPort(subject.destinationEndpointValue),
            SessionExpressionTerm.sameProtocol(.tcp),
        ].compactMap(\.self)
        #expect(terms.count == 5)
        for term in terms {
            #expect(try matches(term, subject), "\(term)")
        }
        #expect(SessionExpressionTerm.sameHost("a*b") == nil)
        #expect(SessionExpressionTerm.narrowing("", with: "tcp") == "tcp")
        #expect(SessionExpressionTerm.narrowing("tcp", with: "udp") == "tcp and udp")
        #expect(SessionExpressionTerm.narrowing("tcp or udp", with: "dns") == "(tcp or udp) and dns")
    }

    // MARK: Library

    @Test @MainActor
    func libraryKeepsRecentAndSavedPerSuite() throws {
        let suite = "com.amunx.tracexy.tests.expressions.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let library = SessionExpressionLibrary()
        library.bind(to: defaults)
        for index in 0 ..< SessionExpressionLibrary.maximumRecent + 3 {
            library.recordApplied("port == \(index)")
        }
        library.recordApplied("  port == 5 ")
        #expect(library.recent.count == SessionExpressionLibrary.maximumRecent)
        #expect(library.recent.first == "port == 5")
        #expect(library.recent.filter { $0 == "port == 5" }.count == 1)

        #expect(library.save("tcp", named: "Web"))
        #expect(library.save("tls", named: "web"))
        #expect(library.saved.count == 1)
        #expect(library.saved.first?.expression == "tls")
        #expect(!library.save(" ", named: "Blank"))

        let reloaded = SessionExpressionLibrary()
        reloaded.bind(to: defaults)
        #expect(reloaded.recent == library.recent)
        #expect(reloaded.saved == library.saved)
        try reloaded.delete(#require(reloaded.saved.first).id)
        #expect(reloaded.saved.isEmpty)
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

    private func matches(_ text: String, _ subject: SessionSummary) throws -> Bool {
        try evaluate(text, over: [subject]).matched.contains { $0.id == subject.id }
    }

    private func evaluate(_ text: String, over sessions: [SessionSummary]) throws -> InvestigationQueryResult {
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

    private func session(host: String, process: String?, destinationPort: UInt16 = 443) -> SessionSummary {
        let source = IPEndpoint(ip: "192.0.2.10", port: 51_000)
        let destination = IPEndpoint(ip: "198.51.100.5", port: destinationPort)
        return SessionSummary(
            id: SessionBuilder.stableID("expression-language-\(host)-\(destinationPort)"),
            startTime: Date(timeIntervalSince1970: 1_000),
            duration: 0,
            processName: process,
            host: host,
            sourceEndpoint: source.display,
            destinationEndpoint: destination.display,
            sourceEndpointValue: source,
            destinationEndpointValue: destination,
            protocolStack: [.tcp],
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
