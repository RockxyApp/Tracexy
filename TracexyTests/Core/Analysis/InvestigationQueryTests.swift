import Foundation
import Testing
@testable import Tracexy

@Suite("InvestigationQueryEngine bounded typed query")
struct InvestigationQueryTests {
    // MARK: Internal

    // MARK: Text predicates — trim/case/missing

    @Test("Process/host substring is trimmed, case-insensitive, with a clean miss and missing path")
    func textSubstringSemantics() throws {
        let hit = session(processName: "com.apple.Safari", host: "Secure.Example.COM")
        // Needle is trimmed and case-folded; the haystack is folded the same way.
        #expect(try matches(.leaf(.processContains("  SAFARI ")), hit))
        #expect(try matches(.leaf(.hostContains("example.com")), hit))
        // Clean miss.
        #expect(try !matches(.leaf(.processContains("chrome")), hit))
        // Missing process attribution is a no-match, never a trap.
        let noProcess = session(processName: nil)
        #expect(try !matches(.leaf(.processContains("safari")), noProcess))
    }

    // MARK: Endpoint predicates — scope / family / CIDR / port edges

    @Test("Exact IP honors source/destination/either scope and the typed-endpoint-only rule")
    func ipEqualsScope() throws {
        let s = v4Session
        let source = try #require(IPAddressValue(parsing: "192.0.2.10"))
        let dest = try #require(IPAddressValue(parsing: "198.51.100.5"))
        #expect(try matches(.leaf(.ipEquals(source, scope: .source)), s))
        #expect(try !matches(.leaf(.ipEquals(source, scope: .destination)), s))
        #expect(try matches(.leaf(.ipEquals(dest, scope: .destination)), s))
        #expect(try matches(.leaf(.ipEquals(dest, scope: .either)), s))
        // A missing typed endpoint is a no-match, never a rendered-string fallback.
        let bare = session(source: nil, destination: nil)
        #expect(try !matches(.leaf(.ipEquals(source, scope: .either)), bare))
    }

    @Test("IPv6 exact and CIDR containment match through the typed endpoint")
    func ipv6ExactAndCIDR() throws {
        let s = v6Session
        let exact = try #require(IPAddressValue(parsing: "2001:db8::10"))
        #expect(try matches(.leaf(.ipEquals(exact, scope: .source)), s))
        let block = try #require(CIDRValue(parsing: "2001:db8::/32"))
        #expect(try matches(.leaf(.cidrContains(block, scope: .source)), s))
        // A different-family block never contains an IPv6 address.
        let v4Block = try #require(CIDRValue(parsing: "192.0.2.0/24"))
        #expect(try !matches(.leaf(.cidrContains(v4Block, scope: .source)), s))
    }

    @Test("CIDR containment covers v4 boundaries and the /32 self case")
    func cidrV4Edges() throws {
        let inside = session(source: ep("192.0.2.200", 1), destination: ep("10.0.0.1", 2))
        let block24 = try #require(CIDRValue(parsing: "192.0.2.0/24"))
        let otherBlock24 = try #require(CIDRValue(parsing: "192.0.3.0/24"))
        let selfBlock = try #require(CIDRValue(parsing: "192.0.2.200/32"))
        let neighborBlock = try #require(CIDRValue(parsing: "192.0.2.201/32"))
        let allV4 = try #require(CIDRValue(parsing: "0.0.0.0/0"))
        #expect(try matches(.leaf(.cidrContains(block24, scope: .source)), inside))
        #expect(try !matches(.leaf(.cidrContains(otherBlock24, scope: .source)), inside))
        // /32 matches only itself.
        #expect(try matches(.leaf(.cidrContains(selfBlock, scope: .source)), inside))
        #expect(try !matches(.leaf(.cidrContains(neighborBlock, scope: .source)), inside))
        // /0 contains every same-family address.
        #expect(try matches(.leaf(.cidrContains(allV4, scope: .either)), inside))
    }

    @Test("Port range is closed and honors scope and its edges")
    func portRangeEdges() throws {
        let s = session(source: ep("192.0.2.10", 1_024), destination: ep("198.51.100.5", 443))
        // Closed range includes both bounds.
        #expect(try matches(.leaf(.portInRange(lower: 443, upper: 443, scope: .destination)), s))
        #expect(try matches(.leaf(.portInRange(lower: 1_024, upper: 2_048, scope: .source)), s))
        #expect(try matches(.leaf(.portInRange(lower: 0, upper: 1_024, scope: .source)), s))
        // Just outside on either side is a miss.
        #expect(try !matches(.leaf(.portInRange(lower: 444, upper: 65_535, scope: .destination)), s))
        #expect(try !matches(.leaf(.portInRange(lower: 0, upper: 442, scope: .destination)), s))
        // Missing endpoint is a no-match.
        let bare = session(source: nil, destination: nil)
        #expect(try !matches(.leaf(.portInRange(lower: 0, upper: 65_535, scope: .either)), bare))
    }

    // MARK: Scalar session predicates

    @Test("Protocol/status/date/bytes hit and miss")
    func scalarPredicates() throws {
        let s = session(
            protocolStack: [.tcp, .tls, .http2],
            status: .warning,
            startTime: Date(timeIntervalSince1970: 1_000),
            bytesUp: 400, bytesDown: 600
        )
        #expect(try matches(.leaf(.protocolStackContains(.tls)), s))
        #expect(try !matches(.leaf(.protocolStackContains(.quic)), s))
        #expect(try matches(.leaf(.statusEquals(.warning)), s))
        #expect(try !matches(.leaf(.statusEquals(.ok)), s))
        let lo = Date(timeIntervalSince1970: 900)
        let hi = Date(timeIntervalSince1970: 1_100)
        #expect(try matches(.leaf(.startDateInRange(lower: lo, upper: hi)), s))
        #expect(try !matches(.leaf(.startDateInRange(lower: hi, upper: Date(timeIntervalSince1970: 1_200))), s))
        #expect(try matches(.leaf(.totalBytesInRange(lower: 1_000, upper: 1_000)), s))
        #expect(try !matches(.leaf(.totalBytesInRange(lower: 0, upper: 999)), s))
    }

    @Test("Total-byte overflow and negative components fail closed to no-match")
    func totalBytesFailsClosed() throws {
        let overflow = session(bytesUp: Int.max, bytesDown: 1)
        #expect(try !matches(.leaf(.totalBytesInRange(lower: 0, upper: Int.max)), overflow))
        let negative = session(bytesUp: -5, bytesDown: 10)
        #expect(try !matches(.leaf(.totalBytesInRange(lower: 0, upper: Int.max)), negative))
    }

    // MARK: hasEvidence — typed presence

    @Test("hasEvidence over the seven typed session facts is two-valued presence")
    func evidenceTypedPresence() throws {
        let full = session(
            processName: "proc", source: ep("192.0.2.10", 1), destination: ep("198.51.100.5", 2),
            latency: 12.5, sni: "secure.example", dnsQuery: "secure.example", dnsAnswers: ["203.0.113.9"]
        )
        let fields: [QueryEvidenceField] = [
            .processAttribution, .latency, .dnsQuery, .dnsAnswer,
            .serverNameIndication, .sourceEndpoint, .destinationEndpoint,
        ]
        for field in fields {
            #expect(try matches(.leaf(.hasEvidence(field)), full), "\(field) should be present")
        }
        let bare = session(
            processName: nil, source: nil, destination: nil,
            latency: nil, sni: nil, dnsQuery: nil, dnsAnswers: []
        )
        for field in fields {
            #expect(try !matches(.leaf(.hasEvidence(field)), bare), "\(field) should be absent")
        }
    }

    // MARK: Three-valued finding logic + applicability + join

    @Test("A retained connection finding is a match; joins by tuple-derived session id")
    func connectionFindingMatch() throws {
        let tuple = tcpTuple
        let snap = snapshot(
            sessions: [tcpSession(for: tuple)],
            connections: connectionSnapshot([resetSummary(tuple: tuple)])
        )
        let result = try run(.leaf(.findingKind(.reset)), over: snap)
        #expect(result.matched.map(\.id) == [SessionBuilder.sessionID(for: tuple)])
        #expect(result.indeterminate.isEmpty)
    }

    @Test("An absent but applicable finding is indeterminate; an inapplicable kind is a known no-match")
    func findingApplicability() throws {
        // A TCP session with no finding: reset applies but is absent -> indeterminate.
        let tcp = tcpSession(for: tcpTuple)
        let tcpSnap = snapshot(sessions: [tcp])
        let applicable = try run(.leaf(.findingKind(.reset)), over: tcpSnap)
        #expect(applicable.matched.isEmpty)
        #expect(applicable.indeterminate == [tcp.id])

        // dnsTruncation cannot apply to a TCP stack -> known no-match (neither list).
        let inapplicable = try run(.leaf(.findingKind(.dnsTruncation)), over: tcpSnap)
        #expect(inapplicable.matched.isEmpty)
        #expect(inapplicable.indeterminate.isEmpty)

        // A reset kind cannot apply to a UDP-DNS stack -> known no-match.
        let dns = session(protocolStack: [.udp, .dns])
        let dnsSnap = snapshot(sessions: [dns])
        let tcpOnUDP = try run(.leaf(.findingKind(.reset)), over: dnsSnap)
        #expect(tcpOnUDP.matched.isEmpty)
        #expect(tcpOnUDP.indeterminate.isEmpty)
    }

    @Test("A retained DNS truncation finding matches its UDP-DNS session")
    func datagramFindingMatch() throws {
        let tuple = dnsTuple
        let sessionID = SessionBuilder.sessionID(for: tuple)
        let snap = snapshot(
            sessions: [session(id: sessionID, protocolStack: [.udp, .dns])],
            datagram: datagramSnapshot([truncatedDNSSummary(tuple: tuple, sessionID: sessionID)])
        )
        let result = try run(.leaf(.findingKind(.dnsTruncation)), over: snap)
        #expect(result.matched.map(\.id) == [sessionID])
    }

    @Test("hasEvidence(anyFinding) is three-valued: present matches, absent is indeterminate")
    func anyFindingThreeValued() throws {
        let tuple = tcpTuple
        let withFinding = snapshot(
            sessions: [tcpSession(for: tuple)],
            connections: connectionSnapshot([resetSummary(tuple: tuple)])
        )
        let present = try run(.leaf(.hasEvidence(.anyFinding)), over: withFinding)
        #expect(present.matched.map(\.id) == [SessionBuilder.sessionID(for: tuple)])

        let bare = tcpSession(for: tuple)
        let absent = try run(.leaf(.hasEvidence(.anyFinding)), over: snapshot(sessions: [bare]))
        #expect(absent.matched.isEmpty)
        #expect(absent.indeterminate == [bare.id])
    }

    @Test("A finding for an absent session yields no orphan result")
    func noOrphanResult() throws {
        // The only present session is unrelated to the finding's tuple.
        let present = tcpSession(for: tcpTuple)
        let snap = snapshot(
            sessions: [present],
            connections: connectionSnapshot([resetSummary(tuple: otherTCPTuple)])
        )
        let result = try run(.leaf(.findingKind(.reset)), over: snap)
        // No match is fabricated for the orphan finding; the present session is merely
        // indeterminate (applicable, no finding of its own).
        #expect(result.matched.isEmpty)
        #expect(result.indeterminate == [present.id])
    }

    // MARK: Kleene NOT / ALL / ANY

    @Test("NOT maps match<->no-match and preserves indeterminate")
    func notSemantics() throws {
        let tuple = tcpTuple
        let snap = snapshot(sessions: [tcpSession(for: tuple)])
        let sid = SessionBuilder.sessionID(for: tuple)
        // not(match) -> no-match.
        #expect(try run(.not(.leaf(.statusEquals(.ok))), over: snap).matched.isEmpty)
        // not(no-match) -> match.
        #expect(try run(.not(.leaf(.statusEquals(.error))), over: snap).matched.map(\.id) == [sid])
        // not(indeterminate) -> indeterminate.
        #expect(try run(.not(.leaf(.findingKind(.reset))), over: snap).indeterminate == [sid])
    }

    @Test("ALL is no-match if any child is, else indeterminate if any child is, else match")
    func allSemantics() throws {
        let tuple = tcpTuple
        let snap = snapshot(sessions: [tcpSession(for: tuple)])
        let sid = SessionBuilder.sessionID(for: tuple)
        let match = InvestigationQuery.leaf(.statusEquals(.ok))
        let noMatch = InvestigationQuery.leaf(.statusEquals(.error))
        let indeterminate = InvestigationQuery.leaf(.findingKind(.reset))
        #expect(try run(.all([match, match]), over: snap).matched.map(\.id) == [sid])
        #expect(try run(.all([match, indeterminate]), over: snap).indeterminate == [sid])
        // A single no-match dominates even alongside an indeterminate.
        let result = try run(.all([indeterminate, noMatch]), over: snap)
        #expect(result.matched.isEmpty)
        #expect(result.indeterminate.isEmpty)
    }

    @Test("ANY is match if any child is, else indeterminate if any child is, else no-match")
    func anySemantics() throws {
        let tuple = tcpTuple
        let snap = snapshot(sessions: [tcpSession(for: tuple)])
        let sid = SessionBuilder.sessionID(for: tuple)
        let match = InvestigationQuery.leaf(.statusEquals(.ok))
        let noMatch = InvestigationQuery.leaf(.statusEquals(.error))
        let indeterminate = InvestigationQuery.leaf(.findingKind(.reset))
        // A single match dominates even alongside an indeterminate.
        #expect(try run(.any([indeterminate, match]), over: snap).matched.map(\.id) == [sid])
        #expect(try run(.any([noMatch, indeterminate]), over: snap).indeterminate == [sid])
        let result = try run(.any([noMatch, noMatch]), over: snap)
        #expect(result.matched.isEmpty)
        #expect(result.indeterminate.isEmpty)
    }

    // MARK: Stable order, no duplication

    @Test("Matched and indeterminate collections preserve snapshot order without duplication")
    func stableOrder() throws {
        // Four sessions in a fixed order; a query that matches #0 and #2, and leaves
        // #1 and #3 indeterminate.
        let s0 = session(id: id(0), protocolStack: [.tcp], status: .ok)
        let s1 = session(id: id(1), protocolStack: [.tcp], status: .warning)
        let s2 = session(id: id(2), protocolStack: [.tcp], status: .ok)
        let s3 = session(id: id(3), protocolStack: [.tcp], status: .warning)
        let snap = snapshot(sessions: [s0, s1, s2, s3])
        // ok -> match; otherwise (warning) fall back to the applicable-but-absent
        // reset finding, which is indeterminate.
        let query = InvestigationQuery.any([.leaf(.statusEquals(.ok)), .leaf(.findingKind(.reset))])
        let result = try run(query, over: snap)
        let matchedIDs = result.matched.map(\.id)
        #expect(matchedIDs == [id(0), id(2)])
        #expect(result.indeterminate == [id(1), id(3)])
    }

    // MARK: Validation — structural bounds

    @Test("Empty groups are rejected")
    func emptyGroupsRejected() {
        #expect(throws: QueryValidationError.emptyGroup) { _ = try engine().compile(.all([])) }
        #expect(throws: QueryValidationError.emptyGroup) { _ = try engine().compile(.any([])) }
    }

    @Test("Node, depth and child ceilings are enforced")
    func structuralCeilings() {
        let leaf = InvestigationQuery.leaf(.statusEquals(.ok))
        // Node cap: a group plus two leaves is three nodes.
        let nodeEngine = engine(.init(maxNodes: 2))
        #expect(throws: QueryValidationError.nodeCountExceeded(limit: 2)) {
            _ = try nodeEngine.compile(.all([leaf, leaf]))
        }
        // Child cap.
        let childEngine = engine(.init(maxChildrenPerGroup: 2))
        #expect(throws: QueryValidationError.childCountExceeded(limit: 2)) {
            _ = try childEngine.compile(.all([leaf, leaf, leaf]))
        }
        // Depth cap: root is depth 1, so not(not(leaf)) reaches depth 3.
        let depthEngine = engine(.init(maxDepth: 2))
        #expect(throws: QueryValidationError.depthExceeded(limit: 2)) {
            _ = try depthEngine.compile(.not(.not(leaf)))
        }
    }

    @Test("Configuration clamps ceilings downward only, never upward")
    func configurationClamps() {
        let raised = InvestigationQueryEngine.Configuration(
            maxNodes: 10_000, maxDepth: 99, maxChildrenPerGroup: 999, maxTextUTF8Bytes: 9_999
        )
        #expect(raised.maxNodes == 128)
        #expect(raised.maxDepth == 8)
        #expect(raised.maxChildrenPerGroup == 16)
        #expect(raised.maxTextUTF8Bytes == 256)

        let lowered = InvestigationQueryEngine.Configuration(
            maxNodes: 4, maxDepth: 3, maxChildrenPerGroup: 2, maxTextUTF8Bytes: 5
        )
        #expect(lowered.maxNodes == 4)
        #expect(lowered.maxDepth == 3)
        #expect(lowered.maxChildrenPerGroup == 2)
        #expect(lowered.maxTextUTF8Bytes == 5)

        // A zero/negative request clamps up to the floor of one.
        #expect(InvestigationQueryEngine.Configuration(maxNodes: 0).maxNodes == 1)
    }

    // MARK: Validation — text and ranges

    @Test("Text operands reject empty, control-containing and overlength normalized strings")
    func textValidation() {
        #expect(throws: QueryValidationError.emptyText) {
            _ = try engine().compile(.leaf(.processContains("   ")))
        }
        #expect(throws: QueryValidationError.controlCharacterInText) {
            _ = try engine().compile(.leaf(.hostContains("ab\u{0007}cd")))
        }
        let overlong = String(repeating: "a", count: 257)
        #expect(throws: QueryValidationError.textTooLong(limit: 256)) {
            _ = try engine().compile(.leaf(.hostContains(overlong)))
        }
        // A lowered text ceiling bites earlier.
        #expect(throws: QueryValidationError.textTooLong(limit: 4)) {
            _ = try engine(.init(maxTextUTF8Bytes: 4)).compile(.leaf(.hostContains("hello")))
        }
    }

    @Test("Range operands reject reversal, negative bytes and non-finite dates")
    func rangeValidation() {
        #expect(throws: QueryValidationError.reversedRange) {
            _ = try engine().compile(.leaf(.portInRange(lower: 100, upper: 10, scope: .either)))
        }
        #expect(throws: QueryValidationError.reversedRange) {
            _ = try engine().compile(.leaf(.totalBytesInRange(lower: 10, upper: 1)))
        }
        #expect(throws: QueryValidationError.negativeByteBound) {
            _ = try engine().compile(.leaf(.totalBytesInRange(lower: -1, upper: 10)))
        }
        let lo = Date(timeIntervalSince1970: 100)
        let hi = Date(timeIntervalSince1970: 10)
        #expect(throws: QueryValidationError.reversedRange) {
            _ = try engine().compile(.leaf(.startDateInRange(lower: lo, upper: hi)))
        }
        let infinite = Date(timeIntervalSinceReferenceDate: .infinity)
        #expect(throws: QueryValidationError.nonFiniteDate) {
            _ = try engine().compile(.leaf(.startDateInRange(lower: infinite, upper: infinite)))
        }
    }

    // MARK: Coverage

    @Test("Coverage is present only when a finding predicate appears")
    func coveragePresence() throws {
        let snap = snapshot(sessions: [tcpSession(for: tcpTuple)])
        // No finding predicate -> no coverage.
        #expect(try run(.leaf(.statusEquals(.ok)), over: snap).coverage == nil)
        // A finding predicate -> coverage present.
        #expect(try run(.leaf(.findingKind(.reset)), over: snap).coverage != nil)
        #expect(try run(.leaf(.hasEvidence(.anyFinding)), over: snap).coverage != nil)
    }

    @Test("A clean, bounded-local context reports no coverage reasons")
    func cleanCoverage() throws {
        let snap = snapshot(
            sessions: [tcpSession(for: tcpTuple)],
            connections: connectionSnapshot([unmappedSummary(tuple: tcpTuple)])
        )
        let coverage = try #require(try run(.leaf(.hasEvidence(.anyFinding)), over: snap).coverage)
        #expect(coverage.isCleanBoundedLocalContext)
        #expect(coverage.reasons.isEmpty)
    }

    @Test("Every coverage reason is derivable from a snapshot fact")
    func everyCoverageReason() throws {
        try assertReason(.connectionSummaryOmission) {
            snapshot(sessions: [anySession], connections: connectionSnapshot([], omittedSummaryCount: 1))
        }
        try assertReason(.connectionFindingOmission) {
            // Two resets coalesce to one finding; a citation cap of 1 drops one.
            snapshot(
                sessions: [anySession],
                connections: connectionSnapshot([resetSummary(tuple: tcpTuple, resets: 2)]),
                connectionAssessor: ConnectionAssessor(configuration: .init(maxCitationsPerFinding: 1))
            )
        }
        try assertReason(.connectionEventOrStateLimitation) {
            snapshot(
                sessions: [anySession],
                connections: connectionSnapshot([resetSummary(tuple: tcpTuple, omittedEventCount: 3)])
            )
        }
        try assertReason(.datagramObservationOmission) {
            snapshot(sessions: [anySession], datagram: datagramSnapshot([], omittedObservationCount: 2))
        }
        try assertReason(.datagramFindingOmission) {
            snapshot(
                sessions: [anySession],
                datagram: datagramSnapshot([truncatedDNSSummary(tuple: dnsTuple, sessionID: dnsSessionID, tcCount: 2)]),
                datagramAssessor: DatagramAssessor(configuration: .init(maxCitationsPerFinding: 1))
            )
        }
        try assertReason(.excludedTCPDNSInput) {
            snapshot(sessions: [anySession], datagram: datagramSnapshot([], excludedTCPDNSFactCount: 1))
        }
        try assertReason(.capacityReached) {
            snapshot(sessions: [anySession], datagram: datagramSnapshot([], capacityReached: true))
        }
        try assertReason(.captureLossReported) {
            snapshot(
                sessions: [anySession],
                connections: connectionSnapshot([resetSummary(tuple: tcpTuple, loss: .lossReported)])
            )
        }
        try assertReason(.captureLossUnknown) {
            snapshot(
                sessions: [anySession],
                connections: connectionSnapshot([resetSummary(tuple: tcpTuple, loss: .unknown)])
            )
        }
        try assertReason(.counterOverflow) {
            snapshot(sessions: [anySession], connections: connectionSnapshot([], countersOverflowed: true))
        }
    }

    @Test("Datagram snap-length truncation qualifies finding coverage")
    func datagramSnapLengthCoverage() throws {
        let summary = DatagramEvidenceSummary(
            sessionID: dnsSessionID,
            tuple: dnsTuple,
            observations: [],
            omittedObservationCount: 0,
            lossKnowledge: .noLossReported,
            snapLengthTruncationObserved: true
        )
        try assertReason(.datagramObservationOmission) {
            snapshot(sessions: [anySession], datagram: datagramSnapshot([summary]))
        }
    }

    // MARK: Cancellation

    @Test("Cancellation throws before the first session")
    func cancelBeforeFirst() {
        let snap = snapshot(sessions: [anySession, anySession])
        #expect(throws: CancellationError.self) {
            _ = try run(.leaf(.statusEquals(.ok)), over: snap, isCancelled: { true })
        }
    }

    @Test("Cancellation throws between later sessions")
    func cancelBetweenSessions() throws {
        let s0 = session(id: id(0))
        let s1 = session(id: id(1))
        let snap = snapshot(sessions: [s0, s1])
        let probe = CancelProbe(trueOnCall: 2) // false for session 0, true before session 1
        #expect(throws: CancellationError.self) {
            _ = try run(.leaf(.statusEquals(.ok)), over: snap, isCancelled: { probe.next() })
        }
        // The probe was consulted exactly twice (before session 0, before session 1).
        #expect(probe.calls == 2)
    }

    // MARK: Private

    /// A mutable cancellation probe returning `true` on its `trueOnCall`-th invocation.
    private final class CancelProbe {
        // MARK: Lifecycle

        init(trueOnCall: Int) {
            self.trueOnCall = trueOnCall
        }

        // MARK: Internal

        private(set) var calls = 0

        func next() -> Bool {
            calls += 1
            return calls == trueOnCall
        }

        // MARK: Private

        private let trueOnCall: Int
    }

    // Fixed endpoints/tuples.

    private var tcpTuple: FiveTuple {
        FiveTuple(proto: .tcp, source: ep("192.0.2.1", 5_000), destination: ep("198.51.100.1", 443))
    }

    private var otherTCPTuple: FiveTuple {
        FiveTuple(proto: .tcp, source: ep("192.0.2.2", 6_000), destination: ep("198.51.100.2", 443))
    }

    private var dnsTuple: FiveTuple {
        FiveTuple(proto: .udp, source: ep("192.0.2.9", 40_000), destination: ep("198.51.100.9", 53))
    }

    private var dnsSessionID: UUID {
        SessionBuilder.sessionID(for: dnsTuple)
    }

    private var v4Session: SessionSummary {
        session(source: ep("192.0.2.10", 1_234), destination: ep("198.51.100.5", 443))
    }

    private var v6Session: SessionSummary {
        session(source: ep("2001:db8::10", 1_234), destination: ep("2001:db8:1::5", 443))
    }

    private var anySession: SessionSummary {
        session()
    }

    private func engine(
        _ configuration: InvestigationQueryEngine.Configuration = .init()
    )
        -> InvestigationQueryEngine
    {
        InvestigationQueryEngine(configuration: configuration)
    }

    private func id(_ index: Int) -> UUID {
        SessionBuilder.stableID("investigation-query-test-session-\(index)")
    }

    private func ep(_ ip: String, _ port: UInt16) -> IPEndpoint {
        IPEndpoint(ip: ip, port: port)
    }

    private func run(
        _ query: InvestigationQuery,
        over snapshot: InvestigationSnapshot,
        queryEngine: InvestigationQueryEngine = InvestigationQueryEngine(),
        isCancelled: () -> Bool = { false }
    )
        throws -> InvestigationQueryResult
    {
        let compiled = try queryEngine.compile(query)
        return try queryEngine.evaluate(compiled, over: snapshot, isCancelled: isCancelled)
    }

    /// Whether a single-session snapshot matches `query` (a match, not indeterminate).
    private func matches(_ query: InvestigationQuery, _ session: SessionSummary) throws -> Bool {
        let result = try run(query, over: snapshot(sessions: [session]))
        return result.matched.contains { $0.id == session.id }
    }

    /// Compile-and-evaluate `hasEvidence(anyFinding)` over the built snapshot and assert
    /// its coverage contains `reason`.
    private func assertReason(
        _ reason: QueryCoverageReason,
        _ build: () -> InvestigationSnapshot
    )
        throws
    {
        let result = try run(.leaf(.hasEvidence(.anyFinding)), over: build())
        let coverage = try #require(result.coverage)
        #expect(coverage.reasons.contains(reason), "expected coverage reason \(reason)")
    }

    // Snapshot/fold construction.

    private func snapshot(
        sessions: [SessionSummary],
        connections: ConnectionTable.Snapshot? = nil,
        datagram: DatagramEvidenceTable.Snapshot? = nil,
        connectionAssessor: ConnectionAssessor = ConnectionAssessor(),
        datagramAssessor: DatagramAssessor = DatagramAssessor()
    )
        -> InvestigationSnapshot
    {
        let fold = SessionFoldSnapshot(
            sessions: sessions,
            connections: connections ?? connectionSnapshot([]),
            datagramEvidence: datagram ?? .empty,
            tlsEvidence: .empty
        )
        return InvestigationSnapshot(
            fold: fold, connectionAssessor: connectionAssessor, datagramAssessor: datagramAssessor
        )
    }

    private func tcpSession(for tuple: FiveTuple) -> SessionSummary {
        session(id: SessionBuilder.sessionID(for: tuple), protocolStack: [.tcp])
    }

    private func session(
        id: UUID = SessionBuilder.stableID("investigation-query-test-default"),
        processName: String? = nil,
        host: String = "host.example",
        source: IPEndpoint? = nil,
        destination: IPEndpoint? = nil,
        protocolStack: [ProtocolKind] = [.tcp],
        status: SessionStatus = .ok,
        startTime: Date = Date(timeIntervalSince1970: 1_000),
        latency: Double? = nil,
        bytesUp: Int = 0,
        bytesDown: Int = 0,
        sni: String? = nil,
        dnsQuery: String? = nil,
        dnsAnswers: [String] = []
    )
        -> SessionSummary
    {
        SessionSummary(
            id: id,
            startTime: startTime,
            duration: 0,
            processName: processName,
            host: host,
            sourceEndpoint: source?.display ?? "—",
            destinationEndpoint: destination?.display ?? "—",
            sourceEndpointValue: source,
            destinationEndpointValue: destination,
            protocolStack: protocolStack,
            status: status,
            latencyMilliseconds: latency,
            bytesUp: bytesUp,
            bytesDown: bytesDown,
            sni: sni,
            dnsQuery: dnsQuery,
            dnsAnswers: dnsAnswers
        )
    }

    // Connection evidence.

    private func connectionSnapshot(
        _ summaries: [ConnectionSummary],
        omittedSummaryCount: UInt64 = 0,
        countersOverflowed: Bool = false
    )
        -> ConnectionTable.Snapshot
    {
        ConnectionTable.Snapshot(
            summaries: summaries,
            omittedSummaryCount: omittedSummaryCount,
            activeConnectionCount: summaries.count,
            publishedSummaryCount: summaries.count,
            retainedEventCount: summaries.reduce(0) { $0 + $1.events.count },
            countersOverflowed: countersOverflowed
        )
    }

    private func resetSummary(
        tuple: FiveTuple,
        resets: Int = 1,
        loss: CaptureLossKnowledge = .noLossReported,
        limitations: ConnectionLimitations = [],
        omittedEventCount: UInt64 = 0
    )
        -> ConnectionSummary
    {
        let connectionID = ConnectionID(tuple: tuple, firstOrdinal: FrameOrdinal(1))
        let events = (0 ..< max(1, resets)).map { index in
            ConnectionEvent(
                connectionID: connectionID,
                kind: .rst,
                timestamp: Date(timeIntervalSince1970: Double(index + 2)),
                provenance: provenance(UInt64(index + 2)),
                direction: .aToB
            )
        }
        return ConnectionSummary(
            id: connectionID,
            tuple: tuple,
            firstProvenance: provenance(1),
            lastProvenance: provenance(UInt64(events.count + 1)),
            initiator: .aToB,
            phase: .active,
            handshake: .none,
            finDirections: [],
            closeReason: nil,
            packetCount: UInt64(events.count),
            capturedByteTotal: 0,
            originalByteTotal: 0,
            lossKnowledge: loss,
            limitations: limitations,
            events: events,
            omittedEventCount: omittedEventCount
        )
    }

    private func unmappedSummary(tuple: FiveTuple) -> ConnectionSummary {
        let connectionID = ConnectionID(tuple: tuple, firstOrdinal: FrameOrdinal(1))
        let event = ConnectionEvent(
            connectionID: connectionID,
            kind: .firstObserved,
            timestamp: Date(timeIntervalSince1970: 1),
            provenance: provenance(1),
            direction: .aToB
        )
        return ConnectionSummary(
            id: connectionID,
            tuple: tuple,
            firstProvenance: provenance(1),
            lastProvenance: provenance(1),
            initiator: .aToB,
            phase: .active,
            handshake: .none,
            finDirections: [],
            closeReason: nil,
            packetCount: 1,
            capturedByteTotal: 0,
            originalByteTotal: 0,
            lossKnowledge: .noLossReported,
            limitations: [],
            events: [event],
            omittedEventCount: 0
        )
    }

    // Datagram evidence.

    private func datagramSnapshot(
        _ summaries: [DatagramEvidenceSummary],
        omittedObservationCount: UInt64 = 0,
        excludedTCPDNSFactCount: UInt64 = 0,
        capacityReached: Bool = false,
        countersOverflowed: Bool = false
    )
        -> DatagramEvidenceTable.Snapshot
    {
        DatagramEvidenceTable.Snapshot(
            summaries: summaries,
            omittedObservationCount: omittedObservationCount,
            retainedObservationCount: summaries.reduce(0) { $0 + $1.observations.count },
            excludedTCPDNSFactCount: excludedTCPDNSFactCount,
            capacityReached: capacityReached,
            countersOverflowed: countersOverflowed
        )
    }

    private func truncatedDNSSummary(
        tuple: FiveTuple,
        sessionID: UUID,
        tcCount: Int = 1
    )
        -> DatagramEvidenceSummary
    {
        let observations = (0 ..< max(1, tcCount)).map { index in
            DatagramEvidenceObservation(
                sessionID: sessionID,
                tuple: tuple,
                direction: .bToA,
                provenance: provenance(UInt64(index + 1)),
                kind: .dns(dnsFacts(truncated: true))
            )
        }
        return DatagramEvidenceSummary(
            sessionID: sessionID,
            tuple: tuple,
            observations: observations,
            omittedObservationCount: 0,
            lossKnowledge: .noLossReported,
            snapLengthTruncationObserved: false
        )
    }

    private func dnsFacts(truncated: Bool) -> DNSMessageFacts {
        var bytes = [UInt8](repeating: 0, count: 12)
        let flags: UInt16 = truncated ? 0x0200 : 0x0000
        bytes[2] = UInt8(flags >> 8)
        bytes[3] = UInt8(flags & 0xFF)
        // The fixed 12-byte header parses cleanly; only the TC bit is exercised here.
        // A full 12-byte header never fails the bounds check.
        guard let facts = try? DNSMessageFacts(dnsHeader: PacketBuffer(bytes)) else {
            fatalError("12-byte DNS header must parse")
        }
        return facts
    }

    private func provenance(_ ordinal: UInt64) -> SessionFrameProvenance {
        SessionFrameProvenance(
            ordinal: FrameOrdinal(ordinal),
            timestamp: Date(timeIntervalSince1970: Double(ordinal)),
            capturedLength: 100,
            originalLength: 100,
            linkType: 1
        )
    }
}
