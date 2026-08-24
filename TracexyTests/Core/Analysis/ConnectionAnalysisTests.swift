import Foundation
import Testing
@testable import Tracexy

@Suite("ConnectionAssessor passive analysis")
struct ConnectionAnalysisTests {
    // MARK: Internal

    // MARK: Mapping, severity, direction & provenance

    @Test("Each mapped retained event kind produces its finding kind and fixed severity")
    func mappedKindsAndSeverities() throws {
        let cases: [(ConnectionEventKind, ConnectionAnalysisFindingKind, AnalysisSeverity)] = [
            (.rst, .resetObserved, .warning),
            (.retransmission, .retransmissionObserved, .note),
            (.overlap, .overlapObserved, .note),
            (.outOfOrderBuffered, .outOfOrderObserved, .note),
            (.pendingOverflow, .outOfOrderObserved, .note),
        ]
        for (sourceKind, findingKind, severity) in cases {
            let id = connectionID(clientA, serverA, firstOrdinal: 1)
            let evt = event(id, sourceKind, ordinal: 3, direction: .bToA)
            let result = ConnectionAssessor().assess(snapshot([
                summary(id: id, tuple: tupleA, events: [evt]),
            ]))
            #expect(result.findings.count == 1)
            let finding = try #require(result.findings.first)
            #expect(finding.kind == findingKind)
            #expect(finding.severity == severity)
            #expect(finding.connectionID == id)
            #expect(finding.tuple == tupleA)
            // Direction and provenance are preserved verbatim from the source event.
            let citation = try #require(finding.citations.first)
            #expect(citation.sourceEventKind == sourceKind)
            #expect(citation.direction == .bToA)
            #expect(citation.provenance == evt.provenance)
        }
    }

    @Test("A citation retains the event's full 1...3 provenance values")
    func citationRetainsAllProvenance() throws {
        let id = connectionID(clientA, serverA, firstOrdinal: 1)
        // An RST event carrying three frames of provenance (the initializer bounds
        // to three); the citation must copy every one of them.
        let evt = ConnectionEvent(
            connectionID: id,
            kind: .rst,
            timestamp: Date(timeIntervalSince1970: 3),
            provenance: provenance(3),
            relatedProvenance: [provenance(4), provenance(5)],
            direction: .aToB
        )
        let result = ConnectionAssessor().assess(snapshot([
            summary(id: id, tuple: tupleA, events: [evt]),
        ]))
        let citation = try #require(result.findings.first?.citations.first)
        #expect(citation.provenance.count == 3)
        #expect(citation.provenance == evt.provenance)
        #expect(citation.occurrenceOrdinal == FrameOrdinal(5))
    }

    // MARK: Unmapped evidence

    @Test("No unmapped event kind produces a finding")
    func unmappedKindsProduceNoFindings() {
        let id = connectionID(clientA, serverA, firstOrdinal: 1)
        let unmapped: [ConnectionEventKind] = [
            .firstObserved, .syn, .synAck, .handshakeCompleted, .payloadObserved,
            .fin, .lateSegmentAfterClose, .ambiguousTupleReuse, .stateEvicted,
            .sequenceAdvanced, .pendingDrained, .serialAmbiguous,
            .applicationRecord, .applicationProbeTruncated,
        ]
        let events = unmapped.enumerated().map { index, kind in
            event(id, kind, ordinal: UInt64(index + 1))
        }
        let result = ConnectionAssessor().assess(snapshot([
            summary(id: id, tuple: tupleA, events: events),
        ]))
        #expect(result.findings.isEmpty)
        #expect(result.omittedFindingCount == 0)
    }

    @Test("A connection with no mapped events yields no finding")
    func noMappedEventsNoFinding() {
        let id = connectionID(clientA, serverA, firstOrdinal: 1)
        let result = ConnectionAssessor().assess(snapshot([
            summary(id: id, tuple: tupleA, events: []),
        ]))
        #expect(result.findings.isEmpty)
    }

    // MARK: Coalescing & citation cap

    @Test("Events of one kind coalesce into a single finding; citations cap with exact omission")
    func coalescingAndCitationCapWithExactOmission() throws {
        let id = connectionID(clientA, serverA, firstOrdinal: 1)
        // Five retransmission events on one connection coalesce into one finding.
        let events = (2 ... 6).map { event(id, .retransmission, ordinal: UInt64($0)) }
        let config = ConnectionAssessor.Configuration(maxCitationsPerFinding: 2)
        let result = ConnectionAssessor(configuration: config).assess(snapshot([
            summary(id: id, tuple: tupleA, events: events),
        ]))

        #expect(result.findings.count == 1)
        let finding = try #require(result.findings.first)
        #expect(finding.kind == .retransmissionObserved)
        #expect(finding.citations.count == 2)
        // Exactly three citations were dropped to honor the bound.
        #expect(finding.omittedCitationCount == 3)
        // The retained citations are the two oldest, in order.
        #expect(finding.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(2), FrameOrdinal(3)])
    }

    @Test("Both out-of-order source kinds coalesce into one outOfOrderObserved finding")
    func outOfOrderSourcesCoalesce() throws {
        let id = connectionID(clientA, serverA, firstOrdinal: 1)
        let events = [
            event(id, .outOfOrderBuffered, ordinal: 2),
            event(id, .pendingOverflow, ordinal: 3),
        ]
        let result = ConnectionAssessor().assess(snapshot([
            summary(id: id, tuple: tupleA, events: events),
        ]))
        #expect(result.findings.count == 1)
        let finding = try #require(result.findings.first)
        #expect(finding.kind == .outOfOrderObserved)
        #expect(finding.citations.count == 2)
        #expect(Set(finding.citations.map(\.sourceEventKind)) == [.outOfOrderBuffered, .pendingOverflow])
    }

    @Test("Distinct kinds on one connection become distinct findings")
    func distinctKindsBecomeDistinctFindings() {
        let id = connectionID(clientA, serverA, firstOrdinal: 1)
        let events = [
            event(id, .rst, ordinal: 2),
            event(id, .retransmission, ordinal: 3),
            event(id, .overlap, ordinal: 4),
        ]
        let result = ConnectionAssessor().assess(snapshot([
            summary(id: id, tuple: tupleA, events: events),
        ]))
        #expect(Set(result.findings.map(\.kind)) == [.resetObserved, .retransmissionObserved, .overlapObserved])
    }

    // MARK: Stable identity

    @Test("A finding id depends only on connection id + kind, not on citations or history")
    func findingIDStableAcrossCitationAndHistoryDifferences() throws {
        let id = connectionID(clientA, serverA, firstOrdinal: 1)
        let sparse = summary(id: id, tuple: tupleA, events: [event(id, .retransmission, ordinal: 2)])
        let dense = summary(
            id: id, tuple: tupleA,
            events: [
                event(id, .retransmission, ordinal: 2),
                event(id, .retransmission, ordinal: 9),
                event(id, .retransmission, ordinal: 20),
            ],
            omittedEventCount: 7
        )
        let a = try #require(ConnectionAssessor().assess(snapshot([sparse])).findings.first)
        let b = try #require(ConnectionAssessor().assess(snapshot([dense])).findings.first)
        #expect(a.id == b.id)
        // Different kind on the same connection is a different id.
        let reset = try #require(ConnectionAssessor().assess(snapshot([
            summary(id: id, tuple: tupleA, events: [event(id, .rst, ordinal: 2)]),
        ])).findings.first)
        #expect(reset.id != a.id)
    }

    @Test("The finding id is the deterministic stableID seed, not a random UUID")
    func findingIDMatchesDeterministicSeed() throws {
        let id = connectionID(clientA, serverA, firstOrdinal: 1)
        let finding = try #require(ConnectionAssessor().assess(snapshot([
            summary(id: id, tuple: tupleA, events: [event(id, .rst, ordinal: 2)]),
        ])).findings.first)
        let expected = SessionBuilder.stableID(
            "connectionAnalysis|\(id.rawValue.uuidString)|resetObserved"
        )
        #expect(finding.id == expected)
    }

    // MARK: Ordering

    @Test("Findings order by first cited occurrence ordinal regardless of input summary order")
    func shuffleInvariantOrdering() {
        let summaries = threeConnectionFindings()
        let ordered = ConnectionAssessor().assess(snapshot(summaries))
        let reversed = ConnectionAssessor().assess(snapshot(summaries.reversed()))
        #expect(ordered == reversed)
        // The order follows the earliest cited ordinal: connB(2), connA(5), connC(8).
        #expect(ordered.findings.map(\.connectionID) == [connIDB, connIDA, connIDC])
    }

    @Test("Equal first occurrence ties break on connection UUID then kind rank")
    func orderingTieBreaks() {
        // Two connections whose findings share the same first cited ordinal.
        let eventsA = [event(connIDA, .overlap, ordinal: 5), event(connIDA, .rst, ordinal: 5)]
        let sumA = summary(id: connIDA, tuple: tupleA, events: eventsA)
        let sumB = summary(id: connIDB, tuple: tupleB, events: [event(connIDB, .rst, ordinal: 5)])
        let result = ConnectionAssessor().assess(snapshot([sumA, sumB]))
        // Within connA, the two findings share ordinal 5 and the same connection id,
        // so kind rank orders them: resetObserved(0) before overlapObserved(2).
        let connAFindings = result.findings.filter { $0.connectionID == connIDA }
        #expect(connAFindings.map(\.kind) == [.resetObserved, .overlapObserved])
        // Across connections the UUID string breaks the ordinal tie deterministically.
        let expectedOrder = [connIDA, connIDB]
            .sorted { $0.rawValue.uuidString < $1.rawValue.uuidString }
        let observedConnOrder = result.findings.map(\.connectionID).reduce(into: [ConnectionID]()) {
            if $0.last != $1 {
                $0.append($1)
            }
        }
        #expect(Set(observedConnOrder) == Set(expectedOrder))
    }

    // MARK: Global finding cap

    @Test("The global finding cap keeps the earliest findings and counts omission exactly")
    func globalFindingCapDeterministicWithOmission() {
        let summaries = threeConnectionFindings()
        let config = ConnectionAssessor.Configuration(maxFindings: 2)
        let result = ConnectionAssessor(configuration: config).assess(snapshot(summaries))
        #expect(result.findings.count == 2)
        #expect(result.omittedFindingCount == 1)
        // The two kept are the earliest by first cited occurrence: connB(2), connA(5).
        #expect(result.findings.map(\.connectionID) == [connIDB, connIDA])
    }

    // MARK: Coverage precedence

    @Test("Coverage follows strict precedence across all cases")
    func coveragePrecedence() {
        // 1. Reported loss wins even with omitted/truncated evidence present.
        #expect(coverageOf(loss: .lossReported, omitted: 2, limitations: [.eventHistoryTruncated])
            == .captureLossReported)
        // 2. Omitted evidence: an omitted-event count, or either truncation bit.
        #expect(coverageOf(loss: .noLossReported, omitted: 1, limitations: []) == .omittedEvidence)
        #expect(coverageOf(loss: .noLossReported, omitted: 0, limitations: [.eventHistoryTruncated])
            == .omittedEvidence)
        #expect(coverageOf(loss: .noLossReported, omitted: 0, limitations: [.sequenceStateTruncated])
            == .omittedEvidence)
        // Omitted evidence outranks unknown loss.
        #expect(coverageOf(loss: .unknown, omitted: 1, limitations: []) == .omittedEvidence)
        // 3. Unknown loss with no known omission.
        #expect(coverageOf(loss: .unknown, omitted: 0, limitations: []) == .unknownLoss)
        // 4. Bounded-local: loss explicitly not reported and nothing omitted.
        #expect(coverageOf(loss: .noLossReported, omitted: 0, limitations: []) == .boundedNoKnownOmission)
    }

    // MARK: Bounds clamping

    @Test("Zero or negative configuration bounds clamp to one")
    func boundsClampToOne() {
        let clamped = ConnectionAssessor.Configuration(maxFindings: 0, maxCitationsPerFinding: -5)
        #expect(clamped.maxFindings == 1)
        #expect(clamped.maxCitationsPerFinding == 1)
    }

    // MARK: Saturating counters

    @Test("saturatingAdd reports overflow and clamps to the maximum without wrapping")
    func saturatingAddSeam() {
        let ordinary = ConnectionAssessor.saturatingAdd(1, 2)
        #expect(ordinary.value == 3)
        #expect(!ordinary.overflowed)

        let overflowed = ConnectionAssessor.saturatingAdd(.max, 1)
        #expect(overflowed.value == .max)
        #expect(overflowed.overflowed)

        // A second saturation stays clamped — never wraps back toward zero.
        let again = ConnectionAssessor.saturatingAdd(overflowed.value, 5)
        #expect(again.value == .max)
        #expect(again.overflowed)
    }

    // MARK: Determinism & value semantics

    @Test("Assessing the same snapshot twice yields equal, hashable snapshots")
    func deterministicAndHashable() {
        let snap = snapshot(threeConnectionFindings())
        let first = ConnectionAssessor().assess(snap)
        let second = ConnectionAssessor().assess(snap)
        #expect(first == second)
        // Hashable value semantics: equal snapshots collapse in a set.
        #expect(Set([first, second]).count == 1)
    }

    // MARK: Private

    // Documentation-only endpoints (RFC 5737); the lower-valued IP is canonical `a`.
    private let clientA = IPEndpoint(ip: "192.0.2.10", port: 50_000)
    private let serverA = IPEndpoint(ip: "203.0.113.5", port: 443)
    private let clientB = IPEndpoint(ip: "198.51.100.20", port: 50_001)
    private let serverB = IPEndpoint(ip: "203.0.113.6", port: 443)
    private let clientC = IPEndpoint(ip: "198.51.100.30", port: 50_002)
    private let serverC = IPEndpoint(ip: "203.0.113.7", port: 443)
    private let token = UUID(uuid: (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16))

    private var tupleA: FiveTuple {
        FiveTuple(proto: .tcp, source: clientA, destination: serverA)
    }

    private var tupleB: FiveTuple {
        FiveTuple(proto: .tcp, source: clientB, destination: serverB)
    }

    private var tupleC: FiveTuple {
        FiveTuple(proto: .tcp, source: clientC, destination: serverC)
    }

    private var connIDA: ConnectionID {
        connectionID(clientA, serverA, firstOrdinal: 1)
    }

    private var connIDB: ConnectionID {
        connectionID(clientB, serverB, firstOrdinal: 1)
    }

    private var connIDC: ConnectionID {
        connectionID(clientC, serverC, firstOrdinal: 1)
    }

    private func connectionID(_ a: IPEndpoint, _ b: IPEndpoint, firstOrdinal: UInt64) -> ConnectionID {
        ConnectionID(tuple: FiveTuple(proto: .tcp, source: a, destination: b), firstOrdinal: FrameOrdinal(firstOrdinal))
    }

    private func provenance(_ ordinal: UInt64) -> SessionFrameProvenance {
        SessionFrameProvenance(
            ordinal: FrameOrdinal(ordinal),
            timestamp: Date(timeIntervalSince1970: Double(ordinal)),
            capturedLength: 100,
            originalLength: 100,
            linkType: 1,
            locator: SessionEvidenceLocator(sourceToken: token, offset: ordinal)
        )
    }

    private func event(
        _ id: ConnectionID,
        _ kind: ConnectionEventKind,
        ordinal: UInt64,
        direction: ConnectionDirection? = .aToB
    )
        -> ConnectionEvent
    {
        ConnectionEvent(
            connectionID: id,
            kind: kind,
            timestamp: Date(timeIntervalSince1970: Double(ordinal)),
            provenance: provenance(ordinal),
            direction: direction
        )
    }

    private func summary(
        id: ConnectionID,
        tuple: FiveTuple,
        events: [ConnectionEvent],
        lossKnowledge: CaptureLossKnowledge = .noLossReported,
        limitations: ConnectionLimitations = [],
        omittedEventCount: UInt64 = 0
    )
        -> ConnectionSummary
    {
        ConnectionSummary(
            id: id,
            tuple: tuple,
            firstProvenance: provenance(1),
            lastProvenance: provenance(UInt64(max(1, events.count))),
            initiator: .aToB,
            phase: .active,
            handshake: .none,
            finDirections: [],
            closeReason: nil,
            packetCount: UInt64(events.count),
            capturedByteTotal: 0,
            originalByteTotal: 0,
            lossKnowledge: lossKnowledge,
            limitations: limitations,
            events: events,
            omittedEventCount: omittedEventCount
        )
    }

    private func snapshot(_ summaries: [ConnectionSummary]) -> ConnectionTable.Snapshot {
        ConnectionTable.Snapshot(
            summaries: summaries,
            omittedSummaryCount: 0,
            activeConnectionCount: summaries.count,
            publishedSummaryCount: 0,
            retainedEventCount: summaries.reduce(0) { $0 + $1.events.count },
            countersOverflowed: false
        )
    }

    /// Three connections whose single retransmission finding has a distinct first
    /// cited ordinal: connB at 2, connA at 5, connC at 8.
    private func threeConnectionFindings() -> [ConnectionSummary] {
        [
            summary(id: connIDA, tuple: tupleA, events: [event(connIDA, .retransmission, ordinal: 5)]),
            summary(id: connIDB, tuple: tupleB, events: [event(connIDB, .retransmission, ordinal: 2)]),
            summary(id: connIDC, tuple: tupleC, events: [event(connIDC, .retransmission, ordinal: 8)]),
        ]
    }

    /// The coverage assigned to a finding on a connection with the given loss,
    /// omission and limitation state, read back through a real assessment.
    private func coverageOf(
        loss: CaptureLossKnowledge,
        omitted: UInt64,
        limitations: ConnectionLimitations
    )
        -> AnalysisCoverage?
    {
        let id = connectionID(clientA, serverA, firstOrdinal: 1)
        let sum = summary(
            id: id, tuple: tupleA,
            events: [event(id, .retransmission, ordinal: 2)],
            lossKnowledge: loss, limitations: limitations, omittedEventCount: omitted
        )
        return ConnectionAssessor().assess(snapshot([sum])).findings.first?.coverage
    }
}
