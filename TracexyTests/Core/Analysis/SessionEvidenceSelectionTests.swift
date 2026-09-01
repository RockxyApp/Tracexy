import Foundation
import Testing
@testable import Tracexy

// MARK: - SessionEvidenceSelectionTests

/// The pure selected-session projection must return every retained connection
/// incarnation for a tuple-derived session in the snapshot's deterministic order,
/// the zero-or-one shared tuple-scoped TLS summary without pairing it to an
/// incarnation, and every per-summary and capture-level coverage fact verbatim.
struct SessionEvidenceSelectionTests {
    // MARK: Internal

    @Test("Two reused-tuple incarnations project in order with one shared TLS summary")
    func reusedTupleIncarnationsAndSharedTLS() {
        let tuple = Self.tuple
        let sessionID = SessionBuilder.sessionID(for: tuple)
        let first = Self.connection(tuple: tuple, firstOrdinal: 1, phase: .closed)
        let second = Self.connection(tuple: tuple, firstOrdinal: 3, phase: .opening)
        // A different tuple/session that must never leak into this selection.
        let other = Self.connection(tuple: Self.otherTuple, firstOrdinal: 2, phase: .active)

        let snapshot = Self.snapshot(
            connections: Self.connectionSnapshot(
                [first, other, second], omittedSummary: 2, active: 1, published: 3, retainedEvents: 4
            ),
            tls: Self.tlsSnapshot(
                [Self.tlsSummary(for: tuple)], omitted: 3, excluded: 1, recoveredTrunc: 0, decoderTrunc: 2,
                capacity: true
            )
        )

        let selection = snapshot.selectingSession(sessionID)

        // Both incarnations, in first-observed snapshot order; the other tuple is out.
        #expect(selection.connections == [first, second])
        #expect(selection.connections.count == 2)
        #expect(Set(selection.connections.map(\.id)).count == 2) // distinct incarnations
        #expect(selection.connections.allSatisfy { $0.tuple == tuple })

        // Exactly one shared tuple/session-scoped TLS summary, never paired to an id.
        #expect(selection.tls?.sessionID == sessionID)
        #expect(selection.tls?.tuple == tuple)
        #expect(!selection.isEmpty)

        // Per-summary coverage is carried verbatim inside the retained values.
        #expect(selection.tls?.decoderTruncatedFrameCount == 2)
        #expect(selection.tls?.snapLengthTruncationObserved == true)
        #expect(selection.connections[0].lossKnowledge == first.lossKnowledge)

        // Capture-level coverage is carried verbatim.
        #expect(selection.connectionCoverage.omittedSummaryCount == 2)
        #expect(selection.connectionCoverage.activeConnectionCount == 1)
        #expect(selection.connectionCoverage.publishedSummaryCount == 3)
        #expect(selection.connectionCoverage.retainedEventCount == 4)
        #expect(selection.tlsCoverage.omittedObservationCount == 3)
        #expect(selection.tlsCoverage.excludedReassembledRecordCount == 1)
        #expect(selection.tlsCoverage.decoderTruncatedFrameCount == 2)
        #expect(selection.tlsCoverage.capacityReached)
    }

    @Test("A missing selected summary keeps capture-level coverage as global unknown coverage")
    func missingSummaryPreservesCaptureLevelCoverage() {
        // The snapshot has evidence for `tuple`, but we select an unrelated session id.
        let snapshot = Self.snapshot(
            connections: Self.connectionSnapshot(
                [Self.connection(tuple: Self.tuple, firstOrdinal: 1, phase: .closed)],
                omittedSummary: 7, active: 2, published: 1, retainedEvents: 0
            ),
            tls: Self.tlsSnapshot(
                [Self.tlsSummary(for: Self.tuple)], omitted: 9, excluded: 4, recoveredTrunc: 1, decoderTrunc: 0,
                capacity: true
            )
        )
        let unrelated = SessionBuilder.sessionID(for: Self.otherTuple)

        let selection = snapshot.selectingSession(unrelated)

        // No retained evidence for this session — but never evidence of absence.
        #expect(selection.connections.isEmpty)
        #expect(selection.tls == nil)
        #expect(selection.isEmpty)

        // The global capture-level coverage remains, as unknown coverage.
        #expect(selection.connectionCoverage.omittedSummaryCount == 7)
        #expect(selection.connectionCoverage.activeConnectionCount == 2)
        #expect(selection.tlsCoverage.omittedObservationCount == 9)
        #expect(selection.tlsCoverage.excludedReassembledRecordCount == 4)
        #expect(selection.tlsCoverage.recoveredTruncationIndicatorCount == 1)
        #expect(selection.tlsCoverage.capacityReached)
    }

    // MARK: Private

    private static let tuple = FiveTuple(
        proto: .tcp,
        source: IPEndpoint(ip: "198.51.100.32", port: 50_002),
        destination: IPEndpoint(ip: "203.0.113.62", port: 443)
    )

    private static let otherTuple = FiveTuple(
        proto: .tcp,
        source: IPEndpoint(ip: "198.51.100.99", port: 51_000),
        destination: IPEndpoint(ip: "203.0.113.9", port: 443)
    )

    private static func provenance(ordinal: UInt64) -> SessionFrameProvenance {
        SessionFrameProvenance(
            ordinal: FrameOrdinal(ordinal),
            timestamp: Date(timeIntervalSince1970: 1_700_000_000 + Double(ordinal)),
            capturedLength: 60,
            originalLength: 60,
            linkType: LinkType.ethernet
        )
    }

    private static func connection(
        tuple: FiveTuple,
        firstOrdinal: UInt64,
        phase: ConnectionPhase
    )
        -> ConnectionSummary
    {
        let prov = provenance(ordinal: firstOrdinal)
        return ConnectionSummary(
            id: ConnectionID(tuple: tuple, firstOrdinal: FrameOrdinal(firstOrdinal)),
            tuple: tuple,
            firstProvenance: prov,
            lastProvenance: prov,
            initiator: .aToB,
            phase: phase,
            handshake: .synObserved,
            finDirections: [],
            closeReason: phase == .closed ? .reset(.aToB) : nil,
            packetCount: 1,
            capturedByteTotal: 60,
            originalByteTotal: 60,
            lossKnowledge: .noLossReported,
            limitations: [.startUnobserved],
            events: [],
            omittedEventCount: 0
        )
    }

    private static func tlsSummary(for tuple: FiveTuple) -> TLSEvidenceSummary {
        TLSEvidenceSummary(
            sessionID: SessionBuilder.sessionID(for: tuple),
            tuple: tuple,
            observations: [],
            omittedObservationCount: 3,
            excludedReassembledRecordCount: 1,
            recoveredTruncationIndicatorCount: 0,
            decoderTruncatedFrameCount: 2,
            lossKnowledge: .noLossReported,
            snapLengthTruncationObserved: true
        )
    }

    private static func connectionSnapshot(
        _ summaries: [ConnectionSummary],
        omittedSummary: UInt64,
        active: Int,
        published: Int,
        retainedEvents: Int
    )
        -> ConnectionTable.Snapshot
    {
        ConnectionTable.Snapshot(
            summaries: summaries,
            omittedSummaryCount: omittedSummary,
            activeConnectionCount: active,
            publishedSummaryCount: published,
            retainedEventCount: retainedEvents,
            countersOverflowed: false
        )
    }

    private static func tlsSnapshot(
        _ summaries: [TLSEvidenceSummary],
        omitted: UInt64,
        excluded: UInt64,
        recoveredTrunc: UInt64,
        decoderTrunc: UInt64,
        capacity: Bool
    )
        -> TLSEvidenceTable.Snapshot
    {
        TLSEvidenceTable.Snapshot(
            summaries: summaries,
            omittedObservationCount: omitted,
            retainedObservationCount: 0,
            excludedReassembledRecordCount: excluded,
            recoveredTruncationIndicatorCount: recoveredTrunc,
            decoderTruncatedFrameCount: decoderTrunc,
            capacityReached: capacity,
            countersOverflowed: false
        )
    }

    private static func snapshot(
        connections: ConnectionTable.Snapshot,
        tls: TLSEvidenceTable.Snapshot
    )
        -> InvestigationSnapshot
    {
        InvestigationSnapshot(
            sessions: [],
            connections: connections,
            datagramEvidence: .empty,
            tlsEvidence: tls,
            connectionAnalysis: .empty,
            datagramAnalysis: .empty
        )
    }
}
