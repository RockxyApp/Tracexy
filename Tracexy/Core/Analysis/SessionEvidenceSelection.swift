import Foundation

// This file declares the frozen, presentation-neutral value for one selected
// session's retained connection and TLS evidence. Like the tables it reads, it is
// observation-only: it carries the exact retained ``ConnectionSummary`` and
// ``TLSEvidenceSummary`` values a fold already produced, plus the relevant
// capture-level coverage counters — never a rendered label, severity, policy, raw
// bytes, URL, path, SNI or certificate. It adds no analysis; it is a filtered,
// deterministic projection of one immutable ``InvestigationSnapshot``.

// MARK: - ConnectionSelectionCoverage

/// The capture-level connection-table coverage a selected session's presentation
/// needs, carried verbatim from ``ConnectionTable/Snapshot``. These are *global*
/// facts: `omittedSummaryCount` and the counts describe the whole capture, never
/// this one session, so a caller must label them as capture-level and never claim
/// they prove this selected session was omitted.
nonisolated struct ConnectionSelectionCoverage: Hashable, Sendable {
    static let empty = ConnectionSelectionCoverage(
        omittedSummaryCount: 0,
        activeConnectionCount: 0,
        publishedSummaryCount: 0,
        retainedEventCount: 0,
        countersOverflowed: false
    )

    let omittedSummaryCount: UInt64
    let activeConnectionCount: Int
    let publishedSummaryCount: Int
    let retainedEventCount: Int
    let countersOverflowed: Bool
}

// MARK: - TLSSelectionCoverage

/// The capture-level TLS-evidence coverage a selected session's presentation needs,
/// carried verbatim from ``TLSEvidenceTable/Snapshot``. As with the connection
/// coverage these are global capture facts; absence of a retained summary for this
/// session is unknown coverage, never evidence of absence.
nonisolated struct TLSSelectionCoverage: Hashable, Sendable {
    static let empty = TLSSelectionCoverage(
        omittedObservationCount: 0,
        retainedObservationCount: 0,
        excludedReassembledRecordCount: 0,
        recoveredTruncationIndicatorCount: 0,
        decoderTruncatedFrameCount: 0,
        capacityReached: false,
        countersOverflowed: false
    )

    let omittedObservationCount: UInt64
    let retainedObservationCount: Int
    let excludedReassembledRecordCount: UInt64
    let recoveredTruncationIndicatorCount: UInt64
    let decoderTruncatedFrameCount: UInt64
    let capacityReached: Bool
    let countersOverflowed: Bool
}

// MARK: - SessionEvidenceSelection

/// The immutable, presentation-neutral view of one selected session's retained
/// connection and TLS evidence.
///
/// A session is tuple-derived, so one session can hold multiple sequential TCP
/// connection incarnations when its tuple is reused. `connections` lists *every*
/// retained incarnation whose tuple-derived session id matches, in the snapshot's
/// existing deterministic (first-observed) order — this value never chooses one as
/// "the connection." `tls` is the zero-or-one retained tuple/session-scoped TLS
/// summary; because current evidence cannot prove which incarnation a tuple-scoped
/// TLS record belongs to, it is shared at session scope and never paired to a
/// specific connection.
///
/// Every per-summary omission, exclusion, truncation, loss, limitation and overflow
/// fact needed by a presentation layer already lives inside the retained
/// ``ConnectionSummary``/``TLSEvidenceSummary`` values carried here; the two
/// coverage members add only the capture-level (global) counters.
nonisolated struct SessionEvidenceSelection: Hashable, Sendable {
    /// The tuple-derived session id this selection was projected for.
    let sessionID: UUID
    /// Every retained connection incarnation for this session in first-observed
    /// order. Bounded by the connection table's published-summary bound.
    let connections: [ConnectionSummary]
    /// The zero-or-one retained tuple/session-scoped TLS summary. Never paired to a
    /// connection incarnation.
    let tls: TLSEvidenceSummary?
    /// Capture-level connection coverage, carried verbatim.
    let connectionCoverage: ConnectionSelectionCoverage
    /// Capture-level TLS coverage, carried verbatim.
    let tlsCoverage: TLSSelectionCoverage

    /// Whether nothing was retained for this session. Capture-level coverage is
    /// still carried so a caller can present it as global unknown coverage.
    var isEmpty: Bool {
        connections.isEmpty && tls == nil
    }
}

// MARK: - InvestigationSnapshot selection

extension InvestigationSnapshot {
    /// Project the retained connection/TLS evidence for one tuple-derived session id.
    ///
    /// Pure and off-main-ready: it filters the wrapped fold's already-produced
    /// connection and TLS summaries — no decode, no re-assessment, no copy of the
    /// snapshot arrays beyond the bounded matches. The connection incarnations keep
    /// the snapshot's deterministic order, and the single tuple-scoped TLS summary is
    /// matched by session id, never re-attributed to an incarnation.
    nonisolated func selectingSession(_ sessionID: UUID) -> SessionEvidenceSelection {
        let connectionSnapshot = connections
        let matchedConnections = connectionSnapshot.summaries.filter {
            SessionBuilder.sessionID(for: $0.tuple) == sessionID
        }
        let tlsSnapshot = tlsEvidence
        let matchedTLS = tlsSnapshot.summaries.first { $0.sessionID == sessionID }

        return SessionEvidenceSelection(
            sessionID: sessionID,
            connections: matchedConnections,
            tls: matchedTLS,
            connectionCoverage: ConnectionSelectionCoverage(
                omittedSummaryCount: connectionSnapshot.omittedSummaryCount,
                activeConnectionCount: connectionSnapshot.activeConnectionCount,
                publishedSummaryCount: connectionSnapshot.publishedSummaryCount,
                retainedEventCount: connectionSnapshot.retainedEventCount,
                countersOverflowed: connectionSnapshot.countersOverflowed
            ),
            tlsCoverage: TLSSelectionCoverage(
                omittedObservationCount: tlsSnapshot.omittedObservationCount,
                retainedObservationCount: tlsSnapshot.retainedObservationCount,
                excludedReassembledRecordCount: tlsSnapshot.excludedReassembledRecordCount,
                recoveredTruncationIndicatorCount: tlsSnapshot.recoveredTruncationIndicatorCount,
                decoderTruncatedFrameCount: tlsSnapshot.decoderTruncatedFrameCount,
                capacityReached: tlsSnapshot.capacityReached,
                countersOverflowed: tlsSnapshot.countersOverflowed
            )
        )
    }
}
