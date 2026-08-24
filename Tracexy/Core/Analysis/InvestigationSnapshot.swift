import Foundation

// MARK: - InvestigationSnapshot

/// The immutable, off-main result of one investigation read: exactly one
/// ``SessionFoldSnapshot`` plus the passive analyses derived from it — the
/// ``ConnectionAnalysisSnapshot`` assessed from its connections and the
/// ``DatagramAnalysisSnapshot`` assessed from its datagram evidence — each produced
/// once at construction.
///
/// It is a thin, allocation-light wrapper: it holds the fold it was built from and
/// the two analyses assessed from it. Its `sessions`, `connections` and
/// `datagramEvidence` projections forward straight to the wrapped fold — no array is
/// copied, duplicated or mutated — and `connectionAnalysis`/`datagramAnalysis` are
/// the exact assessments computed once in `init`, each from its own evidence
/// projection. Assessing the same fold twice therefore yields the same analyses, and
/// nothing here decodes, retains packet history, or touches the `@MainActor`.
///
/// This is observation-only *policy* over the observation-only *evidence* the fold
/// already produced. It adds no state, no clock, and no user-visible copy.
nonisolated struct InvestigationSnapshot: Sendable {
    // MARK: Lifecycle

    /// - Parameters:
    ///   - fold: the already-produced session/connection/datagram fold to wrap.
    ///   - connectionAssessor: the pure connection assessor, injectable so a test can
    ///     force tiny bounds; defaults to the production defaults. It is applied
    ///     exactly once here to `fold.connections`.
    ///   - datagramAssessor: the pure datagram assessor, injectable so a test can
    ///     force tiny bounds; defaults to the production defaults. It is applied
    ///     exactly once here to `fold.datagramEvidence`.
    init(
        fold: SessionFoldSnapshot,
        connectionAssessor: ConnectionAssessor = ConnectionAssessor(),
        datagramAssessor: DatagramAssessor = DatagramAssessor()
    ) {
        self.fold = fold
        connectionAnalysis = connectionAssessor.assess(fold.connections)
        datagramAnalysis = datagramAssessor.assess(fold.datagramEvidence)
    }

    /// Build a publication snapshot from components that were already produced and
    /// assessed together (for example, a final saved-capture load). No assessor runs
    /// here; callers must supply the analyses matching the evidence arguments.
    init(
        sessions: [SessionSummary],
        connections: ConnectionTable.Snapshot,
        datagramEvidence: DatagramEvidenceTable.Snapshot,
        tlsEvidence: TLSEvidenceTable.Snapshot,
        connectionAnalysis: ConnectionAnalysisSnapshot,
        datagramAnalysis: DatagramAnalysisSnapshot
    ) {
        self.init(
            fold: SessionFoldSnapshot(
                sessions: sessions,
                connections: connections,
                datagramEvidence: datagramEvidence,
                tlsEvidence: tlsEvidence
            ),
            connectionAnalysis: connectionAnalysis,
            datagramAnalysis: datagramAnalysis
        )
    }

    private init(
        fold: SessionFoldSnapshot,
        connectionAnalysis: ConnectionAnalysisSnapshot,
        datagramAnalysis: DatagramAnalysisSnapshot
    ) {
        self.fold = fold
        self.connectionAnalysis = connectionAnalysis
        self.datagramAnalysis = datagramAnalysis
    }

    // MARK: Internal

    /// The passive connection analysis, assessed exactly once from `connections`.
    let connectionAnalysis: ConnectionAnalysisSnapshot

    /// The passive datagram analysis, assessed exactly once from `datagramEvidence`.
    let datagramAnalysis: DatagramAnalysisSnapshot

    /// The session summaries in first-seen order — a direct projection of the
    /// wrapped fold, never a copy.
    var sessions: [SessionSummary] {
        fold.sessions
    }

    /// The connection-table snapshot the connection analysis was assessed from — a
    /// direct projection of the wrapped fold, never a copy.
    var connections: ConnectionTable.Snapshot {
        fold.connections
    }

    /// The datagram-evidence snapshot the datagram analysis was assessed from — a
    /// direct projection of the wrapped fold, never a copy.
    var datagramEvidence: DatagramEvidenceTable.Snapshot {
        fold.datagramEvidence
    }

    /// The bounded TLS record evidence — a direct projection of the wrapped fold, never
    /// a copy. N3C2 adds no TLS assessor, finding or policy; this exposes the exact one
    /// table snapshot the same fold produced, for a future publication layer.
    var tlsEvidence: TLSEvidenceTable.Snapshot {
        fold.tlsEvidence
    }

    /// Replace only the published session projection while preserving the exact
    /// evidence and analyses already derived off-main. The coordinator uses this once
    /// after process attribution, so process queries see the same summaries as the UI
    /// without re-assessing evidence or mutating the original snapshot.
    func replacingSessions(with sessions: [SessionSummary]) -> InvestigationSnapshot {
        InvestigationSnapshot(
            sessions: sessions,
            connections: connections,
            datagramEvidence: datagramEvidence,
            tlsEvidence: tlsEvidence,
            connectionAnalysis: connectionAnalysis,
            datagramAnalysis: datagramAnalysis
        )
    }

    // MARK: Private

    /// The single wrapped fold. Held once; every projection reads through it.
    private let fold: SessionFoldSnapshot
}

extension InvestigationSnapshot {
    static let empty = InvestigationSnapshot(fold: SessionFoldSnapshot(
        sessions: [],
        connections: .empty,
        datagramEvidence: .empty,
        tlsEvidence: .empty
    ))
}
