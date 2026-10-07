import Foundation

// MARK: - InvestigationSnapshot

/// The immutable, off-main result of one investigation read: exactly one
/// ``SessionFoldSnapshot`` plus the passive analyses derived from it — the
/// ``ConnectionAnalysisSnapshot`` assessed from its connections, the
/// ``DatagramAnalysisSnapshot`` assessed from its datagram evidence and the
/// ``TLSAnalysisSnapshot`` assessed from its TLS record evidence — each produced
/// once at construction, plus the ``SessionTimingSnapshot`` measured from all three.
///
/// It is a thin, allocation-light wrapper: it holds the fold it was built from and
/// the three analyses assessed from it. Its `sessions`, `connections`,
/// `datagramEvidence` and `tlsEvidence` projections forward straight to the wrapped
/// fold — no array is copied, duplicated or mutated — and `connectionAnalysis`,
/// `datagramAnalysis` and `tlsAnalysis` are the exact assessments computed once in
/// `init`, each from its own evidence projection. Assessing the same fold twice
/// therefore yields the same analyses, and
/// nothing here decodes, retains packet history, or touches the `@MainActor`.
///
/// `timing` is derived, not carried: it is measured from the wrapped fold in *every*
/// initializer rather than threaded in from a loader, because it is a pure projection
/// of the same three evidence snapshots and can never disagree with them. A caller
/// that reconstructs a snapshot from already-assessed components therefore cannot
/// hand it a stale set of measurements.
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
    ///   - tlsAssessor: the pure TLS assessor, injectable so a test can force tiny
    ///     bounds; defaults to the production defaults. It is applied exactly once
    ///     here to `fold.tlsEvidence`.
    ///   - timingAssessor: the pure response-time assessor, injectable so a test can
    ///     force tiny bounds; defaults to the production defaults. It is applied
    ///     exactly once here to all three evidence projections together.
    init(
        fold: SessionFoldSnapshot,
        connectionAssessor: ConnectionAssessor = ConnectionAssessor(),
        datagramAssessor: DatagramAssessor = DatagramAssessor(),
        tlsAssessor: TLSAssessor = TLSAssessor(),
        timingAssessor: SessionTimingAssessor = SessionTimingAssessor()
    ) {
        self.fold = fold
        connectionAnalysis = connectionAssessor.assess(fold.connections)
        datagramAnalysis = datagramAssessor.assess(fold.datagramEvidence)
        tlsAnalysis = tlsAssessor.assess(fold.tlsEvidence)
        timing = timingAssessor.assess(
            connections: fold.connections,
            tls: fold.tlsEvidence,
            datagrams: fold.datagramEvidence
        )
    }

    /// Build a publication snapshot from components that were already produced and
    /// assessed together (for example, a final saved-capture load). No assessor runs
    /// here; callers must supply the analyses matching the evidence arguments.
    init(
        sessions: [SessionSummary],
        connections: ConnectionTable.Snapshot,
        datagramEvidence: DatagramEvidenceTable.Snapshot,
        tlsEvidence: TLSEvidenceTable.Snapshot,
        segmentSeries: TCPSegmentSeriesTable.Snapshot,
        connectionAnalysis: ConnectionAnalysisSnapshot,
        datagramAnalysis: DatagramAnalysisSnapshot,
        tlsAnalysis: TLSAnalysisSnapshot,
        trafficTimeline: TrafficTimeline = .empty
    ) {
        self.init(
            fold: SessionFoldSnapshot(
                sessions: sessions,
                connections: connections,
                datagramEvidence: datagramEvidence,
                tlsEvidence: tlsEvidence,
                segmentSeries: segmentSeries,
                trafficTimeline: trafficTimeline
            ),
            connectionAnalysis: connectionAnalysis,
            datagramAnalysis: datagramAnalysis,
            tlsAnalysis: tlsAnalysis
        )
    }

    private init(
        fold: SessionFoldSnapshot,
        connectionAnalysis: ConnectionAnalysisSnapshot,
        datagramAnalysis: DatagramAnalysisSnapshot,
        tlsAnalysis: TLSAnalysisSnapshot,
        timingAssessor: SessionTimingAssessor = SessionTimingAssessor()
    ) {
        self.fold = fold
        self.connectionAnalysis = connectionAnalysis
        self.datagramAnalysis = datagramAnalysis
        self.tlsAnalysis = tlsAnalysis
        timing = timingAssessor.assess(
            connections: fold.connections,
            tls: fold.tlsEvidence,
            datagrams: fold.datagramEvidence
        )
    }

    // MARK: Internal

    /// The passive connection analysis, assessed exactly once from `connections`.
    let connectionAnalysis: ConnectionAnalysisSnapshot

    /// The passive datagram analysis, assessed exactly once from `datagramEvidence`.
    let datagramAnalysis: DatagramAnalysisSnapshot

    /// The passive TLS analysis, assessed exactly once from `tlsEvidence`.
    let tlsAnalysis: TLSAnalysisSnapshot

    /// The passive response-time measurements, measured exactly once from
    /// `connections`, `tlsEvidence` and `datagramEvidence` together. It carries no
    /// finding, severity or threshold — only intervals and the frames that bound them.
    let timing: SessionTimingSnapshot

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
    /// a copy. It is the exact snapshot ``tlsAnalysis`` was assessed from.
    var tlsEvidence: TLSEvidenceTable.Snapshot {
        fold.tlsEvidence
    }

    /// The bounded per-segment TCP series — a direct projection of the wrapped fold,
    /// never a copy. Each flow's entry is a complete capture-order prefix of its
    /// segments, which is what lets ``TCPStreamHealth`` derive exact series from it.
    var segmentSeries: TCPSegmentSeriesTable.Snapshot {
        fold.segmentSeries
    }

    /// The bounded capture-wide traffic timeline — a direct projection of the
    /// wrapped fold, never a copy.
    var trafficTimeline: TrafficTimeline {
        fold.trafficTimeline
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
            segmentSeries: segmentSeries,
            connectionAnalysis: connectionAnalysis,
            datagramAnalysis: datagramAnalysis,
            tlsAnalysis: tlsAnalysis,
            trafficTimeline: trafficTimeline
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
        tlsEvidence: .empty,
        segmentSeries: .empty
    ))
}
