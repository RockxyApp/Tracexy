import Foundation

// MARK: - HistoryFindingRecord projections

/// The typed analysis findings as neutral History records (schema v3). The kind is
/// the public name the Session Expression language uses for it, so History and
/// the MCP server speak the same vocabulary the user types; nothing here carries a
/// byte, a host, an address or UI copy.
extension HistoryFindingRecord {
    init(_ finding: ConnectionAnalysisFinding) {
        self.init(
            findingID: finding.id,
            sessionID: SessionBuilder.sessionID(for: finding.tuple),
            kind: Self.name(InvestigationQueryEngine.projected(finding.kind)),
            severity: Self.severity(finding.severity),
            coverage: Self.coverageToken(finding.coverage),
            citedObservationCount: finding.citations.count,
            omittedCitationCount: Int64(clamping: finding.omittedCitationCount),
            firstCitedAt: Self.firstInstant(finding.citations.flatMap(\.provenance))
        )
    }

    init(_ finding: DatagramAnalysisFinding) {
        self.init(
            findingID: finding.id,
            sessionID: finding.sessionID,
            kind: Self.name(InvestigationQueryEngine.projected(finding.kind)),
            severity: Self.severity(finding.severity),
            coverage: Self.coverageToken(finding.coverage),
            citedObservationCount: finding.citations.count,
            omittedCitationCount: Int64(clamping: finding.omittedCitationCount),
            firstCitedAt: Self.firstInstant(finding.citations.map(\.provenance))
        )
    }

    init(_ finding: TLSAnalysisFinding) {
        self.init(
            findingID: finding.id,
            sessionID: finding.sessionID,
            kind: Self.name(InvestigationQueryEngine.projected(finding.kind)),
            severity: Self.severity(finding.severity),
            coverage: Self.coverageToken(finding.coverage),
            citedObservationCount: finding.citations.count,
            omittedCitationCount: Int64(clamping: finding.omittedCitationCount),
            firstCitedAt: Self.firstInstant(finding.citations.map(\.provenance))
        )
    }

    /// Every finding of one investigation snapshot, connection findings first, each
    /// layer in its assessor's own deterministic order.
    static func records(
        connection: ConnectionAnalysisSnapshot,
        datagram: DatagramAnalysisSnapshot,
        tls: TLSAnalysisSnapshot
    )
        -> [HistoryFindingRecord]
    {
        connection.findings.map(HistoryFindingRecord.init)
            + datagram.findings.map(HistoryFindingRecord.init)
            + tls.findings.map(HistoryFindingRecord.init)
    }

    private static func name(_ kind: QueryFindingKind) -> String {
        SessionQueryParser.findingName(kind)
    }

    private static func severity(_ severity: AnalysisSeverity) -> HistoryFindingSeverity {
        switch severity {
        case .note: .note
        case .warning: .warning
        }
    }

    private static func coverageToken(_ coverage: AnalysisCoverage) -> String {
        switch coverage {
        case .captureLossReported: "captureLossReported"
        case .omittedEvidence: "omittedEvidence"
        case .unknownLoss: "unknownLoss"
        case .boundedNoKnownOmission: "boundedNoKnownOmission"
        }
    }

    private static func firstInstant(_ provenance: [SessionFrameProvenance]) -> Double? {
        provenance.compactMap(\.timestamp).min().map(\.timeIntervalSince1970)
    }
}
