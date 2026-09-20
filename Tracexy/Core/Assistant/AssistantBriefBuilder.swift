import Foundation

// The pure, off-main projection from one immutable ``InvestigationSnapshot`` to
// one bounded ``AssistantEvidenceBrief``.
//
// It reads only values the fold and the assessors already produced — it decodes
// nothing, opens nothing, and touches no actor. Building the same brief twice
// from the same snapshot, session and disclosure yields byte-identical JSON.

// MARK: - AssistantBriefBuild

/// The brief plus the app-local citation map.
///
/// `provenanceByCitationID` is the half that never leaves the app: it maps a
/// citation id back to the exact ``SessionFrameProvenance`` the existing
/// evidence-navigation coordinator needs. The model only ever sees the id.
nonisolated struct AssistantBriefBuild: Sendable {
    let brief: AssistantEvidenceBrief
    let provenanceByCitationID: [String: SessionFrameProvenance]
    /// The Assistant evidence publication this build was derived from. It never
    /// enters the brief JSON; it is the in-memory identity a send compares
    /// against the current ``AssistantContext`` so a brief built from an older
    /// publication can never be the one that leaves the app.
    let evidenceRevision: Int
}

// MARK: - AssistantBriefBuilder

nonisolated enum AssistantBriefBuilder {
    // MARK: Internal

    /// Project one selected session into a bounded brief.
    ///
    /// - Throws: ``AssistantBriefError/sessionNotFound`` when the snapshot does not
    ///   contain the session — the exact condition a stale selection produces.
    static func build(
        snapshot: InvestigationSnapshot,
        sessionID: UUID,
        projectID: UUID,
        disclosure: AutomationDisclosure,
        evidenceRevision: Int = 0
    )
        throws -> AssistantBriefBuild
    {
        guard let session = snapshot.sessions.first(where: { $0.id == sessionID }) else {
            throw AssistantBriefError.sessionNotFound
        }
        let selection = snapshot.selectingSession(sessionID)

        var citationOrder: [String] = []
        var citations: [String: AssistantCitation] = [:]
        var provenance: [String: SessionFrameProvenance] = [:]
        var globallyOmittedCitations = 0

        /// Register one frame, returning its citation id, or `nil` once the global
        /// citation bound is reached. Re-citing an already-registered frame never
        /// consumes budget: one capture-local frame is one citation.
        func register(_ frame: SessionFrameProvenance) -> String? {
            let id = AssistantCitation.identifier(forOrdinal: frame.ordinal)
            if citations[id] != nil {
                return id
            }
            guard citations.count < AssistantBriefLimits.maxCitations else {
                globallyOmittedCitations += 1
                return nil
            }
            citations[id] = AssistantCitation(frame)
            provenance[id] = frame
            citationOrder.append(id)
            return id
        }

        let (findings, omittedFindings) = self.findings(
            snapshot: snapshot,
            sessionID: sessionID,
            register: register
        )

        let orderedConnections = selection.connections.prefix(AssistantBriefLimits.maxConnections)
        let brief = AssistantEvidenceBrief(
            schemaVersion: AssistantBriefLimits.schemaVersion,
            projectID: projectID.uuidString,
            sessionID: sessionID.uuidString,
            session: AssistantSessionFacts(session, disclosure: disclosure),
            connections: orderedConnections.map(AssistantConnectionFacts.init),
            tls: selection.tls.map(AssistantTLSFacts.init),
            findings: findings,
            citations: citationOrder.compactMap { citations[$0] },
            coverage: AssistantCoverage(
                connectionOmittedSummaryCount: selection.connectionCoverage.omittedSummaryCount,
                connectionPublishedSummaryCount: selection.connectionCoverage.publishedSummaryCount,
                connectionRetainedEventCount: selection.connectionCoverage.retainedEventCount,
                connectionCountersOverflowed: selection.connectionCoverage.countersOverflowed,
                tlsOmittedObservationCount: selection.tlsCoverage.omittedObservationCount,
                tlsRetainedObservationCount: selection.tlsCoverage.retainedObservationCount,
                tlsCapacityReached: selection.tlsCoverage.capacityReached,
                tlsCountersOverflowed: selection.tlsCoverage.countersOverflowed,
                connectionFindingsOmittedCount: snapshot.connectionAnalysis.omittedFindingCount,
                datagramFindingsOmittedCount: snapshot.datagramAnalysis.omittedFindingCount,
                briefOmittedConnectionCount: max(0, selection.connections.count - orderedConnections.count),
                briefOmittedFindingCount: omittedFindings,
                briefOmittedCitationCount: globallyOmittedCitations
            ),
            redaction: AssistantRedaction(disclosure: disclosure)
        )
        return AssistantBriefBuild(
            brief: brief,
            provenanceByCitationID: provenance,
            evidenceRevision: evidenceRevision
        )
    }

    // MARK: Private

    /// The session's findings in a fixed order — connection findings in the
    /// assessor's own deterministic order, then the datagram findings — bounded by
    /// ``AssistantBriefLimits/maxFindings``.
    private static func findings(
        snapshot: InvestigationSnapshot,
        sessionID: UUID,
        register: (SessionFrameProvenance) -> String?
    )
        -> ([AssistantFinding], Int)
    {
        var results: [AssistantFinding] = []
        var omitted = 0

        for finding in snapshot.connectionAnalysis.findings
            where SessionBuilder.sessionID(for: finding.tuple) == sessionID
        {
            guard results.count < AssistantBriefLimits.maxFindings else {
                omitted += 1
                continue
            }
            let frames = finding.citations.flatMap(\.provenance)
            let (ids, dropped) = citationIDs(for: frames, register: register)
            results.append(AssistantFinding(
                id: finding.id.uuidString,
                kind: finding.kind.stableDiscriminator,
                severity: name(for: finding.severity),
                coverage: name(for: finding.coverage),
                citationIDs: ids,
                omittedCitationCount: finding.omittedCitationCount,
                briefOmittedCitationCount: dropped
            ))
        }

        for finding in snapshot.datagramAnalysis.findings where finding.sessionID == sessionID {
            guard results.count < AssistantBriefLimits.maxFindings else {
                omitted += 1
                continue
            }
            let frames = finding.citations.map(\.provenance)
            let (ids, dropped) = citationIDs(for: frames, register: register)
            results.append(AssistantFinding(
                id: finding.id.uuidString,
                kind: finding.kind.stableDiscriminator,
                severity: name(for: finding.severity),
                coverage: name(for: finding.coverage),
                citationIDs: ids,
                omittedCitationCount: finding.omittedCitationCount,
                briefOmittedCitationCount: dropped
            ))
        }

        return (results, omitted)
    }

    /// Register up to ``AssistantBriefLimits/maxCitationsPerFinding`` frames and
    /// report exactly how many this brief dropped.
    private static func citationIDs(
        for frames: [SessionFrameProvenance],
        register: (SessionFrameProvenance) -> String?
    )
        -> ([String], Int)
    {
        var ids: [String] = []
        var dropped = 0
        for frame in frames {
            guard ids.count < AssistantBriefLimits.maxCitationsPerFinding else {
                dropped += 1
                continue
            }
            guard let id = register(frame) else {
                dropped += 1
                continue
            }
            if !ids.contains(id) {
                ids.append(id)
            }
        }
        return (ids, dropped)
    }

    private static func name(for severity: AnalysisSeverity) -> String {
        switch severity {
        case .note: "note"
        case .warning: "warning"
        }
    }

    private static func name(for coverage: AnalysisCoverage) -> String {
        switch coverage {
        case .captureLossReported: "captureLossReported"
        case .omittedEvidence: "omittedEvidence"
        case .unknownLoss: "unknownLoss"
        case .boundedNoKnownOmission: "boundedNoKnownOmission"
        }
    }
}
