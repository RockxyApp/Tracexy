import Foundation

// This file declares the frozen, pure value types for N3B3a — the Community-only
// passive DNS/ICMP datagram analysis. It is observation-only *policy* over the
// observation-only *evidence* the `DatagramEvidenceTable` fold already produced
// (`DatagramEvidenceTable.Snapshot`). It derives nothing from a wall clock, retains
// no state, decodes nothing, and never widens the evidence: a finding exists only
// where a retained `.dns` observation actually carried the TC (truncation) header
// bit, cites only that observation's own single provenance, and carries no raw
// bytes, DNS transaction/name/answer, quoted ICMP body, decoded layer, path, URL,
// endpoint role, UI copy, colour, symbol or product-policy concept.
//
// The only mapped, findable evidence is one neutral signal:
//   a `.dns` observation whose `DNSMessageFacts.isTruncated` is set
//        -> dnsTruncationIndicated (note)
// This is the observed TC bit and nothing more. RFC 6762 uses TC on valid
// multipacket mDNS queries, so even this one accepted signal is a neutral observed
// indication — it never states the message, host, resolver or network failed.
//
// Everything else is deliberately *not* a finding here:
//   - every other DNS header combination (isResponse, opcode, responseCode/RCODE,
//     the four section counts, any flag other than TC) maps to nothing;
//   - every retained `.icmp` observation — for any family, type or code — maps to
//     nothing, and only increments the snapshot's retained ICMP coverage count.
// TCP-DNS facts never reach this layer as observations at all; the table already
// excluded and counted them, and that count is propagated as coverage only.

// MARK: - DatagramAnalysisFindingKind

/// The kind of passively-observed datagram finding. There is exactly one, mapping
/// back to the single retained `.dns` observation whose TC bit was set, with a fixed
/// `note` severity. The `rank` and `stableDiscriminator` are internal, UI-free
/// identifiers used only for deterministic ordering and stable id derivation, never
/// for display. The kind is intentionally the *sole* mapped datagram signal; it
/// shares no identity with the TCP `ConnectionAnalysisFindingKind`.
nonisolated enum DatagramAnalysisFindingKind: Hashable, Sendable {
    /// The DNS TC (truncation) header bit was observed set on a retained UDP-DNS
    /// message (`DNSMessageFacts.isTruncated`). A neutral observed indication — never
    /// a claim that the message, host, resolver or network failed.
    case dnsTruncationIndicated

    // MARK: Internal

    /// The fixed severity for this kind. The one datagram signal is always a `note`:
    /// a benign-but-notable observation, never a `warning` and never an escalation.
    var severity: AnalysisSeverity {
        switch self {
        case .dnsTruncationIndicated: .note
        }
    }

    /// A stable, explicit ordering rank used as the final deterministic tie-break
    /// when ordering findings. Never a timestamp, ordinal or array position.
    var rank: Int {
        switch self {
        case .dnsTruncationIndicated: 0
        }
    }

    /// A stable, explicit discriminator folded into the finding-id seed. It is a
    /// fixed internal token — not UI copy — so a finding's identity depends only on
    /// its session id and its kind, never on citations, counts, timestamps or the
    /// order the observations arrived in.
    var stableDiscriminator: String {
        switch self {
        case .dnsTruncationIndicated: "dnsTruncationIndicated"
        }
    }
}

// MARK: - DatagramAnalysisCitation

/// One retained piece of evidence behind a datagram finding. It cites the
/// tuple-derived session id, the canonical direction the datagram travelled, and the
/// exactly-one existing `SessionFrameProvenance` the source observation carried —
/// nothing more. It copies no DNS facts, names, answers, transaction ids or strings;
/// the fact that mapped (the TC bit) is fully captured by the finding's kind.
nonisolated struct DatagramAnalysisCitation: Hashable, Sendable {
    let sessionID: UUID
    let direction: ConnectionDirection
    /// The single frame of evidence, copied verbatim from the source observation.
    let provenance: SessionFrameProvenance

    /// The capture-local position at which this citation "occurred" — the cited
    /// frame ordinal. Used only for deterministic oldest-first ordering.
    var occurrenceOrdinal: FrameOrdinal {
        provenance.ordinal
    }
}

// MARK: - DatagramAnalysisFinding

/// One coalesced finding for a session: every retained TC observation of the single
/// mapped kind on that session, folded into one finding with a stable id, its fixed
/// severity, the session's coverage, a bounded citation list ordered oldest-first,
/// and an exact count of citations omitted to honor the per-finding bound.
nonisolated struct DatagramAnalysisFinding: Hashable, Sendable {
    /// A deterministic identity seeded only from the session id and the kind's stable
    /// discriminator (via `SessionBuilder.stableID`). It never depends on timestamps,
    /// ordinals, array positions, citation contents or history, so the same
    /// session+kind keeps the same id across snapshots of that capture.
    let id: UUID
    let kind: DatagramAnalysisFindingKind
    let severity: AnalysisSeverity
    /// The tuple-derived session id this finding belongs to (never a TCP
    /// `ConnectionID`).
    let sessionID: UUID
    /// The typed canonical tuple for navigation/query without parsing display text.
    let tuple: FiveTuple
    let coverage: AnalysisCoverage
    /// Citations ordered oldest-first by cited frame ordinal, bounded by the assessor
    /// configuration.
    let citations: [DatagramAnalysisCitation]
    /// Exactly how many citations were dropped to honor the per-finding bound,
    /// counted with saturating addition so it never wraps.
    let omittedCitationCount: UInt64

    /// The occurrence ordinal of the earliest retained citation, used only as the
    /// primary key when ordering findings for the global cap.
    var firstCitedOccurrenceOrdinal: FrameOrdinal {
        citations.first?.occurrenceOrdinal ?? FrameOrdinal(0)
    }
}

// MARK: - DatagramAnalysisSnapshot

/// The immutable result of one datagram assessment: the deterministically ordered,
/// bounded findings, the exact count of findings dropped to honor the global bound,
/// and the propagated input coverage counters from the `DatagramEvidenceTable`
/// snapshot. The propagated counters (retained/omitted input observations, excluded
/// TCP-DNS facts, retained ICMP observations, the input capacity flag) are snapshot
/// coverage only — they never become findings and never claim whole-capture
/// completeness.
nonisolated struct DatagramAnalysisSnapshot: Hashable, Sendable {
    /// The canonical empty analysis: no findings, no omissions, no propagated
    /// coverage, no overflow. It is exactly what ``DatagramAssessor/assess(_:)``
    /// returns for `DatagramEvidenceTable.Snapshot.empty`.
    static let empty = DatagramAnalysisSnapshot(
        findings: [],
        omittedFindingCount: 0,
        retainedInputObservationCount: 0,
        inputOmittedObservationCount: 0,
        excludedTCPDNSFactCount: 0,
        retainedICMPObservationCount: 0,
        inputCapacityReached: false,
        countersOverflowed: false
    )

    let findings: [DatagramAnalysisFinding]
    /// Exact count of findings dropped to honor the global finding bound.
    let omittedFindingCount: UInt64
    /// Total observations the input snapshot retained across all summaries.
    let retainedInputObservationCount: Int
    /// The input snapshot's exact global count of observation occurrences omitted to
    /// honor an evidence-table bound. Propagated coverage, never a finding.
    let inputOmittedObservationCount: UInt64
    /// The input snapshot's exact global count of TCP-DNS fact occurrences the
    /// evidence table deliberately excluded from retention. Propagated coverage.
    let excludedTCPDNSFactCount: UInt64
    /// Exact saturating count of retained `.icmp` observations seen during this
    /// assessment. Every ICMP observation increments this and produces no finding.
    let retainedICMPObservationCount: UInt64
    /// Whether the input evidence table reported that a bound rejected a fact.
    /// Propagated coverage, never a finding.
    let inputCapacityReached: Bool
    /// Whether any saturating counter — the input snapshot's or this assessment's —
    /// reached `UInt64.max`. The two overflow signals are combined, never wrapped.
    let countersOverflowed: Bool
}

// MARK: - DatagramAssessor

/// A pure, stateless assessor from a `DatagramEvidenceTable.Snapshot` to a bounded
/// `DatagramAnalysisSnapshot`. It holds only an injectable `Configuration` — no
/// mutable state — so assessing the same snapshot twice always yields the same
/// result, and the order of summaries in the input never changes the output.
nonisolated struct DatagramAssessor: Hashable, Sendable {
    // MARK: Lifecycle

    init(configuration: Configuration = Configuration()) {
        self.configuration = configuration
    }

    // MARK: Internal

    // MARK: Configuration

    /// Injectable bounds. Both values are clamped to at least one so no bound can
    /// disable findings or citations entirely; test configurations may be tiny. The
    /// defaults mirror the accepted TCP assessor's comparable bounds.
    nonisolated struct Configuration: Hashable, Sendable {
        // MARK: Lifecycle

        init(maxFindings: Int = 4_096, maxCitationsPerFinding: Int = 16) {
            self.maxFindings = max(1, maxFindings)
            self.maxCitationsPerFinding = max(1, maxCitationsPerFinding)
        }

        // MARK: Internal

        let maxFindings: Int
        let maxCitationsPerFinding: Int
    }

    let configuration: Configuration

    /// Saturating unsigned addition. Returns the max on overflow together with a
    /// flag, so callers can both cap a total and record that it saturated. Exposed
    /// as the test seam for the saturating-counter contract, since real assessment
    /// cannot reach `UInt64` overflow on these counters.
    static func saturatingAdd(_ lhs: UInt64, _ rhs: UInt64) -> (value: UInt64, overflowed: Bool) {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? (UInt64.max, true) : (sum, false)
    }

    /// Assess a datagram evidence snapshot into a bounded, deterministically ordered
    /// set of findings plus propagated input coverage. Pure: no clock, no stored
    /// state, order-independent in the input.
    func assess(_ snapshot: DatagramEvidenceTable.Snapshot) -> DatagramAnalysisSnapshot {
        // The input snapshot's own overflow is propagated and combined, never wrapped.
        var countersOverflowed = snapshot.countersOverflowed
        var retainedICMP: UInt64 = 0

        // 1. Coalesce mapped observations by session id + finding kind. Every other
        //    DNS header combination maps to nothing; every `.icmp` observation only
        //    increments the retained ICMP coverage count and is never a finding.
        var groups: [GroupKey: GroupState] = [:]
        for summary in snapshot.summaries {
            let coverage = Self.coverage(for: summary)
            for observation in summary.observations {
                switch observation.kind {
                case let .dns(facts):
                    // The sole mapping: the TC bit was set. Nothing else about the
                    // DNS header — response/query, opcode, RCODE, counts, other flags
                    // — is inspected or mapped.
                    guard facts.isTruncated else {
                        continue
                    }
                    let kind = DatagramAnalysisFindingKind.dnsTruncationIndicated
                    let key = GroupKey(sessionID: observation.sessionID, kind: kind)
                    if groups[key] == nil {
                        groups[key] = GroupState(
                            sessionID: observation.sessionID,
                            tuple: observation.tuple,
                            kind: kind,
                            coverage: coverage
                        )
                    }
                    groups[key]?.observations.append(observation)
                case .icmp:
                    // Family/type/code without quoted inner payload, role or pairing
                    // is useful evidence but never a fault attribution here.
                    let counted = Self.saturatingAdd(retainedICMP, 1)
                    retainedICMP = counted.value
                    countersOverflowed = countersOverflowed || counted.overflowed
                }
            }
        }

        // 2. Build one finding per group, ordering citations oldest-first and capping
        //    them with an exact saturating omission count.
        var findings: [DatagramAnalysisFinding] = []
        findings.reserveCapacity(groups.count)
        for group in groups.values {
            let ordered = group.observations.sorted(by: Self.observationPrecedes)
            let cap = configuration.maxCitationsPerFinding
            var citations: [DatagramAnalysisCitation] = []
            var omittedCitations: UInt64 = 0
            for (index, observation) in ordered.enumerated() {
                if index < cap {
                    citations.append(DatagramAnalysisCitation(
                        sessionID: group.sessionID,
                        direction: observation.direction,
                        provenance: observation.provenance
                    ))
                } else {
                    let sum = Self.saturatingAdd(omittedCitations, 1)
                    omittedCitations = sum.value
                    countersOverflowed = countersOverflowed || sum.overflowed
                }
            }
            let seed = "datagramAnalysis|\(group.sessionID.uuidString)|\(group.kind.stableDiscriminator)"
            findings.append(DatagramAnalysisFinding(
                id: SessionBuilder.stableID(seed),
                kind: group.kind,
                severity: group.kind.severity,
                sessionID: group.sessionID,
                tuple: group.tuple,
                coverage: group.coverage,
                citations: citations,
                omittedCitationCount: omittedCitations
            ))
        }

        // 3. Impose the deterministic global order (earliest retained cited ordinal,
        //    then session UUID string, then explicit kind rank) before capping.
        findings.sort(by: Self.findingPrecedes)

        // 4. Cap the global finding count, counting the omission saturating.
        let cap = configuration.maxFindings
        var omittedFindings: UInt64 = 0
        if findings.count > cap {
            for _ in findings[cap...] {
                let sum = Self.saturatingAdd(omittedFindings, 1)
                omittedFindings = sum.value
                countersOverflowed = countersOverflowed || sum.overflowed
            }
            findings = Array(findings.prefix(cap))
        }

        return DatagramAnalysisSnapshot(
            findings: findings,
            omittedFindingCount: omittedFindings,
            retainedInputObservationCount: snapshot.retainedObservationCount,
            inputOmittedObservationCount: snapshot.omittedObservationCount,
            excludedTCPDNSFactCount: snapshot.excludedTCPDNSFactCount,
            retainedICMPObservationCount: retainedICMP,
            inputCapacityReached: snapshot.capacityReached,
            countersOverflowed: countersOverflowed
        )
    }

    // MARK: Private

    /// The immutable per-group key: one session id and one finding kind. Since the
    /// session id is tuple-derived and the table keys summaries by tuple, this
    /// coalesces every TC observation of a flow into exactly one finding.
    private struct GroupKey: Hashable {
        let sessionID: UUID
        let kind: DatagramAnalysisFindingKind
    }

    /// The mutable per-group accumulator used only inside `assess`; it never leaves
    /// the function, so the assessor itself stays stateless.
    private struct GroupState {
        let sessionID: UUID
        let tuple: FiveTuple
        let kind: DatagramAnalysisFindingKind
        let coverage: AnalysisCoverage
        var observations: [DatagramEvidenceObservation] = []
    }

    /// Session-level coverage with the documented strict precedence: reported loss,
    /// then omitted observations or snap-length truncation, then unknown loss,
    /// otherwise a bounded-local no-known-omission statement. It is a per-summary
    /// caveat and never promises whole-capture completeness.
    private static func coverage(for summary: DatagramEvidenceSummary) -> AnalysisCoverage {
        if summary.lossKnowledge == .lossReported {
            return .captureLossReported
        }
        if summary.omittedObservationCount > 0 || summary.snapLengthTruncationObserved {
            return .omittedEvidence
        }
        if summary.lossKnowledge == .unknown {
            return .unknownLoss
        }
        return .boundedNoKnownOmission
    }

    /// A total order over the observations of one finding, used to keep the oldest
    /// citations deterministically. Ordered by cited frame ordinal, then direction,
    /// then captured/original length, timestamp, link type and optional locator —
    /// enough to break every tie between distinct citation values without inspecting
    /// any DNS fact. If every cited value is equal, citation output is equal too.
    private static func observationPrecedes(
        _ lhs: DatagramEvidenceObservation,
        _ rhs: DatagramEvidenceObservation
    )
        -> Bool
    {
        let lo = lhs.provenance.ordinal.rawValue
        let ro = rhs.provenance.ordinal.rawValue
        if lo != ro {
            return lo < ro
        }
        let ld = directionRank(lhs.direction)
        let rd = directionRank(rhs.direction)
        if ld != rd {
            return ld < rd
        }
        if lhs.provenance.capturedLength != rhs.provenance.capturedLength {
            return lhs.provenance.capturedLength < rhs.provenance.capturedLength
        }
        if lhs.provenance.originalLength != rhs.provenance.originalLength {
            return lhs.provenance.originalLength < rhs.provenance.originalLength
        }
        if lhs.provenance.timestamp != rhs.provenance.timestamp {
            return lhs.provenance.timestamp < rhs.provenance.timestamp
        }
        if lhs.provenance.linkType != rhs.provenance.linkType {
            return lhs.provenance.linkType < rhs.provenance.linkType
        }
        switch (lhs.provenance.locator, rhs.provenance.locator) {
        case (.none, .some):
            return true
        case (.some, .none),
             (.none, .none):
            return false
        case let (.some(lhsLocator), .some(rhsLocator)):
            let lhsToken = lhsLocator.sourceToken.uuidString
            let rhsToken = rhsLocator.sourceToken.uuidString
            if lhsToken != rhsToken {
                return lhsToken < rhsToken
            }
            return lhsLocator.offset < rhsLocator.offset
        }
    }

    /// The deterministic global finding order: earliest retained cited ordinal, then
    /// session UUID string, then explicit kind rank. `(sessionID, kind)` is unique
    /// per finding, so this is a total order invariant to the input summary order.
    private static func findingPrecedes(
        _ lhs: DatagramAnalysisFinding,
        _ rhs: DatagramAnalysisFinding
    )
        -> Bool
    {
        let lo = lhs.firstCitedOccurrenceOrdinal.rawValue
        let ro = rhs.firstCitedOccurrenceOrdinal.rawValue
        if lo != ro {
            return lo < ro
        }
        let lu = lhs.sessionID.uuidString
        let ru = rhs.sessionID.uuidString
        if lu != ru {
            return lu < ru
        }
        return lhs.kind.rank < rhs.kind.rank
    }

    private static func directionRank(_ direction: ConnectionDirection) -> Int {
        switch direction {
        case .aToB: 0
        case .bToA: 1
        }
    }
}
