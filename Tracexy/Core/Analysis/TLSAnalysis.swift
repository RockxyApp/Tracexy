import Foundation

// This file declares the frozen, pure value types for the passive TLS analysis.
// Like `DatagramAnalysis`, it is observation-only
// *policy* over the observation-only *evidence* the `TLSEvidenceTable` fold already
// produced. It derives nothing from a wall clock, retains no state, decodes nothing,
// and never widens the evidence: a finding exists only where retained direct-frame
// records actually carried the mapped facts, cites only those observations' own
// provenance, and carries no raw bytes, SNI, certificate material, key, session
// ticket, decrypted payload, endpoint role, UI copy, colour, symbol or product-policy
// concept.
//
// ## The policy, stated once
//
// 1. **Only complete facts map.** A record fragment, a truncated hello and an
//    incomplete extension region produce no finding. The decoder already refuses to
//    publish `selectedVersion` for an incomplete or HelloRetryRequest ServerHello, and
//    refuses to read an alert body that is not exactly the two plaintext RFC 8446 §6
//    bytes; this layer never works around either refusal.
// 2. **An absence claim needs complete coverage.** A rule whose conclusion depends on
//    *not* having seen something (an unanswered ClientHello) is emitted only for a flow
//    that omitted nothing, excluded no reassembled record, hit no decoder record cap,
//    saw no snap-length truncation and had no capture loss reported. Anything less and
//    the rule stays silent — the missing reply could be exactly what was dropped.
// 3. **Handshakes are never a verdict on secrecy.** Nothing here claims a connection is
//    secure, insecure, downgraded, attacked or trusted. `tlsDeprecatedVersionSelected`
//    states a published-standard fact about the version the server itself selected
//    (RFC 8996 deprecates TLS 1.0/1.1; SSL 3.0 is deprecated by RFC 7568), not a threat
//    assessment of the session.
// 4. **HelloRetryRequest is not an outcome.** An HRR is a normal part of a TLS 1.3
//    negotiation, so one is never a finding. RFC 8446 §4.1.4 allows the server to send
//    at most one per handshake, so a *second* one in the same direction is.
// 5. **Nothing is retained that the evidence table did not already retain.** Reassembled
//    records are excluded by the table and are therefore invisible here; they are
//    coverage, never a finding.
//
// The mapped, findable evidence:
//   an Alert record whose plaintext level byte is fatal (2)
//        -> tlsFatalAlertObserved (warning)
//   an Alert record at warning level that is not close_notify or user_canceled
//        -> tlsWarningAlertObserved (note)
//   a complete, non-HRR ServerHello whose selected version is below TLS 1.2
//        -> tlsDeprecatedVersionSelectedObserved (warning)
//   a second (or later) HelloRetryRequest in one direction of a flow
//        -> tlsRepeatedHelloRetryRequestObserved (warning)
//   a retained ClientHello in a fully-covered flow with no ServerHello, no HRR and no
//   alert observed in reply
//        -> tlsHandshakeUnansweredObserved (warning)
//
// Everything else is deliberately *not* a finding here:
//   - close_notify and user_canceled, which are orderly shutdown and not an error;
//   - an encrypted alert, whose body this layer never sees;
//   - a single HelloRetryRequest, ChangeCipherSpec, Heartbeat, Application Data or any
//     handshake message other than ClientHello/ServerHello;
//   - the selected cipher suite. Naming a cipher "weak" needs a curated strength list
//     that ages, and the observed wire value alone does not prove what was negotiated
//     end to end — it stays an observed fact in the evidence rows.
//   - SNI / ALPN mismatch and an absent certificate chain, which need SNI, ALPN and
//     certificate material this decoder deliberately does not retain. They are left
//     undecided rather than being met with a guess.

// MARK: - TLSAnalysisFindingKind

/// The kind of passively-observed TLS finding. Each maps back to a fixed set of
/// retained `TLSRecordFact` shapes and a fixed severity; the `rank` and
/// `stableDiscriminator` are internal, UI-free identifiers used only for deterministic
/// ordering and stable id derivation, never for display. The kind shares no identity
/// with `ConnectionAnalysisFindingKind` or `DatagramAnalysisFindingKind`.
nonisolated enum TLSAnalysisFindingKind: Hashable, Sendable {
    /// A plaintext alert record carried the fatal level (2). Cites each such record.
    /// It states that the alert was observed — never why the peer sent it.
    case tlsFatalAlertObserved
    /// A plaintext alert record carried the warning level (1) and a description other
    /// than close_notify or user_canceled, both of which are orderly shutdown.
    case tlsWarningAlertObserved
    /// A complete, non-HelloRetryRequest ServerHello selected a version below TLS 1.2:
    /// SSL 3.0 (0x0300, RFC 7568), TLS 1.0 (0x0301) or TLS 1.1 (0x0302), both
    /// deprecated by RFC 8996. Cites each such ServerHello.
    case tlsDeprecatedVersionSelectedObserved
    /// More than one HelloRetryRequest was observed in one direction of this flow.
    /// RFC 8446 §4.1.4 permits at most one per handshake. Cites every retained HRR in
    /// that direction, oldest first.
    case tlsRepeatedHelloRetryRequestObserved
    /// A ClientHello was retained and no ServerHello, HelloRetryRequest or alert was
    /// observed in reply. Emitted only for a flow whose TLS evidence omitted nothing,
    /// so the missing reply cannot be a record this app dropped.
    case tlsHandshakeUnansweredObserved

    // MARK: Internal

    /// The fixed severity for this kind. A non-shutdown warning-level alert is a
    /// `note`; everything else is a `warning`.
    var severity: AnalysisSeverity {
        switch self {
        case .tlsWarningAlertObserved: .note
        case .tlsFatalAlertObserved,
             .tlsDeprecatedVersionSelectedObserved,
             .tlsRepeatedHelloRetryRequestObserved,
             .tlsHandshakeUnansweredObserved: .warning
        }
    }

    /// A stable, explicit ordering rank used as the final deterministic tie-break when
    /// ordering findings. Never a timestamp, ordinal or array position.
    var rank: Int {
        switch self {
        case .tlsFatalAlertObserved: 0
        case .tlsHandshakeUnansweredObserved: 1
        case .tlsRepeatedHelloRetryRequestObserved: 2
        case .tlsDeprecatedVersionSelectedObserved: 3
        case .tlsWarningAlertObserved: 4
        }
    }

    /// A stable, explicit discriminator folded into the finding-id seed. It is a fixed
    /// internal token — not UI copy — so a finding's identity depends only on its
    /// session id and its kind, never on citations, counts, timestamps or arrival order.
    var stableDiscriminator: String {
        switch self {
        case .tlsFatalAlertObserved: "tlsFatalAlertObserved"
        case .tlsWarningAlertObserved: "tlsWarningAlertObserved"
        case .tlsDeprecatedVersionSelectedObserved: "tlsDeprecatedVersionSelectedObserved"
        case .tlsRepeatedHelloRetryRequestObserved: "tlsRepeatedHelloRetryRequestObserved"
        case .tlsHandshakeUnansweredObserved: "tlsHandshakeUnansweredObserved"
        }
    }
}

// MARK: - TLSAnalysisCitation

/// One retained piece of evidence behind a TLS finding: the tuple-derived session id
/// of the flow the cited record belongs to, the canonical direction the record
/// travelled, the zero-based record index within its frame, and the exactly-one
/// existing `SessionFrameProvenance` the source observation carried — nothing more. It
/// copies no alert bytes, version, cipher, hello contents or strings; the fact that
/// mapped is fully captured by the finding's kind.
nonisolated struct TLSAnalysisCitation: Hashable, Sendable {
    let sessionID: UUID
    let direction: ConnectionDirection
    /// Zero-based position of the cited record within its frame's accepted records,
    /// copied verbatim so a frame carrying several records cites the exact one.
    let recordIndex: Int
    /// The single frame of evidence, copied verbatim from the source observation.
    let provenance: SessionFrameProvenance

    /// The capture-local position at which this citation "occurred" — the cited frame
    /// ordinal. Used only for deterministic oldest-first ordering.
    var occurrenceOrdinal: FrameOrdinal {
        provenance.ordinal
    }
}

// MARK: - TLSAnalysisFinding

/// One coalesced finding for a session: every retained observation of one mapped kind
/// on that flow, folded into a single finding with a stable id, its fixed severity, the
/// flow's coverage, a bounded citation list ordered oldest-first, and an exact count of
/// citations omitted to honor the per-finding bound.
nonisolated struct TLSAnalysisFinding: Hashable, Sendable {
    /// A deterministic identity seeded only from the session id and the kind's stable
    /// discriminator (via `SessionBuilder.stableID`). It never depends on timestamps,
    /// ordinals, array positions, citation contents or history, so the same
    /// session+kind keeps the same id across snapshots of that capture.
    let id: UUID
    let kind: TLSAnalysisFindingKind
    let severity: AnalysisSeverity
    /// The tuple-derived session id this finding belongs to (never a TCP
    /// `ConnectionID`).
    let sessionID: UUID
    /// The typed canonical tuple for navigation/query without parsing display text.
    let tuple: FiveTuple
    let coverage: AnalysisCoverage
    /// Citations ordered oldest-first by cited frame ordinal, bounded by the assessor
    /// configuration.
    let citations: [TLSAnalysisCitation]
    /// Exactly how many citations were dropped to honor the per-finding bound, counted
    /// with saturating addition so it never wraps.
    let omittedCitationCount: UInt64

    /// The occurrence ordinal of the earliest retained citation, used only as the
    /// primary key when ordering findings for the global cap.
    var firstCitedOccurrenceOrdinal: FrameOrdinal {
        citations.first?.occurrenceOrdinal ?? FrameOrdinal(0)
    }
}

// MARK: - TLSAnalysisSnapshot

/// The immutable result of one TLS assessment: the deterministically ordered, bounded
/// findings, the exact count of findings dropped to honor the global bound, and the
/// propagated input coverage counters from the `TLSEvidenceTable` snapshot. The
/// propagated counters are snapshot coverage only — they never become findings and
/// never claim whole-capture completeness.
nonisolated struct TLSAnalysisSnapshot: Hashable, Sendable {
    /// The canonical empty analysis: exactly what ``TLSAssessor/assess(_:)`` returns
    /// for `TLSEvidenceTable.Snapshot.empty`.
    static let empty = TLSAnalysisSnapshot(
        findings: [],
        omittedFindingCount: 0,
        retainedInputObservationCount: 0,
        inputOmittedObservationCount: 0,
        excludedReassembledRecordCount: 0,
        decoderTruncatedFrameCount: 0,
        inputCapacityReached: false,
        countersOverflowed: false
    )

    let findings: [TLSAnalysisFinding]
    /// Exact count of findings dropped to honor the global finding bound.
    let omittedFindingCount: UInt64
    /// Total observations the input snapshot retained across all summaries.
    let retainedInputObservationCount: Int
    /// The input snapshot's exact global count of record occurrences omitted to honor
    /// an evidence-table bound. Propagated coverage, never a finding.
    let inputOmittedObservationCount: UInt64
    /// The input snapshot's exact global count of reassembled record occurrences the
    /// evidence table deliberately excluded from retention. Propagated coverage.
    let excludedReassembledRecordCount: UInt64
    /// The input snapshot's exact global count of frames whose direct decode hit the
    /// 32-record cap. Propagated coverage.
    let decoderTruncatedFrameCount: UInt64
    /// Whether the input evidence table reported that a bound rejected a fact.
    let inputCapacityReached: Bool
    /// Whether any saturating counter — the input snapshot's or this assessment's —
    /// reached `UInt64.max`. The two overflow signals are combined, never wrapped.
    let countersOverflowed: Bool
}

// MARK: - TLSAssessor

/// A pure, stateless assessor from a `TLSEvidenceTable.Snapshot` to a bounded
/// `TLSAnalysisSnapshot`. It holds only an injectable `Configuration` — no mutable
/// state — so assessing the same snapshot twice always yields the same result, and the
/// order of summaries in the input never changes the output.
nonisolated struct TLSAssessor: Hashable, Sendable {
    // MARK: Lifecycle

    init(configuration: Configuration = Configuration()) {
        self.configuration = configuration
    }

    // MARK: Internal

    // MARK: Configuration

    /// Injectable bounds. Both values are clamped to at least one so no bound can
    /// disable findings or citations entirely; test configurations may be tiny. The
    /// defaults mirror the connection and datagram assessors.
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

    /// Saturating unsigned addition. Returns the max on overflow together with a flag,
    /// so callers can both cap a total and record that it saturated. Exposed as the
    /// test seam for the saturating-counter contract, since real assessment cannot
    /// reach `UInt64` overflow on these counters.
    static func saturatingAdd(_ lhs: UInt64, _ rhs: UInt64) -> (value: UInt64, overflowed: Bool) {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? (UInt64.max, true) : (sum, false)
    }

    /// Assess a TLS evidence snapshot into a bounded, deterministically ordered set of
    /// findings plus propagated input coverage. Pure: no clock, no stored state,
    /// order-independent in the input.
    func assess(_ snapshot: TLSEvidenceTable.Snapshot) -> TLSAnalysisSnapshot {
        // The input snapshot's own overflow is propagated and combined, never wrapped.
        var countersOverflowed = snapshot.countersOverflowed

        // 1. Coalesce mapped observations by session id + finding kind.
        var groups: [GroupKey: GroupState] = [:]
        for summary in snapshot.summaries {
            let coverage = Self.coverage(for: summary)
            func append(_ observation: TLSEvidenceObservation, to kind: TLSAnalysisFindingKind) {
                let key = GroupKey(sessionID: summary.sessionID, kind: kind)
                if groups[key] == nil {
                    groups[key] = GroupState(
                        sessionID: summary.sessionID,
                        tuple: summary.tuple,
                        kind: kind,
                        coverage: coverage
                    )
                }
                groups[key]?.observations.append(observation)
            }
            // Per-record mappings. Each is independent and states only what that one
            // complete record carried.
            for observation in summary.observations {
                if let kind = Self.alertOutcome(observation.fact) {
                    append(observation, to: kind)
                }
                if Self.selectedDeprecatedVersion(observation.fact) {
                    append(observation, to: .tlsDeprecatedVersionSelectedObserved)
                }
            }
            // Flow-level rules. Both need the whole summary, not one record.
            for observation in Self.repeatedHelloRetryRequests(in: summary) {
                append(observation, to: .tlsRepeatedHelloRetryRequestObserved)
            }
            for observation in Self.unansweredClientHellos(in: summary) {
                append(observation, to: .tlsHandshakeUnansweredObserved)
            }
        }

        // 2. Build one finding per group, ordering citations oldest-first and capping
        //    them with an exact saturating omission count.
        var findings: [TLSAnalysisFinding] = []
        findings.reserveCapacity(groups.count)
        for group in groups.values {
            let ordered = group.observations.sorted(by: Self.observationPrecedes)
            let cap = configuration.maxCitationsPerFinding
            var citations: [TLSAnalysisCitation] = []
            var omittedCitations: UInt64 = 0
            for (index, observation) in ordered.enumerated() {
                if index < cap {
                    citations.append(TLSAnalysisCitation(
                        sessionID: observation.sessionID,
                        direction: observation.direction,
                        recordIndex: observation.recordIndex,
                        provenance: observation.provenance
                    ))
                } else {
                    let sum = Self.saturatingAdd(omittedCitations, 1)
                    omittedCitations = sum.value
                    countersOverflowed = countersOverflowed || sum.overflowed
                }
            }
            let seed = "tlsAnalysis|\(group.sessionID.uuidString)|\(group.kind.stableDiscriminator)"
            findings.append(TLSAnalysisFinding(
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

        return TLSAnalysisSnapshot(
            findings: findings,
            omittedFindingCount: omittedFindings,
            retainedInputObservationCount: snapshot.retainedObservationCount,
            inputOmittedObservationCount: snapshot.omittedObservationCount,
            excludedReassembledRecordCount: snapshot.excludedReassembledRecordCount,
            decoderTruncatedFrameCount: snapshot.decoderTruncatedFrameCount,
            inputCapacityReached: snapshot.capacityReached,
            countersOverflowed: countersOverflowed
        )
    }

    // MARK: Private

    /// The immutable per-group key: one session id and one finding kind.
    private struct GroupKey: Hashable {
        let sessionID: UUID
        let kind: TLSAnalysisFindingKind
    }

    /// The mutable per-group accumulator used only inside `assess`; it never leaves the
    /// function, so the assessor itself stays stateless.
    private struct GroupState {
        let sessionID: UUID
        let tuple: FiveTuple
        let kind: TLSAnalysisFindingKind
        let coverage: AnalysisCoverage
        var observations: [TLSEvidenceObservation] = []
    }

    /// RFC 8446 §6.2 description bytes that are an orderly shutdown rather than a
    /// failure: `close_notify` (0) and `user_canceled` (90). Neither maps.
    private static let shutdownAlertDescriptions: Set<UInt8> = [0, 90]

    /// The lowest version this layer does not call deprecated: TLS 1.2 (0x0303).
    /// Anything below it — SSL 3.0, TLS 1.0, TLS 1.1 — is deprecated by RFC 7568 and
    /// RFC 8996.
    private static let lowestCurrentVersion: UInt16 = 0x0303

    /// The per-record alert mapping. Only a *plaintext* alert has a fact at all, so an
    /// encrypted alert can never map. A fatal level is a warning finding; a
    /// warning-level alert maps only when it is not an orderly shutdown.
    private static func alertOutcome(_ fact: TLSRecordFact) -> TLSAnalysisFindingKind? {
        guard let alert = fact.alert else {
            return nil
        }
        if alert.isFatal {
            return .tlsFatalAlertObserved
        }
        return shutdownAlertDescriptions.contains(alert.description) ? nil : .tlsWarningAlertObserved
    }

    /// Whether this record is a complete, non-HRR ServerHello that selected a version
    /// below TLS 1.2. The decoder publishes `selectedVersion` only for a complete,
    /// well-formed, non-HRR message, so a truncated legacy-0x0303 ServerHello can never
    /// reach this rule.
    private static func selectedDeprecatedVersion(_ fact: TLSRecordFact) -> Bool {
        guard case let .serverHello(server) = fact.handshake,
              let selected = server.selectedVersion else
        {
            return false
        }
        return selected < lowestCurrentVersion
    }

    /// Every retained HelloRetryRequest in a direction that carried more than one. RFC
    /// 8446 §4.1.4 allows at most one per handshake, so the second is the signal and
    /// the whole set is what proves it. Directions are considered separately, so two
    /// HRRs from opposite endpoints of a reused tuple never combine into one claim.
    private static func repeatedHelloRetryRequests(
        in summary: TLSEvidenceSummary
    )
        -> [TLSEvidenceObservation]
    {
        var byDirection: [ConnectionDirection: [TLSEvidenceObservation]] = [:]
        for observation in summary.observations {
            guard case let .serverHello(server) = observation.fact.handshake, server.isHelloRetryRequest else {
                continue
            }
            byDirection[observation.direction, default: []].append(observation)
        }
        return byDirection.values.filter { $0.count >= 2 }.flatMap { $0 }
    }

    /// The retained ClientHellos of a flow in which no ServerHello, HelloRetryRequest
    /// or alert was observed at all. Fails closed: a flow that omitted an observation,
    /// excluded a reassembled record, hit the decoder's record cap, was captured short
    /// of its on-wire length, or had capture loss reported, yields nothing — the
    /// missing reply could be exactly what was dropped.
    private static func unansweredClientHellos(
        in summary: TLSEvidenceSummary
    )
        -> [TLSEvidenceObservation]
    {
        guard summary.omittedObservationCount == 0,
              summary.excludedReassembledRecordCount == 0,
              summary.recoveredTruncationIndicatorCount == 0,
              summary.decoderTruncatedFrameCount == 0,
              !summary.snapLengthTruncationObserved,
              summary.lossKnowledge != .lossReported else
        {
            return []
        }
        var hellos: [TLSEvidenceObservation] = []
        for observation in summary.observations {
            switch observation.fact.handshake {
            case .clientHello:
                hellos.append(observation)
            case .serverHello:
                // Any ServerHello — retry request or not — is a reply.
                return []
            case .none:
                // A plaintext alert is a reply too: the hello was answered, and the
                // alert finding is the truthful statement about that flow.
                if observation.fact.alert != nil {
                    return []
                }
            }
        }
        return hellos
    }

    /// Session-level coverage with the documented strict precedence: reported loss,
    /// then omitted/excluded/truncated evidence, then unknown loss, otherwise a
    /// bounded-local no-known-omission statement. It is a per-summary caveat and never
    /// promises whole-capture completeness.
    private static func coverage(for summary: TLSEvidenceSummary) -> AnalysisCoverage {
        if summary.lossKnowledge == .lossReported {
            return .captureLossReported
        }
        if summary.omittedObservationCount > 0
            || summary.excludedReassembledRecordCount > 0
            || summary.decoderTruncatedFrameCount > 0
            || summary.snapLengthTruncationObserved
        {
            return .omittedEvidence
        }
        if summary.lossKnowledge == .unknown {
            return .unknownLoss
        }
        return .boundedNoKnownOmission
    }

    /// A total order over the observations of one finding, used to keep the oldest
    /// citations deterministically. Ordered by cited frame ordinal, then record index
    /// within that frame, then direction, then captured/original length, timestamp and
    /// link type — enough to break every tie between distinct citation values without
    /// inspecting any TLS fact.
    private static func observationPrecedes(
        _ lhs: TLSEvidenceObservation,
        _ rhs: TLSEvidenceObservation
    )
        -> Bool
    {
        let lo = lhs.provenance.ordinal.rawValue
        let ro = rhs.provenance.ordinal.rawValue
        if lo != ro {
            return lo < ro
        }
        if lhs.recordIndex != rhs.recordIndex {
            return lhs.recordIndex < rhs.recordIndex
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
            // A documented total order over optional capture times: known precedes
            // unknown. Used purely as a tie-break, never as elapsed time.
            return SessionFrameProvenance.timeOrderedBefore(
                lhs.provenance.timestamp, rhs.provenance.timestamp
            )
        }
        return lhs.provenance.linkType < rhs.provenance.linkType
    }

    /// The deterministic global finding order: earliest retained cited ordinal, then
    /// session UUID string, then explicit kind rank. `(sessionID, kind)` is unique per
    /// finding, so this is a total order invariant to the input summary order.
    private static func findingPrecedes(
        _ lhs: TLSAnalysisFinding,
        _ rhs: TLSAnalysisFinding
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
