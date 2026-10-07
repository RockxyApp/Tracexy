import Foundation

// This file declares the frozen, pure value types for the Community-only
// passive DNS/ICMP datagram analysis. It is observation-only *policy* over the
// observation-only *evidence* the `DatagramEvidenceTable` fold already produced
// (`DatagramEvidenceTable.Snapshot`). It derives nothing from a wall clock, retains
// no state, decodes nothing, and never widens the evidence: a finding exists only
// where a retained `.dns` observation actually carried the TC (truncation) header
// bit, cites only that observation's own single provenance, and carries no raw
// bytes, DNS transaction/name/answer, quoted ICMP body, decoded layer, path, URL,
// endpoint role, UI copy, colour, symbol or product-policy concept.
//
// The mapped, findable evidence (including the DNS outcome family):
//   a `.dns` observation whose `DNSMessageFacts.isTruncated` is set
//        -> dnsTruncationIndicated (note)
//   a standard-query (opcode 0) *response* whose RCODE is 3 (NXDOMAIN)
//        -> dnsNameErrorObserved (note)
//   a standard-query response whose RCODE is 2 (SERVFAIL) or 5 (REFUSED)
//        -> dnsServerFailureObserved (warning)
//   a standard, recursion-desired query transaction id seen at least twice in one
//   flow with no response carrying that id, in a flow that omitted nothing and does
//   not involve the mDNS/LLMNR ports
//        -> dnsQueryUnansweredObserved (warning)
//   an `.icmp` observation whose family/type is a destination-unreachable message
//   (IPv4 type 3 except code 4, IPv6 type 1)
//        -> icmpDestinationUnreachableObserved (warning)
//   IPv4 type 3 code 4 (fragmentation needed) or IPv6 type 2 (packet too big)
//        -> icmpPacketTooBigObserved (note)
//   IPv4 type 11 or IPv6 type 3 (time exceeded)
//        -> icmpTimeExceededObserved (note)
//   any of the three above whose message quoted a complete TCP/UDP flow
//        -> the same outcome reported a second time, on the *quoted* session
//           (icmpUnreachableReportedForFlow / icmpPacketTooBigReportedForFlow /
//            icmpTimeExceededReportedForFlow), citing the same ICMP frames
// The three flow-level ICMP findings belong to the ICMP conversation that carried
// the message. The three paired findings belong to the flow that message named, so
// an investigator looking at the affected connection sees the error reported
// against it. Their subjects differ, so neither supersedes the other, and a quoted
// flow that was never captured simply has no session to present the paired finding
// on — the flow-level finding still stands. The quoted flow is decoder-produced
// typed identity (addresses, ports, transport); no quoted payload, sequence number
// or identifier is retained or cited, and pairing never claims the quoted flow was
// captured or that the error is its cause.
// TC is the observed bit and nothing more: RFC 6762 uses TC on valid multipacket
// mDNS queries, so it is a neutral observed indication. The RCODE findings state
// only what the response header said; "unanswered" states only that no response was
// *observed* for a retried id within this flow's retained evidence — never that no
// answer existed. Findings cite provenance only; transaction ids, names and answers
// are used for pairing inside `assess` and never leave it.
//
// Everything else is deliberately *not* a finding here:
//   - every other DNS header combination (other RCODEs, non-standard opcodes,
//     section counts, any flag other than TC/QR/RD in the rules above) maps to nothing;
//   - a single unretried query, or a retried one in a flow whose observations were
//     bounded away, maps to nothing (fail closed);
//   - every other retained `.icmp` type (echo, redirect, parameter problem, router
//     and neighbour discovery, …) maps to nothing; every `.icmp` observation,
//     mapped or not, increments the snapshot's retained ICMP coverage count.
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
    /// A standard-query response carried RCODE 3 (NXDOMAIN): the responder said the
    /// name does not exist. Cites each such response. A note, because a missing name
    /// is often expected (search-domain probes, negative caching).
    case dnsNameErrorObserved
    /// A standard-query response carried RCODE 2 (SERVFAIL) or 5 (REFUSED): the
    /// responder could not or would not answer. Cites each such response.
    case dnsServerFailureObserved
    /// A recursion-desired standard query id was sent at least twice in this flow and
    /// no response with that id was observed. Cites every retained query for the
    /// unanswered ids, oldest first. Only emitted for flows that omitted nothing.
    case dnsQueryUnansweredObserved
    /// An ICMP destination-unreachable message was observed (IPv4 type 3 other than
    /// code 4, IPv6 type 1). Cites each such message on the ICMP flow.
    case icmpDestinationUnreachableObserved
    /// A path-MTU signal was observed: IPv4 type 3 code 4 (fragmentation needed) or
    /// IPv6 type 2 (packet too big). Cites each such message.
    case icmpPacketTooBigObserved
    /// An ICMP time-exceeded message was observed (IPv4 type 11, IPv6 type 3) — the
    /// signature of a routing loop or a traceroute probe. Cites each such message.
    case icmpTimeExceededObserved
    /// A destination-unreachable message quoted *this* session's flow. Reported on
    /// the quoted session, citing the ICMP frames that carried the message.
    case icmpUnreachableReportedForFlow
    /// A path-MTU message (fragmentation needed / packet too big) quoted this
    /// session's flow.
    case icmpPacketTooBigReportedForFlow
    /// A time-exceeded message quoted this session's flow.
    case icmpTimeExceededReportedForFlow

    // MARK: Internal

    /// The fixed severity for this kind. Truncation, a name error, a path-MTU signal
    /// and time exceeded are `note`s; a server failure, an unanswered retried query
    /// and destination unreachable are `warning`s.
    var severity: AnalysisSeverity {
        switch self {
        case .dnsTruncationIndicated,
             .dnsNameErrorObserved,
             .icmpPacketTooBigObserved,
             .icmpTimeExceededObserved,
             .icmpPacketTooBigReportedForFlow,
             .icmpTimeExceededReportedForFlow: .note
        case .dnsServerFailureObserved,
             .dnsQueryUnansweredObserved,
             .icmpDestinationUnreachableObserved,
             .icmpUnreachableReportedForFlow: .warning
        }
    }

    /// A stable, explicit ordering rank used as the final deterministic tie-break
    /// when ordering findings. Never a timestamp, ordinal or array position.
    var rank: Int {
        switch self {
        case .dnsTruncationIndicated: 0
        case .dnsServerFailureObserved: 1
        case .dnsQueryUnansweredObserved: 2
        case .dnsNameErrorObserved: 3
        case .icmpUnreachableReportedForFlow: 4
        case .icmpDestinationUnreachableObserved: 5
        case .icmpPacketTooBigReportedForFlow: 6
        case .icmpPacketTooBigObserved: 7
        case .icmpTimeExceededReportedForFlow: 8
        case .icmpTimeExceededObserved: 9
        }
    }

    /// A stable, explicit discriminator folded into the finding-id seed. It is a
    /// fixed internal token — not UI copy — so a finding's identity depends only on
    /// its session id and its kind, never on citations, counts, timestamps or the
    /// order the observations arrived in.
    var stableDiscriminator: String {
        switch self {
        case .dnsTruncationIndicated: "dnsTruncationIndicated"
        case .dnsNameErrorObserved: "dnsNameErrorObserved"
        case .dnsServerFailureObserved: "dnsServerFailureObserved"
        case .dnsQueryUnansweredObserved: "dnsQueryUnansweredObserved"
        case .icmpDestinationUnreachableObserved: "icmpDestinationUnreachableObserved"
        case .icmpPacketTooBigObserved: "icmpPacketTooBigObserved"
        case .icmpTimeExceededObserved: "icmpTimeExceededObserved"
        case .icmpUnreachableReportedForFlow: "icmpUnreachableReportedForFlow"
        case .icmpPacketTooBigReportedForFlow: "icmpPacketTooBigReportedForFlow"
        case .icmpTimeExceededReportedForFlow: "icmpTimeExceededReportedForFlow"
        }
    }
}

// MARK: - DatagramAnalysisCitation

/// One retained piece of evidence behind a datagram finding. It cites the
/// tuple-derived session id *of the flow the cited frame belongs to*, the canonical
/// direction the datagram travelled within that flow, and the exactly-one existing
/// `SessionFrameProvenance` the source observation carried — nothing more. For every
/// finding except the paired ICMP ones this is the finding's own session; for a
/// paired finding it is the ICMP conversation that carried the message, which is
/// where the frame truthfully lives. It copies no DNS facts, names, answers, transaction ids or strings;
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
            /// Append one observation to the group for `kind` on a named session.
            /// `sessionID`/`tuple` are the *subject* of the finding, which is the
            /// observation's own flow for every rule except the paired ICMP ones,
            /// where the subject is the flow the error message quoted.
            func append(
                _ observation: DatagramEvidenceObservation,
                to kind: DatagramAnalysisFindingKind,
                subject: (sessionID: UUID, tuple: FiveTuple)? = nil
            ) {
                let sessionID = subject?.sessionID ?? observation.sessionID
                let tuple = subject?.tuple ?? observation.tuple
                let key = GroupKey(sessionID: sessionID, kind: kind)
                if groups[key] == nil {
                    groups[key] = GroupState(
                        sessionID: sessionID,
                        tuple: tuple,
                        kind: kind,
                        coverage: coverage
                    )
                }
                groups[key]?.observations.append(observation)
            }
            for observation in summary.observations {
                switch observation.kind {
                case let .dns(facts):
                    // Per-observation header mappings. Each is independent: a truncated
                    // SERVFAIL response contributes to both findings.
                    if facts.isTruncated {
                        append(observation, to: .dnsTruncationIndicated)
                    }
                    if let outcome = Self.responseOutcome(facts) {
                        append(observation, to: outcome)
                    }
                case let .icmp(facts):
                    // Family/type/code. The three error families map onto the ICMP
                    // flow that carried the message; everything else is coverage only.
                    if let kind = Self.icmpOutcome(facts) {
                        append(observation, to: kind)
                    }
                    // When the message quoted a complete TCP/UDP flow, the same
                    // message is *additionally* reported on that quoted session under
                    // its own paired kind. The two findings have different subjects —
                    // the conversation that carried the message, and the flow the
                    // message was about — so neither supersedes the other. A quoted
                    // flow that was never captured simply has no session to present
                    // the paired finding on; the flow-level finding still stands.
                    if let quoted = facts.quotedFlow, let paired = Self.pairedICMPOutcome(facts) {
                        let tuple = quoted.tuple
                        append(
                            observation, to: paired,
                            subject: (SessionBuilder.sessionID(for: tuple), tuple)
                        )
                    }
                    let counted = Self.saturatingAdd(retainedICMP, 1)
                    retainedICMP = counted.value
                    countersOverflowed = countersOverflowed || counted.overflowed
                }
            }
            // Flow-level pairing: retried recursion-desired query ids with no observed
            // response. Transaction ids are compared here and discarded; only the
            // queries' provenance reaches the finding.
            for observation in Self.unansweredQueries(in: summary) {
                append(observation, to: .dnsQueryUnansweredObserved)
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
                        sessionID: observation.sessionID,
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

    /// Ports whose DNS-shaped traffic is multicast/link-local name resolution
    /// (mDNS 5353, LLMNR 5355). Responses there arrive on other tuples, so an
    /// "unanswered" pairing inside one flow would be meaningless.
    private static let multicastNamePorts: Set<UInt16> = [5_353, 5_355]

    /// The per-response outcome mapping: only a standard-query (opcode 0) *response*
    /// maps, and only for RCODE 3 (name error) or RCODE 2/5 (server failure or
    /// refused). Queries, other opcodes and every other RCODE map to nothing.
    private static func responseOutcome(_ facts: DNSMessageFacts) -> DatagramAnalysisFindingKind? {
        guard facts.isResponse, facts.opcode == 0 else {
            return nil
        }
        switch facts.responseCode {
        case 3: return .dnsNameErrorObserved
        case 2,
             5: return .dnsServerFailureObserved
        default: return nil
        }
    }

    /// The per-message ICMP mapping by family and type. Only the three error
    /// families map; codes are not interpreted except to split IPv4 type 3 code 4
    /// (fragmentation needed) into the path-MTU kind.
    private static func icmpOutcome(_ facts: ICMPMessageFacts) -> DatagramAnalysisFindingKind? {
        switch (facts.family, facts.type, facts.code) {
        case (.ipv4, 3, 4),
             (.ipv6, 2, _): .icmpPacketTooBigObserved
        case (.ipv4, 3, _),
             (.ipv6, 1, _): .icmpDestinationUnreachableObserved
        case (.ipv4, 11, _),
             (.ipv6, 3, _): .icmpTimeExceededObserved
        default: nil
        }
    }

    /// The paired mapping for the same message, used only when the message quoted a
    /// complete TCP/UDP flow. It mirrors ``icmpOutcome(_:)`` exactly — same families,
    /// same split of IPv4 type 3 code 4 — so a message can never report one thing on
    /// its own flow and a different thing on the flow it quoted.
    private static func pairedICMPOutcome(_ facts: ICMPMessageFacts) -> DatagramAnalysisFindingKind? {
        switch icmpOutcome(facts) {
        case .icmpDestinationUnreachableObserved: .icmpUnreachableReportedForFlow
        case .icmpPacketTooBigObserved: .icmpPacketTooBigReportedForFlow
        case .icmpTimeExceededObserved: .icmpTimeExceededReportedForFlow
        default: nil
        }
    }

    /// The retained standard, recursion-desired queries whose transaction id appears
    /// at least twice in this flow and never on a response. Fails closed: a flow that
    /// omitted any observation, or that involves a multicast name-resolution port,
    /// yields nothing, because the missing answer could be among the omitted frames
    /// or on another tuple.
    private static func unansweredQueries(in summary: DatagramEvidenceSummary) -> [DatagramEvidenceObservation] {
        guard summary.omittedObservationCount == 0,
              !multicastNamePorts.contains(summary.tuple.a.port),
              !multicastNamePorts.contains(summary.tuple.b.port) else
        {
            return []
        }
        var queriesByID: [UInt16: [DatagramEvidenceObservation]] = [:]
        var answeredIDs: Set<UInt16> = []
        for observation in summary.observations {
            guard case let .dns(facts) = observation.kind, facts.opcode == 0 else {
                continue
            }
            if facts.isResponse {
                answeredIDs.insert(facts.transactionID)
            } else if facts.recursionDesired {
                queriesByID[facts.transactionID, default: []].append(observation)
            }
        }
        return queriesByID
            .filter { id, queries in queries.count >= 2 && !answeredIDs.contains(id) }
            .values
            .flatMap { $0 }
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
            // A documented total order over optional capture times: known precedes
            // unknown. Used purely as a tie-break, never as elapsed time.
            return SessionFrameProvenance.timeOrderedBefore(
                lhs.provenance.timestamp, rhs.provenance.timestamp
            )
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
