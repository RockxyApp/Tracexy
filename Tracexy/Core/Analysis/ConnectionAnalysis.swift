import Foundation

// This file declares the frozen, pure value types for the Community-only
// passive TCP connection analysis. It is observation-only *policy* over the
// observation-only *evidence* the `ConnectionTable` fold already produced. It
// derives nothing from a wall clock, retains no state, and never widens the
// evidence: a finding exists only where a retained `ConnectionEvent` of a mapped
// kind exists, cites only that event's own provenance, and carries no raw bytes,
// payloads, paths, URLs, SNI, DNS strings, decoded layers, titles/subtitles, UI
// copy, colours, symbols, policy, entitlement, licensing, tier or cloud concept.
//
// The mapped, findable evidence is the TCP observations that carry retained
// provenance in a `ConnectionSummary`:
//   rst              -> resetObserved      (warning)
//   retransmission   -> retransmissionObserved (note)
//   overlap          -> overlapObserved    (note)
//   outOfOrderBuffered / pendingOverflow -> outOfOrderObserved (note)
//   zeroWindow / zeroWindowProbe -> zeroWindowObserved (warning)
//   windowFull       -> windowFullObserved (note)
//   duplicateAcknowledgement -> duplicateAcknowledgementObserved (note)
//   keepAlive        -> keepAliveObserved  (note)
//   ambiguousTupleReuse -> tupleReuseObserved (warning)
// plus four *summary-level* findings derived from the summary's observed handshake,
// close and FIN state together with its retained SYN/RST/FIN/payload events:
//   SYN observed, no SYN+ACK ever, then RST from the responder
//                    -> connectionRefusedObserved   (warning; supersedes resetObserved
//                                                    for that connection)
//   SYN observed, retried at least once, no SYN+ACK, no close, still opening
//                    -> handshakeUnansweredObserved (warning; supersedes
//                                                    retransmissionObserved when that
//                                                    finding cites nothing but those
//                                                    same SYN frames)
//   payload observed, then a reset (and not a refused open)
//                    -> abortAfterDataObserved      (warning; supersedes resetObserved)
//   FIN in one direction, then non-retransmitted payload from the peer
//                    -> halfCloseObserved           (note)
// Each cites only retained events of that connection and claims nothing beyond the
// capture window: "unanswered" means no answer was *observed*, "aborted" means a
// reset followed observed data, and the coverage value carries the usual
// loss/omission caveats. None of them names a cause.
// Everything else — a single unanswered SYN, state eviction, serial ambiguity,
// a late segment after close, application records/truncation, the absence of
// packets, any event without retained provenance — is deliberately *not* a finding
// here.

// MARK: - AnalysisSeverity

/// How much attention an observation warrants. Deliberately tiny: this layer only
/// ever emits `note` (a benign-but-notable observation) or `warning` (a noteworthy
/// observed termination). It is not a certainty or a whole-network claim.
nonisolated enum AnalysisSeverity: Hashable, Sendable {
    case note
    case warning
}

// MARK: - ConnectionAnalysisFindingKind

/// The kind of passively-observed connection finding. Each maps back to a fixed
/// set of retained `ConnectionEventKind`s and a fixed severity; the `rank` and
/// `stableDiscriminator` are internal, UI-free identifiers used only for
/// deterministic ordering and stable id derivation, never for display.
nonisolated enum ConnectionAnalysisFindingKind: Hashable, Sendable {
    /// The observed initiator sent a SYN, no SYN+ACK was ever observed, and the
    /// responder side answered with a reset: the passive signature of a refused
    /// connection (closed port, or a host/firewall rejecting the open). Cites the
    /// first retained SYN and the first retained responder RST. When it applies it
    /// replaces `resetObserved` for that connection so the reset is not reported
    /// twice.
    case connectionRefusedObserved
    /// The observed initiator sent a SYN at least twice (a retried open), no
    /// SYN+ACK was observed, and the connection never advanced or closed within the
    /// retained evidence. It is a statement about what the capture showed — a
    /// silently dropped or unreachable destination looks like this — never a claim
    /// that no answer ever existed. Cites every retained SYN, oldest first.
    case handshakeUnansweredObserved
    /// Payload was observed on the connection and a reset followed it: the open was
    /// answered, data moved, and the connection was then torn down abruptly rather
    /// than closed with FINs. It says nothing about which side was at fault or why.
    /// Cites the first payload, the last payload before the reset, and that reset.
    /// When it applies it replaces `resetObserved` for that connection, which cites
    /// the very same reset. A refused open takes precedence over it.
    case abortAfterDataObserved
    /// A FIN was observed in one direction and the peer sent payload after it: the
    /// passive signature of a half-close (one side finished sending while the other
    /// continued). Re-sent bytes do not count. Cites that FIN and the first payload
    /// the peer sent after it.
    case halfCloseObserved
    /// A reset was observed on the connection (`ConnectionEventKind.rst`).
    case resetObserved
    /// One or more retransmissions were observed (`.retransmission`).
    case retransmissionObserved
    /// One or more straddling/overlapping segments were observed (`.overlap`).
    case overlapObserved
    /// One or more out-of-order segments were observed — either buffered ahead of
    /// the expected sequence (`.outOfOrderBuffered`) or dropped when the pending
    /// bound overflowed (`.pendingOverflow`).
    case outOfOrderObserved
    /// One side advertised a zero receive window, or the other side probed such a
    /// window (`.zeroWindow`, `.zeroWindowProbe`): the receiving application was
    /// not draining its socket buffer at that moment.
    case zeroWindowObserved
    /// A data segment filled the peer's advertised receive window exactly
    /// (`.windowFull`): throughput was bounded by the receiver at that moment.
    case windowFullObserved
    /// One or more duplicate acknowledgements were observed
    /// (`.duplicateAcknowledgement`): the receiver re-acknowledged the same edge,
    /// the passive signature of a segment it did not get in order.
    case duplicateAcknowledgementObserved
    /// One or more keep-alive probes were observed (`.keepAlive`): an idle
    /// connection kept open deliberately, not data being retransmitted.
    case keepAliveObserved
    /// A sender re-sent the segment its peer asked for with repeated duplicate
    /// acknowledgements (`.fastRetransmission`). It refines, and does not
    /// replace, `retransmissionObserved`, as Wireshark's two labels do.
    case fastRetransmissionObserved
    /// A sender re-sent bytes its peer had already acknowledged
    /// (`.spuriousRetransmission`). Also a refinement of `retransmissionObserved`.
    case spuriousRetransmissionObserved
    /// A SYN or SYN+ACK conflicting with this connection's observed initiator/ISN
    /// arrived before any terminal was observed (`.ambiguousTupleReuse`): the same
    /// four-tuple carried more than one connection and the fold could not split them,
    /// so this connection's later evidence may mix incarnations. It never claims
    /// which incarnation a given frame belongs to.
    case tupleReuseObserved
    /// A side acknowledged bytes the capture never saw its peer send
    /// (`.ackedUnseenSegment`) — Wireshark's "ACKed segment that wasn't
    /// captured". It describes the capture (frames missing from it), not the
    /// network, so it is a note and never implies loss on the wire.
    case ackedUnseenSegmentObserved
    /// A login secret crossed the wire unencrypted (`.cleartextCredential`: HTTP
    /// Basic, FTP/POP3 PASS, IMAP LOGIN, SMTP AUTH PLAIN/LOGIN). A warning; the
    /// secret itself is never retained, only that one was sent in the clear.
    case cleartextCredentialsObserved

    // MARK: Internal

    /// The fixed severity for this kind. The abrupt-termination findings, reset,
    /// tuple reuse and zero window are `warning`s; the half-close, sequence-space and
    /// remaining flow-control observations are `note`s.
    var severity: AnalysisSeverity {
        switch self {
        case .connectionRefusedObserved,
             .handshakeUnansweredObserved,
             .abortAfterDataObserved,
             .resetObserved,
             .tupleReuseObserved,
             .zeroWindowObserved,
             .cleartextCredentialsObserved: .warning
        case .halfCloseObserved,
             .retransmissionObserved,
             .overlapObserved,
             .outOfOrderObserved,
             .windowFullObserved,
             .duplicateAcknowledgementObserved,
             .keepAliveObserved,
             .fastRetransmissionObserved,
             .spuriousRetransmissionObserved,
             .ackedUnseenSegmentObserved: .note
        }
    }

    /// A stable, explicit ordering rank used as the final deterministic tie-break
    /// when capping findings. Never a timestamp, ordinal or array position.
    var rank: Int {
        switch self {
        case .connectionRefusedObserved: 0
        case .handshakeUnansweredObserved: 1
        case .abortAfterDataObserved: 2
        case .resetObserved: 3
        case .tupleReuseObserved: 4
        case .zeroWindowObserved: 5
        case .retransmissionObserved: 6
        case .windowFullObserved: 7
        case .duplicateAcknowledgementObserved: 8
        case .overlapObserved: 9
        case .outOfOrderObserved: 10
        case .halfCloseObserved: 11
        case .keepAliveObserved: 12
        case .fastRetransmissionObserved: 13
        case .spuriousRetransmissionObserved: 14
        case .ackedUnseenSegmentObserved: 15
        case .cleartextCredentialsObserved: 16
        }
    }

    /// A stable, explicit discriminator folded into the finding-id seed. It is a
    /// fixed internal token — not UI copy — so a finding's identity depends only on
    /// its connection id and its kind, never on citations, counts or history.
    var stableDiscriminator: String {
        switch self {
        case .connectionRefusedObserved: "connectionRefusedObserved"
        case .handshakeUnansweredObserved: "handshakeUnansweredObserved"
        case .abortAfterDataObserved: "abortAfterDataObserved"
        case .halfCloseObserved: "halfCloseObserved"
        case .resetObserved: "resetObserved"
        case .retransmissionObserved: "retransmissionObserved"
        case .overlapObserved: "overlapObserved"
        case .outOfOrderObserved: "outOfOrderObserved"
        case .zeroWindowObserved: "zeroWindowObserved"
        case .windowFullObserved: "windowFullObserved"
        case .duplicateAcknowledgementObserved: "duplicateAcknowledgementObserved"
        case .keepAliveObserved: "keepAliveObserved"
        case .tupleReuseObserved: "tupleReuseObserved"
        case .fastRetransmissionObserved: "fastRetransmissionObserved"
        case .spuriousRetransmissionObserved: "spuriousRetransmissionObserved"
        case .ackedUnseenSegmentObserved: "ackedUnseenSegmentObserved"
        case .cleartextCredentialsObserved: "cleartextCredentialsObserved"
        }
    }
}

// MARK: - AnalysisCoverage

/// How completely one assessed *evidence scope's* retained evidence could support
/// analysis. A scope is whatever unit an assessor coalesces over — a single
/// connection for the connection assessor, a single datagram flow for the datagram
/// assessor — so this shared enum stays neutral about which layer produced it.
///
/// This is scope-level coverage, **not** a finding's certainty, and it never
/// promises whole-network completeness — it says nothing about other scopes or
/// summaries dropped to honor a bound. The precedence is strict and monotone
/// from strongest caveat to weakest:
///   1. `captureLossReported`      — the capture layer reported loss for this
///                                    scope's frames.
///   2. `omittedEvidence`          — no reported loss, but this scope dropped
///                                    evidence to a bound, or its retained state was
///                                    truncated. Each assessor supplies its own
///                                    omission/truncation signals for this case.
///   3. `unknownLoss`              — loss knowledge is simply unknown.
///   4. `boundedNoKnownOmission`   — loss was explicitly *not* reported and no
///                                    omission is known. This is a bounded-local
///                                    statement only: it means nothing was dropped
///                                    for *this* scope within the fold's bounds,
///                                    never that the whole capture or the whole
///                                    network was seen completely.
nonisolated enum AnalysisCoverage: Hashable, Sendable {
    case captureLossReported
    case omittedEvidence
    case unknownLoss
    case boundedNoKnownOmission
}

// MARK: - ConnectionAnalysisCitation

/// One retained piece of evidence behind a finding. It cites a connection, the
/// exact source `ConnectionEventKind` that mapped, that event's canonical
/// direction, and the event's existing 1...3 `SessionFrameProvenance` values —
/// nothing more. It never carries raw bytes, payloads, decoded strings, SNI, DNS
/// answers or any UI copy.
nonisolated struct ConnectionAnalysisCitation: Hashable, Sendable {
    // MARK: Lifecycle

    init(
        connectionID: ConnectionID,
        sourceEventKind: ConnectionEventKind,
        direction: ConnectionDirection?,
        provenance: [SessionFrameProvenance]
    ) {
        self.connectionID = connectionID
        self.sourceEventKind = sourceEventKind
        self.direction = direction
        // The source event already bounds this to 1...3; the prefix keeps the bound
        // true by construction even if a caller passes more.
        self.provenance = Array(provenance.prefix(3))
    }

    // MARK: Internal

    let connectionID: ConnectionID
    let sourceEventKind: ConnectionEventKind
    let direction: ConnectionDirection?
    /// One to three frames of evidence, copied verbatim from the source event.
    let provenance: [SessionFrameProvenance]

    /// The capture-local position at which this citation "occurred" — the latest
    /// cited ordinal, mirroring `ConnectionEvent.occurrenceOrdinal`. Used only for
    /// deterministic ordering.
    var occurrenceOrdinal: FrameOrdinal {
        provenance.map(\.ordinal).max() ?? FrameOrdinal(0)
    }
}

// MARK: - ConnectionAnalysisFinding

/// One coalesced finding for a connection: every retained event of a single mapped
/// kind, folded into one finding with a stable id, its fixed severity, its
/// connection's coverage, a bounded citation list ordered oldest-first, and an
/// exact count of citations omitted to honor the per-finding bound.
nonisolated struct ConnectionAnalysisFinding: Hashable, Sendable {
    /// A deterministic identity seeded only from the connection id and the kind's
    /// stable discriminator (via `SessionBuilder.stableID`). It never depends on
    /// timestamps, ordinals, array positions, citation contents or history, so the
    /// same connection+kind keeps the same id across snapshots of that capture.
    let id: UUID
    let kind: ConnectionAnalysisFindingKind
    let severity: AnalysisSeverity
    let connectionID: ConnectionID
    /// The typed canonical tuple for navigation/query without parsing display text.
    let tuple: FiveTuple
    let coverage: AnalysisCoverage
    /// Citations ordered oldest-first by occurrence ordinal, bounded by the
    /// assessor configuration.
    let citations: [ConnectionAnalysisCitation]
    /// Exactly how many citations were dropped to honor the per-finding bound,
    /// counted with saturating addition so it never wraps.
    let omittedCitationCount: UInt64

    /// The occurrence ordinal of the earliest retained citation, used only as the
    /// primary key when ordering findings for the global cap.
    var firstCitedOccurrenceOrdinal: FrameOrdinal {
        citations.first?.occurrenceOrdinal ?? FrameOrdinal(0)
    }
}

// MARK: - ConnectionAnalysisSnapshot

/// The immutable result of one assessment: the deterministically ordered, bounded
/// findings, the exact count of findings dropped to honor the global bound, and a
/// flag recording whether any saturating counter reached its maximum.
nonisolated struct ConnectionAnalysisSnapshot: Hashable, Sendable {
    /// The canonical empty analysis: no findings, no omissions, no overflow. It is
    /// the reset value coordinator state adopts at every idle/cleared/new-capture
    /// boundary, so resetting never needs to run the assessor over empty evidence.
    /// It is exactly what ``ConnectionAssessor/assess(_:)`` returns for an empty
    /// connection snapshot.
    static let empty = ConnectionAnalysisSnapshot(
        findings: [],
        omittedFindingCount: 0,
        countersOverflowed: false
    )

    let findings: [ConnectionAnalysisFinding]
    let omittedFindingCount: UInt64
    let countersOverflowed: Bool
}

// MARK: - ConnectionAssessor

/// A pure, stateless assessor from a `ConnectionTable.Snapshot` to a bounded
/// `ConnectionAnalysisSnapshot`. It holds only an injectable `Configuration` — no
/// mutable state — so assessing the same snapshot twice always yields the same
/// result, and the order of summaries in the input never changes the output.
nonisolated struct ConnectionAssessor: Hashable, Sendable {
    // MARK: Lifecycle

    init(configuration: Configuration = Configuration()) {
        self.configuration = configuration
    }

    // MARK: Internal

    // MARK: Configuration

    /// Injectable bounds. Both values are clamped to at least one so no bound can
    /// disable findings or citations entirely; test configurations may be tiny.
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

    /// Assess a connection snapshot into a bounded, deterministically ordered set
    /// of findings. Pure: no clock, no stored state, order-independent in the input.
    func assess(_ snapshot: ConnectionTable.Snapshot) -> ConnectionAnalysisSnapshot {
        var countersOverflowed = false

        // 1. Coalesce mapped events by connection id + finding kind. Each group key
        //    maps to exactly one connection, so a group's events all come from one
        //    summary in capture order — independent of the input summary ordering.
        var groups: [GroupKey: GroupState] = [:]
        for summary in snapshot.summaries {
            let coverage = Self.coverage(for: summary)
            for event in summary.events {
                // An event with no retained provenance cites nothing and is not a
                // finding; a kind that does not map is deliberately ignored.
                guard !event.provenance.isEmpty, let kind = Self.findingKind(for: event.kind) else {
                    continue
                }
                let key = GroupKey(connectionID: summary.id, kind: kind)
                if groups[key] == nil {
                    groups[key] = GroupState(
                        connectionID: summary.id,
                        tuple: summary.tuple,
                        kind: kind,
                        coverage: coverage
                    )
                }
                groups[key]?.events.append(event)
            }

            // 1b. Summary-level findings need the observed handshake/close/FIN
            //     state *and* the retained SYN/RST/FIN/payload events together. Each
            //     may supersede a plain event-mapped finding of the same connection
            //     when it already cites the very same frames; every group is inserted
            //     before any supersession is applied, so the order of the rules never
            //     changes the result.
            let observations = Self.summaryObservations(for: summary)
            for observation in observations {
                groups[GroupKey(connectionID: summary.id, kind: observation.kind)] = GroupState(
                    connectionID: summary.id,
                    tuple: summary.tuple,
                    kind: observation.kind,
                    coverage: coverage,
                    events: observation.events
                )
            }
            for superseded in observations.flatMap(\.supersedes) {
                groups.removeValue(forKey: GroupKey(connectionID: summary.id, kind: superseded))
            }
        }

        // 2. Build one finding per group, ordering citations oldest-first and
        //    capping them with an exact saturating omission count.
        var findings: [ConnectionAnalysisFinding] = []
        findings.reserveCapacity(groups.count)
        for group in groups.values {
            let ordered = group.events.sorted(by: Self.eventPrecedes)
            let cap = configuration.maxCitationsPerFinding
            var citations: [ConnectionAnalysisCitation] = []
            var omittedCitations: UInt64 = 0
            for (index, event) in ordered.enumerated() {
                if index < cap {
                    citations.append(ConnectionAnalysisCitation(
                        connectionID: group.connectionID,
                        sourceEventKind: event.kind,
                        direction: event.direction,
                        provenance: event.provenance
                    ))
                } else {
                    let sum = Self.saturatingAdd(omittedCitations, 1)
                    omittedCitations = sum.value
                    countersOverflowed = countersOverflowed || sum.overflowed
                }
            }
            let seed = "connectionAnalysis|\(group.connectionID.rawValue.uuidString)|\(group.kind.stableDiscriminator)"
            findings.append(ConnectionAnalysisFinding(
                id: SessionBuilder.stableID(seed),
                kind: group.kind,
                severity: group.kind.severity,
                connectionID: group.connectionID,
                tuple: group.tuple,
                coverage: group.coverage,
                citations: citations,
                omittedCitationCount: omittedCitations
            ))
        }

        // 3. Impose the deterministic global order (first cited occurrence ordinal,
        //    then connection UUID string, then explicit kind rank) before capping.
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

        return ConnectionAnalysisSnapshot(
            findings: findings,
            omittedFindingCount: omittedFindings,
            countersOverflowed: countersOverflowed
        )
    }

    // MARK: Private

    /// The mutable per-group accumulator used only inside `assess`; it never leaves
    /// the function, so the assessor itself stays stateless.
    private struct GroupKey: Hashable {
        let connectionID: ConnectionID
        let kind: ConnectionAnalysisFindingKind
    }

    private struct GroupState {
        let connectionID: ConnectionID
        let tuple: FiveTuple
        let kind: ConnectionAnalysisFindingKind
        let coverage: AnalysisCoverage
        var events: [ConnectionEvent] = []
    }

    /// One summary-level rule's verdict: the finding kind, the retained events it
    /// cites, and the event-mapped kinds it replaces because it already cites their
    /// evidence. Never leaves `assess`.
    private struct SummaryObservation {
        let kind: ConnectionAnalysisFindingKind
        let events: [ConnectionEvent]
        var supersedes: [ConnectionAnalysisFindingKind] = []
    }

    /// The fixed mapping from a retained event kind to its finding kind, or `nil`
    /// for any kind this layer deliberately does not map. Two out-of-order source
    /// kinds fold into one finding kind, as do the zero-window advertisement and
    /// the probe that answers it. A late segment after close is deliberately not
    /// mapped: the final ACK of an orderly close is one, and it is not a finding.
    private static func findingKind(for kind: ConnectionEventKind) -> ConnectionAnalysisFindingKind? {
        switch kind {
        case .rst: .resetObserved
        case .retransmission: .retransmissionObserved
        case .overlap: .overlapObserved
        case .outOfOrderBuffered,
             .pendingOverflow: .outOfOrderObserved
        case .zeroWindow,
             .zeroWindowProbe: .zeroWindowObserved
        case .windowFull: .windowFullObserved
        case .duplicateAcknowledgement: .duplicateAcknowledgementObserved
        case .keepAlive: .keepAliveObserved
        case .fastRetransmission: .fastRetransmissionObserved
        case .spuriousRetransmission: .spuriousRetransmissionObserved
        case .ambiguousTupleReuse: .tupleReuseObserved
        case .ackedUnseenSegment: .ackedUnseenSegmentObserved
        case .cleartextCredential: .cleartextCredentialsObserved
        default: nil
        }
    }

    /// Every summary-level rule, in a fixed order. Each returns at most one
    /// observation; the caller inserts them all before applying any supersession, so
    /// this order never affects the result. The rules are deliberately disjoint
    /// except for the documented refused/abort precedence.
    private static func summaryObservations(for summary: ConnectionSummary) -> [SummaryObservation] {
        var observations: [SummaryObservation] = []
        if let handshake = handshakeObservation(for: summary) {
            observations.append(handshake)
        }
        // A refused open is the more specific reading of "SYN, then reset", so the
        // abort rule stands down when it applied; both cite the same reset.
        if !observations.contains(where: { $0.kind == .connectionRefusedObserved }),
           let abort = abortObservation(for: summary)
        {
            observations.append(abort)
        }
        if let halfClose = halfCloseObservation(for: summary) {
            observations.append(halfClose)
        }
        return observations
    }

    /// The handshake rules. Both require an observed initiator whose SYN was retained
    /// and a handshake that never reached SYN+ACK (`HandshakeObservation.synObserved`),
    /// so a midstream, SYN+ACK-first or evicted connection never qualifies.
    private static func handshakeObservation(for summary: ConnectionSummary) -> SummaryObservation? {
        guard summary.handshake == .synObserved, let initiator = summary.initiator else {
            return nil
        }
        let syns = summary.events
            .filter { $0.kind == .syn && $0.direction == initiator && !$0.provenance.isEmpty }
            .sorted(by: eventPrecedes)
        guard let firstSYN = syns.first else {
            return nil
        }

        // Refused: the responder answered the open with a reset. The reset must be
        // the observed close reason (not a later, unrelated late segment) and must
        // itself be a retained, cited event.
        if case let .reset(direction)? = summary.closeReason, direction == initiator.opposite {
            let responderRST = summary.events
                .filter { $0.kind == .rst && $0.direction == initiator.opposite && !$0.provenance.isEmpty }
                .min(by: eventPrecedes)
            guard let responderRST else {
                return nil
            }
            return SummaryObservation(
                kind: .connectionRefusedObserved,
                events: [firstSYN, responderRST],
                supersedes: [.resetObserved]
            )
        }

        // Unanswered: at least one retried SYN, nothing else ever happened. A single
        // SYN is not enough — the capture may simply have ended before the answer.
        guard summary.closeReason == nil, summary.phase == .opening, syns.count >= 2 else {
            return nil
        }
        // A retried SYN is a duplicate in sequence space, so the sequence tracker
        // reports it as a retransmission too. When *every* retained retransmission
        // cites nothing but these same SYN frames, that finding adds no frame this
        // one does not already carry, so it is replaced rather than reported twice.
        let synOrdinals = Set(syns.flatMap { $0.provenance.map(\.ordinal) })
        let retransmissions = summary.events.filter { $0.kind == .retransmission && !$0.provenance.isEmpty }
        let citesOnlySYNs = !retransmissions.isEmpty && retransmissions.allSatisfy { event in
            event.provenance.allSatisfy { synOrdinals.contains($0.ordinal) }
        }
        return SummaryObservation(
            kind: .handshakeUnansweredObserved,
            events: syns,
            supersedes: citesOnlySYNs ? [.retransmissionObserved] : []
        )
    }

    /// The abrupt-termination rule: payload was observed, and a reset followed it.
    /// The reset must be the observed close reason and must be retained; the payload
    /// must be retained and strictly older than that reset, so a reset that arrived
    /// before any data (a refused or rejected open) never qualifies. Cites the first
    /// payload, the last payload before the reset when that is a different event, and
    /// the reset itself — never the whole conversation.
    private static func abortObservation(for summary: ConnectionSummary) -> SummaryObservation? {
        guard case .reset? = summary.closeReason else {
            return nil
        }
        let resets = summary.events.filter { $0.kind == .rst && !$0.provenance.isEmpty }
        guard let firstReset = resets.min(by: eventPrecedes) else {
            return nil
        }
        let resetOrdinal = firstReset.occurrenceOrdinal
        let payloads = summary.events
            .filter { $0.kind == .payloadObserved && !$0.provenance.isEmpty }
            .filter { $0.occurrenceOrdinal < resetOrdinal }
            .sorted(by: eventPrecedes)
        guard let firstPayload = payloads.first, let lastPayload = payloads.last else {
            return nil
        }
        let cited = payloads.count == 1
            ? [firstPayload, firstReset]
            : [firstPayload, lastPayload, firstReset]
        return SummaryObservation(kind: .abortAfterDataObserved, events: cited, supersedes: [.resetObserved])
    }

    /// The half-close rule: a FIN was observed in one direction and the peer sent
    /// payload strictly after it — one side finished sending while the other kept
    /// going. Both directions are considered and the oldest qualifying FIN wins, so
    /// a connection that later closes mutually still records the half-close that
    /// actually happened. A peer frame that the sequence tracker also reported as a
    /// retransmission is excluded: re-sent bytes after a FIN are not the peer still
    /// sending. Cites that FIN and the first qualifying peer payload.
    private static func halfCloseObservation(for summary: ConnectionSummary) -> SummaryObservation? {
        guard !summary.finDirections.isEmpty else {
            return nil
        }
        let retransmitted = Set(
            summary.events
                .filter { $0.kind == .retransmission }
                .flatMap { $0.provenance.map(\.ordinal) }
        )
        var best: (fin: ConnectionEvent, payload: ConnectionEvent)?
        for finished in [ConnectionDirection.aToB, .bToA] {
            let fin = summary.events
                .filter { $0.kind == .fin && $0.direction == finished && !$0.provenance.isEmpty }
                .min(by: eventPrecedes)
            guard let fin else {
                continue
            }
            let finOrdinal = fin.occurrenceOrdinal
            let peerPayload = summary.events
                .filter { $0.kind == .payloadObserved && $0.direction == finished.opposite }
                .filter { !$0.provenance.isEmpty && $0.occurrenceOrdinal > finOrdinal }
                .filter { !retransmitted.contains($0.occurrenceOrdinal) }
                .min(by: eventPrecedes)
            guard let peerPayload else {
                continue
            }
            if let current = best {
                if eventPrecedes(fin, current.fin) {
                    best = (fin, peerPayload)
                }
            } else {
                best = (fin, peerPayload)
            }
        }
        guard let best else {
            return nil
        }
        return SummaryObservation(kind: .halfCloseObserved, events: [best.fin, best.payload])
    }

    /// Connection-level coverage with the documented strict precedence: reported
    /// loss, then omitted/truncated evidence, then unknown loss, otherwise a
    /// bounded-local no-known-omission statement.
    private static func coverage(for summary: ConnectionSummary) -> AnalysisCoverage {
        if summary.lossKnowledge == .lossReported {
            return .captureLossReported
        }
        if summary.omittedEventCount > 0
            || summary.limitations.contains(.eventHistoryTruncated)
            || summary.limitations.contains(.sequenceStateTruncated)
        {
            return .omittedEvidence
        }
        if summary.lossKnowledge == .unknown {
            return .unknownLoss
        }
        return .boundedNoKnownOmission
    }

    /// A total order over the events of one finding, used to keep the oldest
    /// citations deterministically. Ordered by occurrence ordinal, then source-kind
    /// rank, then direction, then the triggering facts — enough to break every tie.
    private static func eventPrecedes(_ lhs: ConnectionEvent, _ rhs: ConnectionEvent) -> Bool {
        let lo = lhs.occurrenceOrdinal.rawValue
        let ro = rhs.occurrenceOrdinal.rawValue
        if lo != ro {
            return lo < ro
        }
        let lk = sourceKindRank(lhs.kind)
        let rk = sourceKindRank(rhs.kind)
        if lk != rk {
            return lk < rk
        }
        let ld = directionRank(lhs.direction)
        let rd = directionRank(rhs.direction)
        if ld != rd {
            return ld < rd
        }
        if lhs.payloadLength != rhs.payloadLength {
            return lhs.payloadLength < rhs.payloadLength
        }
        if (lhs.sequenceNumber ?? 0) != (rhs.sequenceNumber ?? 0) {
            return (lhs.sequenceNumber ?? 0) < (rhs.sequenceNumber ?? 0)
        }
        return (lhs.acknowledgementNumber ?? 0) < (rhs.acknowledgementNumber ?? 0)
    }

    /// The deterministic global finding order: first cited occurrence ordinal, then
    /// connection UUID string, then explicit kind rank. `(connectionID, kind)` is
    /// unique per finding, so this is a total order.
    private static func findingPrecedes(
        _ lhs: ConnectionAnalysisFinding,
        _ rhs: ConnectionAnalysisFinding
    )
        -> Bool
    {
        let lo = lhs.firstCitedOccurrenceOrdinal.rawValue
        let ro = rhs.firstCitedOccurrenceOrdinal.rawValue
        if lo != ro {
            return lo < ro
        }
        let lu = lhs.connectionID.rawValue.uuidString
        let ru = rhs.connectionID.rawValue.uuidString
        if lu != ru {
            return lu < ru
        }
        return lhs.kind.rank < rhs.kind.rank
    }

    /// A fixed lifecycle-then-analysis order over the source kinds a citation can
    /// carry. It only ever breaks a tie between two events of the same connection at
    /// the same frame ordinal; the relative order of every previously ranked kind is
    /// preserved, so renumbering it never reorders existing citations.
    private static func sourceKindRank(_ kind: ConnectionEventKind) -> Int {
        switch kind {
        case .syn: 0
        case .payloadObserved: 1
        case .fin: 2
        case .rst: 3
        case .ambiguousTupleReuse: 4
        case .retransmission: 5
        case .overlap: 6
        case .outOfOrderBuffered: 7
        case .pendingOverflow: 8
        case .zeroWindow: 9
        case .zeroWindowProbe: 10
        case .windowFull: 11
        case .duplicateAcknowledgement: 12
        case .keepAlive: 13
        case .fastRetransmission: 14
        case .spuriousRetransmission: 15
        case .ackedUnseenSegment: 16
        case .cleartextCredential: 17
        default: 18
        }
    }

    private static func directionRank(_ direction: ConnectionDirection?) -> Int {
        switch direction {
        case .aToB: 0
        case .bToA: 1
        case .none: 2
        }
    }
}
