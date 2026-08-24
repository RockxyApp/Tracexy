import Foundation

// This file declares the frozen, pure value types for N3A1 — the Community-only
// passive TCP connection analysis. It is observation-only *policy* over the
// observation-only *evidence* the `ConnectionTable` fold already produced. It
// derives nothing from a wall clock, retains no state, and never widens the
// evidence: a finding exists only where a retained `ConnectionEvent` of a mapped
// kind exists, cites only that event's own provenance, and carries no raw bytes,
// payloads, paths, URLs, SNI, DNS strings, decoded layers, titles/subtitles, UI
// copy, colours, symbols, policy, entitlement, licensing, tier or cloud concept.
//
// The only mapped, findable evidence is the four TCP observations that carry retained
// provenance in a `ConnectionSummary`:
//   rst              -> resetObserved      (warning)
//   retransmission   -> retransmissionObserved (note)
//   overlap          -> overlapObserved    (note)
//   outOfOrderBuffered / pendingOverflow -> outOfOrderObserved (note)
// Everything else — handshake incompleteness, state eviction, serial ambiguity,
// application records/truncation, the absence of packets, any event without
// retained provenance — is deliberately *not* a finding here.

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

    // MARK: Internal

    /// The fixed severity for this kind. Reset is a `warning`; the sequence-space
    /// sequence-space observations are `note`s.
    var severity: AnalysisSeverity {
        switch self {
        case .resetObserved: .warning
        case .retransmissionObserved,
             .overlapObserved,
             .outOfOrderObserved: .note
        }
    }

    /// A stable, explicit ordering rank used as the final deterministic tie-break
    /// when capping findings. Never a timestamp, ordinal or array position.
    var rank: Int {
        switch self {
        case .resetObserved: 0
        case .retransmissionObserved: 1
        case .overlapObserved: 2
        case .outOfOrderObserved: 3
        }
    }

    /// A stable, explicit discriminator folded into the finding-id seed. It is a
    /// fixed internal token — not UI copy — so a finding's identity depends only on
    /// its connection id and its kind, never on citations, counts or history.
    var stableDiscriminator: String {
        switch self {
        case .resetObserved: "resetObserved"
        case .retransmissionObserved: "retransmissionObserved"
        case .overlapObserved: "overlapObserved"
        case .outOfOrderObserved: "outOfOrderObserved"
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

    /// The fixed mapping from a retained event kind to its finding kind, or `nil`
    /// for any kind this layer deliberately does not map. Two out-of-order source
    /// kinds fold into one finding kind.
    private static func findingKind(for kind: ConnectionEventKind) -> ConnectionAnalysisFindingKind? {
        switch kind {
        case .rst: .resetObserved
        case .retransmission: .retransmissionObserved
        case .overlap: .overlapObserved
        case .outOfOrderBuffered,
             .pendingOverflow: .outOfOrderObserved
        default: nil
        }
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

    private static func sourceKindRank(_ kind: ConnectionEventKind) -> Int {
        switch kind {
        case .rst: 0
        case .retransmission: 1
        case .overlap: 2
        case .outOfOrderBuffered: 3
        case .pendingOverflow: 4
        default: 5
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
