import Foundation

// This file declares the frozen, pure value types for the passive response-time
// analysis. Like `DatagramAnalysis` and
// `TLSAnalysis` it is observation-only *policy* over the observation-only *evidence*
// the session fold already produced. It decodes nothing, retains no state, reads no
// wall clock, and never widens the evidence: a measurement exists only where two
// retained, capture-timed frames bound it, and it cites exactly those two frames.
//
// ## The measurement policy, stated once
//
// 1. **A measurement is an interval between two cited frames, never an estimate.**
//    Both bounding frames must be retained observations that carry a capture time.
//    One untimed boundary yields no measurement — an interval computed across a
//    missing instant would be an inference from an input this app does not have.
//    A non-finite or negative difference is refused the same way.
// 2. **A "first X then Y" pairing needs complete retention.** Every rule that has to
//    know which observation came *first* is emitted only for a summary that omitted
//    nothing and truncated no history; otherwise the frame this layer would call the
//    first is merely the oldest one still retained, and the interval would be too
//    long or too short by an unknown amount. The one exception is
//    `tcpHandshakeCompletion`, which reads the three frames a single retained
//    `handshakeCompleted` event cites; that event is either retained whole or not at
//    all, so its own interval is exact regardless of what else was dropped.
// 3. **Nothing here names a cause, a role or a verdict.** A measurement says that the
//    peer answered after this long, not that a host, network, resolver or server was
//    slow. There is no threshold, no "slow" class, no colour and no severity: this
//    layer produces no findings at all. A threshold would be a policy about someone
//    else's network that passive frames cannot support.
// 4. **Directions stay canonical.** `applicationResponse` uses the connection's
//    *observed* initiator to tell a request from a reply, and reports nothing when no
//    initiator was observed. Neither side is ever called client or server.
// 5. **Nothing is retained that the evidence tables did not already retain.** Every
//    boundary is an existing `ConnectionEvent`, `TLSEvidenceObservation` or
//    `DatagramEvidenceObservation`; a DNS transaction id is compared inside `assess`
//    and discarded, exactly as the datagram assessor does.
//
// The measured intervals:
//   a retained `syn` at or before the first retained `synAck`
//        -> tcpHandshakeReply        (what the round trip to the peer showed)
//   the SYN and completing ACK cited by one retained `handshakeCompleted`
//        -> tcpHandshakeCompletion   (the whole observed set-up, retries included)
//   the initiator's first retained payload and the responder's first later payload
//        -> applicationResponse      (request to reply, the service response time)
//   a retained ClientHello and the first later ServerHello (or HelloRetryRequest)
//        -> tlsHandshakeReply
//   a retained DNS query and the first later response carrying its transaction id
//        -> dnsResponse
//
// Deliberately *not* measured here:
//   - a smoothed or per-segment RTT series. That needs an ack-matching tracker in the
//     fold, not a projection of retained events.
//   - anything on an mDNS/LLMNR flow (ports 5353/5355), where several hosts answer one
//     multicast question and a transaction id does not identify one exchange.
//   - HTTP request/response timing, which needs request/response boundaries the
//     bounded application probe does not retain.
//     (The Stream facet pairs HTTP/1 exchanges on demand from the followed stream;
//     see `HTTPExchangeReader`.)

// MARK: - SessionTimingMeasurementKind

/// The kind of passively-measured interval. Each maps back to a fixed pair of retained
/// observation shapes; `rank` and `stableDiscriminator` are internal, UI-free
/// identifiers used only for deterministic ordering and stable id derivation, never for
/// display. The kind carries no severity — a measurement is never a finding.
nonisolated enum SessionTimingMeasurementKind: Hashable, Sendable, CaseIterable {
    /// From the last retained SYN at or before the first retained SYN+ACK, to that
    /// SYN+ACK: the attempt that was actually answered, and the round trip the network
    /// showed for it. An earlier unanswered attempt is excluded on purpose, and the
    /// cited frames name which attempt this was.
    case tcpHandshakeReply
    /// From the SYN to the completing ACK cited by one retained `handshakeCompleted`
    /// event: the whole observed set-up, including any retry wait. Read from that one
    /// event's own three citations, so no retention gate applies.
    case tcpHandshakeCompletion
    /// From the observed initiator's first retained payload to the responder's first
    /// later retained payload: request to reply, measured without naming either side a
    /// client or a server.
    case applicationResponse
    /// From a retained ClientHello to the first later ServerHello in the opposite
    /// direction. A HelloRetryRequest is a reply and is measured as one.
    case tlsHandshakeReply
    /// From a retained DNS query to the first later response carrying the same
    /// transaction id on the same flow.
    case dnsResponse

    // MARK: Internal

    /// A stable, explicit ordering rank used as a deterministic tie-break. Never a
    /// timestamp, ordinal or array position.
    var rank: Int {
        switch self {
        case .tcpHandshakeReply: 0
        case .tcpHandshakeCompletion: 1
        case .tlsHandshakeReply: 2
        case .applicationResponse: 3
        case .dnsResponse: 4
        }
    }

    /// A stable internal token folded into the measurement-id seed. Not UI copy.
    var stableDiscriminator: String {
        switch self {
        case .tcpHandshakeReply: "tcpHandshakeReply"
        case .tcpHandshakeCompletion: "tcpHandshakeCompletion"
        case .applicationResponse: "applicationResponse"
        case .tlsHandshakeReply: "tlsHandshakeReply"
        case .dnsResponse: "dnsResponse"
        }
    }
}

// MARK: - SessionTimingBoundary

/// One end of a measured interval: the session it belongs to, the canonical direction
/// the bounding frame travelled, and that frame's provenance copied verbatim. It is
/// the citation a presentation layer routes an "inspect frame" action through.
nonisolated struct SessionTimingBoundary: Hashable, Sendable {
    let sessionID: UUID
    let direction: ConnectionDirection?
    /// The single frame of evidence, copied verbatim from the source observation.
    let provenance: SessionFrameProvenance

    /// The capture-local position of the bounding frame. Used only for deterministic
    /// ordering.
    var occurrenceOrdinal: FrameOrdinal {
        provenance.ordinal
    }
}

// MARK: - SessionTimingMeasurement

/// One measured interval for one session: its kind, the elapsed seconds between its
/// two bounding frames, those two citations, and the sticky capture-loss knowledge of
/// the summary the boundaries came from. It carries no severity, threshold, label or
/// judgement.
nonisolated struct SessionTimingMeasurement: Hashable, Sendable {
    /// A deterministic identity seeded from the session id, the kind's stable
    /// discriminator and the two bounding frame ordinals (via
    /// `SessionBuilder.stableID`). Two measurements of the same kind on the same
    /// session — several DNS transactions, or a reused tuple's second incarnation —
    /// therefore keep distinct, stable ids across snapshots of the same capture.
    let id: UUID
    let kind: SessionTimingMeasurementKind
    /// The tuple-derived session id this measurement belongs to (never a TCP
    /// `ConnectionID`).
    let sessionID: UUID
    /// Elapsed seconds between `start` and `end`. Always finite and non-negative:
    /// anything else was refused rather than clamped.
    let elapsed: TimeInterval
    let start: SessionTimingBoundary
    let end: SessionTimingBoundary
    /// Sticky capture-loss knowledge of the summary both boundaries came from. It is
    /// coverage a presentation layer states once, never part of the interval.
    let lossKnowledge: CaptureLossKnowledge

    /// Elapsed time in milliseconds, for a presentation layer that reports
    /// milliseconds. Derived, never stored.
    var elapsedMilliseconds: Double {
        elapsed * 1_000
    }
}

// MARK: - SessionTimingDistribution

/// The rollup of every measurement of one kind across a set of sessions: how many were
/// measured, the fastest, the median and the slowest, and the session whose slowest
/// measurement it was. The median is the lower of the two middle values for an even
/// count — a fixed choice, never an interpolation that invents an interval nothing was
/// measured at.
nonisolated struct SessionTimingDistribution: Hashable, Sendable {
    let kind: SessionTimingMeasurementKind
    let count: Int
    let fastest: TimeInterval
    let median: TimeInterval
    let slowest: TimeInterval
    /// The session carrying the slowest measurement of this kind. Ties keep the
    /// measurement that comes first in the snapshot's deterministic order.
    let slowestSessionID: UUID
}

// MARK: - SessionTimingSnapshot

/// An immutable, deterministically ordered set of measurements plus the exact
/// accounting for everything that could *not* be measured. The three refusal counters
/// are coverage, never a finding: they say how often a pairing existed but one of the
/// policy conditions above withheld it.
nonisolated struct SessionTimingSnapshot: Hashable, Sendable {
    /// The canonical empty analysis — exactly what `SessionTimingAssessor` returns for
    /// three empty inputs.
    static let empty = SessionTimingSnapshot(
        measurements: [],
        omittedMeasurementCount: 0,
        untimedBoundaryCount: 0,
        incompleteRetentionCount: 0,
        countersOverflowed: false
    )

    /// Measurements in capture order: by start ordinal, then end ordinal, then the
    /// kind's fixed rank. Bounded per session and globally.
    let measurements: [SessionTimingMeasurement]
    /// Exact count of measurements dropped to honor a per-session or global bound.
    let omittedMeasurementCount: UInt64
    /// Exact count of pairings refused because a bounding frame carried no capture
    /// time, or the two instants did not yield a finite non-negative interval.
    let untimedBoundaryCount: UInt64
    /// Exact count of pairings refused because the summary they would come from had
    /// omitted observations or truncated event history, so "first" could not be
    /// established.
    let incompleteRetentionCount: UInt64
    /// Whether any saturating counter reached `UInt64.max`. Never wrapped.
    let countersOverflowed: Bool

    /// Every measurement for one tuple-derived session id, in the snapshot's order.
    func measurements(for sessionID: UUID) -> [SessionTimingMeasurement] {
        measurements.filter { $0.sessionID == sessionID }
    }

    /// Roll the measurements up per kind, optionally restricted to a set of session
    /// ids (the visible scope). Kinds with no measurement are omitted, and the result
    /// is ordered by the kinds' fixed rank so the table never reorders between
    /// renders. Pure and allocation-light: one pass plus one sort per present kind.
    func distributions(limitedTo sessionIDs: Set<UUID>? = nil) -> [SessionTimingDistribution] {
        var byKind: [SessionTimingMeasurementKind: [SessionTimingMeasurement]] = [:]
        for measurement in measurements {
            if let sessionIDs, !sessionIDs.contains(measurement.sessionID) {
                continue
            }
            byKind[measurement.kind, default: []].append(measurement)
        }
        return byKind.keys.sorted { $0.rank < $1.rank }.compactMap { kind in
            guard let group = byKind[kind], !group.isEmpty else {
                return nil
            }
            // `group` keeps the snapshot's deterministic order, and `max(by:)`
            // replaces only on a strictly greater element, so two equally slow
            // measurements resolve to the one that comes first in that order.
            let sorted = group.map(\.elapsed).sorted()
            guard let slowest = group.max(by: { $0.elapsed < $1.elapsed }) else {
                return nil
            }
            return SessionTimingDistribution(
                kind: kind,
                count: sorted.count,
                fastest: sorted[0],
                median: sorted[(sorted.count - 1) / 2],
                slowest: sorted[sorted.count - 1],
                slowestSessionID: slowest.sessionID
            )
        }
    }
}

// MARK: - SessionTimingAssessor

/// A pure, stateless assessor from the three retained evidence snapshots to a bounded
/// `SessionTimingSnapshot`. It holds only an injectable `Configuration` — no mutable
/// state — so assessing the same snapshots twice always yields the same result, and the
/// order of summaries in the inputs never changes the output.
nonisolated struct SessionTimingAssessor: Hashable, Sendable {
    // MARK: Lifecycle

    init(configuration: Configuration = Configuration()) {
        self.configuration = configuration
    }

    // MARK: Internal

    // MARK: Configuration

    /// Injectable bounds. Every value is clamped to at least one so no bound can
    /// disable measurement entirely; test configurations may be tiny.
    nonisolated struct Configuration: Hashable, Sendable {
        // MARK: Lifecycle

        init(
            maxMeasurementsPerSession: Int = 32,
            maxTotalMeasurements: Int = 4_096,
            maxPendingTransactionIDs: Int = 64
        ) {
            self.maxMeasurementsPerSession = max(1, maxMeasurementsPerSession)
            self.maxTotalMeasurements = max(1, maxTotalMeasurements)
            self.maxPendingTransactionIDs = max(1, maxPendingTransactionIDs)
        }

        // MARK: Internal

        /// Largest number of measurements retained for any one session.
        let maxMeasurementsPerSession: Int
        /// Largest number of measurements retained across all sessions.
        let maxTotalMeasurements: Int
        /// Largest number of distinct unanswered DNS transaction ids tracked while
        /// walking one flow. A further distinct id is not tracked, so its response
        /// yields no measurement rather than an unbounded pending table.
        let maxPendingTransactionIDs: Int
    }

    let configuration: Configuration

    /// Saturating unsigned addition. Returns the max on overflow together with a flag,
    /// so callers can both cap a total and record that it saturated.
    static func saturatingAdd(_ lhs: UInt64, _ rhs: UInt64) -> (value: UInt64, overflowed: Bool) {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? (UInt64.max, true) : (sum, false)
    }

    /// Measure every pairing the policy allows across the three retained evidence
    /// snapshots. Pure: no clock, no stored state, order-independent in the inputs.
    func assess(
        connections: ConnectionTable.Snapshot,
        tls: TLSEvidenceTable.Snapshot,
        datagrams: DatagramEvidenceTable.Snapshot
    )
        -> SessionTimingSnapshot
    {
        var context = Context(
            countersOverflowed: connections.countersOverflowed
                || tls.countersOverflowed
                || datagrams.countersOverflowed
        )
        for summary in connections.summaries {
            measureConnection(summary, into: &context)
        }
        for summary in tls.summaries {
            measureTLS(summary, into: &context)
        }
        for summary in datagrams.summaries {
            measureDatagrams(summary, into: &context)
        }
        return bounded(context)
    }

    // MARK: Private

    /// The mutable accumulator threaded through one assessment. It exists only inside
    /// `assess`; the assessor itself stays stateless.
    /// One session's interval identified by its two bounding frames — the key the
    /// supersede pass compares on.
    private struct Pair: Hashable {
        // MARK: Lifecycle

        init(measurement: SessionTimingMeasurement) {
            sessionID = measurement.sessionID
            start = measurement.start.occurrenceOrdinal
            end = measurement.end.occurrenceOrdinal
        }

        // MARK: Internal

        let sessionID: UUID
        let start: FrameOrdinal
        let end: FrameOrdinal
    }

    private struct Context {
        var measurements: [SessionTimingMeasurement] = []
        var untimedBoundaryCount: UInt64 = 0
        var incompleteRetentionCount: UInt64 = 0
        var countersOverflowed: Bool
    }

    // MARK: Measurement rules

    /// Ports whose DNS-shaped traffic is multicast/link-local name resolution (mDNS
    /// 5353, LLMNR 5355). Several hosts answer one multicast question and a transaction
    /// id does not identify one exchange, so no interval is measured there. Same set,
    /// same reason, as the datagram assessor's unanswered-query rule.
    private static var multicastNamePorts: Set<UInt16> {
        [5_353, 5_355]
    }

    /// Whether a summary retained everything it saw, which is what a "first X then Y"
    /// pairing needs before it can call one observation the first.
    private static func retainedEverything(_ summary: ConnectionSummary) -> Bool {
        summary.omittedEventCount == 0 && !summary.limitations.contains(.eventHistoryTruncated)
    }

    /// Drop an `applicationResponse` whose two frames are exactly the two frames a
    /// `tlsHandshakeReply` for the same session already reports.
    ///
    /// A TLS session's first payload *is* its ClientHello, so the generic
    /// request-to-reply rule and the TLS hello rule land on the same pair of frames and
    /// would show one interval twice under two names. The TLS row is strictly more
    /// specific about what those frames were, so it wins. This is not a bound: the
    /// dropped row adds nothing, so it is not counted as an omission. It is the same
    /// supersede pattern the connection and datagram assessors use.
    private static func withoutRedundantApplicationResponse(
        _ measurements: [SessionTimingMeasurement]
    )
        -> [SessionTimingMeasurement]
    {
        let tlsPairs = Set(
            measurements
                .filter { $0.kind == .tlsHandshakeReply }
                .map(Pair.init(measurement:))
        )
        guard !tlsPairs.isEmpty else {
            return measurements
        }
        return measurements.filter { measurement in
            guard measurement.kind == .applicationResponse else {
                return true
            }
            return !tlsPairs.contains(Pair(measurement: measurement))
        }
    }

    /// Deterministic order over measurements: capture order first, then the kind's
    /// fixed rank, so two intervals sharing both boundaries never swap.
    private static func measurementPrecedes(
        _ lhs: SessionTimingMeasurement, _ rhs: SessionTimingMeasurement
    )
        -> Bool
    {
        let lhsStart = lhs.start.occurrenceOrdinal
        let rhsStart = rhs.start.occurrenceOrdinal
        if lhsStart != rhsStart {
            return lhsStart < rhsStart
        }
        let lhsEnd = lhs.end.occurrenceOrdinal
        let rhsEnd = rhs.end.occurrenceOrdinal
        if lhsEnd != rhsEnd {
            return lhsEnd < rhsEnd
        }
        return lhs.kind.rank < rhs.kind.rank
    }

    /// Build one measurement from two bounding frames, or record exactly why not.
    /// The interval must be finite and non-negative; nothing is clamped.
    private func measure(
        kind: SessionTimingMeasurementKind,
        sessionID: UUID,
        start: (direction: ConnectionDirection?, provenance: SessionFrameProvenance),
        end: (direction: ConnectionDirection?, provenance: SessionFrameProvenance),
        lossKnowledge: CaptureLossKnowledge,
        into context: inout Context
    ) {
        guard let startTime = start.provenance.timestamp,
              let endTime = end.provenance.timestamp else
        {
            let counted = Self.saturatingAdd(context.untimedBoundaryCount, 1)
            context.untimedBoundaryCount = counted.value
            context.countersOverflowed = context.countersOverflowed || counted.overflowed
            return
        }
        let elapsed = endTime.timeIntervalSince(startTime)
        guard elapsed.isFinite, elapsed >= 0 else {
            let counted = Self.saturatingAdd(context.untimedBoundaryCount, 1)
            context.untimedBoundaryCount = counted.value
            context.countersOverflowed = context.countersOverflowed || counted.overflowed
            return
        }
        let startBoundary = SessionTimingBoundary(
            sessionID: sessionID, direction: start.direction, provenance: start.provenance
        )
        let endBoundary = SessionTimingBoundary(
            sessionID: sessionID, direction: end.direction, provenance: end.provenance
        )
        context.measurements.append(SessionTimingMeasurement(
            id: SessionBuilder.stableID(
                "timing|\(sessionID.uuidString)|\(kind.stableDiscriminator)"
                    + "|\(startBoundary.occurrenceOrdinal.rawValue)|\(endBoundary.occurrenceOrdinal.rawValue)"
            ),
            kind: kind,
            sessionID: sessionID,
            elapsed: elapsed,
            start: startBoundary,
            end: endBoundary,
            lossKnowledge: lossKnowledge
        ))
    }

    /// Record that a pairing existed but the summary's retention could not establish
    /// which observation was first.
    private func refuseForRetention(into context: inout Context) {
        let counted = Self.saturatingAdd(context.incompleteRetentionCount, 1)
        context.incompleteRetentionCount = counted.value
        context.countersOverflowed = context.countersOverflowed || counted.overflowed
    }

    /// Apply the per-session and global bounds and produce the final ordered snapshot.
    private func bounded(_ context: Context) -> SessionTimingSnapshot {
        var countersOverflowed = context.countersOverflowed
        var omitted: UInt64 = 0
        func drop(_ count: Int) {
            guard count > 0 else {
                return
            }
            let counted = Self.saturatingAdd(omitted, UInt64(count))
            omitted = counted.value
            countersOverflowed = countersOverflowed || counted.overflowed
        }

        let ordered = Self.withoutRedundantApplicationResponse(context.measurements)
            .sorted(by: Self.measurementPrecedes)
        var perSession: [UUID: Int] = [:]
        var kept: [SessionTimingMeasurement] = []
        kept.reserveCapacity(min(ordered.count, configuration.maxTotalMeasurements))
        for measurement in ordered {
            let used = perSession[measurement.sessionID] ?? 0
            guard used < configuration.maxMeasurementsPerSession,
                  kept.count < configuration.maxTotalMeasurements else
            {
                drop(1)
                continue
            }
            perSession[measurement.sessionID] = used + 1
            kept.append(measurement)
        }
        return SessionTimingSnapshot(
            measurements: kept,
            omittedMeasurementCount: omitted,
            untimedBoundaryCount: context.untimedBoundaryCount,
            incompleteRetentionCount: context.incompleteRetentionCount,
            countersOverflowed: countersOverflowed
        )
    }

    /// Measure one connection incarnation: the answered handshake round trip, the whole
    /// observed set-up, and the first request-to-reply interval.
    private func measureConnection(_ summary: ConnectionSummary, into context: inout Context) {
        let sessionID = SessionBuilder.sessionID(for: summary.tuple)
        let events = summary.events.sorted { $0.occurrenceOrdinal < $1.occurrenceOrdinal }
        let complete = Self.retainedEverything(summary)

        // The whole observed set-up, read from one retained event's own three
        // citations: SYN, SYN+ACK and the completing ACK. Because the event is either
        // retained whole or not at all, this interval is exact even when other events
        // of the same connection were dropped — no retention gate applies.
        for event in events where event.kind == .handshakeCompleted && event.provenance.count == 3 {
            guard let first = event.provenance.min(by: { $0.ordinal < $1.ordinal }),
                  let last = event.provenance.max(by: { $0.ordinal < $1.ordinal }) else
            {
                continue
            }
            measure(
                kind: .tcpHandshakeCompletion,
                sessionID: sessionID,
                start: (summary.initiator, first),
                end: (event.direction, last),
                lossKnowledge: summary.lossKnowledge,
                into: &context
            )
        }

        // The attempt that was actually answered: the last SYN at or before the first
        // SYN+ACK. An earlier, unanswered attempt is deliberately excluded, and the two
        // cited frames name which attempt this was.
        if let synAck = events.first(where: { $0.kind == .synAck }),
           let syn = events.last(where: {
               $0.kind == .syn && $0.occurrenceOrdinal <= synAck.occurrenceOrdinal
           })
        {
            if complete {
                measure(
                    kind: .tcpHandshakeReply,
                    sessionID: sessionID,
                    start: (syn.direction, syn.provenance[0]),
                    end: (synAck.direction, synAck.provenance[0]),
                    lossKnowledge: summary.lossKnowledge,
                    into: &context
                )
            } else {
                refuseForRetention(into: &context)
            }
        }

        // Request to reply, told apart by the *observed* initiator only. A connection
        // whose initiator was never observed reports nothing here rather than guessing
        // which side asked.
        guard let initiator = summary.initiator,
              let request = events.first(where: {
                  $0.kind == .payloadObserved && $0.direction == initiator
              }),
              let reply = events.first(where: {
                  $0.kind == .payloadObserved
                      && $0.direction == initiator.opposite
                      && $0.occurrenceOrdinal > request.occurrenceOrdinal
              }) else
        {
            return
        }
        guard complete else {
            refuseForRetention(into: &context)
            return
        }
        measure(
            kind: .applicationResponse,
            sessionID: sessionID,
            start: (request.direction, request.provenance[0]),
            end: (reply.direction, reply.provenance[0]),
            lossKnowledge: summary.lossKnowledge,
            into: &context
        )
    }

    /// Measure one flow's TLS hello exchange: the last retained ClientHello at or
    /// before the first retained ServerHello in the opposite direction, to that
    /// ServerHello. A HelloRetryRequest is a ServerHello and is measured as the reply
    /// it is, so an HRR negotiation reports the first round trip rather than none.
    private func measureTLS(_ summary: TLSEvidenceSummary, into context: inout Context) {
        let observations = summary.observations
        guard let serverHello = observations.first(where: {
            if case .serverHello = $0.fact.handshake {
                true
            } else {
                false
            }
        }) else {
            return
        }
        guard let clientHello = observations.last(where: {
            guard case .clientHello = $0.fact.handshake else {
                return false
            }
            return $0.direction == serverHello.direction.opposite
                && $0.provenance.ordinal <= serverHello.provenance.ordinal
        }) else {
            return
        }
        guard summary.omittedObservationCount == 0 else {
            refuseForRetention(into: &context)
            return
        }
        measure(
            kind: .tlsHandshakeReply,
            sessionID: summary.sessionID,
            start: (clientHello.direction, clientHello.provenance),
            end: (serverHello.direction, serverHello.provenance),
            lossKnowledge: summary.lossKnowledge,
            into: &context
        )
    }

    /// Measure one flow's DNS exchanges: each retained standard query paired with the
    /// first later response carrying its transaction id. The first query for an id
    /// starts the interval — a retry does not restart it, so the measurement reports
    /// how long the whole exchange took, matching the session summary's existing DNS
    /// latency fact. Transaction ids are compared here and discarded; only the two
    /// frames reach the measurement.
    private func measureDatagrams(_ summary: DatagramEvidenceSummary, into context: inout Context) {
        guard !Self.multicastNamePorts.contains(summary.tuple.a.port),
              !Self.multicastNamePorts.contains(summary.tuple.b.port) else
        {
            return
        }
        var pending: [UInt16: DatagramEvidenceObservation] = [:]
        for observation in summary.observations {
            guard case let .dns(facts) = observation.kind, facts.opcode == 0 else {
                continue
            }
            guard facts.isResponse else {
                if pending[facts.transactionID] == nil,
                   pending.count < configuration.maxPendingTransactionIDs
                {
                    pending[facts.transactionID] = observation
                }
                continue
            }
            guard let query = pending.removeValue(forKey: facts.transactionID) else {
                continue
            }
            guard summary.omittedObservationCount == 0 else {
                refuseForRetention(into: &context)
                continue
            }
            measure(
                kind: .dnsResponse,
                sessionID: summary.sessionID,
                start: (query.direction, query.provenance),
                end: (observation.direction, observation.provenance),
                lossKnowledge: summary.lossKnowledge,
                into: &context
            )
        }
    }
}
