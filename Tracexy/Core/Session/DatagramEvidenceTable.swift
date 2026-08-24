import Foundation

// This file declares the frozen, pure value types for passive DNS/ICMP datagram
// evidence. Like `ConnectionTypes`/`ConnectionTable`, everything here is
// observation-only: it records what accepted frames prove, never a finding,
// severity, policy or UI state. No type stores raw bytes, DNS names/answers,
// rendered layers, URLs, file identity or quoted ICMP payload — only typed wire
// facts already produced by the decoder, plus the per-frame provenance the fold
// was already allowed to know. Nothing here reads a wall clock; the sole source of
// state is the ordered `offer` fold in `SessionAccumulator`.

// MARK: - DatagramEvidenceKind

/// The typed datagram fact one observation carries: either the neutral DNS
/// fixed-header facts or the neutral ICMP/ICMPv6 family/type/code facts. Both are
/// decoder-produced wire facts; neither carries a name, answer value or body.
nonisolated enum DatagramEvidenceKind: Hashable, Sendable {
    case dns(DNSMessageFacts)
    case icmp(ICMPMessageFacts)
}

// MARK: - DatagramEvidenceObservation

/// One retained datagram observation: which session/tuple it belongs to, the
/// canonical direction it travelled, the exact frame provenance that justifies it,
/// and the typed kind. `sessionID` is the tuple-derived session id (never a TCP
/// `ConnectionID`); `direction` is derived only by comparing the packet source
/// against the canonical tuple and never names a client or server.
nonisolated struct DatagramEvidenceObservation: Hashable, Sendable {
    let sessionID: UUID
    let tuple: FiveTuple
    let direction: ConnectionDirection
    let provenance: SessionFrameProvenance
    let kind: DatagramEvidenceKind
}

// MARK: - DatagramEvidenceSummary

/// The bounded per-session view of one flow's datagram evidence: its retained
/// observations in accepted-frame order, an exact saturating count of observations
/// omitted to honor the bounds, the sticky capture-loss knowledge merged across its
/// frames, and whether any of its frames was captured shorter than its wire length.
nonisolated struct DatagramEvidenceSummary: Hashable, Sendable {
    let sessionID: UUID
    let tuple: FiveTuple
    /// Retained observations in accepted-frame order; bounded per summary and
    /// globally. Rejected occurrences are counted in `omittedObservationCount`.
    var observations: [DatagramEvidenceObservation]
    /// Exact occurrences rejected for this summary because a per-summary or global
    /// bound was reached. Saturates at `UInt64.max`.
    var omittedObservationCount: UInt64
    /// Sticky capture-loss knowledge merged across this flow's frames.
    var lossKnowledge: CaptureLossKnowledge
    /// Whether any retained-or-rejected frame for this flow was captured shorter
    /// than its original on-wire length.
    var snapLengthTruncationObserved: Bool
}

// MARK: - DatagramEvidenceTable

/// A pure, bounded, passive fold from ordered decoded UDP-DNS/ICMP frames to
/// per-session datagram evidence.
///
/// The only source of state change is `offer`, applied in accepted-frame order.
/// No wall clock, timer or background work mutates anything — replaying the same
/// ordered frames through the same configuration always yields the same
/// `Snapshot`. Every retained collection has a named configuration bound, and every
/// drop is accounted for (per-summary and global omission counts, capacity flag),
/// so nothing is silently lost.
///
/// This layer is observation-only. It records what the frames prove — it never
/// retains a full stream, produces findings, or reaches the UI. It uses the shared
/// tuple-derived session id, never the TCP `ConnectionID`, so DNS/ICMP evidence
/// keys to the same session a summary already publishes.
nonisolated struct DatagramEvidenceTable {
    // MARK: Lifecycle

    init(configuration: Configuration = Configuration()) {
        self.configuration = configuration
    }

    // MARK: Internal

    // MARK: Configuration

    /// Injectable bounds. Every value is clamped to at least one so no bound can
    /// disable the table entirely; test configurations may be tiny. The defaults
    /// are deliberately no larger than the connection table's comparable
    /// summary/event bounds.
    nonisolated struct Configuration: Hashable, Sendable {
        // MARK: Lifecycle

        init(
            maxSummaries: Int = 16_384,
            maxObservationsPerSummary: Int = 256,
            maxTotalObservations: Int = 131_072
        ) {
            self.maxSummaries = max(1, maxSummaries)
            self.maxObservationsPerSummary = max(1, maxObservationsPerSummary)
            self.maxTotalObservations = max(1, maxTotalObservations)
        }

        // MARK: Internal

        /// Largest number of distinct first-seen flows retained. A new flow beyond
        /// this is not retained; each of its fact occurrences is one global omission.
        let maxSummaries: Int
        /// Largest number of observations any one summary retains.
        let maxObservationsPerSummary: Int
        /// Largest number of observations retained across all summaries.
        let maxTotalObservations: Int
    }

    // MARK: Snapshot

    /// An immutable, first-seen-ordered view of every retained flow plus the exact
    /// bound/omission accounting. The extra counts let a caller prove the bounds
    /// hold without an unbounded tombstone set.
    nonisolated struct Snapshot: Hashable, Sendable {
        static let empty = Snapshot(
            summaries: [],
            omittedObservationCount: 0,
            retainedObservationCount: 0,
            excludedTCPDNSFactCount: 0,
            capacityReached: false,
            countersOverflowed: false
        )

        /// First-seen flows.
        let summaries: [DatagramEvidenceSummary]
        /// Exact global count of observation occurrences omitted to honor a bound.
        let omittedObservationCount: UInt64
        /// Total observations retained across all summaries.
        let retainedObservationCount: Int
        /// Exact global count of TCP-DNS fact occurrences deliberately excluded from
        /// retention (see `offer`). This is truthful coverage, never a finding.
        let excludedTCPDNSFactCount: UInt64
        /// Whether any bound rejected a fact (a summary cap, a per-summary cap or the
        /// global observation cap).
        let capacityReached: Bool
        /// Whether any saturating counter reached `UInt64.max`.
        let countersOverflowed: Bool
    }

    /// Saturating unsigned addition. Returns the max on overflow together with a
    /// flag, so callers can both cap the total and record `countersOverflowed`.
    /// Exposed as the test seam for the saturating-counter contract, since real
    /// ingestion cannot reach `UInt64` overflow on any occurrence counter.
    static func saturatingAdd(_ lhs: UInt64, _ rhs: UInt64) -> (value: UInt64, overflowed: Bool) {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? (UInt64.max, true) : (sum, false)
    }

    /// Fold one already-decoded (and application-enriched) frame's datagram
    /// evidence. Frames must arrive in accepted-frame order; the provenance ordinal
    /// is the sequencing key.
    ///
    /// Retention rules:
    /// - Retain UDP DNS only when `dnsFacts` exists; retain ICMP/ICMPv6 only when
    ///   `icmpFacts` exists.
    /// - A TCP (or any non-UDP) DNS fact is deliberately **not** retained — the
    ///   bounded prefix probe does not yet cite all contributing frames — but each
    ///   such occurrence is counted in `excludedTCPDNSFactCount`. That count includes
    ///   both a complete per-frame TCP-DNS fact and a reassembled `dnsFacts`
    ///   propagated transiently onto the enriched packet solely for this count.
    /// - Tupleless/ARP/other packets do nothing.
    mutating func offer(
        _ packet: DecodedPacket,
        provenance: SessionFrameProvenance,
        loss: CaptureLossKnowledge = .unknown
    ) {
        guard let tuple = packet.fiveTuple,
              let source = packet.sourceEndpoint,
              let destination = packet.destinationEndpoint else
        {
            return
        }

        let kind: DatagramEvidenceKind
        if let icmp = packet.icmpFacts {
            kind = .icmp(icmp)
        } else if let dns = packet.dnsFacts {
            guard packet.transport == .udp else {
                // A TCP-DNS fact (per-frame or reassembled): counted, never retained.
                let counted = Self.saturatingAdd(excludedTCPDNSFactCount, 1)
                excludedTCPDNSFactCount = counted.value
                countersOverflowed = countersOverflowed || counted.overflowed
                return
            }
            kind = .dns(dns)
        } else {
            return
        }

        // Direction derives only from the source against the canonical tuple; never
        // client/server. A source/destination that matches neither ordering is left
        // unplaced rather than guessed.
        let direction: ConnectionDirection
        if source == tuple.a, destination == tuple.b {
            direction = .aToB
        } else if source == tuple.b, destination == tuple.a {
            direction = .bToA
        } else {
            return
        }

        let observation = DatagramEvidenceObservation(
            sessionID: SessionBuilder.sessionID(for: tuple),
            tuple: tuple,
            direction: direction,
            provenance: provenance,
            kind: kind
        )
        retain(observation, tuple: tuple, loss: loss, truncated: provenance.originalLength > provenance.capturedLength)
    }

    /// A first-seen-ordered snapshot of every retained flow. Pure; decodes nothing.
    func snapshot() -> Snapshot {
        Snapshot(
            summaries: order.compactMap { summaries[$0] },
            omittedObservationCount: omittedObservationCount,
            retainedObservationCount: retainedObservationTotal,
            excludedTCPDNSFactCount: excludedTCPDNSFactCount,
            capacityReached: capacityReached,
            countersOverflowed: countersOverflowed
        )
    }

    // MARK: Private

    private let configuration: Configuration

    /// Flows in first-seen order, so summaries emit oldest→newest.
    private var order: [FiveTuple] = []
    private var summaries: [FiveTuple: DatagramEvidenceSummary] = [:]

    /// Running total of retained observations across all summaries — the exact
    /// global `maxTotalObservations` accounting source.
    private var retainedObservationTotal = 0
    /// Cumulative observation occurrences omitted to honor a bound.
    private var omittedObservationCount: UInt64 = 0
    /// Cumulative TCP-DNS fact occurrences excluded from retention.
    private var excludedTCPDNSFactCount: UInt64 = 0
    private var capacityReached = false
    private var countersOverflowed = false

    /// Retain one classified observation, folding sticky loss/truncation and
    /// honoring the summary and observation bounds. A new flow beyond the summary
    /// cap is not retained; its occurrence is counted as one global omission.
    private mutating func retain(
        _ observation: DatagramEvidenceObservation,
        tuple: FiveTuple,
        loss: CaptureLossKnowledge,
        truncated: Bool
    ) {
        if var summary = summaries[tuple] {
            summary.lossKnowledge = summary.lossKnowledge.merged(with: loss)
            if truncated {
                summary.snapLengthTruncationObserved = true
            }
            appendOrOmit(&summary, observation)
            summaries[tuple] = summary
            return
        }

        guard order.count < configuration.maxSummaries else {
            // A new unknown flow after the summary cap is not retained. Count exactly
            // one global omitted observation per occurrence; do not claim exact
            // omitted unique flows, which would require an unbounded tombstone set.
            omitGlobally()
            return
        }

        var summary = DatagramEvidenceSummary(
            sessionID: observation.sessionID,
            tuple: tuple,
            observations: [],
            omittedObservationCount: 0,
            lossKnowledge: loss,
            snapLengthTruncationObserved: truncated
        )
        appendOrOmit(&summary, observation)
        order.append(tuple)
        summaries[tuple] = summary
    }

    /// Append the observation if both the per-summary and global observation bounds
    /// allow it; otherwise increment both the summary's and the global exact
    /// occurrence count and flag capacity.
    private mutating func appendOrOmit(
        _ summary: inout DatagramEvidenceSummary,
        _ observation: DatagramEvidenceObservation
    ) {
        guard summary.observations.count < configuration.maxObservationsPerSummary,
              retainedObservationTotal < configuration.maxTotalObservations else
        {
            let perSummary = Self.saturatingAdd(summary.omittedObservationCount, 1)
            summary.omittedObservationCount = perSummary.value
            let global = Self.saturatingAdd(omittedObservationCount, 1)
            omittedObservationCount = global.value
            countersOverflowed = countersOverflowed || perSummary.overflowed || global.overflowed
            capacityReached = true
            return
        }
        summary.observations.append(observation)
        retainedObservationTotal += 1
    }

    /// Count one global omitted observation without a summary (summary cap reached).
    private mutating func omitGlobally() {
        let global = Self.saturatingAdd(omittedObservationCount, 1)
        omittedObservationCount = global.value
        countersOverflowed = countersOverflowed || global.overflowed
        capacityReached = true
    }
}
