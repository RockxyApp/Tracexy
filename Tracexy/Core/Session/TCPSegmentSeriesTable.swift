import Foundation

// This file declares the frozen, pure value types for the per-segment TCP series
// (the per-session TCP health chart). Like `TLSEvidenceTable` and
// `DatagramEvidenceTable`, everything here is observation-only: it records the
// header fields ordered frames carried, never a finding, severity, rate, round-trip
// time, judgement or UI state. No type stores raw bytes, a host, a name, a rendered
// label or a derived series — the arithmetic that turns these observations into a
// chart lives in `TCPStreamHealth`, one layer up, and can be re-derived from the
// same retention at any time.
//
// The one discipline that makes every later derivation exact: **what a summary
// retains is always a complete prefix of its flow's segments, never a sample.**
// When a bound is reached the table stops retaining and counts every further segment
// exactly; it never thins, decimates or evicts what it already holds. A derived rate,
// round trip or in-flight total is therefore arithmetic over an unbroken run of
// frames, and the only thing the user is told is where that run ends.

// MARK: - TCPSegmentObservation

/// One retained TCP segment, as its header stated it: which session/tuple it belongs
/// to, the canonical direction it travelled, its exact frame provenance, and the four
/// header fields a per-segment series is drawn from. `sessionID` is the tuple-derived
/// session id (never a TCP `ConnectionID`); `direction` is derived only by comparing
/// the packet source against the canonical tuple and never names a client or server.
///
/// Nothing here is computed. Sequence space (payload plus one per SYN/FIN), relative
/// sequence numbers, window scaling and every interval are derivations the analysis
/// layer performs from `flags`, `payloadLength` and `windowScale`, so this layer holds
/// no policy that could age.
nonisolated struct TCPSegmentObservation: Hashable, Sendable {
    let sessionID: UUID
    let tuple: FiveTuple
    let direction: ConnectionDirection
    let provenance: SessionFrameProvenance
    /// Raw sequence number (header offset 4).
    let sequenceNumber: UInt32
    /// Raw acknowledgement number (header offset 8). The field is always present on
    /// the wire; `flags` states whether it carries meaning.
    let acknowledgementNumber: UInt32
    /// The eight control bits, retained whole so a later layer never has to guess
    /// which of them the fold considered.
    let flags: TCPFlags
    /// Raw advertised window (header offset 14), before any window-scale shift.
    let windowSize: UInt16
    /// Captured payload bytes. This is the captured length, not a declared one.
    let payloadLength: Int
    /// The effective RFC 7323 shift this segment's Window Scale option offered, or
    /// `nil` when it carried none. Present on SYNs in practice; retained per segment
    /// so the analysis derives the flow's scaling from the frames themselves.
    let windowScale: UInt8?
}

// MARK: - TCPSegmentSeriesSummary

/// The bounded per-session view of one TCP flow's segments: a complete capture-order
/// prefix of them, the exact saturating count of every segment that arrived after the
/// prefix ended, and the two coverage facts a chart has to state — sticky capture-loss
/// knowledge and whether any retained frame was captured shorter than its wire length.
nonisolated struct TCPSegmentSeriesSummary: Hashable, Sendable {
    let sessionID: UUID
    let tuple: FiveTuple
    /// A complete prefix of the flow's segments in capture order. Never thinned and
    /// never evicted, so any derivation over it is exact for the span it covers.
    var observations: [TCPSegmentObservation]
    /// Exact segments of this flow that arrived after a per-summary or global bound
    /// ended the prefix. Saturates at `UInt64.max`.
    var omittedObservationCount: UInt64
    /// Sticky capture-loss knowledge merged across this flow's retained segments.
    var lossKnowledge: CaptureLossKnowledge
    /// Whether any retained segment's frame was captured shorter than its original
    /// on-wire length, so a payload length here may be below what was sent.
    var snapLengthTruncationObserved: Bool
}

// MARK: - TCPSegmentSeriesTable

/// A pure, bounded, passive fold from ordered decoded TCP frames to a per-session
/// prefix of segment headers.
///
/// The only source of state change is `offer`, applied in accepted-frame order. No
/// wall clock, timer or background work mutates anything — replaying the same ordered
/// frames through the same configuration always yields the same `Snapshot`. Every
/// retained collection has a named configuration bound and every drop is accounted
/// for exactly, so nothing is silently lost.
///
/// It is deliberately a *separate* table rather than more state inside
/// `ConnectionTable`: the connection fold owns lifecycle and ordering and its output
/// is pinned by the replay goldens, while this is additive evidence keyed by the same
/// tuple-derived session id the summaries already publish. Its bounds can therefore
/// move without touching a single lifecycle fact.
nonisolated struct TCPSegmentSeriesTable {
    // MARK: Lifecycle

    init(configuration: Configuration = Configuration()) {
        self.configuration = configuration
    }

    // MARK: Internal

    // MARK: Configuration

    /// Injectable bounds. Every value is clamped to at least one so no bound can
    /// disable the table entirely; test configurations may be tiny.
    nonisolated struct Configuration: Hashable, Sendable {
        // MARK: Lifecycle

        init(
            maxSummaries: Int = 16_384,
            maxObservationsPerSummary: Int = 512,
            maxTotalObservations: Int = 65_536
        ) {
            self.maxSummaries = max(1, maxSummaries)
            self.maxObservationsPerSummary = max(1, maxObservationsPerSummary)
            self.maxTotalObservations = max(1, maxTotalObservations)
        }

        // MARK: Internal

        /// Largest number of distinct first-seen TCP flows retained. A new flow beyond
        /// this is not retained; each of its segments is accounted globally.
        let maxSummaries: Int
        /// Largest number of segments any one flow's prefix holds. The default keeps a
        /// chart's worth of a conversation — both handshakes, the whole opening
        /// exchange and several hundred segments of transfer — without letting one
        /// flow claim the global budget.
        let maxObservationsPerSummary: Int
        /// Largest number of segments retained across all flows. Reached first in a
        /// long live capture: flows seen after it hold an empty prefix, which the
        /// chart states rather than hides.
        let maxTotalObservations: Int
    }

    // MARK: Snapshot

    /// An immutable, first-seen-ordered view of every retained flow plus the exact
    /// bound/omission accounting, so a caller can prove the bounds hold without an
    /// unbounded tombstone set.
    nonisolated struct Snapshot: Hashable, Sendable {
        static let empty = Snapshot(
            summaries: [],
            omittedObservationCount: 0,
            retainedObservationCount: 0,
            capacityReached: false,
            countersOverflowed: false
        )

        /// First-seen flows.
        let summaries: [TCPSegmentSeriesSummary]
        /// Exact global count of segments not retained because a bound was reached.
        let omittedObservationCount: UInt64
        /// Total segments retained across all summaries.
        let retainedObservationCount: Int
        /// Whether any bound rejected a segment (the summary cap, a per-summary cap or
        /// the global observation cap).
        let capacityReached: Bool
        /// Whether any saturating counter reached `UInt64.max`.
        let countersOverflowed: Bool

        /// The retained prefix for one tuple-derived session id, or `nil` when this
        /// capture retained no TCP segments for it.
        func summary(for sessionID: UUID) -> TCPSegmentSeriesSummary? {
            summaries.first { $0.sessionID == sessionID }
        }
    }

    /// Saturating unsigned addition. Returns the max on overflow together with a flag,
    /// so callers can both cap the total and record `countersOverflowed`. Exposed as
    /// the test seam for the saturating-counter contract, since real ingestion cannot
    /// reach `UInt64` overflow on a segment counter.
    static func saturatingAdd(_ lhs: UInt64, _ rhs: UInt64) -> (value: UInt64, overflowed: Bool) {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? (UInt64.max, true) : (sum, false)
    }

    /// Fold one already-decoded frame's TCP header. Frames must arrive in
    /// accepted-frame order; the provenance ordinal is the sequencing key.
    ///
    /// Retention rules:
    /// - A frame with no TCP facts, no five-tuple, or a source/destination matching
    ///   neither canonical ordering does nothing — the direction is never guessed.
    /// - Every other TCP segment is one observation, appended to its flow's prefix
    ///   while both the per-summary and global bounds allow it.
    /// - Once a bound rejects a segment, the flow's prefix is closed for good and each
    ///   further segment is counted exactly. A later segment is never admitted past a
    ///   rejected one, so the prefix can never contain a hole.
    /// - A brand-new flow beyond the summary cap retains nothing and counts every one
    ///   of its segments globally.
    mutating func offer(
        _ packet: DecodedPacket,
        provenance: SessionFrameProvenance,
        loss: CaptureLossKnowledge = .unknown
    ) {
        guard let facts = packet.tcpFacts,
              let tuple = packet.fiveTuple,
              let source = packet.sourceEndpoint,
              let destination = packet.destinationEndpoint else
        {
            return
        }

        // Direction derives only from the source against the canonical tuple; never
        // client/server. A source/destination matching neither ordering is left
        // unplaced rather than guessed.
        let direction: ConnectionDirection
        if source == tuple.a, destination == tuple.b {
            direction = .aToB
        } else if source == tuple.b, destination == tuple.a {
            direction = .bToA
        } else {
            return
        }

        guard var summary = summaryEntry(for: tuple) else {
            // A new unknown flow after the summary cap retains nothing. Account the
            // segment globally; do not claim exact omitted unique flows, which would
            // require an unbounded tombstone set.
            capacityReached = true
            countersOverflowed = Self.add(&omittedObservationCount, by: 1) || countersOverflowed
            return
        }

        guard summary.observations.count < configuration.maxObservationsPerSummary,
              retainedObservationTotal < configuration.maxTotalObservations else
        {
            // The prefix is closed. Coverage facts stay at what the retained frames
            // proved, so a caveat can never describe a frame the chart does not draw.
            countersOverflowed = Self.bump(
                &summary.omittedObservationCount,
                into: &omittedObservationCount,
                by: 1
            ) || countersOverflowed
            capacityReached = true
            summaries[tuple] = summary
            return
        }

        summary.lossKnowledge = summary.lossKnowledge.merged(with: loss)
        if provenance.originalLength > provenance.capturedLength {
            summary.snapLengthTruncationObserved = true
        }
        summary.observations.append(
            TCPSegmentObservation(
                sessionID: summary.sessionID,
                tuple: tuple,
                direction: direction,
                provenance: provenance,
                sequenceNumber: facts.sequenceNumber,
                acknowledgementNumber: facts.acknowledgementNumber,
                flags: facts.flags,
                windowSize: facts.windowSize,
                payloadLength: facts.payloadLength,
                windowScale: facts.options.windowScale
            )
        )
        retainedObservationTotal += 1
        summaries[tuple] = summary
    }

    /// A first-seen-ordered snapshot of every retained flow. Pure; decodes nothing.
    func snapshot() -> Snapshot {
        Snapshot(
            summaries: order.compactMap { summaries[$0] },
            omittedObservationCount: omittedObservationCount,
            retainedObservationCount: retainedObservationTotal,
            capacityReached: capacityReached,
            countersOverflowed: countersOverflowed
        )
    }

    // MARK: Private

    private let configuration: Configuration

    /// Flows in first-seen order, so summaries emit oldest→newest.
    private var order: [FiveTuple] = []
    private var summaries: [FiveTuple: TCPSegmentSeriesSummary] = [:]

    /// Running total of retained segments across all summaries — the exact global
    /// `maxTotalObservations` accounting source.
    private var retainedObservationTotal = 0
    private var omittedObservationCount: UInt64 = 0
    private var capacityReached = false
    private var countersOverflowed = false

    /// Increment a per-summary and the matching global counter together, returning
    /// whether either saturated.
    private static func bump(_ perSummary: inout UInt64, into global: inout UInt64, by count: UInt64) -> Bool {
        let summed = Self.saturatingAdd(perSummary, count)
        perSummary = summed.value
        let globalSummed = Self.saturatingAdd(global, count)
        global = globalSummed.value
        return summed.overflowed || globalSummed.overflowed
    }

    /// Increment a single global counter, returning whether it saturated.
    private static func add(_ global: inout UInt64, by count: UInt64) -> Bool {
        let summed = Self.saturatingAdd(global, count)
        global = summed.value
        return summed.overflowed
    }

    /// The existing summary for this flow, or a fresh one appended in first-seen order
    /// when the summary cap allows. `nil` only when a brand-new flow would exceed the
    /// summary cap — the caller then accounts the segment globally.
    private mutating func summaryEntry(for tuple: FiveTuple) -> TCPSegmentSeriesSummary? {
        if let existing = summaries[tuple] {
            return existing
        }
        guard order.count < configuration.maxSummaries else {
            return nil
        }
        order.append(tuple)
        let fresh = TCPSegmentSeriesSummary(
            sessionID: SessionBuilder.sessionID(for: tuple),
            tuple: tuple,
            observations: [],
            omittedObservationCount: 0,
            lossKnowledge: .unknown,
            snapLengthTruncationObserved: false
        )
        summaries[tuple] = fresh
        return fresh
    }
}
