import Foundation

// This file declares the frozen, pure value types for passive TLS record evidence.
// Like `DatagramEvidenceTable`, everything here is observation-only: it records what
// accepted frames prove, never a finding, severity, policy, TLS-version judgement or
// UI state. No type stores raw bytes, SNI, host, DNS, path, URL, certificate
// material, a rendered label or a negotiation verdict — only the neutral N3C1
// `TLSRecordFact` the decoder already produced, plus the per-frame provenance the
// fold was already allowed to know. Nothing here reads a wall clock; the sole source
// of state is the ordered `offer` fold in `SessionAccumulator`.
//
// The one non-obvious discipline versus the datagram table: a TLS record recovered by
// the multi-frame prefix probe is *never* retained or cited, because the current
// bounded probe does not cite the full set of contributing frames (see the N3C
// provenance decision). Such recovered records are counted as excluded — truthful
// coverage — but only when the current frame carried no direct record facts of its
// own, so a complete single-frame record is never double-counted.

// MARK: - TLSEvidenceObservation

/// One retained TLS record observation: which session/tuple it belongs to, the
/// canonical direction it travelled, the exact direct-frame provenance that justifies
/// it, its zero-based index within that frame's accepted record array, and the single
/// accepted `TLSRecordFact`. `sessionID` is the tuple-derived session id (never a TCP
/// `ConnectionID`); `direction` is derived only by comparing the packet source against
/// the canonical tuple and never names a client or server. Every observation cites a
/// direct per-frame record — a reassembled fact is excluded-counted, never retained.
nonisolated struct TLSEvidenceObservation: Hashable, Sendable {
    let sessionID: UUID
    let tuple: FiveTuple
    let direction: ConnectionDirection
    let provenance: SessionFrameProvenance
    /// Zero-based position of this record within its frame's accepted `tlsRecords`.
    let recordIndex: Int
    let fact: TLSRecordFact
}

// MARK: - TLSEvidenceSummary

/// The bounded per-session view of one flow's TLS record evidence: its retained
/// direct-frame observations in accepted-frame/record order, plus the exact saturating
/// counters that account for everything not retained — direct occurrences omitted to
/// honor a bound, reassembled record occurrences deliberately excluded, recovered
/// truncation indicators, and frames whose direct decode hit the 32-record cap. Sticky
/// capture-loss knowledge and snap-length truncation are merged across the flow.
nonisolated struct TLSEvidenceSummary: Hashable, Sendable {
    let sessionID: UUID
    let tuple: FiveTuple
    /// Retained direct-frame observations in accepted-frame then within-frame record
    /// order; bounded per summary and globally. Rejected direct occurrences are
    /// counted in `omittedObservationCount`.
    var observations: [TLSEvidenceObservation]
    /// Exact direct record occurrences rejected for this summary because a per-summary
    /// or global bound was reached. Saturates at `UInt64.max`.
    var omittedObservationCount: UInt64
    /// Exact reassembled (multi-frame) record occurrences deliberately excluded from
    /// retention because the bounded prefix probe does not cite all contributing
    /// frames. Only counted for a frame with no direct facts, so a complete
    /// single-frame record is never double-counted. Truthful coverage, never a finding.
    var excludedReassembledRecordCount: UInt64
    /// Exact count of recovered (reassembled) truncation indicators: a reassembled
    /// handoff whose own decode reported `tlsRecordsTruncated`. Counted separately from
    /// the excluded record occurrences, and only for an excluded frame.
    var recoveredTruncationIndicatorCount: UInt64
    /// Exact count of direct frames whose accepted `tlsRecords` array reported
    /// `tlsRecordsTruncated` — the 32-record decoder walk stopped with another
    /// recognizable header. A lower-bound/completeness condition per frame; the unknown
    /// number of records beyond the cap is never invented.
    var decoderTruncatedFrameCount: UInt64
    /// Sticky capture-loss knowledge merged across this flow's TLS-bearing frames.
    var lossKnowledge: CaptureLossKnowledge
    /// Whether any TLS-bearing frame for this flow was captured shorter than its
    /// original on-wire length.
    var snapLengthTruncationObserved: Bool
}

// MARK: - TLSEvidenceTable

/// A pure, bounded, passive fold from ordered decoded TLS frames to per-session TLS
/// record evidence.
///
/// The only source of state change is `offer`, applied in accepted-frame order. No
/// wall clock, timer or background work mutates anything — replaying the same ordered
/// frames through the same configuration always yields the same `Snapshot`. Every
/// retained collection has a named configuration bound, and every drop is accounted
/// for (per-summary and global omission counts, excluded/recovered/decoder-truncation
/// counters, capacity flag), so nothing is silently lost.
///
/// This layer is observation-only. It records what direct frames prove — it never
/// retains a full stream, produces findings, judges a TLS version, or reaches the UI.
/// It uses the shared tuple-derived session id, never the TCP `ConnectionID`, so TLS
/// evidence keys to the same session a summary already publishes.
nonisolated struct TLSEvidenceTable {
    // MARK: Lifecycle

    init(configuration: Configuration = Configuration()) {
        self.configuration = configuration
    }

    // MARK: Internal

    // MARK: Configuration

    /// Injectable bounds. Every value is clamped to at least one so no bound can
    /// disable the table entirely; test configurations may be tiny. The defaults match
    /// the datagram table's comparable summary/observation bounds.
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
        /// this is not retained; each of its record occurrences is accounted globally.
        let maxSummaries: Int
        /// Largest number of observations any one summary retains.
        let maxObservationsPerSummary: Int
        /// Largest number of observations retained across all summaries.
        let maxTotalObservations: Int
    }

    // MARK: Snapshot

    /// An immutable, first-seen-ordered view of every retained flow plus the exact
    /// bound/omission/exclusion accounting. The extra counts let a caller prove the
    /// bounds hold without an unbounded tombstone set.
    nonisolated struct Snapshot: Hashable, Sendable {
        static let empty = Snapshot(
            summaries: [],
            omittedObservationCount: 0,
            retainedObservationCount: 0,
            excludedReassembledRecordCount: 0,
            recoveredTruncationIndicatorCount: 0,
            decoderTruncatedFrameCount: 0,
            capacityReached: false,
            countersOverflowed: false
        )

        /// First-seen flows.
        let summaries: [TLSEvidenceSummary]
        /// Exact global count of direct record occurrences omitted to honor a bound.
        let omittedObservationCount: UInt64
        /// Total observations retained across all summaries.
        let retainedObservationCount: Int
        /// Exact global count of reassembled record occurrences deliberately excluded
        /// from retention (see `offer`). Truthful coverage, never a finding.
        let excludedReassembledRecordCount: UInt64
        /// Exact global count of recovered (reassembled) truncation indicators.
        let recoveredTruncationIndicatorCount: UInt64
        /// Exact global count of direct frames whose decode hit the 32-record cap.
        let decoderTruncatedFrameCount: UInt64
        /// Whether any bound rejected a fact (a summary cap, a per-summary cap or the
        /// global observation cap).
        let capacityReached: Bool
        /// Whether any saturating counter reached `UInt64.max`.
        let countersOverflowed: Bool
    }

    /// Saturating unsigned addition. Returns the max on overflow together with a flag,
    /// so callers can both cap the total and record `countersOverflowed`. Exposed as
    /// the test seam for the saturating-counter contract, since real ingestion cannot
    /// reach `UInt64` overflow on any occurrence counter.
    static func saturatingAdd(_ lhs: UInt64, _ rhs: UInt64) -> (value: UInt64, overflowed: Bool) {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? (UInt64.max, true) : (sum, false)
    }

    /// Fold one already-decoded frame's TLS evidence. Frames must arrive in
    /// accepted-frame order; the provenance ordinal is the sequencing key.
    ///
    /// - Parameters:
    ///   - packet: the *original* per-frame decode. Its `tlsRecords` are direct facts
    ///     that cite exactly this frame's provenance and are eligible for retention;
    ///     its `tlsRecordsTruncated` bit is the direct 32-record-cap coverage signal.
    ///   - application: the connection table's reassembled first-record handoff for
    ///     this frame, if any. Its `tlsRecords`/`tlsRecordsTruncated` are recovered
    ///     multi-frame metadata — never retained or cited. They are excluded-counted
    ///     only when the current frame carried no direct facts, so a complete
    ///     single-frame record is never double-counted.
    ///
    /// Retention rules:
    /// - Retain each direct `packet.tlsRecords` fact as one observation, in record
    ///   index order, bounded per-summary and globally.
    /// - Count a direct `tlsRecordsTruncated` frame once as a lower-bound coverage
    ///   condition; never fabricate the record count beyond the cap.
    /// - When the frame has no direct facts but the reassembled handoff has typed
    ///   records, count those occurrences as excluded-reassembled and, if the handoff
    ///   reported truncation, one recovered truncation indicator.
    /// - A frame with no direct facts, no direct truncation and no excludable recovered
    ///   records does nothing, so summaries stay TLS-only.
    /// - Tupleless/ARP/other packets do nothing.
    mutating func offer(
        _ packet: DecodedPacket,
        application: PacketDecoder.ReassembledTCPApplication?,
        provenance: SessionFrameProvenance,
        loss: CaptureLossKnowledge = .unknown
    ) {
        // A recovered (reassembled) record set is eligible for exclusion-counting only
        // when the current frame has no direct facts of its own — otherwise a complete
        // single-frame record would be double-counted.
        let hasDirect = !packet.tlsRecords.isEmpty
        let reassembledRecords = application?.tlsRecords ?? []
        let excludedReassembled = (!hasDirect && !reassembledRecords.isEmpty) ? reassembledRecords.count : 0
        let recoveredTruncation = (excludedReassembled > 0 && (application?.tlsRecordsTruncated ?? false)) ? 1 : 0

        // Nothing TLS about this frame: no direct records, no direct decoder
        // truncation and no excludable recovered records. Keep summaries TLS-only.
        guard hasDirect || packet.tlsRecordsTruncated || excludedReassembled > 0 else {
            return
        }

        guard let tuple = packet.fiveTuple,
              let source = packet.sourceEndpoint,
              let destination = packet.destinationEndpoint else
        {
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

        let truncatedSnap = provenance.originalLength > provenance.capturedLength

        guard var summary = summaryEntry(for: tuple) else {
            // A new unknown flow after the summary cap is not retained. Account every
            // occurrence globally; do not claim exact omitted unique flows, which would
            // require an unbounded tombstone set.
            globallyAccount(
                directCount: packet.tlsRecords.count,
                decoderTruncated: packet.tlsRecordsTruncated,
                excludedReassembled: excludedReassembled,
                recoveredTruncation: recoveredTruncation
            )
            return
        }

        summary.lossKnowledge = summary.lossKnowledge.merged(with: loss)
        if truncatedSnap {
            summary.snapLengthTruncationObserved = true
        }

        for (index, fact) in packet.tlsRecords.enumerated() {
            let observation = TLSEvidenceObservation(
                sessionID: summary.sessionID,
                tuple: tuple,
                direction: direction,
                provenance: provenance,
                recordIndex: index,
                fact: fact
            )
            appendOrOmit(&summary, observation)
        }

        if packet.tlsRecordsTruncated {
            countersOverflowed = Self.bump(
                &summary.decoderTruncatedFrameCount,
                into: &decoderTruncatedFrameCount,
                by: 1
            ) || countersOverflowed
        }

        if excludedReassembled > 0 {
            countersOverflowed = Self.bump(
                &summary.excludedReassembledRecordCount,
                into: &excludedReassembledRecordCount,
                by: UInt64(excludedReassembled)
            ) || countersOverflowed
            if recoveredTruncation > 0 {
                countersOverflowed = Self.bump(
                    &summary.recoveredTruncationIndicatorCount,
                    into: &recoveredTruncationIndicatorCount,
                    by: 1
                ) || countersOverflowed
            }
        }

        summaries[tuple] = summary
    }

    /// A first-seen-ordered snapshot of every retained flow. Pure; decodes nothing.
    func snapshot() -> Snapshot {
        Snapshot(
            summaries: order.compactMap { summaries[$0] },
            omittedObservationCount: omittedObservationCount,
            retainedObservationCount: retainedObservationTotal,
            excludedReassembledRecordCount: excludedReassembledRecordCount,
            recoveredTruncationIndicatorCount: recoveredTruncationIndicatorCount,
            decoderTruncatedFrameCount: decoderTruncatedFrameCount,
            capacityReached: capacityReached,
            countersOverflowed: countersOverflowed
        )
    }

    // MARK: Private

    private let configuration: Configuration

    /// Flows in first-seen order, so summaries emit oldest→newest.
    private var order: [FiveTuple] = []
    private var summaries: [FiveTuple: TLSEvidenceSummary] = [:]

    /// Running total of retained observations across all summaries — the exact global
    /// `maxTotalObservations` accounting source.
    private var retainedObservationTotal = 0
    private var omittedObservationCount: UInt64 = 0
    private var excludedReassembledRecordCount: UInt64 = 0
    private var recoveredTruncationIndicatorCount: UInt64 = 0
    private var decoderTruncatedFrameCount: UInt64 = 0
    private var capacityReached = false
    private var countersOverflowed = false

    /// Increment a per-summary and the matching global counter together, folding the
    /// overflow flag into `countersOverflowed`.
    private static func bump(_ perSummary: inout UInt64, into global: inout UInt64, by count: UInt64) -> Bool {
        let summed = Self.saturatingAdd(perSummary, count)
        perSummary = summed.value
        let globalSummed = Self.saturatingAdd(global, count)
        global = globalSummed.value
        return summed.overflowed || globalSummed.overflowed
    }

    /// Increment a single global counter, folding its overflow into `countersOverflowed`.
    private static func add(_ global: inout UInt64, by count: UInt64) -> Bool {
        let summed = Self.saturatingAdd(global, count)
        global = summed.value
        return summed.overflowed
    }

    /// The existing summary for this flow, or a fresh one appended in first-seen order
    /// when the summary cap allows. `nil` only when a brand-new flow would exceed the
    /// summary cap — the caller then accounts every occurrence globally.
    private mutating func summaryEntry(for tuple: FiveTuple) -> TLSEvidenceSummary? {
        if let existing = summaries[tuple] {
            return existing
        }
        guard order.count < configuration.maxSummaries else {
            return nil
        }
        order.append(tuple)
        let fresh = TLSEvidenceSummary(
            sessionID: SessionBuilder.sessionID(for: tuple),
            tuple: tuple,
            observations: [],
            omittedObservationCount: 0,
            excludedReassembledRecordCount: 0,
            recoveredTruncationIndicatorCount: 0,
            decoderTruncatedFrameCount: 0,
            lossKnowledge: .unknown,
            snapLengthTruncationObserved: false
        )
        summaries[tuple] = fresh
        return fresh
    }

    /// Append the observation if both the per-summary and global observation bounds
    /// allow it; otherwise increment both the summary's and the global exact occurrence
    /// count and flag capacity.
    private mutating func appendOrOmit(
        _ summary: inout TLSEvidenceSummary,
        _ observation: TLSEvidenceObservation
    ) {
        guard summary.observations.count < configuration.maxObservationsPerSummary,
              retainedObservationTotal < configuration.maxTotalObservations else
        {
            countersOverflowed = Self.bump(
                &summary.omittedObservationCount,
                into: &omittedObservationCount,
                by: 1
            ) || countersOverflowed
            capacityReached = true
            return
        }
        summary.observations.append(observation)
        retainedObservationTotal += 1
    }

    /// Account every occurrence of a summary-cap-dropped new flow globally. The dropped
    /// direct records are global omissions (a capacity event); the excluded/recovered/
    /// decoder-truncation coverage is still counted so nothing is silently lost.
    private mutating func globallyAccount(
        directCount: Int,
        decoderTruncated: Bool,
        excludedReassembled: Int,
        recoveredTruncation: Int
    ) {
        capacityReached = true
        if directCount > 0 {
            countersOverflowed = Self.add(&omittedObservationCount, by: UInt64(directCount)) || countersOverflowed
        }
        if decoderTruncated {
            countersOverflowed = Self.add(&decoderTruncatedFrameCount, by: 1) || countersOverflowed
        }
        if excludedReassembled > 0 {
            countersOverflowed = Self.add(
                &excludedReassembledRecordCount,
                by: UInt64(excludedReassembled)
            ) || countersOverflowed
            if recoveredTruncation > 0 {
                countersOverflowed = Self.add(&recoveredTruncationIndicatorCount, by: 1) || countersOverflowed
            }
        }
    }
}
