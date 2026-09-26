import Foundation

// The per-session TCP health chart. This file turns one flow's retained
// segment prefix (`TCPSegmentSeriesSummary`) into the four series a packet analyst
// reads off a trace: sequence progress, throughput, round trip and receive window.
// It is pure, order-independent given the prefix, and adds no state, clock or copy.
//
// **The derivation policy. Read it before adding a series or a role.**
//
// 1. **Every point is a frame that was retained, or an exact sum of them.** Nothing
//    is interpolated, smoothed, averaged across a gap or extrapolated past the last
//    retained frame. A chart drawn from this is a picture of frames, not a model.
// 2. **A point needs a capture time.** A retained frame carrying none is skipped by
//    every series and counted in `untimedSegmentCount`; it is never stamped with an
//    epoch or a neighbour's instant.
// 3. **Relative sequence is relative to what was observed.** Each direction's base is
//    the sequence number of its *first retained* segment — not an initial sequence
//    number, which a midstream capture never saw. The presentation says so; this layer
//    never implies the base is an ISN.
// 4. **Round trips are Karn-safe.** Only a segment that extended its direction's
//    highest sequence end starts a sample, so a retransmission or duplicate — whose
//    acknowledgement is ambiguous by construction — never produces one. The sample
//    closes on the first later opposite-direction acknowledgement that covers that
//    end. A sample the prefix never sees acknowledged is not a point and is not a
//    claim.
// 5. **A window is scaled only when the frames prove the shift.** RFC 7323 §2.2: the
//    shift is in effect only when *both* SYNs carried the Window Scale option, and a
//    SYN's own window is never scaled. When the prefix does not hold both, the raw
//    value is plotted and `windowScalingKnown` is false so the caption can say the
//    scale was not observed. A guessed edge would be a fabricated observation.
// 6. **Bytes in flight is what one direction sent that the peer had not yet
//    acknowledged.** It exists only after the peer has acknowledged something: before
//    that, no frame establishes the baseline, so there is no point.
// 7. **Throughput is an exact sum over equal buckets** of the covered span — each
//    bucket holds the wire lengths of the retained frames whose capture time falls in
//    it, divided by the bucket's own duration. The bucketing derives from the covered
//    span alone, so the same prefix always buckets identically.
// 8. **Nothing names a cause, a role or a verdict.** No threshold, no "slow", no
//    severity: like `SessionTimingAnalysis`, this layer produces no findings at all.
//
// The prefix these rules read is, by `TCPSegmentSeriesTable`'s contract, a *complete*
// run of the flow's segments from its first retained one. That is what makes rules 4,
// 6 and 7 exact rather than approximate: there is no hole inside the covered span,
// only an end to it, and the end is stated once.

// MARK: - TCPStreamSeriesKind

/// One chart a user can look at. The order is the reading order of the picker and is
/// fixed, so the surface never reorders between renders.
nonisolated enum TCPStreamSeriesKind: Int, Hashable, Sendable, CaseIterable {
    /// Sequence progress over time, with the peer's acknowledged edge beside it.
    case sequence
    /// Wire bytes per second, per direction, in equal buckets.
    case throughput
    /// The interval from a data segment to the acknowledgement that covered it.
    case roundTrip
    /// The receive window offered to a direction, with that direction's
    /// unacknowledged bytes beside it.
    case receiveWindow
}

// MARK: - TCPStreamSeriesRole

/// What one series' values mean. A role belongs to exactly one kind and fixes both
/// the unit and the direction the values are *about*.
nonisolated enum TCPStreamSeriesRole: Int, Hashable, Sendable {
    /// Relative sequence number this direction's data reached (bytes from its base).
    case sequenceReached
    /// Relative sequence number in this direction's space the peer acknowledged.
    case sequenceAcknowledged
    /// Wire bytes per second sent by this direction.
    case throughput
    /// Seconds from this direction's data segment to the acknowledgement covering it.
    case roundTrip
    /// Bytes the peer offered to receive from this direction (scaled where proven).
    case receiveWindowOffered
    /// Bytes this direction had sent that the peer had not yet acknowledged.
    case bytesInFlight

    // MARK: Internal

    var kind: TCPStreamSeriesKind {
        switch self {
        case .sequenceReached,
             .sequenceAcknowledged: .sequence
        case .throughput: .throughput
        case .roundTrip: .roundTrip
        case .receiveWindowOffered,
             .bytesInFlight: .receiveWindow
        }
    }
}

// MARK: - TCPWindowScalingObservation

/// What the retained frames prove about RFC 7323 window scaling for a flow. The three
/// cases are deliberately distinct: "no scaling is in effect" is a *known* answer that
/// makes the raw advertised values correct, while "not observed" is an admission that
/// the true receive window may be up to 2^14 times what is plotted.
nonisolated enum TCPWindowScalingObservation: Hashable, Sendable {
    /// Both SYNs were retained and both carried Window Scale, so every non-SYN window
    /// is plotted shifted by its sender's offered shift.
    case applied
    /// Both SYNs were retained and at least one carried no Window Scale option, so
    /// RFC 7323 §2.2 puts no scaling in effect and the raw values are exact.
    case notInEffect
    /// At least one SYN was not retained, so the shift — if any — is unknown and the
    /// raw advertised values are plotted unscaled.
    case notObserved
}

// MARK: - TCPStreamPoint

/// One plotted value: when it was observed, what it was, and the frames that prove
/// it. `provenance` is the frame the value belongs to — `nil` only for a throughput
/// bucket, which is a sum over frames rather than one of them. `relatedProvenance`
/// carries the second bounding frame of an interval (the acknowledgement that closed
/// a round trip).
nonisolated struct TCPStreamPoint: Hashable, Sendable, Identifiable {
    let id: Int
    let date: Date
    let value: Double
    let provenance: SessionFrameProvenance?
    let relatedProvenance: SessionFrameProvenance?
}

// MARK: - TCPStreamSeries

/// One line on one chart: its role, the canonical direction it is about, and its
/// points in capture order.
nonisolated struct TCPStreamSeries: Hashable, Sendable, Identifiable {
    let role: TCPStreamSeriesRole
    let direction: ConnectionDirection
    let points: [TCPStreamPoint]

    var kind: TCPStreamSeriesKind {
        role.kind
    }

    /// Stable within one health projection: the role and the direction identify a
    /// series exactly once, so `ForEach` never re-keys between renders.
    var id: Int {
        role.rawValue * 2 + (direction == .aToB ? 0 : 1)
    }
}

// MARK: - TCPStreamCoverage

/// Exactly what the chart is drawn from, so the surface can state its limits once
/// instead of hedging every value. Every count here is a fact about retention, never
/// a judgement about the network.
nonisolated struct TCPStreamCoverage: Hashable, Sendable {
    static let empty = TCPStreamCoverage(
        retainedSegmentCount: 0,
        omittedSegmentCount: 0,
        untimedSegmentCount: 0,
        unclassifiableSegmentCount: 0,
        firstOrdinal: nil,
        lastOrdinal: nil,
        lossKnowledge: .unknown,
        snapLengthTruncationObserved: false,
        windowScaling: .notObserved
    )

    /// Segments in the retained prefix.
    let retainedSegmentCount: Int
    /// Segments of this flow that arrived after the prefix ended.
    let omittedSegmentCount: UInt64
    /// Retained segments skipped by every series because their frame carried no
    /// capture time.
    let untimedSegmentCount: Int
    /// Retained segments whose sequence space could not be expressed (a payload length
    /// outside `UInt32`, or a SYN/FIN addition that would overflow), so their ordering
    /// was left unclassified rather than guessed.
    let unclassifiableSegmentCount: Int
    /// The first and last retained frame ordinals, naming the run the chart covers.
    let firstOrdinal: UInt64?
    let lastOrdinal: UInt64?
    let lossKnowledge: CaptureLossKnowledge
    let snapLengthTruncationObserved: Bool
    /// What the retained frames prove about window scaling, and so whether the plotted
    /// windows are scaled, exact-unscaled, or unscaled-because-unknown.
    let windowScaling: TCPWindowScalingObservation

    /// Whether the prefix ended before the flow did.
    var isTruncated: Bool {
        omittedSegmentCount > 0
    }
}

// MARK: - TCPStreamHealth

/// The four charts for one session, derived once from its retained segment prefix.
nonisolated struct TCPStreamHealth: Hashable, Sendable {
    // MARK: Lifecycle

    /// Derive every available series for one flow. The result holds only series with
    /// at least one point, so a kind with nothing to draw is simply absent.
    init(summary: TCPSegmentSeriesSummary) {
        sessionID = summary.sessionID
        tuple = summary.tuple

        var builder = Builder(observations: summary.observations)
        builder.run()

        series = builder.series
        coverage = TCPStreamCoverage(
            retainedSegmentCount: summary.observations.count,
            omittedSegmentCount: summary.omittedObservationCount,
            untimedSegmentCount: builder.untimedCount,
            unclassifiableSegmentCount: builder.unclassifiableCount,
            firstOrdinal: summary.observations.first?.provenance.ordinal.rawValue,
            lastOrdinal: summary.observations.last?.provenance.ordinal.rawValue,
            lossKnowledge: summary.lossKnowledge,
            snapLengthTruncationObserved: summary.snapLengthTruncationObserved,
            windowScaling: builder.windowScaling
        )
    }

    private init(sessionID: UUID, tuple: FiveTuple, series: [TCPStreamSeries], coverage: TCPStreamCoverage) {
        self.sessionID = sessionID
        self.tuple = tuple
        self.series = series
        self.coverage = coverage
    }

    // MARK: Internal

    let sessionID: UUID
    let tuple: FiveTuple
    /// Every series with at least one point, ordered by kind, then role, then
    /// direction, so the surface never reorders between renders.
    let series: [TCPStreamSeries]
    let coverage: TCPStreamCoverage

    /// Nothing can be drawn for this session.
    var isEmpty: Bool {
        series.isEmpty
    }

    /// The kinds that have at least one series, in their fixed order.
    var availableKinds: [TCPStreamSeriesKind] {
        TCPStreamSeriesKind.allCases.filter { kind in
            series.contains { $0.kind == kind }
        }
    }

    /// The projection for a session with no retained TCP segments at all.
    static func empty(sessionID: UUID, tuple: FiveTuple) -> TCPStreamHealth {
        TCPStreamHealth(sessionID: sessionID, tuple: tuple, series: [], coverage: .empty)
    }

    /// Every series belonging to one chart, in the projection's own order.
    func series(for kind: TCPStreamSeriesKind) -> [TCPStreamSeries] {
        series.filter { $0.kind == kind }
    }
}

// MARK: TCPStreamHealth.Builder

private extension TCPStreamHealth {
    /// The single ordered walk that produces all six roles. It keeps one small state
    /// value per direction and never looks backwards, so the derivation is exact over
    /// the prefix and costs one pass.
    nonisolated struct Builder {
        // MARK: Lifecycle

        init(observations: [TCPSegmentObservation]) {
            self.observations = observations
        }

        // MARK: Internal

        /// One direction's derived state during the walk. Everything is expressed in
        /// that direction's own relative sequence space.
        nonisolated struct DirectionState {
            var base: UInt32?
            var highestEnd: Int64?
            /// Data segments awaiting an acknowledgement, oldest first. Bounded by the
            /// prefix itself, which is bounded by the table.
            var pending: [(end: Int64, date: Date, provenance: SessionFrameProvenance)] = []
            var lastAcknowledged: Int64?
            var windowShift: UInt8?
            var synRetained = false
            var sequenceReached: [TCPStreamPoint] = []
            var sequenceAcknowledged: [TCPStreamPoint] = []
            var roundTrip: [TCPStreamPoint] = []
            var receiveWindowOffered: [TCPStreamPoint] = []
            var bytesInFlight: [TCPStreamPoint] = []
            var throughput: [TCPStreamPoint] = []
        }

        private(set) var series: [TCPStreamSeries] = []
        private(set) var untimedCount = 0
        private(set) var unclassifiableCount = 0
        private(set) var windowScaling: TCPWindowScalingObservation = .notObserved

        mutating func run() {
            guard !observations.isEmpty else {
                return
            }
            resolveBases()
            resolveWindowScaling()
            walk()
            assemble()
        }

        // MARK: Private

        private static let throughputBucketCount = 48

        private let observations: [TCPSegmentObservation]
        private var aToB = DirectionState()
        private var bToA = DirectionState()

        /// RFC 1982 signed distance, trusted only while the magnitude is unambiguous.
        /// The exact half-space is irreducible and yields `nil`.
        private static func distance(from base: UInt32, to value: UInt32) -> Int64? {
            let raw = value &- base
            guard raw != 0x80000000 else {
                return nil
            }
            return Int64(Int32(bitPattern: raw))
        }

        /// Sequence space: captured payload plus one for SYN and one for FIN. `nil`
        /// when the length cannot be expressed — the caller counts that segment as
        /// unclassifiable rather than guessing its extent.
        private static func sequenceSpace(of observation: TCPSegmentObservation) -> UInt32? {
            guard observation.payloadLength >= 0, observation.payloadLength <= Int(UInt32.max) else {
                return nil
            }
            let control = UInt32(
                (observation.flags.contains(.syn) ? 1 : 0) + (observation.flags.contains(.fin) ? 1 : 0)
            )
            let (sum, overflow) = UInt32(observation.payloadLength).addingReportingOverflow(control)
            return overflow ? nil : sum
        }

        private subscript(direction: ConnectionDirection) -> DirectionState {
            get { direction == .aToB ? aToB : bToA }
            set {
                if direction == .aToB {
                    aToB = newValue
                } else {
                    bToA = newValue
                }
            }
        }

        /// Each direction's base is the sequence number of its first retained segment.
        private mutating func resolveBases() {
            for observation in observations {
                var state = self[observation.direction]
                if state.base == nil {
                    state.base = observation.sequenceNumber
                    self[observation.direction] = state
                }
            }
        }

        /// RFC 7323 §2.2: the shift is in effect only when both SYNs carried the
        /// option. Anything less leaves every window plotted raw.
        private mutating func resolveWindowScaling() {
            for observation in observations where observation.flags.contains(.syn) {
                var state = self[observation.direction]
                state.synRetained = true
                if state.windowShift == nil, let scale = observation.windowScale {
                    state.windowShift = min(scale, 14)
                }
                self[observation.direction] = state
            }
            if !aToB.synRetained || !bToA.synRetained {
                windowScaling = .notObserved
            } else if aToB.windowShift != nil, bToA.windowShift != nil {
                windowScaling = .applied
            } else {
                windowScaling = .notInEffect
            }
        }

        private mutating func walk() {
            for observation in observations {
                guard let date = observation.provenance.timestamp else {
                    untimedCount += 1
                    continue
                }
                guard let space = Self.sequenceSpace(of: observation) else {
                    unclassifiableCount += 1
                    continue
                }
                foldSequence(observation, date: date, space: space)
                foldAcknowledgement(observation, date: date)
                foldWindow(observation, date: date)
            }
        }

        /// This direction's own data: where its sequence space reached, whether that
        /// extended the flow (and so may be timed), and how much was outstanding.
        private mutating func foldSequence(_ observation: TCPSegmentObservation, date: Date, space: UInt32) {
            let direction = observation.direction
            var state = self[direction]
            guard let base = state.base else {
                return
            }
            guard let start = Self.distance(from: base, to: observation.sequenceNumber) else {
                // An exact half-space distance is irreducible: the segment's position
                // is left unclassified rather than placed at a guessed offset.
                unclassifiableCount += 1
                return
            }
            guard space > 0 else {
                return
            }
            let end = start + Int64(space)
            state.sequenceReached.append(
                point(
                    index: state.sequenceReached.count,
                    date: date,
                    value: Double(end),
                    provenance: observation.provenance
                )
            )
            // Karn: only a segment that extends the flow can be timed, because an
            // acknowledgement of re-sent sequence space cannot say which copy it
            // answered.
            let extendsFlow = state.highestEnd.map { end > $0 } ?? true
            if extendsFlow {
                state.highestEnd = end
                state.pending.append((end: end, date: date, provenance: observation.provenance))
            }
            if let acknowledged = state.lastAcknowledged, let highest = state.highestEnd {
                let outstanding = highest - acknowledged
                if outstanding >= 0 {
                    state.bytesInFlight.append(
                        point(
                            index: state.bytesInFlight.count,
                            date: date,
                            value: Double(outstanding),
                            provenance: observation.provenance
                        )
                    )
                }
            }
            self[direction] = state
        }

        /// What this segment acknowledged of the *peer's* sequence space: the peer's
        /// acknowledged edge, and every round trip that edge closes.
        private mutating func foldAcknowledgement(_ observation: TCPSegmentObservation, date: Date) {
            guard observation.flags.contains(.ack), !observation.flags.contains(.rst) else {
                return
            }
            let peerDirection = observation.direction.opposite
            var peer = self[peerDirection]
            guard let base = peer.base,
                  let acknowledged = Self.distance(from: base, to: observation.acknowledgementNumber) else
            {
                return
            }
            peer.sequenceAcknowledged.append(
                point(
                    index: peer.sequenceAcknowledged.count,
                    date: date,
                    value: Double(acknowledged),
                    provenance: observation.provenance
                )
            )
            if peer.lastAcknowledged.map({ acknowledged > $0 }) ?? true {
                peer.lastAcknowledged = acknowledged
            }
            while let first = peer.pending.first, first.end <= acknowledged {
                peer.pending.removeFirst()
                let elapsed = date.timeIntervalSince(first.date)
                guard elapsed.isFinite, elapsed >= 0 else {
                    continue
                }
                peer.roundTrip.append(
                    TCPStreamPoint(
                        id: peer.roundTrip.count,
                        date: first.date,
                        value: elapsed,
                        provenance: first.provenance,
                        relatedProvenance: observation.provenance
                    )
                )
            }
            self[peerDirection] = peer
        }

        /// The window this segment advertised, credited to the direction it constrains
        /// — the peer, whose data it is willing to receive.
        private mutating func foldWindow(_ observation: TCPSegmentObservation, date: Date) {
            guard !observation.flags.contains(.rst) else {
                return
            }
            let peerDirection = observation.direction.opposite
            var peer = self[peerDirection]
            var window = UInt32(observation.windowSize)
            // RFC 7323 §2.2: a SYN's own window is never scaled, and scaling applies
            // only when both sides offered it.
            if windowScaling == .applied, !observation.flags.contains(.syn),
               let shift = self[observation.direction].windowShift
            {
                window <<= UInt32(shift)
            }
            peer.receiveWindowOffered.append(
                point(
                    index: peer.receiveWindowOffered.count,
                    date: date,
                    value: Double(window),
                    provenance: observation.provenance
                )
            )
            self[peerDirection] = peer
        }

        private func point(
            index: Int,
            date: Date,
            value: Double,
            provenance: SessionFrameProvenance?
        )
            -> TCPStreamPoint
        {
            TCPStreamPoint(id: index, date: date, value: value, provenance: provenance, relatedProvenance: nil)
        }

        /// Throughput, then every non-empty series in its fixed order.
        private mutating func assemble() {
            buildThroughput()
            var built: [TCPStreamSeries] = []
            for direction in [ConnectionDirection.aToB, .bToA] {
                let state = self[direction]
                let roles: [(TCPStreamSeriesRole, [TCPStreamPoint])] = [
                    (.sequenceReached, state.sequenceReached),
                    (.sequenceAcknowledged, state.sequenceAcknowledged),
                    (.throughput, state.throughput),
                    (.roundTrip, state.roundTrip),
                    (.receiveWindowOffered, state.receiveWindowOffered),
                    (.bytesInFlight, state.bytesInFlight),
                ]
                for (role, points) in roles where !points.isEmpty {
                    built.append(TCPStreamSeries(role: role, direction: direction, points: points))
                }
            }
            series = built.sorted { lhs, rhs in
                if lhs.kind.rawValue != rhs.kind.rawValue {
                    return lhs.kind.rawValue < rhs.kind.rawValue
                }
                if lhs.role.rawValue != rhs.role.rawValue {
                    return lhs.role.rawValue < rhs.role.rawValue
                }
                return lhs.direction == .aToB
            }
        }

        /// Equal buckets across the covered span, each an exact sum of the wire lengths
        /// of the retained frames inside it. A span of zero — a single frame, or frames
        /// sharing one instant — yields no series rather than an infinite rate.
        private mutating func buildThroughput() {
            let timed = observations.compactMap { observation -> (Date, ConnectionDirection, Int)? in
                guard let date = observation.provenance.timestamp else {
                    return nil
                }
                return (date, observation.direction, observation.provenance.originalLength)
            }
            guard let first = timed.first?.0, let last = timed.last?.0 else {
                return
            }
            let span = last.timeIntervalSince(first)
            guard span.isFinite, span > 0 else {
                return
            }
            let bucketDuration = span / Double(Self.throughputBucketCount)
            var totals = [
                ConnectionDirection.aToB: [Int64](repeating: 0, count: Self.throughputBucketCount),
                ConnectionDirection.bToA: [Int64](repeating: 0, count: Self.throughputBucketCount)
            ]
            for (date, direction, bytes) in timed {
                let offset = date.timeIntervalSince(first)
                let index = min(Self.throughputBucketCount - 1, max(0, Int(offset / bucketDuration)))
                totals[direction]?[index] += Int64(max(0, bytes))
            }
            for direction in [ConnectionDirection.aToB, .bToA] {
                guard let buckets = totals[direction], buckets.contains(where: { $0 > 0 }) else {
                    continue
                }
                var state = self[direction]
                state.throughput = buckets.enumerated().map { index, bytes in
                    TCPStreamPoint(
                        id: index,
                        date: first.addingTimeInterval(bucketDuration * Double(index) + bucketDuration / 2),
                        value: Double(bytes) / bucketDuration,
                        provenance: nil,
                        relatedProvenance: nil
                    )
                }
                self[direction] = state
            }
        }
    }
}
