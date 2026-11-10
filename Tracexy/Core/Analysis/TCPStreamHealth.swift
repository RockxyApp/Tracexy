import Foundation

// The per-session TCP health chart. This file turns one flow's retained
// segment prefix (`TCPSegmentSeriesSummary`) into the four charts a packet analyst
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
// 4. **Cumulative-ACK round trips are Karn-safe.** Only a segment that extends its direction's
//    highest sequence end starts a sample. When an observed segment overlaps a
//    pending sample's sequence range, that candidate is discarded because a later
//    acknowledgement cannot identify which transmission it covered. A segment that
//    starts below the high-water mark is conservatively not sampled, even when it may
//    be the first captured copy of an out-of-order range. The caveat counts discarded
//    candidates; timestamps are not used to excuse an ambiguous retransmission.
//    The separate SACK-reported RTT role matches an exact captured payload range to
//    the first later retained SACK block, excludes overlap ambiguity, and cites both
//    frames. A receiver report is not evidence of application delivery.
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
    /// Cumulative-ACK and receiver-reported SACK intervals from data to acknowledgement.
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
    /// Cumulatively acknowledged sequence-space bytes per second for this direction.
    case goodput
    /// A receiver-reported SACK interval in this direction's sequence space.
    case sackRange
    /// The payload byte interval carried by this observed segment.
    case sequencePayload
    /// Seconds from a payload range to the first retained SACK block that exactly reports it.
    case sackRoundTrip
    /// A receiver-reported duplicate SACK range identified by RFC 2883 block ordering.
    case duplicateSACKRange

    // MARK: Internal

    var kind: TCPStreamSeriesKind {
        switch self {
        case .sequenceReached,
             .sequenceAcknowledged,
             .sackRange,
             .duplicateSACKRange,
             .sequencePayload: .sequence
        case .throughput,
             .goodput: .throughput
        case .roundTrip,
             .sackRoundTrip: .roundTrip
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
/// it. `provenance` is the frame the value belongs to — `nil` for aggregate rate
/// buckets, which sum observations from multiple frames. `relatedProvenance`
/// carries the second bounding frame of an interval (the acknowledgement that closed
/// a round trip).
nonisolated struct TCPStreamPoint: Hashable, Sendable, Identifiable {
    // MARK: Lifecycle

    init(
        id: Int,
        date: Date,
        value: Double,
        provenance: SessionFrameProvenance?,
        relatedProvenance: SessionFrameProvenance?,
        rangeEnd: Double? = nil
    ) {
        self.id = id
        self.date = date
        self.value = value
        self.provenance = provenance
        self.relatedProvenance = relatedProvenance
        self.rangeEnd = rangeEnd
    }

    // MARK: Internal

    let id: Int
    let date: Date
    let value: Double
    let provenance: SessionFrameProvenance?
    let relatedProvenance: SessionFrameProvenance?
    /// Exclusive right edge when this point represents a half-open sequence range.
    let rangeEnd: Double?
}

// MARK: - TCPStreamSeries

/// One line on one chart: its role, the canonical direction it is about, and its
/// points in capture order.
nonisolated struct TCPStreamSeries: Hashable, Sendable, Identifiable {
    let role: TCPStreamSeriesRole
    let direction: ConnectionDirection
    /// Wire-order block index for SACK ranges; zero for every other role.
    var variant = 0
    let points: [TCPStreamPoint]

    var kind: TCPStreamSeriesKind {
        role.kind
    }

    /// Stable within one health projection: the role and the direction identify a
    /// series exactly once, so `ForEach` never re-keys between renders.
    var id: Int {
        role == .sackRange
            ? 100 + variant * 2 + (direction == .aToB ? 0 : 1)
            : role.rawValue * 2 + (direction == .aToB ? 0 : 1)
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
        ambiguousRoundTripSampleCount: 0,
        unclassifiableSegmentCount: 0,
        unplottableSACKRangeCount: 0,
        unplottablePayloadRangeCount: 0,
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
    /// Pending round-trip candidates discarded after an overlapping observed range.
    let ambiguousRoundTripSampleCount: Int
    /// Retained segments whose sequence space could not be expressed (a payload length
    /// outside `UInt32`, or a SYN/FIN addition that would overflow), so their ordering
    /// was left unclassified rather than guessed.
    let unclassifiableSegmentCount: Int
    /// Receiver-reported SACK blocks omitted because their sequence range could not
    /// be placed relative to this flow's first observed sequence.
    let unplottableSACKRangeCount: Int
    /// Captured payload ranges omitted because their exclusive edge crosses the
    /// observed signed half-space boundary.
    let unplottablePayloadRangeCount: Int
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
        var builder = Builder(observations: summary.observations)
        _ = builder.run(checkingCancellation: { true })
        self.init(summary: summary, builder: builder)
    }

    /// Full-source scans use this initializer to stop derivation cooperatively.
    init(summary: TCPSegmentSeriesSummary, checkingCancellation: () -> Bool) throws {
        var builder = Builder(observations: summary.observations)
        guard builder.run(checkingCancellation: checkingCancellation) else {
            throw CancellationError()
        }
        self.init(summary: summary, builder: builder)
    }

    private init(summary: TCPSegmentSeriesSummary, builder: Builder) {
        sessionID = summary.sessionID
        tuple = summary.tuple
        series = builder.series
        coverage = TCPStreamCoverage(
            retainedSegmentCount: summary.observations.count,
            omittedSegmentCount: summary.omittedObservationCount,
            untimedSegmentCount: builder.untimedCount,
            ambiguousRoundTripSampleCount: builder.ambiguousRoundTripSampleCount,
            unclassifiableSegmentCount: builder.unclassifiableCount,
            unplottableSACKRangeCount: builder.unplottableSACKRangeCount,
            unplottablePayloadRangeCount: builder.unplottablePayloadRangeCount,
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
    /// The single ordered walk that produces the session's series roles. It keeps one small state
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
        /// Reference semantics keep growing series arrays uniquely owned while the
        /// builder appends observations during a full-source scan.
        nonisolated final class DirectionState {
            struct PendingRoundTrip {
                let start: Int64
                let end: Int64
                let date: Date
                let provenance: SessionFrameProvenance
                let isPayloadRange: Bool
                var isAmbiguous = false
                var sackReported = false
            }

            var base: UInt32?
            /// Highest sequence end seen, including untimed frames, for ambiguity
            /// checks. Untimed observations never enter plotted sequence totals.
            var highestObservedEnd: Int64?
            var highestEnd: Int64?
            /// Data segments awaiting an acknowledgement, oldest first. Bounded by the
            /// prefix itself, which is bounded by the table. `pendingHead` advances
            /// instead of removing from the front, so a long ACK train stays linear.
            var pending: [PendingRoundTrip] = []
            var pendingHead = 0
            /// Successor links skip candidates already invalidated by overlap.
            var nextUnambiguousPending = [0]
            var lastAcknowledged: Int64?
            var windowShift: UInt8?
            var synRetained = false
            var sequenceReached: [TCPStreamPoint] = []
            var sequencePayload: [TCPStreamPoint] = []
            var sequenceAcknowledged: [TCPStreamPoint] = []
            var sackRanges = Array(repeating: [TCPStreamPoint](), count: TCPOptionFacts.maximumSACKBlockCount)
            var duplicateSACKRanges: [TCPStreamPoint] = []
            var roundTrip: [TCPStreamPoint] = []
            var sackRoundTrip: [TCPStreamPoint] = []
            var receiveWindowOffered: [TCPStreamPoint] = []
            var bytesInFlight: [TCPStreamPoint] = []
            var throughput: [TCPStreamPoint] = []
            var goodput: [TCPStreamPoint] = []

            func firstUnambiguousPending(
                atOrAfter index: Int,
                checkingCancellation: () -> Bool
            )
                -> Int?
            {
                var root = index
                var traversed = 0
                while nextUnambiguousPending[root] != root {
                    if traversed.isMultiple(of: Builder.cancellationCheckInterval), !checkingCancellation() {
                        return nil
                    }
                    root = nextUnambiguousPending[root]
                    traversed += 1
                }
                var cursor = index
                traversed = 0
                while nextUnambiguousPending[cursor] != cursor {
                    if traversed.isMultiple(of: Builder.cancellationCheckInterval), !checkingCancellation() {
                        return nil
                    }
                    let next = nextUnambiguousPending[cursor]
                    nextUnambiguousPending[cursor] = root
                    cursor = next
                    traversed += 1
                }
                return root
            }
        }

        private(set) var series: [TCPStreamSeries] = []
        private(set) var untimedCount = 0
        private(set) var ambiguousRoundTripSampleCount = 0
        private(set) var unclassifiableCount = 0
        private(set) var unplottableSACKRangeCount = 0
        private(set) var unplottablePayloadRangeCount = 0
        private(set) var windowScaling: TCPWindowScalingObservation = .notObserved

        mutating func run(checkingCancellation: () -> Bool) -> Bool {
            guard checkingCancellation() else {
                return false
            }
            guard !observations.isEmpty else {
                return true
            }
            guard resolveBases(checkingCancellation: checkingCancellation),
                  resolveWindowScaling(checkingCancellation: checkingCancellation),
                  walk(checkingCancellation: checkingCancellation),
                  assemble(checkingCancellation: checkingCancellation) else
            {
                return false
            }
            return checkingCancellation()
        }

        // MARK: Private

        private struct GoodputRange {
            let direction: ConnectionDirection
            let date: Date
            let start: Int64
            let end: Int64
        }

        private struct GoodputEvent {
            let direction: ConnectionDirection
            let date: Date
            let bytes: Int64
        }

        /// Monotone interval coverage over compressed sequence-space endpoints.
        /// Each range is credited once; a later cumulative ACK covers and therefore
        /// does not re-credit bytes already reported by SACK.
        private struct GoodputCoverageTree {
            // MARK: Lifecycle

            init(coordinates: [Int64]) {
                self.coordinates = coordinates
                let nodeCount = max(4, coordinates.count * 4)
                coveredLengths = [Int64](repeating: 0, count: nodeCount)
                fullyCovered = [Bool](repeating: false, count: nodeCount)
            }

            // MARK: Internal

            mutating func cover(start: Int64, end: Int64) -> Int64 {
                guard start < end,
                      let lower = Self.index(of: start, in: coordinates),
                      let upper = Self.index(of: end, in: coordinates),
                      lower < upper,
                      coordinates.count > 1 else
                {
                    return 0
                }
                return cover(
                    from: lower,
                    to: upper,
                    node: 1,
                    lowerBound: 0,
                    upperBound: coordinates.count - 1
                )
            }

            // MARK: Private

            private let coordinates: [Int64]
            private var coveredLengths: [Int64]
            private var fullyCovered: [Bool]

            private static func index(of value: Int64, in values: [Int64]) -> Int? {
                var lower = 0
                var upper = values.count
                while lower < upper {
                    let middle = lower + (upper - lower) / 2
                    if values[middle] < value {
                        lower = middle + 1
                    } else {
                        upper = middle
                    }
                }
                return lower < values.count && values[lower] == value ? lower : nil
            }

            private mutating func cover(
                from queryLower: Int,
                to queryUpper: Int,
                node: Int,
                lowerBound: Int,
                upperBound: Int
            )
                -> Int64
            {
                if fullyCovered[node] {
                    return 0
                }
                let totalLength = coordinates[upperBound] - coordinates[lowerBound]
                if queryLower <= lowerBound, upperBound <= queryUpper {
                    let newlyCovered = totalLength - coveredLengths[node]
                    coveredLengths[node] = totalLength
                    fullyCovered[node] = true
                    return newlyCovered
                }
                let middle = lowerBound + (upperBound - lowerBound) / 2
                var newlyCovered: Int64 = 0
                if queryLower < middle {
                    newlyCovered += cover(
                        from: queryLower,
                        to: queryUpper,
                        node: node * 2,
                        lowerBound: lowerBound,
                        upperBound: middle
                    )
                }
                if queryUpper > middle {
                    newlyCovered += cover(
                        from: queryLower,
                        to: queryUpper,
                        node: node * 2 + 1,
                        lowerBound: middle,
                        upperBound: upperBound
                    )
                }
                coveredLengths[node] = coveredLengths[node * 2] + coveredLengths[node * 2 + 1]
                fullyCovered[node] = coveredLengths[node] == totalLength
                return newlyCovered
            }
        }

        private static let cancellationCheckInterval = 256

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

        /// Map a serial-number interval only when both edges share the same signed
        /// coordinate epoch around the observed base.
        private static func sequenceRange(
            from left: UInt32,
            to right: UInt32,
            base: UInt32
        )
            -> (start: Int64, end: Int64)?
        {
            let length = right &- left
            guard length > 0, length < 0x80000000,
                  let start = distance(from: base, to: left),
                  let end = distance(from: base, to: right),
                  end == start + Int64(length) else
            {
                return nil
            }
            return (start, end)
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

        private static func isDuplicateSACK(
            first: (blockIndex: Int, start: Int64, end: Int64)?,
            second: (blockIndex: Int, start: Int64, end: Int64)?,
            acknowledgement: Int64?
        )
            -> Bool
        {
            guard let first, let acknowledgement else {
                return false
            }
            if first.end <= acknowledgement {
                return true
            }
            guard first.start > acknowledgement, let second else {
                return false
            }
            return second.start <= first.start && first.end <= second.end
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
        private mutating func resolveBases(checkingCancellation: () -> Bool) -> Bool {
            for (index, observation) in observations.enumerated() {
                if index.isMultiple(of: Self.cancellationCheckInterval), !checkingCancellation() {
                    return false
                }
                let state = self[observation.direction]
                if state.base == nil {
                    state.base = observation.sequenceNumber
                    self[observation.direction] = state
                }
            }
            return true
        }

        /// RFC 7323 §2.2: the shift is in effect only when both SYNs carried the
        /// option. Anything less leaves every window plotted raw.
        private mutating func resolveWindowScaling(checkingCancellation: () -> Bool) -> Bool {
            for (index, observation) in observations.enumerated() {
                if index.isMultiple(of: Self.cancellationCheckInterval), !checkingCancellation() {
                    return false
                }
                guard observation.flags.contains(.syn) else {
                    continue
                }
                let state = self[observation.direction]
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
            return true
        }

        private mutating func walk(checkingCancellation: () -> Bool) -> Bool {
            for (index, observation) in observations.enumerated() {
                if index.isMultiple(of: Self.cancellationCheckInterval), !checkingCancellation() {
                    return false
                }
                guard let date = observation.provenance.timestamp else {
                    untimedCount += 1
                    unplottableSACKRangeCount += observation.sackBlocks.count
                    guard invalidateUntimedRetransmission(observation, checkingCancellation: checkingCancellation) else {
                        return false
                    }
                    continue
                }
                guard let space = Self.sequenceSpace(of: observation) else {
                    unclassifiableCount += 1
                    continue
                }
                guard foldSequence(observation, date: date, space: space, checkingCancellation: checkingCancellation) else {
                    return false
                }
                foldSACKRanges(observation, date: date)
                guard foldSACKAcknowledgement(observation, date: date, checkingCancellation: checkingCancellation) else {
                    return false
                }
                guard foldAcknowledgement(observation, date: date, checkingCancellation: checkingCancellation) else {
                    return false
                }
                foldWindow(observation, date: date)
            }
            return true
        }

        /// This direction's own data: where its sequence space reached, whether that
        /// extended the flow (and so may be timed), and how much was outstanding.
        private mutating func foldSequence(
            _ observation: TCPSegmentObservation,
            date: Date,
            space: UInt32,
            checkingCancellation: () -> Bool
        )
            -> Bool
        {
            let direction = observation.direction
            var state = self[direction]
            guard let base = state.base else {
                return true
            }
            guard let start = Self.distance(from: base, to: observation.sequenceNumber) else {
                // An exact half-space distance is irreducible: the segment's position
                // is left unclassified rather than placed at a guessed offset.
                unclassifiableCount += 1
                return true
            }
            guard space > 0 else {
                return true
            }
            let end = start + Int64(space)
            guard invalidateAmbiguousSamples(
                from: start, to: end, state: &state, checkingCancellation: checkingCancellation
            ) else {
                return false
            }
            state.sequenceReached.append(
                point(
                    index: state.sequenceReached.count,
                    date: date,
                    value: Double(end),
                    provenance: observation.provenance
                )
            )
            if observation.payloadLength > 0 {
                let payloadLeft = observation.sequenceNumber &+ (observation.flags.contains(.syn) ? 1 : 0)
                let payloadRight = payloadLeft &+ UInt32(observation.payloadLength)
                if let range = Self.sequenceRange(from: payloadLeft, to: payloadRight, base: base) {
                    state.sequencePayload.append(TCPStreamPoint(
                        id: state.sequencePayload.count,
                        date: date,
                        value: Double(range.start),
                        provenance: observation.provenance,
                        relatedProvenance: nil,
                        rangeEnd: Double(range.end)
                    ))
                } else {
                    unplottablePayloadRangeCount += 1
                }
            }
            // Karn: only a segment that extends the flow can be timed, because an
            // acknowledgement of re-sent sequence space cannot say which copy it
            // answered.
            let priorHighestEnd = state.highestEnd
            let priorObservedEnd = state.highestObservedEnd
            let extendsFlow = priorHighestEnd.map { end > $0 } ?? true
            let startsBeyondObservedRange = priorObservedEnd.map { start >= $0 } ?? true
            if extendsFlow {
                state.highestEnd = end
                if startsBeyondObservedRange {
                    state.pending.append(.init(
                        start: start,
                        end: end,
                        date: date,
                        provenance: observation.provenance,
                        isPayloadRange: observation.payloadLength > 0
                            && !observation.flags.contains(.syn) && !observation.flags.contains(.fin)
                    ))
                    state.nextUnambiguousPending.append(state.nextUnambiguousPending.count)
                }
            }
            state.highestObservedEnd = max(priorObservedEnd ?? end, end)
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
            return true
        }

        /// An untimed retransmission can still make a previously timed RTT candidate
        /// ambiguous. It does not advance plotted sequence state or create a sample.
        private mutating func invalidateUntimedRetransmission(
            _ observation: TCPSegmentObservation,
            checkingCancellation: () -> Bool
        )
            -> Bool
        {
            guard let space = Self.sequenceSpace(of: observation), space > 0,
                  let base = self[observation.direction].base,
                  let start = Self.distance(from: base, to: observation.sequenceNumber) else
            {
                return true
            }
            var state = self[observation.direction]
            guard invalidateAmbiguousSamples(
                from: start, to: start + Int64(space), state: &state, checkingCancellation: checkingCancellation
            ) else {
                return false
            }
            let end = start + Int64(space)
            state.highestObservedEnd = max(state.highestObservedEnd ?? end, end)
            self[observation.direction] = state
            return true
        }

        /// Mark every pending candidate whose byte range overlaps this observed
        /// segment. Candidates are appended in non-overlapping sequence order, so a
        /// binary search finds the first possible overlap. Each candidate is marked
        /// at most once, keeping a long retransmission trace bounded to O(N log N).
        private mutating func invalidateAmbiguousSamples(
            from start: Int64,
            to end: Int64,
            state: inout DirectionState,
            checkingCancellation: () -> Bool
        )
            -> Bool
        {
            guard let highWater = state.highestObservedEnd, start < highWater else {
                return true
            }
            var lower = state.pendingHead
            var upper = state.pending.count
            while lower < upper {
                let middle = lower + (upper - lower) / 2
                if state.pending[middle].end <= start {
                    lower = middle + 1
                } else {
                    upper = middle
                }
            }
            guard var index = state.firstUnambiguousPending(
                atOrAfter: lower, checkingCancellation: checkingCancellation
            ) else {
                return false
            }
            var visited = 0
            while index < state.pending.count, state.pending[index].start < end {
                if visited.isMultiple(of: Self.cancellationCheckInterval), !checkingCancellation() {
                    return false
                }
                state.pending[index].isAmbiguous = true
                ambiguousRoundTripSampleCount += 1
                guard let successor = state.firstUnambiguousPending(
                    atOrAfter: index + 1, checkingCancellation: checkingCancellation
                ) else {
                    return false
                }
                state.nextUnambiguousPending[index] = successor
                index = successor
                visited += 1
            }
            return true
        }

        /// What this segment acknowledged of the *peer's* sequence space: the peer's
        /// acknowledged edge, and every round trip that edge closes.
        private mutating func foldAcknowledgement(
            _ observation: TCPSegmentObservation,
            date: Date,
            checkingCancellation: () -> Bool
        )
            -> Bool
        {
            guard observation.flags.contains(.ack), !observation.flags.contains(.rst) else {
                return true
            }
            let peerDirection = observation.direction.opposite
            let peer = self[peerDirection]
            guard let base = peer.base,
                  let acknowledged = Self.distance(from: base, to: observation.acknowledgementNumber) else
            {
                return true
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
            var drained = 0
            while peer.pendingHead < peer.pending.count,
                  peer.pending[peer.pendingHead].end <= acknowledged
            {
                if drained.isMultiple(of: Self.cancellationCheckInterval), !checkingCancellation() {
                    return false
                }
                let first = peer.pending[peer.pendingHead]
                peer.pendingHead += 1
                drained += 1
                guard !first.isAmbiguous else {
                    continue
                }
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
            return true
        }

        /// Match exact pending payload ranges to receiver-reported SACK blocks.
        /// This remains separate from Karn's cumulative-ACK RTT line and does not
        /// imply application delivery.
        private mutating func foldSACKAcknowledgement(
            _ observation: TCPSegmentObservation,
            date: Date,
            checkingCancellation: () -> Bool
        )
            -> Bool
        {
            guard observation.flags.contains(.ack), !observation.flags.contains(.rst),
                  !observation.sackBlocks.isEmpty else
            {
                return true
            }
            let direction = observation.direction.opposite
            guard let base = self[direction].base else {
                return true
            }
            var state = self[direction]
            for block in observation.sackBlocks.prefix(TCPOptionFacts.maximumSACKBlockCount) {
                guard let range = Self.sequenceRange(from: block.leftEdge, to: block.rightEdge, base: base) else {
                    continue
                }
                var low = state.pendingHead
                var high = state.pending.count
                while low < high {
                    if (low - state.pendingHead).isMultiple(of: Self.cancellationCheckInterval),
                       !checkingCancellation()
                    {
                        return false
                    }
                    let middle = low + (high - low) / 2
                    if state.pending[middle].start < range.start {
                        low = middle + 1
                    } else {
                        high = middle
                    }
                }
                guard low < state.pending.count else {
                    continue
                }
                let candidate = state.pending[low]
                guard candidate.start == range.start, candidate.end == range.end,
                      candidate.isPayloadRange, !candidate.isAmbiguous, !candidate.sackReported else
                {
                    continue
                }
                let elapsed = date.timeIntervalSince(candidate.date)
                guard elapsed.isFinite, elapsed >= 0 else {
                    continue
                }
                state.pending[low].sackReported = true
                state.sackRoundTrip.append(TCPStreamPoint(
                    id: state.sackRoundTrip.count,
                    date: candidate.date,
                    value: elapsed,
                    provenance: candidate.provenance,
                    relatedProvenance: observation.provenance
                ))
            }
            self[direction] = state
            return true
        }

        /// The window this segment advertised, credited to the direction it constrains
        /// — the peer, whose data it is willing to receive.
        private mutating func foldWindow(_ observation: TCPSegmentObservation, date: Date) {
            guard !observation.flags.contains(.rst) else {
                return
            }
            let peerDirection = observation.direction.opposite
            let peer = self[peerDirection]
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

        /// SACK blocks describe receiver-reported ranges in the peer's sequence
        /// space. Preserve every range at the citing ACK's time, including midstream
        /// observations; do not infer delivery or SACK negotiation from a missing SYN.
        private mutating func foldSACKRanges(_ observation: TCPSegmentObservation, date: Date) {
            guard observation.flags.contains(.ack), !observation.sackBlocks.isEmpty else {
                return
            }
            let sender = observation.direction.opposite
            guard let base = self[sender].base else {
                unplottableSACKRangeCount += observation.sackBlocks.count
                return
            }
            let state = self[sender]
            var ranges: [(blockIndex: Int, start: Int64, end: Int64)] = []
            for (blockIndex, block) in observation.sackBlocks.prefix(TCPOptionFacts.maximumSACKBlockCount)
                .enumerated()
            {
                guard let range = Self.sequenceRange(from: block.leftEdge, to: block.rightEdge, base: base) else {
                    unplottableSACKRangeCount += 1
                    continue
                }
                ranges.append((blockIndex, range.start, range.end))
            }
            let acknowledgement = Self.distance(from: base, to: observation.acknowledgementNumber)
            let first = ranges.first { $0.blockIndex == 0 }
            let second = ranges.first { $0.blockIndex == 1 }
            let isDuplicate = Self.isDuplicateSACK(first: first, second: second, acknowledgement: acknowledgement)
            for range in ranges {
                let point = TCPStreamPoint(
                    id: isDuplicate && range.blockIndex == 0
                        ? state.duplicateSACKRanges.count
                        : state.sackRanges[range.blockIndex].count,
                    date: date,
                    value: Double(range.start),
                    provenance: observation.provenance,
                    relatedProvenance: nil,
                    rangeEnd: Double(range.end)
                )
                if isDuplicate, range.blockIndex == 0 {
                    state.duplicateSACKRanges.append(point)
                } else {
                    state.sackRanges[range.blockIndex].append(point)
                }
            }
            self[sender] = state
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

        /// Credit newly covered sequence space from cumulative ACK advances and SACK
        /// blocks. Coordinate compression plus monotone segment-tree updates prevents
        /// duplicate credit without a quadratic scan through prior SACK ranges.
        private func buildGoodputEvents(checkingCancellation: () -> Bool) -> [GoodputEvent]? {
            var ranges: [GoodputRange] = []
            ranges.reserveCapacity(observations.count * (1 + TCPOptionFacts.maximumSACKBlockCount))
            var lastAcknowledgedAtoB: Int64?
            var lastAcknowledgedBtoA: Int64?

            for (index, observation) in observations.enumerated() {
                if index.isMultiple(of: Self.cancellationCheckInterval), !checkingCancellation() {
                    return nil
                }
                guard let date = observation.provenance.timestamp,
                      observation.flags.contains(.ack), !observation.flags.contains(.rst) else
                {
                    continue
                }
                let acknowledgedDirection = observation.direction.opposite
                let acknowledgedBase = self[acknowledgedDirection].base
                let acknowledged = acknowledgedBase.flatMap {
                    Self.distance(from: $0, to: observation.acknowledgementNumber)
                }
                guard let acknowledgedBase, let acknowledged else {
                    continue
                }
                var previous = acknowledgedDirection == .aToB
                    ? lastAcknowledgedAtoB
                    : lastAcknowledgedBtoA
                if let previous, acknowledged < previous {
                    continue
                }
                if let previous, acknowledged > previous {
                    ranges.append(GoodputRange(
                        direction: acknowledgedDirection,
                        date: date,
                        start: previous,
                        end: acknowledged
                    ))
                }
                if previous.map({ acknowledged > $0 }) ?? true {
                    previous = acknowledged
                }
                if acknowledgedDirection == .aToB {
                    lastAcknowledgedAtoB = previous
                } else {
                    lastAcknowledgedBtoA = previous
                }

                var sackRanges: [(blockIndex: Int, start: Int64, end: Int64)] = []
                for (blockIndex, block) in observation.sackBlocks
                    .prefix(TCPOptionFacts.maximumSACKBlockCount)
                    .enumerated()
                {
                    guard let range = Self.sequenceRange(
                        from: block.leftEdge, to: block.rightEdge, base: acknowledgedBase
                    ) else {
                        continue
                    }
                    sackRanges.append((blockIndex, range.start, range.end))
                }
                let firstBlock = sackRanges.first { $0.blockIndex == 0 }
                let secondBlock = sackRanges.first { $0.blockIndex == 1 }
                let firstBlockIsDuplicate = Self.isDuplicateSACK(
                    first: firstBlock,
                    second: secondBlock,
                    acknowledgement: acknowledged
                )
                for sackRange in sackRanges {
                    // RFC 2883 defines the first block as D-SACK when it is wholly
                    // below this packet's ACK edge or contained by the next block.
                    // Keep the raw overlay, but do not call duplicate bytes goodput.
                    guard sackRange.blockIndex != 0 || !firstBlockIsDuplicate else {
                        continue
                    }
                    let start = max(sackRange.start, acknowledged)
                    guard start < sackRange.end else {
                        continue
                    }
                    ranges.append(GoodputRange(
                        direction: acknowledgedDirection,
                        date: date,
                        start: start,
                        end: sackRange.end
                    ))
                }
            }
            guard checkingCancellation() else {
                return nil
            }
            guard !ranges.isEmpty else {
                return []
            }

            func coordinates(for direction: ConnectionDirection) -> [Int64] {
                var values: [Int64] = []
                for range in ranges where range.direction == direction {
                    values.append(range.start)
                    values.append(range.end)
                }
                values.sort()
                var unique: [Int64] = []
                unique.reserveCapacity(values.count)
                for value in values where unique.last != value {
                    unique.append(value)
                }
                return unique
            }

            var aToBCoverage = GoodputCoverageTree(coordinates: coordinates(for: .aToB))
            var bToACoverage = GoodputCoverageTree(coordinates: coordinates(for: .bToA))
            var events: [GoodputEvent] = []
            events.reserveCapacity(ranges.count)
            for (index, range) in ranges.enumerated() {
                if index.isMultiple(of: Self.cancellationCheckInterval), !checkingCancellation() {
                    return nil
                }
                let bytes: Int64 = if range.direction == .aToB {
                    aToBCoverage.cover(start: range.start, end: range.end)
                } else {
                    bToACoverage.cover(start: range.start, end: range.end)
                }
                if bytes > 0 {
                    events.append(GoodputEvent(direction: range.direction, date: range.date, bytes: bytes))
                }
            }
            return checkingCancellation() ? events : nil
        }

        /// Throughput and goodput, then every non-empty series in its fixed order.
        private mutating func assemble(checkingCancellation: () -> Bool) -> Bool {
            guard buildThroughput(checkingCancellation: checkingCancellation) else {
                return false
            }
            var built: [TCPStreamSeries] = []
            for direction in [ConnectionDirection.aToB, .bToA] {
                let state = self[direction]
                let roles: [(TCPStreamSeriesRole, [TCPStreamPoint])] = [
                    (.sequenceReached, state.sequenceReached),
                    (.sequencePayload, state.sequencePayload),
                    (.sequenceAcknowledged, state.sequenceAcknowledged),
                    (.throughput, state.throughput),
                    (.goodput, state.goodput),
                    (.roundTrip, state.roundTrip),
                    (.sackRoundTrip, state.sackRoundTrip),
                    (.duplicateSACKRange, state.duplicateSACKRanges),
                    (.receiveWindowOffered, state.receiveWindowOffered),
                    (.bytesInFlight, state.bytesInFlight),
                ]
                for (role, points) in roles where !points.isEmpty {
                    built.append(TCPStreamSeries(role: role, direction: direction, points: points))
                }
                for (variant, points) in state.sackRanges.enumerated() where !points.isEmpty {
                    built.append(TCPStreamSeries(
                        role: .sackRange,
                        direction: direction,
                        variant: variant,
                        points: points
                    ))
                }
            }
            series = built.sorted { lhs, rhs in
                if lhs.kind.rawValue != rhs.kind.rawValue {
                    return lhs.kind.rawValue < rhs.kind.rawValue
                }
                if lhs.role.rawValue != rhs.role.rawValue {
                    return lhs.role.rawValue < rhs.role.rawValue
                }
                if lhs.variant != rhs.variant {
                    return lhs.variant < rhs.variant
                }
                return lhs.direction == .aToB
            }
            return checkingCancellation()
        }

        /// Equal buckets across the covered span, each an exact sum of the wire lengths
        /// of the retained frames inside it. A span of zero — a single frame, or frames
        /// sharing one instant — yields no series rather than an infinite rate.
        private mutating func buildThroughput(checkingCancellation: () -> Bool) -> Bool {
            var timed: [(Date, ConnectionDirection, Int)] = []
            timed.reserveCapacity(observations.count)
            for (index, observation) in observations.enumerated() {
                if index.isMultiple(of: Self.cancellationCheckInterval), !checkingCancellation() {
                    return false
                }
                guard let date = observation.provenance.timestamp else {
                    continue
                }
                timed.append((date, observation.direction, observation.provenance.originalLength))
            }
            guard let first = timed.first?.0, let last = timed.last?.0 else {
                return true
            }
            let span = last.timeIntervalSince(first)
            guard span.isFinite, span > 0 else {
                return true
            }
            guard let goodputEvents = buildGoodputEvents(checkingCancellation: checkingCancellation) else {
                return false
            }
            let bucketDuration = span / Double(Self.throughputBucketCount)
            var totals = [
                ConnectionDirection.aToB: [Int64](repeating: 0, count: Self.throughputBucketCount),
                ConnectionDirection.bToA: [Int64](repeating: 0, count: Self.throughputBucketCount)
            ]
            var goodputTotals = totals
            for (index, (date, direction, bytes)) in timed.enumerated() {
                if index.isMultiple(of: Self.cancellationCheckInterval), !checkingCancellation() {
                    return false
                }
                let offset = date.timeIntervalSince(first)
                let index = min(Self.throughputBucketCount - 1, max(0, Int(offset / bucketDuration)))
                totals[direction]?[index] += Int64(max(0, bytes))
            }
            for (index, event) in goodputEvents.enumerated() {
                if index.isMultiple(of: Self.cancellationCheckInterval), !checkingCancellation() {
                    return false
                }
                let offset = event.date.timeIntervalSince(first)
                let bucket = min(Self.throughputBucketCount - 1, max(0, Int(offset / bucketDuration)))
                goodputTotals[event.direction]?[bucket] += event.bytes
            }
            for direction in [ConnectionDirection.aToB, .bToA] {
                guard let buckets = totals[direction],
                      buckets.contains(where: { $0 > 0 }) || goodputTotals[direction]?
                      .contains(where: { $0 > 0 }) == true else
                {
                    continue
                }
                let state = self[direction]
                if buckets.contains(where: { $0 > 0 }) {
                    state.throughput = buckets.enumerated().map { index, bytes in
                        TCPStreamPoint(
                            id: index,
                            date: first.addingTimeInterval(bucketDuration * Double(index) + bucketDuration / 2),
                            value: Double(bytes) / bucketDuration,
                            provenance: nil,
                            relatedProvenance: nil
                        )
                    }
                }
                let goodputBuckets = goodputTotals[direction] ?? []
                if goodputBuckets.contains(where: { $0 > 0 }) {
                    state.goodput = goodputBuckets.enumerated().map { index, bytes in
                        TCPStreamPoint(
                            id: index,
                            date: first.addingTimeInterval(bucketDuration * Double(index) + bucketDuration / 2),
                            value: Double(bytes) / bucketDuration,
                            provenance: nil,
                            relatedProvenance: nil
                        )
                    }
                }
                self[direction] = state
            }
            return true
        }
    }
}
