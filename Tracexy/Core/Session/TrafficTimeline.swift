import Foundation

// MARK: - TrafficDirection

/// Which way an accepted frame travelled relative to the session it folded into.
///
/// `sent` is the session client's direction — the same fact `SessionSummary.bytesUp`
/// totals — and `received` is the server's. A frame that belongs to no five-tuple
/// (ARP, ICMP without a tuple, undecodable framing) still carries bytes over the
/// wire, so it is counted as `unattributed` rather than dropped or guessed.
nonisolated enum TrafficDirection: Hashable, Sendable, CaseIterable {
    case sent
    case received
    case unattributed
}

// MARK: - TrafficTotals

/// Additive byte and frame tallies split by ``TrafficDirection``.
nonisolated struct TrafficTotals: Equatable, Sendable {
    var frames = 0
    var bytes = 0
    var sentBytes = 0
    var receivedBytes = 0
    var unattributedBytes = 0

    var isEmpty: Bool {
        frames == 0
    }

    /// Whether any byte was attributed to a session direction. When false the
    /// whole timeline is best drawn as one total series rather than two empty ones.
    var hasDirectionalBytes: Bool {
        sentBytes > 0 || receivedBytes > 0
    }

    mutating func add(bytes count: Int, direction: TrafficDirection) {
        frames += 1
        bytes += count
        switch direction {
        case .sent: sentBytes += count
        case .received: receivedBytes += count
        case .unattributed: unattributedBytes += count
        }
    }

    mutating func add(_ other: TrafficTotals) {
        frames += other.frames
        bytes += other.bytes
        sentBytes += other.sentBytes
        receivedBytes += other.receivedBytes
        unattributedBytes += other.unattributedBytes
    }
}

// MARK: - TrafficTimelinePoint

/// One rendered column of the traffic-over-time chart: the start instant of a
/// fixed-width slice of capture time and the totals that landed in it.
nonisolated struct TrafficTimelinePoint: Identifiable, Equatable, Sendable {
    let date: Date
    let totals: TrafficTotals

    var id: Date {
        date
    }
}

// MARK: - TrafficTimeline

/// A bounded, deterministic aggregation of every accepted frame's on-wire bytes
/// over real capture time, split by session direction.
///
/// Buckets are keyed by absolute time (`floor(timestamp / bucketWidth)`), so
/// out-of-order timestamps in a saved file land in the right slice without an
/// origin shift. The bucket count is capped: whenever a new frame would exceed the
/// cap the width doubles and neighbouring buckets merge, so memory is bounded by
/// the cap and not by capture length. Untimed frames contribute to the exact
/// totals and are counted, never bucketed.
nonisolated struct TrafficTimeline: Equatable, Sendable {
    // MARK: Lifecycle

    fileprivate init(
        buckets: [Int64: TrafficTotals],
        bucketWidth: TimeInterval,
        totals: TrafficTotals,
        directionMayHaveChanged: Bool,
        untimedFrameCount: Int,
        firstTimedFrame: Date?,
        lastTimedFrame: Date?
    ) {
        self.buckets = buckets
        self.bucketWidth = bucketWidth
        self.totals = totals
        self.directionMayHaveChanged = directionMayHaveChanged
        self.untimedFrameCount = untimedFrameCount
        self.firstTimedFrame = firstTimedFrame
        self.lastTimedFrame = lastTimedFrame
    }

    // MARK: Internal

    static let empty = TrafficTimeline(
        buckets: [:],
        bucketWidth: 1,
        totals: TrafficTotals(),
        directionMayHaveChanged: false,
        untimedFrameCount: 0,
        firstTimedFrame: nil,
        lastTimedFrame: nil
    )

    /// Largest number of points ``points(maxCount:)`` renders by default — enough
    /// to show shape on a wide chart, few enough to hover through comfortably.
    static let defaultRenderedPointCount = 240

    /// Exact totals over every accepted frame, timed or not.
    let totals: TrafficTotals
    /// A later frame changed a session's client orientation after earlier
    /// columns were folded. Show only the exact total series in this case.
    let directionMayHaveChanged: Bool
    /// Accepted frames whose source carried no capture time. Counted in
    /// ``totals`` and excluded from every bucket and from the span.
    let untimedFrameCount: Int
    /// Instant of the earliest and latest timed frame, or `nil` with no timed frame.
    let firstTimedFrame: Date?
    let lastTimedFrame: Date?
    /// Width of one retained bucket in seconds. Starts at one second and only ever
    /// doubles.
    let bucketWidth: TimeInterval

    var isEmpty: Bool {
        totals.isEmpty
    }

    var hasStableDirectionalBytes: Bool {
        totals.hasDirectionalBytes && !directionMayHaveChanged
    }

    /// Whole-capture span of the timed frames, in seconds. Describes the timed
    /// subset only when ``untimedFrameCount`` is non-zero.
    var timedSpan: TimeInterval {
        guard let firstTimedFrame, let lastTimedFrame else {
            return 0
        }
        return max(0, lastTimedFrame.timeIntervalSince(firstTimedFrame))
    }

    /// Distinct retained buckets. Exposed for bounds tests.
    var bucketCount: Int {
        buckets.count
    }

    /// Chronological, gap-filled points for rendering, coalesced so at most
    /// `maxCount` columns cover the timed span. A slice with no traffic renders as
    /// a zero point rather than letting a line interpolate across the gap.
    func points(maxCount: Int = TrafficTimeline.defaultRenderedPointCount) -> [TrafficTimelinePoint] {
        guard let minimumKey = buckets.keys.min(),
              let maximumKey = buckets.keys.max() else
        {
            return []
        }
        let cap = max(1, maxCount)
        // Coarsen by whole powers of two so every retained bucket maps onto
        // exactly one rendered column, and count the columns the same way the
        // rendering does — from the coarsened first and last key.
        var shift = 0
        func columnCount(shift: Int) -> Int64 {
            (maximumKey >> shift) - (minimumKey >> shift) + 1
        }
        while columnCount(shift: shift) > Int64(cap), shift < 62 {
            shift += 1
        }
        let renderedWidth = bucketWidth * Double(1 << shift)
        var rendered: [Int64: TrafficTotals] = [:]
        for (key, totals) in buckets {
            rendered[key >> shift, default: TrafficTotals()].add(totals)
        }
        let first = minimumKey >> shift
        let last = maximumKey >> shift
        return (first ... last).map { key in
            TrafficTimelinePoint(
                date: Date(timeIntervalSince1970: Double(key) * renderedWidth),
                totals: rendered[key] ?? TrafficTotals()
            )
        }
    }

    // MARK: Fileprivate

    fileprivate let buckets: [Int64: TrafficTotals]
}

// MARK: - TrafficTimelineAccumulator

/// Incremental builder for ``TrafficTimeline``. Folds one accepted frame at a time
/// and keeps at most `maxBuckets` buckets by doubling the width and merging pairs,
/// which is deterministic: the same frame sequence always yields the same buckets.
nonisolated struct TrafficTimelineAccumulator: Sendable {
    // MARK: Lifecycle

    init(maxBuckets: Int = TrafficTimelineAccumulator.defaultBucketCap) {
        cap = max(1, maxBuckets)
    }

    // MARK: Internal

    /// Retained-bucket ceiling. One second of resolution for the first ~17 minutes
    /// of a capture, doubling thereafter; about 20 KB of state at the cap.
    static let defaultBucketCap = 1_024

    mutating func add(timestamp: Date?, originalLength: Int, direction: TrafficDirection) {
        totals.add(bytes: originalLength, direction: direction)
        guard let timestamp else {
            untimedFrames += 1
            return
        }
        if let first = firstTimed, timestamp < first {
            firstTimed = timestamp
        } else if firstTimed == nil {
            firstTimed = timestamp
        }
        if let last = lastTimed, timestamp > last {
            lastTimed = timestamp
        } else if lastTimed == nil {
            lastTimed = timestamp
        }

        // A frame landing in a fresh slice past the cap widens the axis: every
        // doubling at least halves the retained count or folds the key into an
        // existing bucket, so the loop terminates.
        var key = Self.key(for: timestamp, width: width)
        while buckets[key] == nil, buckets.count >= cap {
            doubleWidthAndMerge()
            key = Self.key(for: timestamp, width: width)
        }
        buckets[key, default: TrafficTotals()].add(bytes: originalLength, direction: direction)
    }

    mutating func markDirectionUnstable() {
        directionMayHaveChanged = true
    }

    mutating func reset() {
        buckets.removeAll(keepingCapacity: false)
        width = 1
        totals = TrafficTotals()
        directionMayHaveChanged = false
        untimedFrames = 0
        firstTimed = nil
        lastTimed = nil
    }

    func timeline() -> TrafficTimeline {
        TrafficTimeline(
            buckets: buckets,
            bucketWidth: width,
            totals: totals,
            directionMayHaveChanged: directionMayHaveChanged,
            untimedFrameCount: untimedFrames,
            firstTimedFrame: firstTimed,
            lastTimedFrame: lastTimed
        )
    }

    // MARK: Private

    private let cap: Int
    private var buckets: [Int64: TrafficTotals] = [:]
    private var width: TimeInterval = 1
    private var totals = TrafficTotals()
    private var directionMayHaveChanged = false
    private var untimedFrames = 0
    private var firstTimed: Date?
    private var lastTimed: Date?

    private static func key(for timestamp: Date, width: TimeInterval) -> Int64 {
        let position = (timestamp.timeIntervalSince1970 / width).rounded(.down)
        // Clamp instead of trapping on an absurd (but validly decoded) instant.
        if position >= Double(Int64.max) {
            return Int64.max
        }
        if position <= Double(Int64.min) {
            return Int64.min
        }
        return Int64(position)
    }

    /// Doubling the width halves every key (arithmetic shift, so negative keys
    /// floor the same way `key(for:width:)` does), merging each neighbouring pair.
    private mutating func doubleWidthAndMerge() {
        width *= 2
        var merged: [Int64: TrafficTotals] = [:]
        merged.reserveCapacity((buckets.count + 1) / 2)
        for (key, totals) in buckets {
            merged[key >> 1, default: TrafficTotals()].add(totals)
        }
        buckets = merged
    }
}
