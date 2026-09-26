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
    var sentFrames = 0
    var receivedFrames = 0

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
        case .sent:
            sentBytes += count
            sentFrames += 1
        case .received:
            receivedBytes += count
            receivedFrames += 1
        case .unattributed: unattributedBytes += count
        }
    }

    mutating func add(_ other: TrafficTotals) {
        frames += other.frames
        bytes += other.bytes
        sentBytes += other.sentBytes
        receivedBytes += other.receivedBytes
        unattributedBytes += other.unattributedBytes
        sentFrames += other.sentFrames
        receivedFrames += other.receivedFrames
    }
}

// MARK: - TrafficMeasure

/// What the traffic-over-time chart plots on its y axis. Every measure is read
/// from the same additive totals, so switching never refolds anything.
nonisolated enum TrafficMeasure: String, CaseIterable, Identifiable, Sendable {
    case bytes
    case packets
    case bitsPerSecond

    // MARK: Internal

    /// Which part of a column's totals a series draws.
    enum Part: Sendable {
        case total
        case sent
        case received
    }

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .bytes: "Bytes"
        case .packets: "Packets"
        case .bitsPerSecond: "Bits/s"
        }
    }

    /// Decimal SI prefixes, as network rates are quoted: 1 kb/s = 1,000 bit/s.
    static func bitRate(_ bitsPerSecond: Double) -> String {
        let units = ["b/s", "kb/s", "Mb/s", "Gb/s", "Tb/s"]
        var value = bitsPerSecond
        var index = 0
        while value >= 1_000, index < units.count - 1 {
            value /= 1_000
            index += 1
        }
        let digits = index == 0 || value >= 100 ? 0 : 1
        return "\(value.formatted(.number.precision(.fractionLength(digits)))) \(units[index])"
    }

    /// The plotted value for `part` of `totals` in a column `columnWidth` seconds
    /// wide. Bits per second is the column's bytes × 8 over its width — an average
    /// across the column, never a peak.
    func value(of totals: TrafficTotals, part: Part = .total, columnWidth: TimeInterval) -> Double {
        switch self {
        case .bytes:
            Double(Self.bytes(of: totals, part: part))
        case .packets:
            switch part {
            case .total: Double(totals.frames)
            case .sent: Double(totals.sentFrames)
            case .received: Double(totals.receivedFrames)
            }
        case .bitsPerSecond:
            columnWidth > 0 ? Double(Self.bytes(of: totals, part: part)) * 8 / columnWidth : 0
        }
    }

    /// A compact label for an axis tick or a readout.
    func format(_ value: Double) -> String {
        switch self {
        case .bytes:
            ByteCountFormatter.string(fromByteCount: Int64(max(0, value)), countStyle: .binary)
        case .packets:
            Int(max(0, value).rounded()).formatted()
        case .bitsPerSecond:
            Self.bitRate(max(0, value))
        }
    }

    // MARK: Private

    private static func bytes(of totals: TrafficTotals, part: Part) -> Int {
        switch part {
        case .total: totals.bytes
        case .sent: totals.sentBytes
        case .received: totals.receivedBytes
        }
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
        lastTimedFrame: Date?,
        sessionBuckets: [UUID: [Int64: TrafficSessionCell]] = [:],
        sessionSeriesComplete: Bool = true
    ) {
        self.sessionBuckets = sessionBuckets
        self.sessionSeriesComplete = sessionSeriesComplete
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

    /// `false` once the per-session bound was reached: some session's bytes in
    /// some slice were not recorded per session, so a scoped series may be lower
    /// than the traffic of that scope. The capture-wide series is unaffected.
    let sessionSeriesComplete: Bool

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
        guard let columns = columns(maxCount: maxCount) else {
            return []
        }
        var rendered: [Int64: TrafficTotals] = [:]
        for (key, totals) in buckets {
            rendered[key >> columns.shift, default: TrafficTotals()].add(totals)
        }
        return (columns.first ... columns.last).map { key in
            TrafficTimelinePoint(
                date: Date(timeIntervalSince1970: Double(key) * columns.width),
                totals: rendered[key] ?? TrafficTotals()
            )
        }
    }

    /// The bytes of the sessions in `scope` on exactly the columns
    /// ``points(maxCount:)`` renders, one value per column in the same order.
    /// Directions are not split per session, so only `bytes` and `frames` are set.
    func points(
        maxCount: Int = TrafficTimeline.defaultRenderedPointCount,
        scope: Set<UUID>
    )
        -> [TrafficTimelinePoint]
    {
        guard let columns = columns(maxCount: maxCount) else {
            return []
        }
        var rendered: [Int64: TrafficSessionCell] = [:]
        for id in scope {
            guard let series = sessionBuckets[id] else {
                continue
            }
            for (key, cell) in series {
                rendered[key >> columns.shift, default: TrafficSessionCell()].add(cell)
            }
        }
        return (columns.first ... columns.last).map { key in
            var totals = TrafficTotals()
            totals.bytes = rendered[key]?.bytes ?? 0
            totals.frames = rendered[key]?.frames ?? 0
            return TrafficTimelinePoint(date: Date(timeIntervalSince1970: Double(key) * columns.width), totals: totals)
        }
    }

    // MARK: Fileprivate

    fileprivate let buckets: [Int64: TrafficTotals]
    /// Each session's bytes and frames per retained bucket, keyed like `buckets`.
    fileprivate let sessionBuckets: [UUID: [Int64: TrafficSessionCell]]

    // MARK: Private

    /// Coarsen by whole powers of two so every retained bucket maps onto exactly
    /// one rendered column, counting columns from the coarsened first and last key.
    private func columns(maxCount: Int) -> (shift: Int, first: Int64, last: Int64, width: TimeInterval)? {
        guard let minimumKey = buckets.keys.min(),
              let maximumKey = buckets.keys.max() else
        {
            return nil
        }
        let cap = max(1, maxCount)
        var shift = 0
        while (maximumKey >> shift) - (minimumKey >> shift) + 1 > Int64(cap), shift < 62 {
            shift += 1
        }
        return (shift, minimumKey >> shift, maximumKey >> shift, bucketWidth * Double(1 << shift))
    }
}

// MARK: - TrafficTimelineAccumulator

/// Incremental builder for ``TrafficTimeline``. Folds one accepted frame at a time
/// and keeps at most `maxBuckets` buckets by doubling the width and merging pairs,
/// which is deterministic: the same frame sequence always yields the same buckets.
nonisolated struct TrafficTimelineAccumulator: Sendable {
    // MARK: Lifecycle

    init(
        maxBuckets: Int = TrafficTimelineAccumulator.defaultBucketCap,
        maxSessionEntries: Int = TrafficTimelineAccumulator.defaultSessionEntryCap
    ) {
        cap = max(1, maxBuckets)
        sessionEntryCap = max(0, maxSessionEntries)
    }

    // MARK: Internal

    /// Retained-bucket ceiling. One second of resolution for the first ~17 minutes
    /// of a capture, doubling thereafter; about 20 KB of state at the cap.
    static let defaultBucketCap = 1_024

    /// Bound on (session, bucket) entries kept for scoped series across the whole
    /// capture: a few MB at most. Past it, new entries are not recorded and the
    /// timeline says its per-session series are incomplete.
    static let defaultSessionEntryCap = 262_144

    mutating func add(
        timestamp: Date?,
        originalLength: Int,
        direction: TrafficDirection,
        sessionID: UUID? = nil
    ) {
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
        if let sessionID {
            addSessionBytes(originalLength, key: key, sessionID: sessionID)
        }
    }

    mutating func markDirectionUnstable() {
        directionMayHaveChanged = true
    }

    mutating func reset() {
        sessionBuckets.removeAll(keepingCapacity: false)
        sessionEntryCount = 0
        sessionSeriesComplete = true
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
            lastTimedFrame: lastTimed,
            sessionBuckets: sessionBuckets,
            sessionSeriesComplete: sessionSeriesComplete
        )
    }

    // MARK: Private

    private let cap: Int
    private let sessionEntryCap: Int
    private var sessionBuckets: [UUID: [Int64: TrafficSessionCell]] = [:]
    private var sessionEntryCount = 0
    private var sessionSeriesComplete = true
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
        var entries = 0
        for (id, series) in sessionBuckets {
            var halved: [Int64: TrafficSessionCell] = [:]
            for (key, cell) in series {
                halved[key >> 1, default: TrafficSessionCell()].add(cell)
            }
            entries += halved.count
            sessionBuckets[id] = halved
        }
        sessionEntryCount = entries
    }

    private mutating func addSessionBytes(_ bytes: Int, key: Int64, sessionID: UUID) {
        if sessionBuckets[sessionID]?[key] != nil {
            sessionBuckets[sessionID]?[key]?.add(TrafficSessionCell(bytes: bytes, frames: 1))
            return
        }
        guard sessionEntryCount < sessionEntryCap else {
            sessionSeriesComplete = false
            return
        }
        sessionBuckets[sessionID, default: [:]][key] = TrafficSessionCell(bytes: bytes, frames: 1)
        sessionEntryCount += 1
    }
}

// MARK: - TrafficSessionCell

/// One session's share of one retained bucket.
nonisolated struct TrafficSessionCell: Equatable, Sendable {
    var bytes = 0
    var frames = 0

    mutating func add(_ other: TrafficSessionCell) {
        bytes += other.bytes
        frames += other.frames
    }
}
