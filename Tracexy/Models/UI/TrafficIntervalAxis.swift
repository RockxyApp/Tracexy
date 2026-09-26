import Foundation

// MARK: - TrafficIntervalAxis

/// The time columns a traffic-over-time graph is plotted on.
///
/// The traffic fold keeps frames and bytes per retained slice. A slice starts one
/// second wide and only ever doubles, and slices are aligned to whole multiples of
/// their width on the clock. An interval that is a whole multiple of the slice
/// width therefore contains whole slices only, so every plotted value is exact.
/// Intervals finer than the retained slice are not offered: there is no per-frame
/// time left to split a slice with.
nonisolated struct TrafficIntervalAxis: Equatable, Sendable {
    /// The standard intervals offered, before the capture's resolution and span
    /// narrow them.
    static let candidateIntervals: [TimeInterval] = [1, 2, 5, 10, 30, 60, 120, 300, 600, 1_800, 3_600]
    /// Most intervals one graph plots, so a long capture at a fine interval can
    /// never ask a chart for an unbounded number of marks.
    static let maximumColumns = 2_000
    /// Most retained slices read in one pass.
    static let maximumBaseColumns = 16_384

    /// Width in seconds of the retained slices the graph is built from.
    let resolution: TimeInterval
    /// Width in seconds of one plotted interval.
    let interval: TimeInterval
    /// The intervals this capture supports, ascending.
    let availableIntervals: [TimeInterval]
    /// `floor(start / interval)` of the first plotted interval.
    let firstColumnKey: Int64
    let columnCount: Int

    /// Start of the first plotted interval; the origin of the relative axis.
    var origin: Date {
        columnStart(0)
    }

    /// The plotted span from the first interval's start to the last one's end.
    var span: TimeInterval {
        Double(columnCount) * interval
    }

    /// A short label for an interval: "1 s", "5 min", "1 h".
    static func intervalTitle(_ interval: TimeInterval) -> String {
        if interval >= 3_600, interval.truncatingRemainder(dividingBy: 3_600) == 0 {
            return String(localized: "\(Int(interval / 3_600)) h")
        }
        if interval >= 60, interval.truncatingRemainder(dividingBy: 60) == 0 {
            return String(localized: "\(Int(interval / 60)) min")
        }
        if interval >= 1 {
            return String(localized: "\(Int(interval)) s")
        }
        return String(localized: "\(Int((interval * 1_000).rounded())) ms")
    }

    /// Plan the columns for `timeline` at the interval nearest `requested`, or `nil`
    /// when no timed frame has been folded.
    static func plan(for timeline: TrafficTimeline, requested: TimeInterval) -> TrafficIntervalAxis? {
        let base = timeline.points(maxCount: maximumBaseColumns)
        guard let first = base.first, let last = base.last else {
            return nil
        }
        let resolution = base.count >= 2 ? base[1].date.timeIntervalSince(first.date) : timeline.bucketWidth
        guard resolution > 0, resolution.isFinite else {
            return nil
        }
        let firstStart = first.date.timeIntervalSince1970
        let lastStart = last.date.timeIntervalSince1970
        let covered = lastStart + resolution - firstStart
        func columns(_ interval: TimeInterval) -> Int64 {
            key(lastStart, width: interval) - key(firstStart, width: interval) + 1
        }

        var options = Set(candidateIntervals)
        options.insert(resolution)
        var available = options.filter { interval in
            isWholeMultiple(interval, of: resolution)
                && columns(interval) <= Int64(maximumColumns)
                && interval <= max(covered, resolution)
        }
        if available.isEmpty {
            // Nothing standard fits (an unusually coarse resolution or a very long,
            // sparse capture): offer the finest power-of-two multiple that does.
            var interval = resolution
            while columns(interval) > Int64(maximumColumns), interval < .greatestFiniteMagnitude / 2 {
                interval *= 2
            }
            available.insert(interval)
        }
        let sorted = available.sorted()
        let interval = sorted.first { abs($0 - requested) < 1e-9 }
            ?? sorted.first { $0 >= requested }
            ?? sorted[sorted.count - 1]
        let firstKey = key(firstStart, width: interval)
        return TrafficIntervalAxis(
            resolution: resolution,
            interval: interval,
            availableIntervals: sorted,
            firstColumnKey: firstKey,
            columnCount: Int(key(lastStart, width: interval) - firstKey + 1)
        )
    }

    /// `floor(seconds / width)` as a key, clamped instead of trapping.
    static func key(_ seconds: TimeInterval, width: TimeInterval) -> Int64 {
        let position = (seconds / width).rounded(.down)
        if position >= Double(Int64.max) {
            return Int64.max
        }
        if position <= Double(Int64.min) {
            return Int64.min
        }
        return Int64(position)
    }

    /// Whether `interval` is a whole number (at least one) of `resolution` widths.
    static func isWholeMultiple(_ interval: TimeInterval, of resolution: TimeInterval) -> Bool {
        let ratio = interval / resolution
        return ratio >= 1 && abs(ratio - ratio.rounded()) < 1e-9
    }

    func columnStart(_ column: Int) -> Date {
        Date(timeIntervalSince1970: Double(firstColumnKey + Int64(column)) * interval)
    }

    /// Seconds from ``origin`` to the start of `column`.
    func offset(ofColumn column: Int) -> TimeInterval {
        Double(column) * interval
    }

    /// The plotted column holding `date`, or `nil` outside the axis.
    func column(containing date: Date) -> Int? {
        let key = Self.key(date.timeIntervalSince1970, width: interval)
        let column = key - firstColumnKey
        guard column >= 0, column < Int64(columnCount) else {
            return nil
        }
        return Int(column)
    }
}

// MARK: - TrafficRateGraph

/// The traffic of the open capture per interval, as packets per second and bytes
/// per second — Wireshark's I/O Graph with its two standard series.
///
/// Built from the capture-wide traffic fold, so it counts every timed frame the
/// capture holds, whether or not it belongs to a session in view. A value is the
/// interval's total divided by the interval width: an average across the
/// interval, never a peak.
nonisolated struct TrafficRateGraph: Equatable, Sendable {
    struct Column: Identifiable, Equatable, Sendable {
        let index: Int
        let start: Date
        let frames: Int
        let bytes: Int
        let packetsPerSecond: Double
        let bytesPerSecond: Double

        var id: Int {
            index
        }
    }

    static let empty = TrafficRateGraph(axis: nil, columns: [], untimedFrameCount: 0)

    /// `nil` when no timed frame has been folded yet.
    let axis: TrafficIntervalAxis?
    let columns: [Column]
    /// Frames without a capture time: counted by the capture, in no interval.
    let untimedFrameCount: Int

    var totalFrames: Int {
        columns.reduce(0) { $0 + $1.frames }
    }

    var totalBytes: Int {
        columns.reduce(0) { $0 + $1.bytes }
    }

    static func compute(from timeline: TrafficTimeline, requestedInterval: TimeInterval) -> TrafficRateGraph {
        guard let axis = TrafficIntervalAxis.plan(for: timeline, requested: requestedInterval) else {
            return TrafficRateGraph(axis: nil, columns: [], untimedFrameCount: timeline.untimedFrameCount)
        }
        var frames = [Int](repeating: 0, count: axis.columnCount)
        var bytes = [Int](repeating: 0, count: axis.columnCount)
        for point in timeline.points(maxCount: TrafficIntervalAxis.maximumBaseColumns) where point.totals.frames > 0 {
            guard let column = axis.column(containing: point.date) else {
                continue
            }
            frames[column] += point.totals.frames
            bytes[column] += point.totals.bytes
        }
        let columns = (0 ..< axis.columnCount).map { index in
            Column(
                index: index,
                start: axis.columnStart(index),
                frames: frames[index],
                bytes: bytes[index],
                packetsPerSecond: Double(frames[index]) / axis.interval,
                bytesPerSecond: Double(bytes[index]) / axis.interval
            )
        }
        return TrafficRateGraph(axis: axis, columns: columns, untimedFrameCount: timeline.untimedFrameCount)
    }

    /// One row per interval: start offset, frames, bytes and both rates.
    func csv() -> String {
        let header = "Interval start (s),Frames,Bytes,Packets per second,Bytes per second"
        guard let axis else {
            return header
        }
        let lines = columns.map { column in
            [
                String(format: "%.3f", axis.offset(ofColumn: column.index)),
                String(column.frames),
                String(column.bytes),
                String(format: "%.4f", column.packetsPerSecond),
                String(format: "%.4f", column.bytesPerSecond),
            ].joined(separator: ",")
        }
        return ([header] + lines).joined(separator: "\n")
    }
}
