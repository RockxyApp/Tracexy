import Foundation

// MARK: - CaptureActivityBucket

/// One column of the Overview's "frames over capture time" chart: a bounded slice
/// of capture time carrying how many frames and on-wire bytes landed in it. Only
/// aggregate counts cross this seam — never the captured packet bytes themselves.
nonisolated struct CaptureActivityBucket: Identifiable, Equatable, Sendable {
    /// Position of this bucket in the ordered sequence (`0` is the earliest).
    let index: Int
    /// Seconds from the first captured frame to the start of this bucket.
    let startOffset: TimeInterval
    let frameCount: Int
    let byteCount: Int

    var id: Int {
        index
    }
}

// MARK: - CaptureActivity

/// A bounded, deterministic aggregation of a capture's frames over time, derived
/// from real frame timestamps and on-wire lengths. Built once at the open/import
/// boundary (see ``MainContentCoordinator.savedCaptureActivity``) so the Overview
/// chart never re-scans frames on each SwiftUI body update, and never receives
/// packet payloads — only these per-bucket totals.
nonisolated struct CaptureActivity: Equatable, Sendable {
    /// Ordered time buckets, earliest first. Empty when no accepted frame carried
    /// a capture time — untimed frames never enter a bucket.
    let buckets: [CaptureActivityBucket]
    /// Wall-clock span from the first to the last *timed* frame, in seconds. When
    /// ``untimedFrameCount`` is non-zero this describes the timed subset only, not
    /// the whole capture.
    let timedSpan: TimeInterval
    /// Every accepted frame, timed or not.
    let totalFrames: Int
    /// On-wire bytes of every accepted frame, timed or not.
    let totalBytes: Int
    /// Width of each bucket in seconds (`0` for an empty or single-instant capture).
    let bucketWidth: TimeInterval
    /// Accepted frames whose source carried no capture time. They are counted in
    /// ``totalFrames``/``totalBytes`` and excluded from every bucket and span.
    let untimedFrameCount: Int

    /// No frames at all — distinct from "frames present but none of them timed".
    var isEmpty: Bool {
        totalFrames == 0
    }

    /// Accepted frames that did carry a capture time.
    var timedFrameCount: Int {
        max(0, totalFrames - untimedFrameCount)
    }

    /// The whole capture's duration, or `nil` when at least one accepted frame
    /// carried no capture time — a span that omits frames is not a duration.
    var duration: TimeInterval? {
        untimedFrameCount == 0 ? timedSpan : nil
    }

    /// Whether ``timedSpan`` describes only part of the accepted frames, so a time
    /// range must be labelled as the timed subset rather than the capture.
    var coversTimedSubsetOnly: Bool {
        untimedFrameCount > 0 && timedFrameCount > 0
    }

    /// The largest per-bucket frame count, for normalizing bar heights. `0` when
    /// empty, so callers can guard division without a special case.
    var peakFrameCount: Int {
        buckets.map(\.frameCount).max() ?? 0
    }
}

// MARK: - CaptureActivityBuilder

/// Pure aggregator that folds captured frames into a bounded set of time buckets.
///
/// Deterministic and total: it handles the empty capture, a single frame (or many
/// frames sharing one instant), and a normal multi-frame span without ever
/// dividing by zero or producing more buckets than the cap. The bucket count is
/// `min(cap, frameCount)`, so a tiny capture is not padded with empty columns and
/// a huge one is bounded to `cap` regardless of size.
nonisolated enum CaptureActivityBuilder {
    /// Upper bound on bucket count. Small enough to read as a compact bar strip,
    /// large enough to show shape; the visualization stays bounded on any capture.
    static let defaultBucketCap = 24

    static func build(frames: [CapturedFrame], maxBuckets: Int = defaultBucketCap) -> CaptureActivity {
        let cap = max(1, maxBuckets)
        var totalBytes = 0
        var untimedFrames = 0
        var timedBytes = 0
        var minTime: Date?
        var maxTime: Date?
        for frame in frames {
            totalBytes += frame.originalLength
            guard let timestamp = frame.timestamp else {
                // Bytes and frames are always retained; only bucketing is skipped.
                untimedFrames += 1
                continue
            }
            timedBytes += frame.originalLength
            minTime = minTime.map { min($0, timestamp) } ?? timestamp
            maxTime = maxTime.map { max($0, timestamp) } ?? timestamp
        }

        let frameCount = frames.count
        let timedCount = frameCount - untimedFrames
        // No frame carried a capture time: there is no timed axis to bucket at all,
        // and the totals still report every retained frame and byte.
        guard let minTime, let maxTime, timedCount > 0 else {
            return CaptureActivity(
                buckets: [],
                timedSpan: 0,
                totalFrames: frameCount,
                totalBytes: totalBytes,
                bucketWidth: 0,
                untimedFrameCount: untimedFrames
            )
        }
        let span = max(0, maxTime.timeIntervalSince(minTime))

        // A single timed frame, or many sharing one instant: no span to divide, so
        // the timed frames collapse into one truthful bucket rather than trapping.
        guard span > 0 else {
            let bucket = CaptureActivityBucket(
                index: 0, startOffset: 0, frameCount: timedCount, byteCount: timedBytes
            )
            return CaptureActivity(
                buckets: [bucket],
                timedSpan: 0,
                totalFrames: frameCount,
                totalBytes: totalBytes,
                bucketWidth: 0,
                untimedFrameCount: untimedFrames
            )
        }

        // `span > 0` implies at least two distinct timestamps, so `timedCount >= 2`
        // and `bucketCount >= 1`; `width` is therefore strictly positive.
        let bucketCount = min(cap, timedCount)
        let width = span / Double(bucketCount)
        var frameCounts = [Int](repeating: 0, count: bucketCount)
        var byteCounts = [Int](repeating: 0, count: bucketCount)
        for frame in frames {
            guard let timestamp = frame.timestamp else {
                continue
            }
            let offset = timestamp.timeIntervalSince(minTime)
            var index = Int(offset / width)
            // The final frame lands exactly on the trailing edge; clamp it into the
            // last bucket rather than spilling past the array.
            if index >= bucketCount {
                index = bucketCount - 1
            }
            if index < 0 {
                index = 0
            }
            frameCounts[index] += 1
            byteCounts[index] += frame.originalLength
        }

        let buckets = (0 ..< bucketCount).map { index in
            CaptureActivityBucket(
                index: index,
                startOffset: Double(index) * width,
                frameCount: frameCounts[index],
                byteCount: byteCounts[index]
            )
        }
        return CaptureActivity(
            buckets: buckets,
            timedSpan: span,
            totalFrames: frameCount,
            totalBytes: totalBytes,
            bucketWidth: width,
            untimedFrameCount: untimedFrames
        )
    }
}

// MARK: - CaptureActivityAccumulator

/// A bounded, incremental version of ``CaptureActivityBuilder`` for the streaming
/// saved-open path, where frames arrive one at a time and the full frame array is
/// never held in memory.
///
/// It folds frames as they stream and keeps **at most `maxBuckets` buckets** at
/// every moment, so its memory is bounded by the cap rather than by the capture
/// size — no per-frame timestamp history is retained, so nothing frame-sized
/// crosses the task boundary when the completed activity is handed back.
///
/// Bounding is achieved by doubling the bucket width and merging adjacent
/// (chronological) bucket pairs whenever a new frame would push the bucket count
/// past the cap. Because the width only ever doubles, a merge combines exactly two
/// neighbours and is fully deterministic: the same frame sequence always yields
/// the same buckets. Exact `totalFrames`, `totalBytes`, `untimedFrameCount` and the
/// min→max `timedSpan`
/// are tracked directly from every frame and are never approximated by the
/// bucketing, so they equal a batch ``CaptureActivityBuilder/build(frames:maxBuckets:)``
/// over the same frames even when the bucket *shape* differs.
nonisolated struct CaptureActivityAccumulator: Sendable {
    // MARK: Lifecycle

    init(maxBuckets: Int = CaptureActivityBuilder.defaultBucketCap) {
        cap = max(1, maxBuckets)
    }

    // MARK: Internal

    /// Fold one frame's optional timestamp and on-wire length. Deterministic and
    /// total: it handles the first frame, many frames sharing one instant, an
    /// expanding span, and a frame with no capture time at all, without ever
    /// dividing by zero or exceeding the bucket cap.
    ///
    /// A `nil` timestamp still contributes its frame and bytes to the totals; it is
    /// counted as untimed and never placed in a bucket or used to widen the span.
    mutating func add(timestamp: Date?, originalLength: Int) {
        totalFrames += 1
        totalBytes += originalLength

        guard let timestamp else {
            untimedFrames += 1
            return
        }

        guard let origin else {
            self.origin = timestamp
            minTime = timestamp
            maxTime = timestamp
            width = 0
            frameCounts = [1]
            byteCounts = [originalLength]
            return
        }

        if let current = minTime, timestamp < current {
            minTime = timestamp
        }
        if let current = maxTime, timestamp > current {
            maxTime = timestamp
        }

        // An earlier frame changes the axis origin. Existing aggregate buckets
        // cannot be split without retaining every timestamp; collapse them into
        // one honest coarse interval instead of clamping the new frame onto the
        // old axis and presenting misleading offsets.
        if timestamp < origin {
            self.origin = timestamp
            width = maxTime.map { $0.timeIntervalSince(timestamp).nextUp } ?? 0
            frameCounts = [frameCounts.reduce(0, +) + 1]
            byteCounts = [byteCounts.reduce(0, +) + originalLength]
            return
        }

        // Still a single instant relative to the origin: everything folds into the
        // first bucket, and there is no span to divide by yet.
        let delta = timestamp.timeIntervalSince(origin)
        if width == 0 {
            if delta <= 0 {
                frameCounts[0] += 1
                byteCounts[0] += originalLength
                return
            }
            // First positive span: seed the width so this frame lands one bucket
            // past the origin, then let the cap logic merge if the cap is 1.
            width = delta
        }

        // Widen in floating point before narrowing to an integer. A tiny initial
        // interval followed by a distant but finite timestamp can exceed Int.max.
        var position = (delta / width).rounded(.down)
        while position >= Double(cap) {
            doubleWidthAndMerge()
            position = (delta / width).rounded(.down)
        }
        let index = position <= 0 ? 0 : Int(position)
        while frameCounts.count <= index {
            frameCounts.append(0)
            byteCounts.append(0)
        }
        frameCounts[index] += 1
        byteCounts[index] += originalLength
    }

    /// Materialize the bounded activity. Buckets are the accumulated columns; the
    /// duration is the exact min→max span regardless of the bucket width.
    func activity() -> CaptureActivity {
        guard let minTime, let maxTime else {
            // Either no frames at all, or frames that all lacked a capture time:
            // no timed axis exists, and every retained total is still reported.
            return CaptureActivity(
                buckets: [],
                timedSpan: 0,
                totalFrames: totalFrames,
                totalBytes: totalBytes,
                bucketWidth: 0,
                untimedFrameCount: untimedFrames
            )
        }
        let span = max(0, maxTime.timeIntervalSince(minTime))
        let buckets = (0 ..< frameCounts.count).map { index in
            CaptureActivityBucket(
                index: index,
                startOffset: width * Double(index),
                frameCount: frameCounts[index],
                byteCount: byteCounts[index]
            )
        }
        return CaptureActivity(
            buckets: buckets,
            timedSpan: span,
            totalFrames: totalFrames,
            totalBytes: totalBytes,
            bucketWidth: width,
            untimedFrameCount: untimedFrames
        )
    }

    // MARK: Private

    private let cap: Int
    private var origin: Date?
    private var minTime: Date?
    private var maxTime: Date?
    private var totalFrames = 0
    private var totalBytes = 0
    /// Frames folded with no capture time. Counted, never bucketed.
    private var untimedFrames = 0
    /// Width of each bucket in seconds; `0` while every frame shares one instant.
    private var width: TimeInterval = 0
    private var frameCounts: [Int] = []
    private var byteCounts: [Int] = []

    /// Double the bucket width and merge each adjacent pair, halving the bucket
    /// count while conserving every frame and byte. Deterministic because the
    /// width only ever doubles, so a merge always combines exactly two neighbours.
    private mutating func doubleWidthAndMerge() {
        width *= 2
        let mergedCount = (frameCounts.count + 1) / 2
        var mergedFrames = [Int](repeating: 0, count: mergedCount)
        var mergedBytes = [Int](repeating: 0, count: mergedCount)
        for index in frameCounts.indices {
            let target = index / 2
            mergedFrames[target] += frameCounts[index]
            mergedBytes[target] += byteCounts[index]
        }
        frameCounts = mergedFrames
        byteCounts = mergedBytes
    }
}
