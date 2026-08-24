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
    /// Ordered time buckets, earliest first. Empty only for an empty capture.
    let buckets: [CaptureActivityBucket]
    /// Wall-clock span from the first to the last captured frame, in seconds.
    let duration: TimeInterval
    let totalFrames: Int
    let totalBytes: Int
    /// Width of each bucket in seconds (`0` for an empty or single-instant capture).
    let bucketWidth: TimeInterval

    var isEmpty: Bool {
        buckets.isEmpty
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
        guard let firstFrame = frames.first else {
            return CaptureActivity(buckets: [], duration: 0, totalFrames: 0, totalBytes: 0, bucketWidth: 0)
        }

        var minTime = firstFrame.timestamp
        var maxTime = firstFrame.timestamp
        var totalBytes = 0
        for frame in frames {
            if frame.timestamp < minTime {
                minTime = frame.timestamp
            }
            if frame.timestamp > maxTime {
                maxTime = frame.timestamp
            }
            totalBytes += frame.originalLength
        }

        let frameCount = frames.count
        let span = max(0, maxTime.timeIntervalSince(minTime))

        // A single frame, or many frames sharing one instant: no span to divide,
        // so everything collapses into one truthful bucket rather than trapping.
        guard span > 0 else {
            let bucket = CaptureActivityBucket(
                index: 0, startOffset: 0, frameCount: frameCount, byteCount: totalBytes
            )
            return CaptureActivity(
                buckets: [bucket], duration: 0, totalFrames: frameCount, totalBytes: totalBytes, bucketWidth: 0
            )
        }

        // `span > 0` implies at least two distinct timestamps, so `frameCount >= 2`
        // and `bucketCount >= 1`; `width` is therefore strictly positive.
        let bucketCount = min(cap, frameCount)
        let width = span / Double(bucketCount)
        var frameCounts = [Int](repeating: 0, count: bucketCount)
        var byteCounts = [Int](repeating: 0, count: bucketCount)
        for frame in frames {
            let offset = frame.timestamp.timeIntervalSince(minTime)
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
            buckets: buckets, duration: span, totalFrames: frameCount, totalBytes: totalBytes, bucketWidth: width
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
/// the same buckets. Exact `totalFrames`, `totalBytes` and the min→max `duration`
/// are tracked directly from every frame and are never approximated by the
/// bucketing, so they equal a batch ``CaptureActivityBuilder/build(frames:maxBuckets:)``
/// over the same frames even when the bucket *shape* differs.
nonisolated struct CaptureActivityAccumulator: Sendable {
    // MARK: Lifecycle

    init(maxBuckets: Int = CaptureActivityBuilder.defaultBucketCap) {
        cap = max(1, maxBuckets)
    }

    // MARK: Internal

    /// Fold one frame's timestamp and on-wire length. Deterministic and total: it
    /// handles the first frame, many frames sharing one instant, and an expanding
    /// span without ever dividing by zero or exceeding the bucket cap.
    mutating func add(timestamp: Date, originalLength: Int) {
        totalFrames += 1
        totalBytes += originalLength

        guard let origin else {
            self.origin = timestamp
            minTime = timestamp
            maxTime = timestamp
            width = 0
            frameCounts = [1]
            byteCounts = [originalLength]
            return
        }

        if timestamp < minTime {
            minTime = timestamp
        }
        if timestamp > maxTime {
            maxTime = timestamp
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

        var index = Int((delta / width).rounded(.down))
        if index < 0 {
            index = 0
        }
        // Grow the width (halving resolution) until the target index fits the cap.
        while index >= cap {
            doubleWidthAndMerge()
            index = Int((timestamp.timeIntervalSince(origin) / width).rounded(.down))
            if index < 0 {
                index = 0
            }
        }
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
        guard origin != nil else {
            return CaptureActivity(buckets: [], duration: 0, totalFrames: 0, totalBytes: 0, bucketWidth: 0)
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
            duration: span,
            totalFrames: totalFrames,
            totalBytes: totalBytes,
            bucketWidth: width
        )
    }

    // MARK: Private

    private let cap: Int
    private var origin: Date?
    private var minTime = Date(timeIntervalSince1970: 0)
    private var maxTime = Date(timeIntervalSince1970: 0)
    private var totalFrames = 0
    private var totalBytes = 0
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
