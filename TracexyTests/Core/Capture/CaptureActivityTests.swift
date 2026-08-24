import Foundation
import Testing
@testable import Tracexy

// MARK: - CaptureActivityTests

@Suite("Capture activity aggregation")
struct CaptureActivityTests {
    // MARK: Internal

    @Test("An empty capture aggregates to nothing without trapping")
    func emptyCapture() {
        let activity = CaptureActivityBuilder.build(frames: [])
        #expect(activity.buckets.isEmpty)
        #expect(activity.isEmpty)
        #expect(activity.duration == 0)
        #expect(activity.totalFrames == 0)
        #expect(activity.totalBytes == 0)
        #expect(activity.bucketWidth == 0)
        #expect(activity.peakFrameCount == 0)
    }

    @Test("A single instant collapses into one truthful bucket, never dividing by zero")
    func singleInstant() {
        // Several frames sharing one timestamp: no span to bucket over.
        let frames = (0 ..< 4).map { _ in frame(atOffset: 0, bytes: 100) }
        let activity = CaptureActivityBuilder.build(frames: frames)

        #expect(activity.buckets.count == 1)
        #expect(activity.duration == 0)
        #expect(activity.bucketWidth == 0)
        #expect(activity.totalFrames == 4)
        #expect(activity.totalBytes == 400)
        #expect(activity.buckets.first?.frameCount == 4)
        #expect(activity.buckets.first?.byteCount == 400)
    }

    @Test("A single frame is one bucket carrying it")
    func singleFrame() {
        let activity = CaptureActivityBuilder.build(frames: [frame(atOffset: 5, bytes: 42)])
        #expect(activity.buckets.count == 1)
        #expect(activity.totalFrames == 1)
        #expect(activity.totalBytes == 42)
        #expect(activity.duration == 0)
    }

    @Test("A normal multi-frame span buckets to min(cap, frameCount) and conserves totals")
    func multiBucketConservesTotals() {
        // Ten frames one second apart, span = 9 s. cap 5 → exactly five buckets.
        let frames = (0 ..< 10).map { index in
            frame(atOffset: Double(index), bytes: 10 * (index + 1))
        }
        let activity = CaptureActivityBuilder.build(frames: frames, maxBuckets: 5)

        #expect(activity.buckets.count == 5)
        #expect(activity.duration == 9)
        #expect(activity.bucketWidth == 9.0 / 5.0)
        // Every frame lands in exactly one bucket, so per-bucket totals sum to the
        // capture totals — no frame or byte is lost or double-counted.
        #expect(activity.buckets.reduce(0) { $0 + $1.frameCount } == activity.totalFrames)
        #expect(activity.buckets.reduce(0) { $0 + $1.byteCount } == activity.totalBytes)
        #expect(activity.totalFrames == 10)
        #expect(activity.totalBytes == frames.reduce(0) { $0 + $1.originalLength })
        // Bucket offsets are the ordered left edges.
        #expect(activity.buckets.map(\.index) == [0, 1, 2, 3, 4])
        #expect(activity.buckets.first?.startOffset == 0)
    }

    @Test("The bucket count stays bounded by the cap on a large capture")
    func boundedByCap() {
        let frames = (0 ..< 5_000).map { index in
            frame(atOffset: Double(index) * 0.01, bytes: 1)
        }
        let activity = CaptureActivityBuilder.build(frames: frames, maxBuckets: 24)
        #expect(activity.buckets.count == 24)
        #expect(activity.totalFrames == 5_000)
        #expect(activity.buckets.reduce(0) { $0 + $1.frameCount } == 5_000)
    }

    @Test("Aggregation is deterministic for identical input")
    func deterministic() {
        let frames = (0 ..< 30).map { index in frame(atOffset: Double(index) * 0.5, bytes: index) }
        let first = CaptureActivityBuilder.build(frames: frames)
        let second = CaptureActivityBuilder.build(frames: frames)
        #expect(first == second)
    }

    @Test("The trailing frame is clamped into the final bucket, not spilled past it")
    func trailingEdgeClamped() {
        // The last frame sits exactly on the span's trailing edge, which would map
        // to index == bucketCount without clamping.
        let frames = (0 ..< 8).map { index in frame(atOffset: Double(index), bytes: 1) }
        let activity = CaptureActivityBuilder.build(frames: frames, maxBuckets: 4)
        #expect(activity.buckets.count == 4)
        #expect(activity.buckets.reduce(0) { $0 + $1.frameCount } == 8)
    }

    // MARK: - Incremental accumulator

    @Test("The incremental accumulator aggregates to nothing for an empty capture")
    func accumulatorEmpty() {
        let accumulator = CaptureActivityAccumulator()
        let activity = accumulator.activity()
        #expect(activity.isEmpty)
        #expect(activity.totalFrames == 0)
        #expect(activity.totalBytes == 0)
        #expect(activity.duration == 0)
        #expect(activity.bucketWidth == 0)
    }

    @Test("Many frames sharing one instant collapse into one bucket without dividing by zero")
    func accumulatorSingleInstant() {
        var accumulator = CaptureActivityAccumulator()
        for _ in 0 ..< 4 {
            accumulator.add(timestamp: Self.base, originalLength: 100)
        }
        let activity = accumulator.activity()
        #expect(activity.buckets.count == 1)
        #expect(activity.duration == 0)
        #expect(activity.bucketWidth == 0)
        #expect(activity.totalFrames == 4)
        #expect(activity.totalBytes == 400)
    }

    @Test("The incremental accumulator stays within the cap while totals and duration stay exact")
    func accumulatorBoundedWithExactTotals() {
        var accumulator = CaptureActivityAccumulator(maxBuckets: 8)
        var expectedBytes = 0
        for index in 0 ..< 500 {
            let bytes = index + 1
            expectedBytes += bytes
            accumulator.add(timestamp: Self.base.addingTimeInterval(Double(index) * 0.1), originalLength: bytes)
        }
        let activity = accumulator.activity()
        #expect(activity.buckets.count <= 8)
        #expect(activity.totalFrames == 500)
        #expect(activity.totalBytes == expectedBytes)
        // 499 steps of 0.1 s.
        #expect(abs(activity.duration - 49.9) < 1e-6)
        // Every frame and byte is conserved across the merges.
        #expect(activity.buckets.reduce(0) { $0 + $1.frameCount } == 500)
        #expect(activity.buckets.reduce(0) { $0 + $1.byteCount } == expectedBytes)
    }

    @Test("Incremental accumulation is deterministic for an identical frame sequence")
    func accumulatorDeterministic() {
        func run() -> CaptureActivity {
            var accumulator = CaptureActivityAccumulator(maxBuckets: 6)
            for index in 0 ..< 60 {
                accumulator.add(timestamp: Self.base.addingTimeInterval(Double(index) * 0.5), originalLength: index)
            }
            return accumulator.activity()
        }
        let first = run()
        let second = run()
        #expect(first == second)
    }

    @Test("Incremental and batch aggregation agree on the exact totals and duration")
    func accumulatorMatchesBatchTotals() {
        let frames = (0 ..< 120).map { index in frame(atOffset: Double(index) * 0.25, bytes: index * 3) }
        let batch = CaptureActivityBuilder.build(frames: frames, maxBuckets: 10)
        var accumulator = CaptureActivityAccumulator(maxBuckets: 10)
        for frame in frames {
            accumulator.add(timestamp: frame.timestamp, originalLength: frame.originalLength)
        }
        let incremental = accumulator.activity()
        #expect(incremental.totalFrames == batch.totalFrames)
        #expect(incremental.totalBytes == batch.totalBytes)
        #expect(abs(incremental.duration - batch.duration) < 1e-6)
        #expect(incremental.buckets.count <= 10)
    }

    // MARK: Private

    private static let base = Date(timeIntervalSince1970: 1_700_000_000)

    private func frame(atOffset offset: TimeInterval, bytes: Int) -> CapturedFrame {
        CapturedFrame(
            bytes: [UInt8](repeating: 0, count: max(0, bytes)),
            timestamp: Self.base.addingTimeInterval(offset),
            originalLength: bytes
        )
    }
}
