import Foundation

// MARK: - BoundedFrameBuffer

/// A fixed-capacity FIFO staging buffer with explicit, cumulative drop counting.
///
/// The helper stages captured frames here between the capture worker producing
/// them and the app draining them. When the app falls behind, the buffer must
/// bound its memory — but it must never do so *silently*. The old code called
/// `removeFirst` on an unbounded array and told no one; a drop that no number
/// records is indistinguishable from a clean capture, which is the one thing a
/// capture tool may not fake. This type evicts the oldest frames and records
/// exactly how many it evicted, so the loss travels to the UI as a real figure.
///
/// This is the real primitive the helper's `CaptureService` uses. It lives in
/// `Shared` (compiled into app + helper) so it can be tested directly, rather
/// than asserted about via source text against helper-only code the test bundle
/// cannot import.
nonisolated struct BoundedFrameBuffer<Element> {
    // MARK: Lifecycle

    init(capacity: Int) {
        self.capacity = max(1, capacity)
    }

    // MARK: Internal

    /// Frames retained and not yet drained, oldest first.
    private(set) var frames: [Element] = []

    /// Cumulative frames evicted since the last ``reset()``. Saturating: it
    /// widens to `UInt64` and clamps at the maximum rather than wrapping, so a
    /// pathological run can never make the loss *look smaller* than it was.
    private(set) var droppedCount: UInt64 = 0

    /// The most frames retained at once.
    let capacity: Int

    /// Stage newly captured frames, evicting the oldest if capacity is exceeded.
    mutating func append(contentsOf newFrames: [Element]) {
        guard !newFrames.isEmpty else {
            return
        }
        frames.append(contentsOf: newFrames)
        if frames.count > capacity {
            let overflow = frames.count - capacity
            frames.removeFirst(overflow)
            droppedCount = BoundedFrameBuffer.saturatingAdd(droppedCount, UInt64(overflow))
        }
    }

    /// Hands off every retained frame and clears the staging area, *keeping* the
    /// cumulative drop count — the count spans the whole capture, not one drain,
    /// so each drained batch reports the running total.
    mutating func drain() -> [Element] {
        let out = frames
        frames.removeAll(keepingCapacity: true)
        return out
    }

    /// Clears both retained frames and the cumulative drop count. Called only at
    /// a capture boundary (start/stop), where the counter genuinely resets to
    /// zero — never on a drain, which would understate loss.
    mutating func reset() {
        frames.removeAll(keepingCapacity: false)
        droppedCount = 0
    }

    // MARK: Private

    private static func saturatingAdd(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? UInt64.max : sum
    }
}
