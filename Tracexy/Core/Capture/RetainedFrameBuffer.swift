import Foundation

// MARK: - RetainedFrameBuffer

/// A fixed-capacity FIFO window of raw frames retained solely for save/export.
///
/// This bounds *memory*, not capture fidelity. Sessions accumulate independently
/// in `LiveSessionEngine`, so evicting the oldest retained frame here never drops
/// a session, and never forces a re-decode of history — it leaves only the recent
/// tail available to a `.pcap` save. Every eviction is counted cumulatively (saturating),
/// so the truncation can be surfaced as exactly what it is: **save/export
/// retention truncation, never captured-packet loss**. Conflating it with helper
/// or kernel drop counters would misstate where fidelity was lost.
///
/// Distinct from the helper's `BoundedFrameBuffer`: that one *drains* frames to
/// the app and counts capture-source loss; this one *keeps* frames for the user
/// to save and counts only the local retention tail it had to trim.
nonisolated struct RetainedFrameBuffer {
    // MARK: Lifecycle

    init(capacity: Int) {
        self.capacity = max(1, capacity)
    }

    // MARK: Internal

    /// Frames retained for save/export, oldest first.
    private(set) var frames: [CapturedFrame] = []

    /// Cumulative frames evicted from the window since the last ``reset()``.
    /// Saturating at `UInt64.max` rather than wrapping, so a pathological run can
    /// never make the truncation *look smaller* than it was.
    private(set) var evictionCount: UInt64 = 0

    /// Sum of the captured (on-disk) lengths of the frames currently retained.
    /// Maintained incrementally on append/evict/replace so the Overview can show a
    /// truthful "estimated save size" without re-summing the window on every UI
    /// refresh. Tracks captured length — the bytes a `.pcap`/`.pcapng` save writes
    /// — not the original on-wire length.
    private(set) var capturedByteCount: Int = 0

    /// The most frames retained at once.
    let capacity: Int

    var isEmpty: Bool {
        frames.isEmpty
    }

    var count: Int {
        frames.count
    }

    /// Stage newly captured frames, evicting the oldest — and counting them — once
    /// the window is full.
    mutating func append(contentsOf newFrames: [CapturedFrame]) {
        guard !newFrames.isEmpty else {
            return
        }
        frames.append(contentsOf: newFrames)
        capturedByteCount += newFrames.reduce(0) { $0 + $1.capturedLength }
        if frames.count > capacity {
            let overflow = frames.count - capacity
            capturedByteCount -= frames.prefix(overflow).reduce(0) { $0 + $1.capturedLength }
            frames.removeFirst(overflow)
            let (sum, overflowed) = evictionCount.addingReportingOverflow(UInt64(overflow))
            evictionCount = overflowed ? UInt64.max : sum
        }
    }

    /// Replace the whole window with the frames of an opened saved capture, and
    /// zero the eviction count. A file is the source of truth and is shown in
    /// full — the live retention bound intentionally does not apply, so opening a
    /// large capture never reports a truncation that did not happen here.
    mutating func replace(with newFrames: [CapturedFrame]) {
        frames = newFrames
        evictionCount = 0
        capturedByteCount = newFrames.reduce(0) { $0 + $1.capturedLength }
    }

    /// Clears both retained frames and the cumulative eviction count. Called at
    /// capture boundaries (start / clear), where the counter genuinely resets.
    mutating func reset() {
        frames.removeAll(keepingCapacity: false)
        evictionCount = 0
        capturedByteCount = 0
    }
}
