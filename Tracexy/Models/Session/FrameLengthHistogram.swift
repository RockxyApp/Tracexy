import Foundation

// MARK: - FrameLengthHistogram

/// Frame lengths on the wire, counted into Wireshark's Packet Lengths ranges
/// (0–19, 20–39, 40–79 … 2560–5119, 5120 and greater) with a sum, minimum and
/// maximum per range. Fixed size, so a session's histogram costs the same whatever
/// its length, and histograms add, so a report over any set of sessions is exact.
nonisolated struct FrameLengthHistogram: Hashable, Sendable {
    struct Bucket: Hashable, Sendable {
        var count = 0
        var sum = 0
        var minimum = Int.max
        var maximum = 0

        /// `count < 1` rather than `== 0`, so the formatter's isEmpty rule cannot
        /// turn this property into a call to itself (and the linter's empty-count rule
        /// has nothing to flag).
        var isEmpty: Bool {
            count < 1
        }

        var average: Double? {
            isEmpty ? nil : Double(sum) / Double(count)
        }
    }

    /// Lower bounds of the ranges; the last range is open-ended.
    static let lowerBounds = [0, 20, 40, 80, 160, 320, 640, 1_280, 2_560, 5_120]

    private(set) var buckets = [Bucket](repeating: Bucket(), count: lowerBounds.count)

    var total: Bucket {
        buckets.reduce(into: Bucket()) { result, bucket in
            result.count += bucket.count
            result.sum += bucket.sum
            result.minimum = min(result.minimum, bucket.minimum)
            result.maximum = max(result.maximum, bucket.maximum)
        }
    }

    var isEmpty: Bool {
        buckets.allSatisfy(\.isEmpty)
    }

    /// "0-19", "5120 and greater" — Wireshark's labels.
    static func label(ofBucket index: Int) -> String {
        guard index + 1 < lowerBounds.count else {
            // A byte count, not a quantity: never grouped by locale ("5120", not "5,120").
            return String(localized: "\(String(lowerBounds[index])) and greater")
        }
        return "\(lowerBounds[index])–\(lowerBounds[index + 1] - 1)"
    }

    mutating func record(_ length: Int) {
        let length = max(0, length)
        let index = (Self.lowerBounds.lastIndex { $0 <= length }) ?? 0
        buckets[index].count += 1
        buckets[index].sum += length
        buckets[index].minimum = min(buckets[index].minimum, length)
        buckets[index].maximum = max(buckets[index].maximum, length)
    }

    mutating func add(_ other: FrameLengthHistogram) {
        for index in buckets.indices {
            let bucket = other.buckets[index]
            guard !bucket.isEmpty else {
                continue
            }
            buckets[index].count += bucket.count
            buckets[index].sum += bucket.sum
            buckets[index].minimum = min(buckets[index].minimum, bucket.minimum)
            buckets[index].maximum = max(buckets[index].maximum, bucket.maximum)
        }
    }
}
