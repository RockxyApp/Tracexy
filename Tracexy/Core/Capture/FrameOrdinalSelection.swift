import Foundation

/// Capture-wide, one-based frame numbers. Intervals stay compact even when a
/// user selects millions of frames; the source scan supplies the actual bound.
nonisolated struct FrameOrdinalSelection: Equatable, Sendable {
    // MARK: Internal

    struct Interval: Equatable, Sendable {
        let first: UInt64
        let last: UInt64?

        func contains(_ ordinal: UInt64) -> Bool {
            ordinal >= first && (last.map { ordinal <= $0 } ?? true)
        }
    }

    let intervals: [Interval]

    static func parse(_ specification: String) -> Self? {
        guard specification.utf8.count <= 4_096 else {
            return nil
        }
        let terms = specification.split(separator: ",", omittingEmptySubsequences: false)
        guard !terms.isEmpty, terms.count <= 256 else {
            return nil
        }
        var intervals: [Interval] = []
        intervals.reserveCapacity(terms.count)
        for term in terms {
            let trimmed = term.trimmingCharacters(in: .whitespaces)
            let bounds = trimmed.split(separator: "-", omittingEmptySubsequences: false)
            guard bounds.count == 1 || bounds.count == 2,
                  let first = decimal(bounds[0]), first > 0 else
            {
                return nil
            }
            let last: UInt64?
            if bounds.count == 1 {
                last = first
            } else if bounds[1].isEmpty {
                last = nil
            } else {
                guard let upper = decimal(bounds[1]), upper >= first else {
                    return nil
                }
                last = upper
            }
            intervals.append(Interval(first: first, last: last))
        }
        intervals.sort { $0.first < $1.first }
        var merged: [Interval] = []
        for interval in intervals {
            if let previous = merged.last,
               previous.last.map({ interval.first <= $0 || ($0 < UInt64.max && interval.first == $0 + 1) }) ?? true
            {
                merged[merged.count - 1] = Interval(
                    first: previous.first,
                    last: mergeUpper(previous.last, interval.last)
                )
            } else {
                merged.append(interval)
            }
        }
        return Self(intervals: merged)
    }

    func contains(_ ordinal: UInt64) -> Bool {
        var lower = 0
        var upper = intervals.count
        while lower < upper {
            let middle = lower + (upper - lower) / 2
            let interval = intervals[middle]
            if ordinal < interval.first {
                upper = middle
            } else if interval.contains(ordinal) {
                return true
            } else {
                lower = middle + 1
            }
        }
        return false
    }

    // MARK: Private

    private static func decimal(_ text: Substring) -> UInt64? {
        guard !text.isEmpty, text.utf8.allSatisfy({ (48 ... 57).contains($0) }) else {
            return nil
        }
        return UInt64(text)
    }

    private static func mergeUpper(_ first: UInt64?, _ second: UInt64?) -> UInt64? {
        guard let first, let second else {
            return nil
        }
        return max(first, second)
    }
}
