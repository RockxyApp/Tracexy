import Foundation

// MARK: - WildcardPattern

/// A shell-style wildcard over already-normalized text: `*` matches any run of
/// characters (including none) and `?` matches exactly one. Every other character
/// matches itself.
///
/// This is deliberately **not** a regular expression. A regex engine that backtracks
/// can take exponential time on a crafted pattern; this matcher is the classic greedy
/// wildcard walk with a single resume point, which runs in O(text × pattern) in the
/// worst case and O(text + pattern) for patterns in practice. Both operands are
/// bounded by the query engine's text ceiling, so no pattern can stall an evaluation.
nonisolated struct WildcardPattern: Hashable, Sendable {
    // MARK: Lifecycle

    /// `pattern` must already be normalized the way the engine normalizes text.
    init(normalized pattern: String) {
        characters = Array(pattern)
        text = pattern
    }

    // MARK: Internal

    /// The normalized pattern text, for diagnostics and equality.
    let text: String

    /// Whether the whole of `candidate` (already normalized) matches the pattern.
    func matches(_ candidate: String) -> Bool {
        let value = Array(candidate)
        var valueIndex = 0
        var patternIndex = 0
        // The most recent `*` and the value position it is currently standing in for.
        var starIndex: Int?
        var resumeIndex = 0
        while valueIndex < value.count {
            if patternIndex < characters.count,
               characters[patternIndex] == "?" || characters[patternIndex] == value[valueIndex]
            {
                valueIndex += 1
                patternIndex += 1
            } else if patternIndex < characters.count, characters[patternIndex] == "*" {
                starIndex = patternIndex
                resumeIndex = valueIndex
                patternIndex += 1
            } else if let star = starIndex {
                // Let the last `*` absorb one more character and retry after it.
                patternIndex = star + 1
                resumeIndex += 1
                valueIndex = resumeIndex
            } else {
                return false
            }
        }
        while patternIndex < characters.count, characters[patternIndex] == "*" {
            patternIndex += 1
        }
        return patternIndex == characters.count
    }

    // MARK: Private

    private let characters: [Character]
}
