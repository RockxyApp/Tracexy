import Foundation

/// Capture or displayed-list predecessor state. `unknown` differs from a known
/// first frame and from a known predecessor whose timestamp is missing.
nonisolated enum FrameTimePredecessor: Hashable, Sendable {
    case none
    case timestamp(Date)
    case unknown
}
