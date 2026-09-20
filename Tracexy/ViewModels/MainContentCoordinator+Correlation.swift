import Foundation

// MARK: - Session correlation

@MainActor
extension MainContentCoordinator {
    /// The action the given session belongs to, or `nil` when nothing could
    /// attribute it.
    ///
    /// Correlation is computed over a time-bounded slice around the session
    /// rather than the whole capture. Grouping every session on demand would be
    /// O(capture) on the main actor and violate the bounded UI publication path;
    /// a causal window of tens of seconds cannot reach further than this slice
    /// anyway, so the narrower input costs no accuracy.
    func activity(containing session: SessionSummary) -> Activity? {
        // Correlation is time-dependent, so a session with no known start has no
        // slice to correlate within and no action to belong to.
        guard let anchor = session.startTime else {
            return nil
        }
        let window = ActivityBuilder.dnsCausalWindow
        let slice = presentedSessions.filter {
            guard let start = $0.startTime else {
                return false
            }
            return abs(start.timeIntervalSince(anchor)) <= window
        }
        guard slice.count > 1 else {
            return nil
        }
        return ActivityBuilder.build(from: slice)
            .activities
            .first { $0.sessions.contains { $0.id == session.id } }
    }
}
