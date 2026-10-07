import Foundation

// MARK: - Finding navigation

/// View ▸ Next / Previous Session With a Finding. Steps through the sessions in view
/// — after every pill, search, scope and expression — in capture order, stopping only
/// on sessions that carry at least one finding. It does not wrap: past the last one the
/// command does nothing. The menu is enabled from a constant-time check, because the
/// command bar re-evaluates on every published change and the full step is O(n).
@MainActor
extension MainContentCoordinator {
    enum FindingStep {
        case next
        case previous
    }

    /// Whether any analysis reported a finding — constant time, for menu enabling.
    var hasAnyFinding: Bool {
        !connectionAnalysisSnapshot.findings.isEmpty
            || !datagramAnalysisSnapshot.findings.isEmpty
            || !tlsAnalysisSnapshot.findings.isEmpty
    }

    /// The session a step would select, or `nil` when there is none in that direction.
    func sessionWithFinding(_ step: FindingStep) -> SessionSummary? {
        let flagged = Set(findings.map(\.sessionID))
        let sessions = visibleSessions
        let current = activeWorkspace.selectedSessionID.flatMap { id in sessions.firstIndex { $0.id == id } }
        switch step {
        case .next:
            let start = current.map { $0 + 1 } ?? 0
            guard start < sessions.count else {
                return nil
            }
            return sessions[start...].first { flagged.contains($0.id) }
        case .previous:
            guard let current, current > 0 else {
                return nil
            }
            return sessions[..<current].last { flagged.contains($0.id) }
        }
    }

    func selectSessionWithFinding(_ step: FindingStep) {
        guard let session = sessionWithFinding(step) else {
            return
        }
        select(session)
    }
}
