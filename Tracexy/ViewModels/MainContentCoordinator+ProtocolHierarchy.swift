import Foundation

@MainActor
extension MainContentCoordinator {
    /// Statistics ▸ Protocol Hierarchy: narrow to the sessions that carry every protocol on
    /// `path`, as one recorded drill-in (Back to Previous Scope returns).
    func showSessionsForProtocolPath(_ path: [ProtocolKind]) {
        guard !path.isEmpty else {
            return
        }
        let workspace = activeWorkspace
        recordSessionScopeDrillIn(in: workspace) {
            if let lens = workspace.sidebarSelection.protocolFilter {
                workspace.aggregateProtocolFilters.insert(lens)
            }
            workspace.sidebarSelection = .sessions
            workspace.aggregateProtocolFilters.formUnion(path)
            workspace.isFilterBarVisible = true
        }
    }
}
