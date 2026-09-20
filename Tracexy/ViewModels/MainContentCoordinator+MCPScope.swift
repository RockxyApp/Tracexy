import Foundation

// The coordinator's one read-only accessor for the MCP grant scope.
//
// A grant may only ever name the Project that is active right now and the History
// database that Project owns. Deriving the scope here — rather than letting the
// Settings pane assemble one — is what makes "you cannot grant access to a
// database this Project does not own" a structural fact instead of a rule.

@MainActor
extension MainContentCoordinator {
    /// The only scope a grant may be issued for, or `nil` while Projects are still
    /// loading or this Project has no resolved History location.
    var mcpGrantScope: MCPGrantScope? {
        guard hasHydratedProjects, let location = activeRuntime.location else {
            return nil
        }
        return MCPGrantScope(
            projectID: location.projectID,
            projectName: projectStore.activeProject.name,
            historyDatabaseURL: location.historyDatabaseURL
        )
    }
}
