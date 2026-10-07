import Foundation

// MARK: - Apply as Filter / Prepare as Filter

@MainActor
extension MainContentCoordinator {
    /// Wireshark's Apply as Filter (`applying`) and Prepare as Filter from the decode
    /// tree: joins `term` to the expression in the editor as `combination` says, then
    /// applies it, or leaves it in the opened editor to change before applying.
    func filterSessions(with term: String, combination: DecodedFieldFilter.Combination, applying: Bool) {
        let workspace = activeWorkspace
        let current = workspace.investigationDraft.mode == .expression ? workspace.investigationDraft.expression : ""
        let expression = combination.combine(current, term)
        workspace.sidebarSelection = .sessions
        if applying {
            applySessionExpression(expression, in: workspace)
        } else {
            var draft = workspace.investigationDraft
            draft.mode = .expression
            draft.expression = expression
            workspace.investigationDraft = draft
            workspace.isInvestigationEditorPresented = true
        }
    }
}
