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

    /// Apply or prepare a typed packet-level predicate in View ▸ All Frames.
    /// This state and grammar remain independent of the session investigation editor.
    func filterFrames(with term: String, combination: DecodedFieldFilter.Combination, applying: Bool) {
        let state = allFrames
        state.updateFrameExpressionDraft(combination.combineFrame(state.frameExpressionDraft, term))
        if applying {
            state.applyFrameExpression()
        }
    }

    /// Highlight frames for a decoded-field term without changing the Frame
    /// Expression draft or applied filter.
    func highlightFrames(with term: String) {
        allFrames.highlightFrames(with: term)
    }
}
