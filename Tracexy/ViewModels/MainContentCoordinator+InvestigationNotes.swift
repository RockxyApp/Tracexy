import Foundation

// MARK: - Investigation notes

/// Notes are keyed by the capture they were written about. A saved file's scope is
/// its content identity, read off the main actor after the file is adopted; a live
/// run's scope is set when the run begins and follows the capture into the Library
/// file when it is saved.
@MainActor
extension MainContentCoordinator {
    /// Why notes cannot be written right now, or `nil` when they can.
    var investigationNotesUnavailableReason: String? {
        if investigationNotes.scope != nil {
            return nil
        }
        if isViewingSavedCapture, savedCaptureEvidenceURL != nil {
            return "Reading the capture file…"
        }
        return "Open or capture traffic to write notes about it."
    }

    /// Recompute the scope for the adopted saved file. The scope is `nil` while the
    /// digest is read, so nothing can be written against the previous capture.
    func refreshInvestigationNoteScope() {
        guard isViewingSavedCapture, let url = savedCaptureEvidenceURL else {
            return
        }
        investigationNotes.scope = nil
        let generation = startGeneration
        investigationNotes.pendingScopeTask = Task.detached(priority: .utility) { [weak self] in
            let scope = try? InvestigationNoteScope.capture(at: url)
            await self?.adoptInvestigationNoteScope(scope, for: url, generation: generation)
        }
    }

    /// Carry the notes written during a live run over to the file it was saved as.
    /// The saved file is read once, off the main actor, for its content identity.
    func carryInvestigationNotes(from liveScope: InvestigationNoteScope, toCaptureAt url: URL, projectID: UUID) {
        investigationNotes.pendingScopeTask = Task.detached(priority: .utility) { [weak self] in
            guard let destination = try? InvestigationNoteScope.capture(at: url) else {
                return
            }
            await self?.moveInvestigationNotes(from: liveScope, to: destination, projectID: projectID)
        }
    }

    /// The notes on `session` in the current capture, as a session export carries
    /// them: the session note first, then finding notes with the finding's title.
    func exportedNotes(for session: SessionSummary) -> [SessionExportNote] {
        let titles = Dictionary(
            findings.filter { $0.sessionID == session.id }.map { ($0.id, $0.title) },
            uniquingKeysWith: { first, _ in first }
        )
        return investigationNotes.notes(onSession: session.id).map { note in
            switch note.target {
            case .session:
                SessionExportNote(subject: "session", findingTitle: nil, text: note.text, updatedAt: note.updatedAt)
            case let .finding(id, _):
                SessionExportNote(
                    subject: "finding", findingTitle: titles[id], text: note.text, updatedAt: note.updatedAt
                )
            }
        }
    }

    /// Test/diagnostic seam for the exact scope task handle; no wall-clock sleep.
    func waitForInvestigationNoteScope() async {
        let task = investigationNotes.pendingScopeTask
        await task?.value
    }

    /// Remember where the active workspace left this capture file: the selected
    /// session and the applied session expression. A live run is not remembered.
    func rememberInvestigationViewState() {
        guard isViewingSavedCapture, let scope = investigationNotes.scope else {
            return
        }
        let workspace = activeWorkspace
        let accepted = workspace.acceptedInvestigationDraft
        let expression = accepted?.mode == .expression
            ? accepted?.expression.trimmingCharacters(in: .whitespacesAndNewlines)
            : nil
        investigationViewStates.remember(
            InvestigationViewState(
                selectedSessionID: workspace.selectedSessionID,
                expression: expression?.isEmpty == false ? expression : nil,
                updatedAt: Date()
            ),
            for: scope
        )
    }

    // MARK: Private

    private func adoptInvestigationNoteScope(_ scope: InvestigationNoteScope?, for url: URL, generation: Int) {
        guard startGeneration == generation, isViewingSavedCapture, savedCaptureEvidenceURL == url else {
            return
        }
        investigationNotes.scope = scope
        if let scope {
            restoreInvestigationViewState(for: scope)
        }
    }

    /// Put the capture back where it was left, unless the investigator has already
    /// moved on while the file's identity was being read. A remembered session that
    /// is no longer in the capture is ignored rather than guessed at.
    private func restoreInvestigationViewState(for scope: InvestigationNoteScope) {
        guard let state = investigationViewStates.state(for: scope) else {
            return
        }
        let workspace = activeWorkspace
        if let expression = state.expression, workspace.acceptedInvestigationDraft == nil {
            applySessionExpression(expression, in: workspace)
        }
        if workspace.selectedSessionID == nil,
           let id = state.selectedSessionID,
           let session = presentedSessions.first(where: { $0.id == id })
        {
            select(session)
        }
    }

    private func moveInvestigationNotes(
        from source: InvestigationNoteScope,
        to destination: InvestigationNoteScope,
        projectID: UUID
    ) {
        // The store is bound to the active Project's suite; a save that finished after
        // a Project switch must not write the other Project's notes.
        guard activeRuntime.projectID == projectID else {
            return
        }
        investigationNotes.move(from: source, to: destination)
    }
}
