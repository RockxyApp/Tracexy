import Foundation

// The coordinator's small, explicit seam for the AI Assistant.
//
// It gives the assistant three things and nothing else: the identity it must be
// guarded against, an off-main brief built from the current immutable snapshot,
// and the existing evidence-navigation route for one citation. No assistant state
// lives on the coordinator, and no assistant call can start capture, mutate
// evidence, or reach the helper.

// MARK: - AssistantContext

/// The exact identity one assistant run is bound to. Any difference between the
/// context a run started with and the context at adoption time cancels the run:
/// a Project switch, a workspace change, a new selection or a new capture
/// generation each make the in-flight answer describe something that is no longer
/// on screen.
nonisolated struct AssistantContext: Sendable, Equatable {
    let projectID: UUID
    let workspaceID: UUID
    let sessionID: UUID?
    let generation: Int
    /// The Assistant evidence publication identity. It advances on every adopted
    /// ``InvestigationSnapshot`` — including republication inside one capture
    /// generation — so a brief or a streamed answer derived from an earlier
    /// publication is stale even when nothing else about the context moved.
    let evidenceRevision: Int

    var conversationKey: AssistantConversationKey {
        AssistantConversationKey(projectID: projectID, workspaceID: workspaceID)
    }
}

// MARK: - Assistant seam

@MainActor
extension MainContentCoordinator {
    /// The current identity an assistant run must be guarded by.
    var assistantContext: AssistantContext {
        AssistantContext(
            projectID: projectStore.activeProjectID,
            workspaceID: activeWorkspace.id,
            sessionID: activeWorkspace.selectedSessionID,
            generation: startGeneration,
            evidenceRevision: assistantEvidenceRevision
        )
    }

    /// Build the bounded brief for the current selection off the main actor.
    ///
    /// The snapshot is immutable, so the detached build sees exactly the evidence
    /// that was published when the request started; a later publication produces a
    /// new context and therefore a new brief.
    func makeAssistantBrief(disclosure: AutomationDisclosure) async throws -> AssistantBriefBuild {
        guard let sessionID = activeWorkspace.selectedSessionID else {
            throw AssistantBriefError.sessionNotFound
        }
        let snapshot = investigationSnapshot
        let projectID = projectStore.activeProjectID
        let evidenceRevision = assistantEvidenceRevision
        return try await Task.detached(priority: .userInitiated) {
            try AssistantBriefBuilder.build(
                snapshot: snapshot,
                sessionID: sessionID,
                projectID: projectID,
                disclosure: disclosure,
                evidenceRevision: evidenceRevision
            )
        }.value
    }

    /// Route one assistant citation through the existing evidence navigation.
    ///
    /// It never selects a different session and never reads a frame itself: if the
    /// citation belongs to a session that is no longer selected, nothing happens,
    /// which is the same guard a Findings row already obeys.
    func navigateToAssistantCitation(sessionID: UUID, provenance: SessionFrameProvenance) {
        guard activeWorkspace.selectedSessionID == sessionID else {
            return
        }
        inspectCitedFrame(sessionID: sessionID, provenance: provenance)
    }
}

// MARK: - Assistant demo fixture

@MainActor
extension MainContentCoordinator {
    /// Publish the deterministic documentation-range fixture snapshot and select
    /// its one session, so the Assistant dock can be exercised without a capture.
    ///
    /// It is reachable only from the explicit `--assistant-demo` launch argument.
    func adoptAssistantDemoFixture() async {
        let eventOrdinals: [UInt64] = [10, 11, 12]
        let frames = AssistantDemoFixture.capturedFrames(eventOrdinals: eventOrdinals)
        var snapshot = AssistantDemoFixture.snapshot(
            eventOrdinals: eventOrdinals,
            locatorByOrdinal: [:]
        )
        do {
            let epoch = startGeneration
            try await liveCaptureSpool.reset(epoch: epoch)
            let result = try await liveCaptureSpool.append(
                frames,
                defaultLinkType: LinkType.ethernet,
                epoch: epoch
            )
            if case let .appended(locators) = result, locators.count == eventOrdinals.count {
                snapshot = AssistantDemoFixture.snapshot(
                    eventOrdinals: eventOrdinals,
                    locatorByOrdinal: Dictionary(uniqueKeysWithValues: zip(eventOrdinals, locators))
                )
            }
        } catch {
            // The walkthrough remains usable for review/streaming when its
            // disposable spool cannot be created. Its citations are then marked
            // non-local and cannot become false navigation affordances.
        }
        sessions = snapshot.sessions
        adoptInvestigation(snapshot)
        // The walkthrough is about a session, and the right dock is deliberately
        // hidden on the History surface — so the sidebar is placed on Sessions
        // before the dock is revealed.
        activeWorkspace.sidebarSelection = .sessions
        if let session = snapshot.sessions.first {
            select(session)
        }
        activeWorkspace.contextDockTab = .aiAssistant
        if !isContextDockVisible {
            toggleContextDock()
        }
    }
}
