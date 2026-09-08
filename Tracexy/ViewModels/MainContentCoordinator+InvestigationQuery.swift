import Foundation

// MARK: - InvestigationQueryExecution

/// One immutable off-main compile/evaluate result ready for guarded MainActor adoption.
nonisolated struct InvestigationQueryExecution: Sendable {
    let compilation: CompiledInvestigationQueryDraft
    let result: InvestigationQueryResult
}

// MARK: - InvestigationQueryTask

/// A handle plus a process-local identity. Workspace UUIDs and request counters can
/// be recreated by Project hydration, so neither alone proves that a completion still
/// owns the dictionary slot it is about to remove.
struct InvestigationQueryTask {
    let token: UUID
    let task: Task<Void, Never>
}

// MARK: - Capture-local Investigation query

@MainActor
extension MainContentCoordinator {
    /// Apply a structured draft to one workspace. Until both compilation and evaluation
    /// succeed, its previous accepted query/results remain untouched.
    func applyInvestigationQuery(
        _ draft: InvestigationQueryDraft,
        in workspace: WorkspaceState? = nil
    ) {
        let workspace = workspace ?? activeWorkspace
        workspace.investigationDraft = draft
        scheduleInvestigationQuery(draft, in: workspace, clearsError: true)
    }

    /// Disable the accepted query without altering any persisted search/filter values.
    /// The editable draft stays available if the user opens Investigate again.
    func clearInvestigationQuery(in workspace: WorkspaceState? = nil) {
        let workspace = workspace ?? activeWorkspace
        workspace.investigationQueryRequestID &+= 1
        investigationQueryTasks.removeValue(forKey: workspace.id)?.task.cancel()
        workspace.acceptedInvestigationDraft = nil
        workspace.investigationMatchedSessionIDs.removeAll()
        workspace.investigationIndeterminateSessionIDs.removeAll()
        workspace.investigationCoverageReasons.removeAll()
        workspace.investigationQueryError = nil
        workspace.isEvaluatingInvestigationQuery = false
        reconcileLiveFollowing(in: workspace)
    }

    /// Capture-boundary retirement. Drafts are reset too because Investigation query
    /// state is capture-local; persisted FocusSets and ordinary filter/search state are
    /// deliberately not touched.
    func clearAllInvestigationQueries() {
        for task in investigationQueryTasks.values {
            task.task.cancel()
        }
        investigationQueryTasks.removeAll()
        for workspace in workspaces.workspaces {
            workspace.investigationQueryRequestID &+= 1
            workspace.investigationDraft = InvestigationQueryDraft()
            workspace.acceptedInvestigationDraft = nil
            workspace.investigationMatchedSessionIDs.removeAll()
            workspace.investigationIndeterminateSessionIDs.removeAll()
            workspace.investigationCoverageReasons.removeAll()
            workspace.investigationQueryError = nil
            workspace.isEvaluatingInvestigationQuery = false
        }
    }

    /// Project-boundary retirement. Retires only the *in-flight evaluation*: the
    /// parked Project keeps its structured drafts, its accepted queries and their
    /// results, because those are user state that belongs to it and are restored
    /// verbatim when it comes back. Bumping each workspace's request ID retires any
    /// evaluation still in flight, so a late result can never adopt into a workspace
    /// under another Project's published snapshot.
    func cancelInFlightInvestigationQueries() {
        for task in investigationQueryTasks.values {
            task.task.cancel()
        }
        investigationQueryTasks.removeAll()
        for workspace in workspaces.workspaces {
            workspace.investigationQueryRequestID &+= 1
            workspace.isEvaluatingInvestigationQuery = false
        }
    }

    /// Reevaluate only accepted queries after the current capture publishes a new
    /// immutable snapshot. Existing matched IDs stay visible until the fresh guarded
    /// result arrives, avoiding a transient unfiltered flash on live updates.
    func refreshActiveInvestigationQueries() {
        for workspace in workspaces.workspaces {
            guard let draft = workspace.acceptedInvestigationDraft else {
                continue
            }
            scheduleInvestigationQuery(draft, in: workspace, clearsError: false)
        }
    }

    /// Test/runtime synchronization seam; awaiting it never performs evaluation on the
    /// MainActor because the stored task delegates the bounded work to a detached task.
    func waitForInvestigationQuery(in workspace: WorkspaceState) async {
        await investigationQueryTasks[workspace.id]?.task.value
    }

    private func scheduleInvestigationQuery(
        _ draft: InvestigationQueryDraft,
        in workspace: WorkspaceState,
        clearsError: Bool
    ) {
        workspace.investigationQueryRequestID &+= 1
        let requestID = workspace.investigationQueryRequestID
        let workspaceID = workspace.id
        let taskToken = UUID()
        let expectedGeneration = startGeneration
        let snapshot = investigationSnapshot
        investigationQueryTasks.removeValue(forKey: workspaceID)?.task.cancel()
        workspace.isEvaluatingInvestigationQuery = true
        if clearsError {
            workspace.investigationQueryError = nil
        }

        // Keep the exact initiating workspace long enough to retire its progress state,
        // even if Project hydration replaces the live WorkspaceStore while evaluation
        // is suspended. Adoption additionally requires object identity in the current
        // store; request, task and generation identities protect later work.
        let task = Task { @MainActor [weak self, workspace] in
            do {
                let execution = try await Self.executeInvestigationQuery(
                    draft,
                    over: snapshot
                )
                guard let self else {
                    return
                }
                guard workspace.investigationQueryRequestID == requestID else {
                    return
                }
                guard self.workspaces.workspaces.contains(where: { $0 === workspace }) else {
                    self.finishCancelledInvestigationQuery(
                        workspace,
                        requestID: requestID,
                        taskToken: taskToken
                    )
                    return
                }
                guard self.startGeneration == expectedGeneration else {
                    self.removeInvestigationQueryTask(workspaceID: workspaceID, taskToken: taskToken)
                    workspace.isEvaluatingInvestigationQuery = false
                    return
                }
                self.removeInvestigationQueryTask(workspaceID: workspaceID, taskToken: taskToken)
                workspace.acceptedInvestigationDraft = draft
                workspace.investigationMatchedSessionIDs = Set(execution.result.matched.map(\.id))
                workspace.investigationIndeterminateSessionIDs = Set(execution.result.indeterminate)
                workspace.investigationCoverageReasons = execution.result.coverage?.reasons ?? []
                workspace.investigationQueryError = nil
                workspace.isEvaluatingInvestigationQuery = false
                self.reconcileLiveFollowing(in: workspace)
            } catch is CancellationError {
                self?.finishCancelledInvestigationQuery(
                    workspace,
                    requestID: requestID,
                    taskToken: taskToken
                )
            } catch let error as InvestigationQueryDraftError {
                self?.finishInvalidInvestigationQuery(
                    error,
                    in: workspace,
                    requestID: requestID,
                    expectedGeneration: expectedGeneration,
                    taskToken: taskToken
                )
            } catch {
                self?.finishCancelledInvestigationQuery(
                    workspace,
                    requestID: requestID,
                    taskToken: taskToken
                )
            }
        }
        investigationQueryTasks[workspaceID] = InvestigationQueryTask(token: taskToken, task: task)
    }

    private func finishCancelledInvestigationQuery(
        _ workspace: WorkspaceState,
        requestID: Int,
        taskToken: UUID
    ) {
        guard workspace.investigationQueryRequestID == requestID else {
            return
        }
        removeInvestigationQueryTask(workspaceID: workspace.id, taskToken: taskToken)
        workspace.isEvaluatingInvestigationQuery = false
    }

    private func finishInvalidInvestigationQuery(
        _ error: InvestigationQueryDraftError,
        in workspace: WorkspaceState,
        requestID: Int,
        expectedGeneration: Int,
        taskToken: UUID
    ) {
        guard workspace.investigationQueryRequestID == requestID else {
            return
        }
        guard startGeneration == expectedGeneration else {
            removeInvestigationQueryTask(workspaceID: workspace.id, taskToken: taskToken)
            workspace.isEvaluatingInvestigationQuery = false
            return
        }
        guard workspaces.workspaces.contains(where: { $0 === workspace }) else {
            finishCancelledInvestigationQuery(
                workspace,
                requestID: requestID,
                taskToken: taskToken
            )
            return
        }
        removeInvestigationQueryTask(workspaceID: workspace.id, taskToken: taskToken)
        workspace.investigationQueryError = error
        workspace.isEvaluatingInvestigationQuery = false
    }

    private func removeInvestigationQueryTask(workspaceID: UUID, taskToken: UUID) {
        guard investigationQueryTasks[workspaceID]?.token == taskToken else {
            return
        }
        investigationQueryTasks.removeValue(forKey: workspaceID)
    }

    nonisolated private static func executeInvestigationQuery(
        _ draft: InvestigationQueryDraft,
        over snapshot: InvestigationSnapshot
    )
        async throws -> InvestigationQueryExecution
    {
        let task = Task.detached(priority: .userInitiated) {
            let compiler = InvestigationQueryDraftCompiler()
            let compilation = try compiler.compile(draft)
            try Task.checkCancellation()
            let result = try compiler.engine.evaluate(
                compilation.compiled,
                over: snapshot,
                isCancelled: { Task.isCancelled }
            )
            return InvestigationQueryExecution(compilation: compilation, result: result)
        }
        return try await withTaskCancellationHandler {
            try await task.value
        } onCancel: {
            task.cancel()
        }
    }
}
