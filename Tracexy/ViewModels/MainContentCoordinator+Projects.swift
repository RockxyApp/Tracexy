import Foundation
import Observation

// MARK: - ProjectWorkspaceObservationTarget

private final class ProjectWorkspaceObservationTarget: @unchecked Sendable {
    // MARK: Lifecycle

    init(_ coordinator: MainContentCoordinator) {
        self.coordinator = coordinator
    }

    // MARK: Internal

    weak var coordinator: MainContentCoordinator?
}

// MARK: - Project lifecycle and workspace configuration

extension MainContentCoordinator {
    /// Load the local Project catalog once, bind the launch runtime to the *real*
    /// active Project, and only then allow capture intake.
    ///
    /// Order matters. The legacy-data owner is assigned and persisted before any
    /// History write, Library scan, or capture can happen, so the pre-Projects
    /// database and Captures folder can never end up attached to the wrong
    /// Project. A load or persistence failure leaves the runtime unbound: the app
    /// keeps running, Repair is offered, and capture is refused rather than taken
    /// in for an owner Tracexy cannot name.
    func hydrateProjectsOnLaunch() async {
        if let projectHydrationTask {
            await projectHydrationTask.value
            return
        }
        guard !hasHydratedProjects else {
            return
        }

        let task = Task { @MainActor [weak self] in
            guard let self else {
                return
            }
            await self.projectStore.loadPersistedCatalog()
            guard self.projectStore.loadState == .ready else {
                self.isProjectRecoveryPresented = true
                return
            }
            do {
                try self.projectStore.assignLegacyDataOwnerIfNeeded()
            } catch let error as ProjectMutationError {
                self.lastProjectOperationError = error
                self.isProjectRecoveryPresented = true
                return
            } catch {
                self.projectTransferErrorMessage = error.localizedDescription
                self.isProjectRecoveryPresented = true
                return
            }
            // The owner must be durable before intake, so a crash between now and
            // the first write can never leave the data unowned or reassignable.
            await self.projectStore.waitForPendingPersistence()
            guard self.projectStore.isMutable else {
                self.lastProjectOperationError = .storeNotReady
                self.isProjectRecoveryPresented = true
                return
            }
            await self.finishProjectHydration()
        }
        projectHydrationTask = task
        await task.value
        if !hasHydratedProjects {
            projectHydrationTask = nil
        }
    }

    @discardableResult
    func switchToProject(id: UUID) -> Bool {
        guard id != projectStore.activeProjectID else {
            lastProjectOperationError = nil
            return true
        }
        guard projectStore.projects.contains(where: { $0.id == id }) else {
            lastProjectOperationError = .projectNotFound
            return false
        }
        return beginProjectTransition(.switchProject(id))
    }

    /// Creating a Project is a Project change like any other: it uses the same
    /// lifecycle path, so a running capture is stopped and drained first and the
    /// new Project starts genuinely empty.
    ///
    /// The returned Project is the *validated destination* of a transition that has
    /// been accepted and started. Its identity is minted when the catalog change is
    /// validated, so it is known here, but it becomes the active Project only once
    /// the change has been written durably — await ``waitForProjectTransition()``
    /// to observe that outcome. `nil` means the change was rejected outright, or
    /// needs the Stop-and-Switch confirmation first.
    @discardableResult
    func createProject(named name: String) -> Project? {
        guard beginProjectTransition(.createProject(name)) else {
            return nil
        }
        return preparedProjectTransition?.destinationProject
    }

    @discardableResult
    func renameProject(id: UUID, to name: String) -> Bool {
        do {
            try projectStore.renameProject(id: id, to: name)
            lastProjectOperationError = nil
            return true
        } catch let error as ProjectMutationError {
            lastProjectOperationError = error
            return false
        } catch {
            projectTransferErrorMessage = error.localizedDescription
            return false
        }
    }

    /// Deleting a Project never deletes its saved capture files. The JSON configuration
    /// is removed from the catalog and the in-memory bucket is released; the
    /// Project's History database and Captures folder stay exactly where they are.
    @discardableResult
    func deleteProject(id: UUID) -> Bool {
        beginProjectTransition(.deleteProject(id))
    }

    @discardableResult
    func flushProjectWorkspaceSnapshot() -> Bool {
        guard projectStore.isMutable else {
            lastProjectOperationError = .storeNotReady
            return false
        }
        do {
            try projectStore.updateActiveProjectWorkspaces(
                workspaces.captureProjectWorkspaces(),
                activeWorkspaceID: workspaces.activeWorkspaceID
            )
            lastProjectOperationError = nil
            return true
        } catch let error as ProjectMutationError {
            lastProjectOperationError = error
            return false
        } catch {
            projectTransferErrorMessage = error.localizedDescription
            return false
        }
    }

    func flushProjectStateForTermination() async {
        _ = await projectTransitionTask?.value
        await pendingCaptureIOTask?.value
        await waitForHistory()
        projectWorkspaceAutosaveTask?.cancel()
        projectWorkspaceAutosaveTask = nil
        projectWorkspaceAutosaveOwner = nil
        _ = flushProjectWorkspaceSnapshot()
        await projectStore.waitForPendingPersistence()
    }

    func retryProjectCatalogLoad() async {
        // Reload is startup recovery, not permission to replace an investigation
        // already in memory with an older file. Explicit Reset has its own path.
        guard !hasHydratedProjects else {
            projectTransitionStatus = .failed(
                "Your investigation is still open. Save any unsaved capture before restarting Tracexy to reload the catalog."
            )
            return
        }
        // Reloading rebinds the runtime, so nothing may still be owed against the
        // store, spool or Library the current runtime is holding.
        guard canRebindProjectRuntime else {
            projectTransitionStatus = .failed(
                "Finish the running capture and its pending writes before repairing Projects."
            )
            return
        }
        projectTransitionStatus = .pending
        defer {
            if projectTransitionStatus.isPending {
                projectTransitionStatus = .idle
            }
        }
        await projectStore.retryLoad()
        guard projectStore.loadState == .ready else {
            return
        }
        do {
            try projectStore.assignLegacyDataOwnerIfNeeded()
        } catch {
            return
        }
        // The owner must be durable before intake, so a crash between now and the
        // first write can never leave the data unowned or reassignable.
        await projectStore.waitForPendingPersistence()
        guard projectStore.isMutable else {
            return
        }
        await finishProjectHydration()
        isProjectRecoveryPresented = false
    }

    /// Replace the catalog with a fresh default one. Recovery never reassigns the
    /// pre-Projects data: the owner is preserved when it is known and retired
    /// otherwise, so the files stay on disk and no new Project inherits them.
    func resetProjectCatalog() async {
        guard projectTransitionTask == nil else {
            return
        }
        let task = Task { @MainActor in
            await self.performProjectCatalogReset()
            return self.projectTransitionStatus == .idle
        }
        projectTransitionTask = task
        _ = await task.value
        projectTransitionTask = nil
    }

    private func performProjectCatalogReset() async {
        guard canRebindProjectRuntime else {
            projectTransitionStatus = .failed(
                "Stop the running capture and let its pending writes finish before repairing Projects."
            )
            return
        }
        let prepared: PreparedProjectCatalogTransition
        do {
            prepared = try projectStore.prepareResetTransition()
        } catch {
            projectTransitionStatus = .failed("Projects could not be prepared for reset. Nothing was discarded.")
            return
        }
        projectTransitionStatus = .pending
        suspendProjectWorkspaceObservation()
        do {
            let runtime = try await makeProjectRuntime(for: prepared.destinationProject)
            try await projectStore.commitPreparedTransition(prepared)
            invalidateOutgoingProjectWork()
            projectRuntimes.removeAll()
            hydratePersistedWorkspaces(of: prepared.destinationProject, into: runtime)
            projectRuntimes[prepared.destinationProject.id] = runtime
            hasBoundInitialRuntime = true
            adoptProjectRuntime(runtime)
            hasHydratedProjects = true
            projectTransitionStatus = .idle
            configureHistoryAutoClear(runtime.historyAutoClear)
            resumeProjectWorkspaceObservation()
            isProjectRecoveryPresented = false
        } catch {
            projectStore.discardPreparedTransition(prepared)
            resumeProjectWorkspaceObservation()
            projectTransitionStatus =
                .failed("Projects could not be reset. The previous catalog and investigation were preserved.")
        }
    }

    func presentNewProjectEditor() {
        guard projectStore.isMutable else {
            lastProjectOperationError = .storeNotReady
            return
        }
        guard projectStore.canCreateProject else {
            lastProjectOperationError = .capacityReached(limit: projectStore.maxProjects)
            return
        }
        projectNameEditorContext = ProjectNameEditorContext(
            mode: .create,
            initialName: nextUntakenProjectName()
        )
    }

    func presentRenameProjectEditor(id: UUID) {
        guard let project = projectStore.projects.first(where: { $0.id == id }) else {
            lastProjectOperationError = .projectNotFound
            return
        }
        projectNameEditorContext = ProjectNameEditorContext(
            mode: .rename(project.id),
            initialName: project.name
        )
    }

    func requestProjectDeletion(_ project: Project) {
        projectDeletionRequest = ProjectDeletionRequest(
            projectID: project.id,
            projectName: project.name
        )
    }

    var projectOperationErrorMessage: String? {
        guard let error = lastProjectOperationError else {
            return projectTransferErrorMessage
        }
        return error.userFacingDescription
    }

    var projectPersistenceWarningMessage: String? {
        switch projectStore.loadState {
        case .failed:
            "Projects could not be loaded. Workspace changes will not be saved until Projects are repaired."
        default:
            if case .failed = projectStore.persistenceStatus {
                "Projects could not be saved. Your current workspace is still available in this app session."
            } else if projectStore.legacyDataOwnerProjectID == ProjectCatalog.retiredLegacyDataOwnerID {
                "Capture data written before this Project catalog was repaired is still on disk, but it is "
                    + "not attached to any Project. Tracexy will not hand it to a new Project."
            } else {
                nil
            }
        }
    }

    // MARK: Workspace hydration and autosave

    /// Apply a Project's durable workspace configuration onto a freshly built
    /// runtime. Called once per bucket; a Project that is already open keeps its
    /// real workspace instances instead.
    func hydratePersistedWorkspaces(of project: Project, into runtime: ProjectRuntimeState) {
        runtime.workspaces.applyProjectWorkspaces(
            project.workspaces,
            activeWorkspaceID: project.activeWorkspaceID,
            maxFilterRules: policy.maxSessionFilterRules
        )
    }

    /// Re-arm the Observation-backed autosave against whichever ``WorkspaceStore``
    /// is now active, stamped with the Project that owns it.
    func resumeProjectWorkspaceObservation() {
        guard hasHydratedProjects else {
            return
        }
        isObservingProjectWorkspaces = true
        armProjectWorkspaceObservation()
    }

    /// Stop the Observation-backed autosave. A debounce that survives into a frozen
    /// catalog can only fail; the next boundary re-arms it against whichever
    /// ``WorkspaceStore`` becomes active.
    func suspendProjectWorkspaceObservation() {
        projectWorkspaceAutosaveTask?.cancel()
        projectWorkspaceAutosaveTask = nil
        projectWorkspaceAutosaveOwner = nil
        isObservingProjectWorkspaces = false
    }

    // MARK: Private

    /// True when the runtime may be torn down and rebound: no capture is running,
    /// no stop still owes its final drain, no transition is in flight, and neither
    /// the managed save nor the History mutation tail is still owed against the
    /// store, spool and Library the current runtime holds.
    private var canRebindProjectRuntime: Bool {
        !isCapturing && !isStarting && !isProjectBoundaryBusy
            && !isOpeningSavedCapture && !isExportingSession
            && projectStore.loadState != .loading
            && pendingProjectSwitchConfirmation == nil
            && pendingCaptureIOTask == nil
            && historyMutationTask == nil
    }

    private func finishProjectHydration() async {
        do {
            try await bindInitialProjectRuntime()
        } catch {
            lastProjectOperationError = .storeNotReady
            projectTransitionStatus = .failed(
                (error as? ProjectRuntimeError)?.userFacingDescription ?? error.localizedDescription
            )
            isProjectRecoveryPresented = true
            return
        }
        hydratePersistedWorkspaces(of: projectStore.activeProject, into: activeRuntime)
        // Raw/evidence work is selection-scoped; the freshly hydrated workspaces
        // carry no capture selection yet.
        cancelFollowStream(clearResult: true)
        evidenceNavigationDidChangeSelection()
        hasHydratedProjects = true
        projectTransitionStatus = .idle
        configureHistoryAutoClear(activeRuntime.historyAutoClear)
        resumeProjectWorkspaceObservation()
    }

    private func armProjectWorkspaceObservation() {
        let target = ProjectWorkspaceObservationTarget(self)
        let owner = projectStore.activeProjectID
        withObservationTracking {
            _ = workspaces.activeWorkspaceID
            _ = workspaces.captureProjectWorkspaces()
        } onChange: {
            Task { @MainActor in
                guard let coordinator = target.coordinator,
                      coordinator.isObservingProjectWorkspaces,
                      coordinator.projectStore.activeProjectID == owner else
                {
                    return
                }
                coordinator.armProjectWorkspaceObservation()
                guard !coordinator.isApplyingProjectSnapshot else {
                    return
                }
                coordinator.scheduleProjectWorkspaceAutosave(owner: owner)
            }
        }
    }

    private func scheduleProjectWorkspaceAutosave(owner: UUID) {
        projectWorkspaceAutosaveTask?.cancel()
        projectWorkspaceAutosaveOwner = owner
        projectWorkspaceAutosaveTask = Task { @MainActor [weak self] in
            do {
                try await Task.sleep(for: .milliseconds(500))
            } catch {
                return
            }
            guard let self, !Task.isCancelled else {
                return
            }
            // A debounce that outlived its Project must never write the incoming
            // Project's workspaces into the outgoing Project's catalog entry.
            guard self.projectWorkspaceAutosaveOwner == owner,
                  self.projectStore.activeProjectID == owner else
            {
                self.projectWorkspaceAutosaveTask = nil
                return
            }
            _ = self.flushProjectWorkspaceSnapshot()
            self.projectWorkspaceAutosaveTask = nil
            self.projectWorkspaceAutosaveOwner = nil
        }
    }

    private func nextUntakenProjectName() -> String {
        let base = String(localized: "New Project")
        let used = Set(projectStore.projects.map { ProjectNameNormalization.uniquenessKey($0.name) })
        if !used.contains(ProjectNameNormalization.uniquenessKey(base)) {
            return base
        }
        for number in 2 ... projectStore.maxProjects + 1 {
            let candidate = "\(base) \(number)"
            if !used.contains(ProjectNameNormalization.uniquenessKey(candidate)) {
                return candidate
            }
        }
        return base
    }
}
