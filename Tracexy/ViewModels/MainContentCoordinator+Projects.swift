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
    /// Loads the local Project catalog once, then applies only the active
    /// Project's durable workspace configuration. Capture/session/History state
    /// is intentionally untouched.
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
            self.activateCurrentProjectWorkspaces()
            self.hasHydratedProjects = true
            self.beginProjectWorkspaceObservation()
        }
        projectHydrationTask = task
        await task.value
        if !hasHydratedProjects {
            projectHydrationTask = nil
        }
    }

    @discardableResult
    func switchToProject(id: UUID) -> Bool {
        guard projectStore.isMutable else {
            lastProjectOperationError = .storeNotReady
            return false
        }
        guard id != projectStore.activeProjectID else {
            lastProjectOperationError = nil
            return true
        }
        guard projectStore.projects.contains(where: { $0.id == id }) else {
            lastProjectOperationError = .projectNotFound
            return false
        }
        guard flushProjectWorkspaceSnapshot() else {
            return false
        }
        do {
            try projectStore.selectProject(id: id)
            activateCurrentProjectWorkspaces()
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

    @discardableResult
    func createProject(named name: String) -> Project? {
        guard flushProjectWorkspaceSnapshot() else {
            return nil
        }
        do {
            let project = try projectStore.createProject(name: name)
            activateCurrentProjectWorkspaces()
            lastProjectOperationError = nil
            return project
        } catch let error as ProjectMutationError {
            lastProjectOperationError = error
            return nil
        } catch {
            projectTransferErrorMessage = error.localizedDescription
            return nil
        }
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

    @discardableResult
    func deleteProject(id: UUID) -> Bool {
        guard flushProjectWorkspaceSnapshot() else {
            return false
        }
        let deletingActive = id == projectStore.activeProjectID
        do {
            try projectStore.deleteProject(id: id)
            if deletingActive {
                activateCurrentProjectWorkspaces()
            }
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
        projectWorkspaceAutosaveTask?.cancel()
        projectWorkspaceAutosaveTask = nil
        _ = flushProjectWorkspaceSnapshot()
        await projectStore.waitForPendingPersistence()
    }

    func retryProjectCatalogLoad() async {
        await projectStore.retryLoad()
        guard projectStore.loadState == .ready else {
            return
        }
        activateCurrentProjectWorkspaces()
        hasHydratedProjects = true
        isProjectRecoveryPresented = false
        beginProjectWorkspaceObservation()
    }

    func resetProjectCatalog() async {
        await projectStore.resetToDefaultCatalog()
        guard projectStore.loadState == .ready else {
            return
        }
        activateCurrentProjectWorkspaces()
        hasHydratedProjects = true
        isProjectRecoveryPresented = false
        beginProjectWorkspaceObservation()
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
            } else {
                nil
            }
        }
    }

    // MARK: Private helpers

    func activateCurrentProjectWorkspaces() {
        let project = projectStore.activeProject
        isApplyingProjectSnapshot = true
        workspaces.applyProjectWorkspaces(
            project.workspaces,
            activeWorkspaceID: project.activeWorkspaceID,
            maxFilterRules: policy.maxSessionFilterRules
        )
        isApplyingProjectSnapshot = false

        // Raw/evidence work is selection-scoped. Hydrated workspaces deliberately
        // have no capture selection, so retire any presentation from the outgoing
        // Project without touching the capture itself.
        cancelFollowStream(clearResult: true)
        evidenceNavigationDidChangeSelection()
    }

    private func beginProjectWorkspaceObservation() {
        guard hasHydratedProjects, !isObservingProjectWorkspaces else {
            return
        }
        isObservingProjectWorkspaces = true
        armProjectWorkspaceObservation()
    }

    private func armProjectWorkspaceObservation() {
        let target = ProjectWorkspaceObservationTarget(self)
        withObservationTracking {
            _ = workspaces.activeWorkspaceID
            _ = workspaces.captureProjectWorkspaces()
        } onChange: {
            Task { @MainActor in
                guard let coordinator = target.coordinator,
                      coordinator.isObservingProjectWorkspaces else
                {
                    return
                }
                coordinator.armProjectWorkspaceObservation()
                guard !coordinator.isApplyingProjectSnapshot else {
                    return
                }
                coordinator.scheduleProjectWorkspaceAutosave()
            }
        }
    }

    private func scheduleProjectWorkspaceAutosave() {
        projectWorkspaceAutosaveTask?.cancel()
        projectWorkspaceAutosaveTask = Task { @MainActor [weak self] in
            do {
                try await Task.sleep(for: .milliseconds(500))
            } catch {
                return
            }
            guard let self, !Task.isCancelled else {
                return
            }
            _ = self.flushProjectWorkspaceSnapshot()
            self.projectWorkspaceAutosaveTask = nil
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
