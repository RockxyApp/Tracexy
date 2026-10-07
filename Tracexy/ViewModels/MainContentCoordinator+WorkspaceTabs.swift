import Foundation

// MARK: - Workspace tabs

/// The active Project's workspace tabs: each keeps its own view of the same
/// traffic (sidebar selection, filters, grouping, panels). Opening, closing and
/// renaming a tab is saved to the Project at once, so a relaunch finds the tabs as
/// they were left.
@MainActor
extension MainContentCoordinator {
    /// Whether tab commands apply now: not while Projects load or change.
    var canEditWorkspaceTabs: Bool {
        hasHydratedProjects && !projectTransitionStatus.isPending
    }

    var canCloseActiveWorkspaceTab: Bool {
        canEditWorkspaceTabs && activeWorkspace.isClosable
    }

    var canShowAdjacentWorkspaceTab: Bool {
        canEditWorkspaceTabs && workspaces.workspaces.count > 1
    }

    /// Opens a new tab and makes it active, or says why not.
    func newWorkspaceTab() {
        guard canEditWorkspaceTabs else {
            return
        }
        do {
            let tab = try workspaces.addWorkspace(title: nextWorkspaceTabTitle())
            policyNotice = nil
            if !flushProjectWorkspaceSnapshot(), lastProjectOperationError == .catalogStorageFull {
                // The Project has no room to keep it, so it is not left open unsaved.
                workspaces.closeWorkspace(tab.id)
                policyNotice = ProjectMutationError.catalogStorageFull.userFacingDescription
            }
        } catch {
            policyNotice = error.localizedDescription
        }
    }

    func selectWorkspaceTab(_ id: WorkspaceState.ID) {
        guard canEditWorkspaceTabs, workspaces.activeWorkspaceID != id,
              workspaces.workspaces.contains(where: { $0.id == id }) else
        {
            return
        }
        workspaces.activeWorkspaceID = id
        flushProjectWorkspaceSnapshot()
    }

    func showAdjacentWorkspaceTab(_ offset: Int) {
        guard canShowAdjacentWorkspaceTab else {
            return
        }
        workspaces.selectAdjacentWorkspace(offset: offset)
        flushProjectWorkspaceSnapshot()
    }

    func closeWorkspaceTab(_ id: WorkspaceState.ID) {
        guard canEditWorkspaceTabs, workspaces.workspaces.first(where: { $0.id == id })?.isClosable == true else {
            return
        }
        workspaces.closeWorkspace(id)
        flushProjectWorkspaceSnapshot()
    }

    /// What to tell the user before closing every other tab when the Project holds
    /// more tabs than can be added now: the tabs closed could not all be added
    /// back. `nil` when the Project is within its limit, so nothing is lost.
    func closeOtherWorkspaceTabsWarning(keeping id: WorkspaceState.ID) -> String? {
        let count = workspaces.workspaces.count
        let limit = workspaces.maxWorkspaces
        guard canEditWorkspaceTabs, count > limit else {
            return nil
        }
        return String(
            localized: "This Project has \(count) tabs. New tabs can be added up to \(limit) per Project, so the tabs closed now cannot all be added back."
        )
    }

    func closeOtherWorkspaceTabs(keeping id: WorkspaceState.ID) {
        guard canEditWorkspaceTabs else {
            return
        }
        workspaces.closeOtherWorkspaces(keeping: id)
        flushProjectWorkspaceSnapshot()
    }

    /// Drag-reordering from the tab strip; see ``WorkspaceStore/moveWorkspace(_:toInsertionIndex:)``.
    func moveWorkspaceTab(_ id: WorkspaceState.ID, toInsertionIndex insertionIndex: Int) {
        guard canEditWorkspaceTabs, workspaces.moveWorkspace(id, toInsertionIndex: insertionIndex) else {
            return
        }
        flushProjectWorkspaceSnapshot()
    }

    @discardableResult
    func renameWorkspaceTab(_ id: WorkspaceState.ID, to title: String) -> Bool {
        guard canEditWorkspaceTabs, workspaces.renameWorkspace(id, to: title) else {
            return false
        }
        flushProjectWorkspaceSnapshot()
        return true
    }

    /// "Workspace N", with N one past the highest number already used that way,
    /// so closing a middle tab never produces two tabs with the same name.
    private func nextWorkspaceTabTitle() -> String {
        let prefix = String(localized: "Workspace")
        let used = workspaces.workspaces.compactMap { workspace -> Int? in
            guard workspace.title.hasPrefix(prefix + " ") else {
                return nil
            }
            return Int(workspace.title.dropFirst(prefix.count + 1))
        }
        let next = max(workspaces.workspaces.count, used.max() ?? 0) + 1
        return "\(prefix) \(next)"
    }
}
