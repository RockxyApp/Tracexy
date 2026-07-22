import Foundation
import Observation

@Observable
final class WorkspaceStore {
    // MARK: Lifecycle

    /// `maxWorkspaces` arrives as a plain number: the store enforces a cap, it
    /// does not decide one. The composition root resolves it from the app
    /// policy and hands the value in.
    init(maxWorkspaces: Int, layoutPreferences: WorkspaceLayoutPreferences? = nil) {
        self.maxWorkspaces = maxWorkspaces
        let preferences = layoutPreferences ?? WorkspaceLayoutPreferences()
        self.layoutPreferences = preferences
        // Honor the General → "Default view" preference for the first workspace.
        let stored = UserDefaults.standard.string(forKey: SettingsKeys.defaultView)
        let landing = stored.flatMap(DefaultView.init(rawValue:))?.sidebarItem ?? .sessions
        // Both panels start closed, whatever the remembered preference is.
        //
        // They are detail *about a selection*, and at launch there is no
        // selection — so restoring them put a pane reading "No Session Selected"
        // over half the window before the user had done anything. The app should
        // open on its subject: the traffic arriving right now, full width.
        //
        // The preference is not discarded, only deferred: it decides what
        // happens the moment a selection exists, in `revealPanelsForSelection`.
        let initial = WorkspaceState(
            title: "Live",
            isClosable: false,
            sidebarSelection: landing,
            inspectorLayout: .hidden,
            isContextDockVisible: false
        )
        initial.allowsAutomaticInspectorReveal = preferences.allowsAutomaticInspectorReveal
        self.workspaces = [initial]
        self.activeWorkspaceID = initial.id
    }

    // MARK: Internal

    private(set) var workspaces: [WorkspaceState]
    var activeWorkspaceID: WorkspaceState.ID

    /// Maximum tabs this store will hold open, injected at construction.
    let maxWorkspaces: Int

    var activeWorkspace: WorkspaceState {
        workspaces.first { $0.id == activeWorkspaceID } ?? workspaces[0]
    }

    var canAddWorkspace: Bool {
        workspaces.count < maxWorkspaces
    }

    /// Throws ``AppPolicyViolation/workspaceTabLimitReached(limit:)`` at the cap
    /// rather than returning nothing: a "New Tab" that quietly does nothing is
    /// a bug from where the user sits, so the caller gets something to say.
    @discardableResult
    func addWorkspace(title: String? = nil) throws -> WorkspaceState {
        guard canAddWorkspace else {
            throw AppPolicyViolation.workspaceTabLimitReached(limit: maxWorkspaces)
        }
        // Same reasoning as the first workspace: a new tab has no selection yet,
        // so it opens on the list rather than on two panes describing nothing.
        let ws = WorkspaceState(
            title: title ?? "Workspace \(workspaces.count + 1)",
            inspectorLayout: .hidden,
            isContextDockVisible: false
        )
        ws.allowsAutomaticInspectorReveal = layoutPreferences.allowsAutomaticInspectorReveal
        workspaces.append(ws)
        activeWorkspaceID = ws.id
        return ws
    }

    func closeWorkspace(_ id: WorkspaceState.ID) {
        guard let index = workspaces.firstIndex(where: { $0.id == id }),
              workspaces[index].isClosable else
        {
            return
        }
        workspaces.remove(at: index)
        if activeWorkspaceID == id {
            activeWorkspaceID = workspaces[max(0, index - 1)].id
        }
    }

    // MARK: Private

    /// Seeds new workspaces from the remembered inspector-dock choice.
    private let layoutPreferences: WorkspaceLayoutPreferences
}
