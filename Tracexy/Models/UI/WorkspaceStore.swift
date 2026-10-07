import Foundation
import Observation

@Observable
final class WorkspaceStore {
    // MARK: Lifecycle

    /// `maxWorkspaces` arrives as a plain number: the store enforces a cap, it
    /// does not decide one. The composition root resolves it from the app
    /// policy and hands the value in.
    /// `defaults` is the active Project's preferences suite, so "Default view" is
    /// resolved per Project rather than app-wide.
    init(
        maxWorkspaces: Int,
        layoutPreferences: WorkspaceLayoutPreferences? = nil,
        defaults: UserDefaults = .standard
    ) {
        self.maxWorkspaces = Self.boundedLimit(maxWorkspaces)
        let preferences = layoutPreferences ?? WorkspaceLayoutPreferences(defaults: defaults)
        self.layoutPreferences = preferences
        // Honor the General → "Default view" preference for the first workspace.
        let stored = defaults.string(forKey: SettingsKeys.defaultView)
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

    /// Maximum tabs a user may grow this store to, never above what a Project
    /// can persist. Injected at construction and re-injected through
    /// ``updateLimit(_:)``; restored tabs above it stay open.
    private(set) var maxWorkspaces: Int

    var activeWorkspace: WorkspaceState {
        workspaces.first { $0.id == activeWorkspaceID } ?? workspaces[0]
    }

    var canAddWorkspace: Bool {
        workspaces.count < maxWorkspaces
    }

    /// A tab title as it is kept: trimmed, without control characters, at most
    /// ``ProjectLimits/maximumNameLength`` characters; `nil` when nothing is left.
    static func normalizedTitle(_ title: String) -> String? {
        let cleaned = String(String.UnicodeScalarView(title.unicodeScalars.filter {
            !CharacterSet.controlCharacters.contains($0)
        }))
        let trimmed = cleaned.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }
        return String(trimmed.prefix(ProjectLimits.maximumNameLength))
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

    /// Closes every closable tab except `id`; the first tab always stays.
    func closeOtherWorkspaces(keeping id: WorkspaceState.ID) {
        guard workspaces.contains(where: { $0.id == id }) else {
            return
        }
        workspaces.removeAll { $0.id != id && $0.isClosable }
        activeWorkspaceID = id
    }

    /// Renames a tab. Returns `false` when the title is empty after trimming, so
    /// the tab keeps the name it had.
    @discardableResult
    func renameWorkspace(_ id: WorkspaceState.ID, to title: String) -> Bool {
        guard let workspace = workspaces.first(where: { $0.id == id }),
              let normalized = Self.normalizedTitle(title) else
        {
            return false
        }
        workspace.title = normalized
        return true
    }

    /// Moves a tab so it lands before the tab now at `insertionIndex` (or last
    /// when the index is past the end). Tabs that cannot be closed stay where
    /// they are and nothing is moved in front of them, so "Live" remains first.
    /// Returns `false` when the order does not change.
    @discardableResult
    func moveWorkspace(_ id: WorkspaceState.ID, toInsertionIndex insertionIndex: Int) -> Bool {
        guard let source = workspaces.firstIndex(where: { $0.id == id }),
              workspaces[source].isClosable else
        {
            return false
        }
        let pinned = workspaces.prefix { !$0.isClosable }.count
        var destination = min(max(insertionIndex, pinned), workspaces.count)
        if destination > source {
            destination -= 1
        }
        guard destination != source else {
            return false
        }
        let workspace = workspaces.remove(at: source)
        workspaces.insert(workspace, at: destination)
        return true
    }

    /// Makes the tab `offset` places after the active one active, wrapping around.
    func selectAdjacentWorkspace(offset: Int) {
        guard workspaces.count > 1,
              let index = workspaces.firstIndex(where: { $0.id == activeWorkspaceID }) else
        {
            return
        }
        let count = workspaces.count
        activeWorkspaceID = workspaces[((index + offset) % count + count) % count].id
    }

    /// Captures only the bounded, durable view intent owned by the active
    /// Project. Session selection, Investigation results, and capture evidence
    /// deliberately remain outside the Project catalog.
    func captureProjectWorkspaces() -> [ProjectWorkspaceSnapshot] {
        workspaces.map(ProjectWorkspaceSnapshot.init(capturing:))
    }

    /// Replaces the live workspace set from a validated Project snapshot. This
    /// changes presentation only: the coordinator's capture/session/History
    /// state is app-wide and is never swapped or cleared by Project navigation.
    func applyProjectWorkspaces(
        _ snapshots: [ProjectWorkspaceSnapshot],
        activeWorkspaceID desiredActiveWorkspaceID: UUID
    ) {
        let hydrated = snapshots.map {
            $0.hydrateWorkspaceState(
                allowsAutomaticInspectorReveal: layoutPreferences.allowsAutomaticInspectorReveal
            )
        }
        guard !hydrated.isEmpty else {
            return
        }
        workspaces = hydrated
        activeWorkspaceID = hydrated.contains { $0.id == desiredActiveWorkspaceID }
            ? desiredActiveWorkspaceID
            : hydrated[0].id
    }

    /// Re-inject the growth limit. Open tabs are never closed by it.
    func updateLimit(_ maxWorkspaces: Int) {
        let bounded = Self.boundedLimit(maxWorkspaces)
        if self.maxWorkspaces != bounded {
            self.maxWorkspaces = bounded
        }
    }

    // MARK: Private

    /// Seeds new workspaces from the remembered inspector-dock choice.
    private let layoutPreferences: WorkspaceLayoutPreferences

    /// A store may never hold more tabs than the Project catalog can save.
    private static func boundedLimit(_ limit: Int) -> Int {
        min(max(1, limit), ProjectLimits.maximumWorkspacesPerProject)
    }
}
