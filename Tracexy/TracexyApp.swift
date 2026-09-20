import AppKit
import SwiftUI

// MARK: - TracexyApp

@main
struct TracexyApp: App {
    // MARK: Internal

    static let focusSetEditorWindowID = "focus-set-editor"
    static let noiseControlWindowID = "noise-control"
    static let sessionInspectorWindowID = "session-inspector"

    var body: some Scene {
        mainWindowScene

        // Focus / Noise managers open as real Mac windows (not sheets), sharing the
        // one app-level coordinator so edits flow straight back to the main window.
        // The auxiliary editors are remounted on the Project identity, so a draft
        // left open across a Project change cannot be saved into the new Project.
        focusSetEditorScene
        noiseControlScene

        SessionInspectorWindowScene(
            coordinator: coordinator,
            colorScheme: colorScheme
        )

        settingsScene
    }

    // MARK: Private

    /// Demo settings never share the production defaults domain. If Foundation
    /// cannot create the dedicated suite, demo composition fails closed instead
    /// of silently writing through `.standard`.
    private static let isHistoryDemoMode = HistoryDemoLaunchMode.isEnabled()
    private static let historyDemoDefaults: UserDefaults? = isHistoryDemoMode
        ? HistoryDemoLaunchMode.freshSettingsDefaults()
        : nil

    private static var applicationDefaults: UserDefaults {
        guard isHistoryDemoMode else {
            return TracexyIdentity.applicationDefaults
        }
        guard let historyDemoDefaults else {
            preconditionFailure("Synthetic History requires an isolated settings store.")
        }
        return historyDemoDefaults
    }

    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    /// The single shared coordinator, owned by the app so every scene (main
    /// window + editor/manager windows) reads and mutates the same state.
    ///
    /// This is the composition root: the app's capacity limits are resolved
    /// once, here, and handed down. No type below this line asks what build it
    /// is running in.
    @State private var coordinator = TracexyApp.composeCoordinator()
    @StateObject private var updater = AppUpdater.shared

    /// The user's General → Appearance preference, applied app-wide. `nil` follows
    /// the system.
    /// Appearance is an application preference, so it names the shared domain
    /// explicitly and is unaffected by the per-Project settings suites.
    @AppStorage(SettingsKeys.appearance, store: TracexyApp.applicationDefaults)
    private var appearance = AppAppearance.system.rawValue

    /// The Focus Set editor is a transient editing window: like the auxiliary
    /// inspector it is excluded from state restoration so it cannot reopen empty
    /// after a relaunch.
    private var focusSetEditorScene: some Scene {
        let base = Window("Edit Focus Set", id: Self.focusSetEditorWindowID) {
            FocusSetEditorWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 600, height: 420)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Noise Control is a transient manager window on the same terms.
    private var noiseControlScene: some Scene {
        let base = Window("Noise Control", id: Self.noiseControlWindowID) {
            NoiseControlWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 460, height: 560)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Settings is reopened on demand (⌘,). No window in this app is restored by
    /// AppKit state restoration: with the main group excluded, a restored
    /// auxiliary window would otherwise be the *only* window after a force-quit
    /// relaunch, and SwiftUI would not open the main workspace beside it.
    private var settingsScene: some Scene {
        let base = Window("Settings", id: "settings") {
            SettingsView(
                updater: updater,
                applicationDefaults: Self.applicationDefaults,
                activeProjectName: coordinator.projectStore.activeProject.name,
                isProjectReady: coordinator.hasHydratedProjects,
                historyRetentionError: coordinator.historyRetentionError,
                isHistoryDemoMode: coordinator.isHistoryDemoMode,
                mcpScope: coordinator.mcpGrantScope,
                assistant: coordinator.assistant,
                mcpAccess: coordinator.mcpAccess,
                onAutoClearChange: { coordinator.configureHistoryAutoClear($0) }
            )
            // Capture, Privacy and default-view preferences belong to the active
            // Project's own suite. Remounting on the Project identity is what stops
            // an editor left open across a switch from applying one Project's draft
            // to another; the panes that must stay app-wide (appearance, updater,
            // helper, selected tab) name `.standard` explicitly.
            .defaultAppStorage(coordinator.activeProjectDefaults)
            .id(coordinator.projectStore.activeProjectID)
            .disabled(coordinator.projectTransitionStatus.isPending)
            .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 900, height: 640)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unified(showsTitle: true))
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// The one main workspace window. Its frame persists through the ordinary
    /// window-frame autosave; AppKit *state* restoration is disabled because after
    /// a force-quit or crash the restored window comes back beside the fresh one
    /// SwiftUI opens for the group, leaving two identical main windows.
    private var mainWindowScene: some Scene {
        let base = WindowGroup {
            RootView(coordinator: coordinator)
                .frame(minWidth: 1_000, minHeight: 640)
                .preferredColorScheme(colorScheme)
                .onChange(of: appearance, initial: true) { _, newValue in
                    // Force the preference app-wide at the AppKit level (menus,
                    // panels, alerts, any future AppKit window) — not just SwiftUI
                    // scene content. `initial: true` applies the saved preference
                    // once at launch.
                    AppThemeApplier.apply(AppAppearance(rawValue: newValue) ?? .system)
                }
                .task {
                    appDelegate.attach(coordinator, applicationDefaults: Self.applicationDefaults)
                    updater.startIfConfigured()
                    if AssistantDemoLaunchMode.prefersNarrowWindow() {
                        await Task.yield()
                        NSApplication.shared.keyWindow?.setContentSize(NSSize(width: 1_000, height: 640))
                    }
                }
        }
        .defaultSize(
            width: AssistantDemoLaunchMode.prefersNarrowWindow() ? 1_000 : 1_320,
            height: AssistantDemoLaunchMode.prefersNarrowWindow() ? 640 : 840
        )
        .windowStyle(.hiddenTitleBar)
        .windowToolbarStyle(.unified)
        // A capture opened from Finder is handled by the app delegate as an
        // import into the existing window; without this, SwiftUI also opens a
        // second, empty main window for the same external event.
        .handlesExternalEvents(matching: [])
        .commands {
            TracexySettingsCommands()
            TracexyProjectCommands(coordinator: coordinator)

            // File ▸ Import Capture… (⌘O). It routes through the same coordinator
            // panel action as the sidebar's Import buttons, so the menu, its
            // shortcut and the sidebar cannot drift apart in what they accept or
            // which Project they file a capture into.
            CommandGroup(after: .newItem) {
                Button("Import Capture…") {
                    coordinator.presentCaptureImportPanel()
                }
                .keyboardShortcut("o", modifiers: .command)
            }

            // View ▸ Show/Hide Sidebar (⌃⌘S). Routes through the NSSplitViewController
            // responder chain, so the native collapse KVO resynchronizes RootView's
            // `isSidebarPresented` with the native toolbar toggle.
            SidebarCommands()

            // Edit ▸ Find (⌘F). Reuses the standard Find placement so the shortcut
            // reads as native, then routes to the Sessions search box the app
            // already has — no `.searchable`, no new surface. Repeated presses
            // re-focus the field via the workspace's focus token.
            CommandGroup(after: .textEditing) {
                Button("Find") {
                    coordinator.beginSessionSearch()
                }
                .keyboardShortcut("f", modifiers: .command)
            }

            // View ▸ Back to Previous Scope (⌘[). The same single route the shared
            // scope notice offers, so the menu and the notice can never disagree
            // about what going back means.
            //
            // Disabled when the current source has no valid return point.
            CommandGroup(after: .sidebar) {
                Button(SessionScopeReturnAction.title) {
                    coordinator.returnToPreviousSessionScope()
                }
                .keyboardShortcut("[", modifiers: .command)
                .disabled(!coordinator.canReturnToPreviousSessionScope)
                Divider()
            }

            CommandGroup(after: .appInfo) {
                Button("Check for Updates…") {
                    updater.checkForUpdates()
                }
                .disabled(!updater.canInitiateUpdateCheck)
            }

            // Grouping belongs in the View menu, not on a tab strip over the
            // table. It is a way of looking at the list, not a place to go — and
            // an always-visible control for a rarely-changed setting is chrome
            // competing with the data it describes.
            CommandGroup(after: .toolbar) {
                Picker("Session Grouping", selection: Binding(
                    get: { coordinator.activeWorkspace.sessionGrouping },
                    set: { coordinator.activeWorkspace.sessionGrouping = $0 }
                )) {
                    Text("Group Into Actions").tag(SessionGrouping.action)
                    Text("Show Every Session").tag(SessionGrouping.none)
                }
                .pickerStyle(.inline)
                Divider()
            }
        }

        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    private var colorScheme: ColorScheme? {
        AppAppearance(rawValue: appearance)?.colorScheme
    }

    /// Resolve the terminal-history store for production. A directory/open/migration
    /// failure is isolated here: the app and capture engine start regardless, and
    /// History simply reports itself unavailable.
    /// Resolve per-Project storage for production. History, the managed capture
    /// Library and the preferences suite are now resolved *per Project* by the
    /// provider at hydration, so a directory/open/migration failure stays isolated
    /// to the Project it belongs to: the app and capture engine start regardless,
    /// and that Project's History simply reports itself unavailable.
    private static func composeCoordinator() -> MainContentCoordinator {
        if isHistoryDemoMode {
            let demoDefaults = applicationDefaults
            let demoRoot = FileManager.default.temporaryDirectory
                .appendingPathComponent("Tracexy-HistoryDemo-\(UUID().uuidString)", isDirectory: true)
            let provider = DefaultProjectDataProvider(
                applicationSupportRoot: demoRoot.appendingPathComponent("Support", isDirectory: true),
                cacheRoot: demoRoot.appendingPathComponent("Cache", isDirectory: true),
                settingsSuitePrefix: "\(HistoryDemoLaunchMode.settingsSuiteName()).project",
                legacySettingsSource: nil
            )
            do {
                // The demo never shares the production defaults domain, and its
                // Project suites are namespaced under the demo suite as well.
                return try MainContentCoordinator(
                    policy: AppPolicyProvider.current,
                    sessionStore: SessionStore(),
                    projectDataProvider: provider,
                    isHistoryDemoMode: true,
                    settingsDefaults: demoDefaults
                )
            } catch {
                let coordinator = MainContentCoordinator(
                    policy: AppPolicyProvider.current,
                    projectDataProvider: provider,
                    isHistoryDemoMode: true,
                    settingsDefaults: demoDefaults
                )
                coordinator.historyError = "Synthetic History couldn’t start — \(error.localizedDescription)"
                return coordinator
            }
        }

        return MainContentCoordinator(
            policy: AppPolicyProvider.current,
            projectRepository: JSONProjectCatalogRepository(
                directoryURL: TracexyIdentity.current.appSupportPath("Projects", fileManager: .default)
            ),
            projectDataProvider: DefaultProjectDataProvider(),
            settingsDefaults: applicationDefaults
        )
    }
}

// MARK: - TracexyProjectCommands

private struct TracexyProjectCommands: Commands {
    let coordinator: MainContentCoordinator

    var body: some Commands {
        CommandMenu("Project") {
            Button("New Project…") {
                coordinator.presentNewProjectEditor()
            }
            .keyboardShortcut("n", modifiers: [.command, .shift])
            .disabled(!coordinator.projectStore.canCreateProject)

            Button("Rename Project…") {
                coordinator.presentRenameProjectEditor(id: coordinator.projectStore.activeProjectID)
            }
            .disabled(!coordinator.projectStore.isMutable)

            Button("Manage Projects…") {
                coordinator.isProjectManagerPresented = true
            }

            Divider()

            Button("Export Project Configuration…") {
                coordinator.exportProjectConfiguration(coordinator.projectStore.activeProject)
            }
            .disabled(!coordinator.projectStore.isMutable)

            Button("Import Project Configuration…") {
                coordinator.importProjectConfiguration()
            }
            .disabled(!coordinator.projectStore.canCreateProject)

            Divider()

            ForEach(coordinator.projectStore.projects) { project in
                Button {
                    coordinator.switchToProject(id: project.id)
                } label: {
                    if project.id == coordinator.projectStore.activeProjectID {
                        Label(project.name, systemImage: "checkmark")
                    } else {
                        Text(project.name)
                    }
                }
                .disabled(!coordinator.projectStore.isMutable)
            }

            if case .failed = coordinator.projectStore.loadState {
                Divider()
                Button("Repair Projects…") {
                    coordinator.isProjectRecoveryPresented = true
                }
            }
        }
    }
}

// MARK: - SessionInspectorWindowScene

/// An opt-in auxiliary inspector that follows the main window's current
/// selection. It mirrors macOS inspector semantics: choosing another session
/// updates the panel, while the primary workspace and bottom split stay intact.
private struct SessionInspectorWindowScene: Scene {
    let coordinator: MainContentCoordinator
    let colorScheme: ColorScheme?

    var body: some Scene {
        let base = Window("Session Inspector", id: TracexyApp.sessionInspectorWindowID) {
            InspectorView(coordinator: coordinator, allowsDetaching: false)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(coordinator.projectTransitionStatus.isPending)
                .frame(minWidth: 640, minHeight: 400)
                .preferredColorScheme(colorScheme)
        }
        .commandsRemoved()
        .defaultSize(width: 1_040, height: 680)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)

        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }
}

// MARK: - TracexySettingsCommands

private struct TracexySettingsCommands: Commands {
    // MARK: Internal

    var body: some Commands {
        CommandGroup(replacing: .appSettings) {
            Button("Settings…") {
                openWindow(id: "settings")
            }
            .keyboardShortcut(",", modifiers: .command)
        }
    }

    // MARK: Private

    @Environment(\.openWindow) private var openWindow
}
