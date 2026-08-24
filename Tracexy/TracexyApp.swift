import SwiftUI

@main
struct TracexyApp: App {
    // MARK: Internal

    static let focusSetEditorWindowID = "focus-set-editor"
    static let noiseControlWindowID = "noise-control"

    var body: some Scene {
        WindowGroup {
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
                    updater.startIfConfigured()
                }
        }
        .defaultSize(width: 1_320, height: 840)
        .windowStyle(.hiddenTitleBar)
        .windowToolbarStyle(.unified)
        .commands {
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

        // Focus / Noise managers open as real Mac windows (not sheets), sharing the
        // one app-level coordinator so edits flow straight back to the main window.
        Window("Edit Focus Set", id: Self.focusSetEditorWindowID) {
            FocusSetEditorWindow(coordinator: coordinator)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 600, height: 420)
        .windowResizability(.contentMinSize)

        Window("Noise Control", id: Self.noiseControlWindowID) {
            NoiseControlWindow(coordinator: coordinator)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 460, height: 560)
        .windowResizability(.contentMinSize)

        Settings {
            SettingsView(updater: updater)
                .preferredColorScheme(colorScheme)
        }
    }

    // MARK: Private

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
    @AppStorage(SettingsKeys.appearance) private var appearance = AppAppearance.system.rawValue

    private var colorScheme: ColorScheme? {
        AppAppearance(rawValue: appearance)?.colorScheme
    }

    /// Resolve the terminal-history store for production. A directory/open/migration
    /// failure is isolated here: the app and capture engine start regardless, and
    /// History simply reports itself unavailable.
    private static func composeCoordinator() -> MainContentCoordinator {
        switch HistoryStoreFactory.production() {
        case let .ready(store):
            return MainContentCoordinator(policy: AppPolicyProvider.current, sessionStore: store)
        case let .unavailable(reason):
            let coordinator = MainContentCoordinator(policy: AppPolicyProvider.current)
            coordinator.historyError = reason
            return coordinator
        }
    }
}
