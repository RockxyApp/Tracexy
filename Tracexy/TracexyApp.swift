import AppKit
import SwiftUI

// MARK: - TracexyApp

/// Started from `main.swift`, which first gives the built-in command line a chance
/// to handle the invocation.
struct TracexyApp: App {
    // MARK: Internal

    static let focusSetEditorWindowID = "focus-set-editor"
    static let noiseControlWindowID = "noise-control"
    static let sessionInspectorWindowID = "session-inspector"
    static let captureInfoWindowID = "capture-info"
    static let keyboardShortcutsWindowID = "keyboard-shortcuts"
    static let resolvedAddressesWindowID = "resolved-addresses"
    static let protocolHierarchyWindowID = "protocol-hierarchy"
    static let dnsLookupsWindowID = "dns-lookups"
    static let messageCountsWindowID = "message-counts"
    static let findingsWindowID = "findings"
    static let conversationsWindowID = "conversations"
    static let endpointsWindowID = "endpoints"
    static let packetLengthsWindowID = "packet-lengths"
    static let packetBytesWindowID = "packet-bytes"
    static let allFramesWindowID = "all-frames"
    static let flowGraphWindowID = "flow-graph"
    static let httpStatisticsWindowID = "http-statistics"
    static let firewallRulesWindowID = "firewall-rules"
    static let manageInterfacesWindowID = "manage-interfaces"
    static let exportObjectsWindowID = "export-objects"
    static let dnsStatisticsWindowID = "dns-statistics"
    static let rtpStreamsWindowID = "rtp-streams"
    static let multicastStreamsWindowID = "multicast-streams"
    static let valueDistributionWindowID = "value-distribution"
    static let fieldPlotWindowID = "field-plot"
    static let ioGraphWindowID = "io-graph"
    static let fileStructureWindowID = "file-structure"
    static let supportedProtocolsWindowID = "supported-protocols"
    static let ipStatisticsWindowID = "ip-statistics"
    static let sipStatisticsWindowID = "sip-statistics"
    static let serviceResponseTimeWindowID = "service-response-time"
    static let voipCallsWindowID = "voip-calls"
    static let decodeAsWindowID = "decode-as"

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

        // File ▸ Get Info (⌘I). A regular auxiliary window, not a panel: it keeps
        // the facts of the capture it was opened for (HIG Panels), re-binds only
        // when a different capture is adopted, and closes with the Project.
        CaptureInfoWindowScene(coordinator: coordinator, colorScheme: colorScheme)

        settingsScene

        keyboardShortcutsScene

        resolvedAddressesScene

        dnsLookupsScene

        messageCountsScene

        packetBytesScene

        allFramesScene

        firewallRulesScene

        manageInterfacesScene

        exportObjectsScene

        fileStructureScene

        supportedProtocolsScene

        // Statistics ▸ …: the capture-wide statistics windows, each remounted on
        // the Project identity like every auxiliary window.
        StatisticsWindowScenes(coordinator: coordinator, colorScheme: colorScheme)

        decodeAsScene
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
    /// The active Project's GeoIP/ASN databases and the locations they give.
    @State private var geoIP = GeoIPController()

    /// The user's General → Appearance preference, applied app-wide. `nil` follows
    /// the system.
    /// Appearance is an application preference, so it names the shared domain
    /// explicitly and is unaffected by the per-Project settings suites.
    @AppStorage(SettingsKeys.appearance, store: TracexyApp.applicationDefaults)
    private var appearance = AppAppearance.system.rawValue

    /// Help ▸ Keyboard Shortcuts: a reference window, never restored.
    private var keyboardShortcutsScene: some Scene {
        let base = Window("Keyboard Shortcuts", id: Self.keyboardShortcutsWindowID) {
            KeyboardShortcutsView()
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 420, height: 520)
        .windowResizability(.contentMinSize)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Statistics ▸ Resolved Addresses: a transient reference window on the same terms as
    /// Noise Control, remounted with the Project.
    private var resolvedAddressesScene: some Scene {
        let base = Window("Resolved Addresses", id: Self.resolvedAddressesWindowID) {
            ResolvedAddressesWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 660, height: 480)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Statistics ▸ DNS Lookups, on the same terms as Resolved Addresses.
    private var dnsLookupsScene: some Scene {
        let base = Window("DNS Lookups", id: Self.dnsLookupsWindowID) {
            DNSLookupsWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 720, height: 440)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Statistics ▸ Message Counts, on the same terms as Resolved Addresses.
    private var messageCountsScene: some Scene {
        let base = Window("Message Counts", id: Self.messageCountsWindowID) {
            MessageCountsWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 460, height: 440)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Show Packet Bytes, opened from the Layers facet or an HTTP exchange.
    private var packetBytesScene: some Scene {
        let base = Window("Show Packet Bytes", id: Self.packetBytesWindowID) {
            PacketBytesWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 760, height: 560)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// View ▸ All Frames: the whole capture's frame list.
    private var allFramesScene: some Scene {
        let base = Window("All Frames", id: Self.allFramesWindowID) {
            AllFramesWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 1_000, height: 600)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Help ▸ Supported Protocols, what Tracexy recognizes and how to find it.
    private var supportedProtocolsScene: some Scene {
        let base = Window("Supported Protocols", id: Self.supportedProtocolsWindowID) {
            SupportedProtocolsWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 900, height: 560)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// File ▸ Show File Structure, the capture file's own blocks.
    private var fileStructureScene: some Scene {
        let base = Window("File Structure", id: Self.fileStructureWindowID) {
            FileStructureWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 860, height: 480)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// File ▸ Export Objects, on the same terms as All Frames.
    private var exportObjectsScene: some Scene {
        let base = Window("Export Objects", id: Self.exportObjectsWindowID) {
            ExportObjectsWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 820, height: 480)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Tools ▸ Firewall Rules, for the session selected in the main window.
    private var firewallRulesScene: some Scene {
        let base = Window("Firewall Rules", id: Self.firewallRulesWindowID) {
            FirewallRulesWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 560, height: 380)
        .windowResizability(.contentMinSize)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Capture ▸ Manage Interfaces: app-wide, like the interfaces it lists.
    private var manageInterfacesScene: some Scene {
        let base = Window("Manage Interfaces", id: Self.manageInterfacesWindowID) {
            ManageInterfacesWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 760, height: 420)
        .windowResizability(.contentMinSize)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Capture ▸ Decode As…: the Project's port → protocol rules.
    private var decodeAsScene: some Scene {
        let base = Window("Decode As", id: Self.decodeAsWindowID) {
            DecodeAsWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 620, height: 340)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

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
        // Auxiliary windows never answer an external open event (a Finder file
        // open belongs to the workspace), so none of them appears on its own.
        .handlesExternalEvents(matching: [])
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
        // Auxiliary windows never answer an external open event (a Finder file
        // open belongs to the workspace), so none of them appears on its own.
        .handlesExternalEvents(matching: [])
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
                mcpScope: { coordinator.mcpGrantScope },
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
            // Settings can open before the workspace's launch task runs. Share
            // the same idempotent hydration so grant scope cannot stay pending.
            .task { await coordinator.hydrateProjectsOnLaunch() }
        }
        .defaultSize(width: 900, height: 640)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unified(showsTitle: true))
        .handlesExternalEvents(matching: [])
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
                .expressionLibrarySupport(coordinator: coordinator)
                .workspaceTabsSupport(coordinator: coordinator)
                .geoIPSupport(
                    coordinator: coordinator,
                    controller: geoIP,
                    applicationDefaults: Self.applicationDefaults
                )
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
            TracexySettingsCommands(coordinator: coordinator)
            TracexyProjectCommands(coordinator: coordinator)

            // File menu, in the HIG's order: Open… ⌘O (in place), Open Recent ▸,
            // Import into Library… ⌥⌘O (managed copy), Close Capture ⇧⌘W, Reload ⌘R,
            // Get Info ⌘I. Every item is always listed and disabled when it does
            // not apply, and each routes through the same coordinator action the
            // sidebar and toolbar use, so the routes cannot drift apart.
            WorkspaceTabCommands(coordinator: coordinator)
            TracexyCaptureFileCommands(coordinator: coordinator, geoIP: geoIP)

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
                // Edit ▸ Pin Session: keeps the selected session above the table
                // whatever the filter shows, as Wireshark pins a packet.
                let selectedID = coordinator.activeWorkspace.selectedSessionID
                Button(selectedID.map(coordinator.isSessionPinned) == true ? "Unpin Session" : "Pin Session") {
                    if let selectedID {
                        coordinator.togglePinSession(selectedID)
                    }
                }
                .disabled(selectedID == nil)
            }

            // View ▸ Investigate Sessions… (⌥⌘I). The Session Expression editor was
            // reachable only from the toolbar's overflow menu, which leaves a primary
            // analysis command off the keyboard and off the menu bar. This is the same
            // single route the overflow item uses — both set the workspace's own flag.
            CommandGroup(after: .sidebar) {
                Button("Investigate Sessions…") {
                    coordinator.activeWorkspace.isInvestigationEditorPresented = true
                }
                .keyboardShortcut("i", modifiers: [.command, .option])
                .disabled(coordinator.sessions.isEmpty)

                // Step between flagged sessions from anywhere in the window, in
                // capture order over what the list currently shows.
                Button("Next Session With a Finding") {
                    coordinator.selectSessionWithFinding(.next)
                }
                .keyboardShortcut(.downArrow, modifiers: [.command, .option])
                .disabled(!coordinator.hasAnyFinding)
                Button("Previous Session With a Finding") {
                    coordinator.selectSessionWithFinding(.previous)
                }
                .keyboardShortcut(.upArrow, modifiers: [.command, .option])
                .disabled(!coordinator.hasAnyFinding)
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
                Button(SessionScopeForwardAction.title) {
                    coordinator.goForwardToNextSessionScope()
                }
                .keyboardShortcut("]", modifiers: .command)
                .disabled(!coordinator.canGoForwardToNextSessionScope)
                .help(SessionScopeForwardAction.help)
                Divider()
            }

            // View ▸ Expression Library: filter buttons and macros.
            ExpressionLibraryCommands(controller: coordinator.filterLibrary)

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
        // Auxiliary windows never answer an external open event (a Finder file
        // open belongs to the workspace), so none of them appears on its own.
        .handlesExternalEvents(matching: [])

        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }
}

// MARK: - TracexyCaptureFileCommands

private struct TracexyCaptureFileCommands: Commands {
    // MARK: Internal

    let coordinator: MainContentCoordinator
    let geoIP: GeoIPController

    var body: some Commands {
        CommandGroup(after: .newItem) {
            Button("Open…") {
                coordinator.presentCaptureOpenPanel()
            }
            .keyboardShortcut("o", modifiers: .command)

            Menu("Open Recent") {
                ForEach(coordinator.recentCaptureURLs, id: \.self) { url in
                    Button {
                        coordinator.openRecentCapture(url)
                    } label: {
                        // Names only — never paths — with the file's own icon, as
                        // the HIG describes the standard Open Recent submenu.
                        Label {
                            Text(url.lastPathComponent)
                        } icon: {
                            Image(nsImage: NSWorkspace.shared.icon(forFile: url.path))
                        }
                    }
                }
                if !coordinator.recentCaptureURLs.isEmpty {
                    Divider()
                }
                Button("Clear Menu") {
                    coordinator.clearRecentCaptures()
                }
                .disabled(coordinator.recentCaptureURLs.isEmpty)
            }

            Button("Import into Library…") {
                coordinator.presentCaptureImportPanel()
            }
            .keyboardShortcut("o", modifiers: [.command, .option])

            Button("Merge Captures…") {
                coordinator.presentMergeCapturesPanel()
            }
            .disabled(!coordinator.canMergeCaptures)

            Button("Split Capture…") {
                coordinator.presentSplitCapture()
            }
            .disabled(!coordinator.canSplitCapture)

            Button("Show File Set in Finder") {
                coordinator.revealLastFileSet()
            }
            .disabled(coordinator.lastFileSet == nil)
        }

        // After the system Close items, in HIG order: Close Capture (⇧⌘W, the
        // "Close File" slot), Reload, Get Info, File Set.
        CommandGroup(after: .saveItem) {
            Button("Close Capture") {
                coordinator.closeCapture()
            }
            .keyboardShortcut("w", modifiers: [.command, .shift])
            .disabled(!coordinator.canCloseCapture)

            Button("Reload") {
                coordinator.reloadActiveSavedCapture()
            }
            .keyboardShortcut("r", modifiers: .command)
            .disabled(!coordinator.canReloadActiveSavedCapture)

            Divider()

            Button("Get Info") {
                openWindow(id: TracexyApp.captureInfoWindowID)
            }
            .keyboardShortcut("i", modifiers: .command)
            .disabled(!coordinator.canShowCaptureInfo)

            // Wireshark's Reload as File Format/Capture (⇧⌘F): the file's own blocks.
            Button("Show File Structure") {
                openWindow(id: TracexyApp.fileStructureWindowID)
            }
            .keyboardShortcut("f", modifiers: [.command, .shift])
            .disabled(!coordinator.canShowCaptureInfo)

            // Ring-buffer sets (dumpcap/tcpdump rotation): step through the
            // members in place. Always listed; disabled when the open capture is
            // not a member or has no neighbour.
            Menu("File Set") {
                Button("Next File") {
                    coordinator.openNextInFileSet()
                }
                .disabled(!coordinator.canOpenNextInFileSet)
                Button("Previous File") {
                    coordinator.openPreviousInFileSet()
                }
                .disabled(!coordinator.canOpenPreviousInFileSet)
                if let set = coordinator.activeCaptureFileSet {
                    Divider()
                    Text("File \(set.currentIndex + 1) of \(set.count) in “\(set.prefix)”")
                }
            }
        }

        // File ▸ Export Frames… sits with the other export items (HIG: prefer a
        // format pop-up in the Save sheet; no custom shortcut for an occasional
        // command).
        CommandGroup(after: .importExport) {
            Button("Export Frames…") {
                coordinator.presentFrameExportPanel()
            }
            .disabled(!coordinator.canExportFrames)
            // The sessions in view, as a table or a report — what the list shows now,
            // including its filters, findings and notes.
            Menu("Export Investigation") {
                ForEach(InvestigationExportKind.allCases) { kind in
                    Button(kind.menuTitle) {
                        coordinator.exportInvestigation(kind)
                    }
                }
            }
            .disabled(!coordinator.canExportInvestigation)
            // Wireshark's File ▸ Export Objects: the files and messages the capture carried.
            Menu("Export Objects") {
                ForEach(CaptureObjectKind.allCases) { kind in
                    Button("\(kind.title)…") {
                        coordinator.loadExportObjects(kind)
                        openWindow(id: TracexyApp.exportObjectsWindowID)
                    }
                }
            }
            .disabled(coordinator.allFramesUnavailableReason != nil)
            // Wireshark's File ▸ Export PDUs to File, at the application layer.
            Button("Export PDUs…") {
                PDUExportController.shared.export(from: coordinator)
            }
            .disabled(!coordinator.canExportFrames || PDUExportController.shared.isExporting)
            // Wireshark's File ▸ Export Packet Dissections: every frame's layers as text or JSON.
            Button("Export Packet Dissections…") {
                DissectionExportController.shared.export(from: coordinator)
            }
            .disabled(!coordinator.canExportFrames || DissectionExportController.shared.isExporting)
        }

        // View ▸ Session Time: how the Sessions table shows start times.
        CommandGroup(after: .sidebar) {
            // View ▸ All Frames: Wireshark's packet list for the whole capture.
            Button("All Frames") {
                openWindow(id: TracexyApp.allFramesWindowID)
            }
            .keyboardShortcut("a", modifiers: [.command, .option])
            Picker("Session Time", selection: Binding(
                get: { coordinator.sessionTimeDisplay.format },
                set: { coordinator.sessionTimeDisplay.format = $0 }
            )) {
                ForEach(SessionTimeFormat.allCases) { format in
                    Text(format.menuTitle).tag(format)
                }
            }
            // View ▸ Frame Time: Wireshark's time display formats for frame lists, and
            // its ⌘T time reference on the frame last chosen in one.
            Picker("Frame Time", selection: Binding(
                get: { coordinator.sessionTimeDisplay.frameFormat },
                set: { coordinator.sessionTimeDisplay.frameFormat = $0 }
            )) {
                ForEach(FrameTimeFormat.allCases) { format in
                    Text(format.menuTitle).tag(format)
                }
            }
            // View ▸ Validate Checksums: Wireshark's per-protocol checksum checks,
            // off by default because frames sent from this Mac are often offloaded.
            Toggle("Validate Checksums", isOn: Binding(
                get: { coordinator.packetDetailOptions.validateChecksums },
                set: { coordinator.packetDetailOptions.validateChecksums = $0 }
            ))
            // View ▸ Name Resolution: names from this Project and the capture itself only.
            Menu("Name Resolution") {
                Toggle("Resolve Network Addresses", isOn: Binding(
                    get: { coordinator.packetDetailOptions.resolvesNetworkAddresses },
                    set: { coordinator.packetDetailOptions.resolvesNetworkAddresses = $0 }
                ))
            }
            // View ▸ Show Bytes as Bits: the bytes pane's Show as, from the menu bar too.
            Toggle("Show Bytes as Bits", isOn: Binding(
                get: { coordinator.packetDetailOptions.byteDumpStyle == .bits },
                set: { coordinator.packetDetailOptions.byteDumpStyle = $0 ? .bits : .hex }
            ))
            // View ▸ Zoom: packet text (hex, decode tree, streams, frame lists), as
            // Wireshark's ⌘+ / ⌘− / ⌘0 zoom its packet panes.
            Button("Zoom In") {
                coordinator.packetDetailOptions.zoom(by: 1)
            }
            .keyboardShortcut("+", modifiers: .command)
            .disabled(!coordinator.packetDetailOptions.canZoomIn)
            Button("Zoom Out") {
                coordinator.packetDetailOptions.zoom(by: -1)
            }
            .keyboardShortcut("-", modifiers: .command)
            .disabled(!coordinator.packetDetailOptions.canZoomOut)
            Button("Actual Size") {
                coordinator.packetDetailOptions.textZoom = 0
            }
            .keyboardShortcut("0", modifiers: .command)
            .disabled(coordinator.packetDetailOptions.textZoom == 0)
            if coordinator.sessionTimeDisplay.selectedFrameIsReference {
                Button("Clear Time Reference") {
                    coordinator.sessionTimeDisplay.toggleReferenceOnSelectedFrame()
                }
                .keyboardShortcut("t", modifiers: .command)
            } else {
                Button("Set Time Reference") {
                    coordinator.sessionTimeDisplay.toggleReferenceOnSelectedFrame()
                }
                .keyboardShortcut("t", modifiers: .command)
                .disabled(coordinator.sessionTimeDisplay.selectedFrame == nil)
            }
        }

        // Statistics: the report windows over the sessions in view, as Wireshark's
        // Statistics menu. Each is a separate tool window, so they live here rather
        // than in View, which changes how the main window presents its content.
        // Capture ▸ Start/Stop (⌘E, as in Wireshark): the toolbar's primary
        // command also belongs in the menu bar and on the keyboard.
        CommandMenu("Capture") {
            Button(coordinator.isCapturing || coordinator.isStarting ? "Stop Capture" : "Start Capture") {
                coordinator.toggleCapture()
            }
            .keyboardShortcut("e", modifiers: .command)
            Button("Restart Capture") {
                coordinator.restartCapture()
            }
            // ⌘R is File ▸ Reload for saved captures.
            .keyboardShortcut("r", modifiers: [.command, .shift])
            .disabled(!coordinator.canRestartCapture)
            Button("Refresh Interfaces") {
                coordinator.refreshInterfaces()
            }
            Button("Manage Interfaces…") {
                openWindow(id: TracexyApp.manageInterfacesWindowID)
            }
            Divider()
            Button("Decode As…") {
                coordinator.decodeAs.showsEnabledProtocols = false
                openWindow(id: TracexyApp.decodeAsWindowID)
            }
            Button("Enabled Protocols…") {
                coordinator.decodeAs.showsEnabledProtocols = true
                openWindow(id: TracexyApp.decodeAsWindowID)
            }
        }

        CommandMenu("Statistics") {
            Button("Findings") {
                openWindow(id: TracexyApp.findingsWindowID)
            }
            .keyboardShortcut("e", modifiers: [.command, .option])
            Divider()
            Button("Conversations") {
                openWindow(id: TracexyApp.conversationsWindowID)
            }
            Button("Endpoints") {
                openWindow(id: TracexyApp.endpointsWindowID)
            }
            Button("Protocol Hierarchy") {
                openWindow(id: TracexyApp.protocolHierarchyWindowID)
            }
            Button("Packet Lengths") {
                openWindow(id: TracexyApp.packetLengthsWindowID)
            }
            Button("I/O Graph") {
                openWindow(id: TracexyApp.ioGraphWindowID)
            }
            Button("Flow Graph") {
                coordinator.allFrames.flowCallID = nil
                openWindow(id: TracexyApp.flowGraphWindowID)
            }
            Button("Value Distribution…") {
                openWindow(id: TracexyApp.valueDistributionWindowID)
            }
            Button("Plot…") {
                openWindow(id: TracexyApp.fieldPlotWindowID)
            }
            Divider()
            Button("HTTP") {
                openWindow(id: TracexyApp.httpStatisticsWindowID)
            }
            Button("IP Statistics") {
                openWindow(id: TracexyApp.ipStatisticsWindowID)
            }
            Button("DNS") {
                openWindow(id: TracexyApp.dnsStatisticsWindowID)
            }
            Button("RTP Streams") {
                openWindow(id: TracexyApp.rtpStreamsWindowID)
            }
            Button("Service Response Time") {
                openWindow(id: TracexyApp.serviceResponseTimeWindowID)
            }
            Button("SIP") {
                openWindow(id: TracexyApp.sipStatisticsWindowID)
            }
            Button("UDP Multicast Streams") {
                openWindow(id: TracexyApp.multicastStreamsWindowID)
            }
            Button("VoIP Calls") {
                openWindow(id: TracexyApp.voipCallsWindowID)
            }
            Button("DNS Lookups") {
                openWindow(id: TracexyApp.dnsLookupsWindowID)
            }
            Button("Message Counts") {
                openWindow(id: TracexyApp.messageCountsWindowID)
            }
            Button("Resolved Addresses") {
                openWindow(id: TracexyApp.resolvedAddressesWindowID)
            }
            GeoIPDatabasesMenuItem(controller: geoIP)
        }

        // Tools, as in Wireshark: helpers that act on the selection.
        CommandMenu("Tools") {
            Button("Firewall Rules…") {
                openWindow(id: TracexyApp.firewallRulesWindowID)
            }
        }
    }

    // MARK: Private

    @Environment(\.openWindow) private var openWindow
}

// MARK: - CaptureInfoWindowScene

private struct CaptureInfoWindowScene: Scene {
    let coordinator: MainContentCoordinator
    let colorScheme: ColorScheme?

    var body: some Scene {
        let base = Window("Capture Info", id: TracexyApp.captureInfoWindowID) {
            CaptureInfoView(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .id(coordinator.captureInfoIdentityToken)
                .disabled(coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .commandsRemoved()
        .defaultSize(width: 680, height: 620)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        // Auxiliary windows never answer an external open event (a Finder file
        // open belongs to the workspace), so none of them appears on its own.
        .handlesExternalEvents(matching: [])

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

    /// Help ▸ links, as Wireshark's Help menu offers its guide, release notes and
    /// sample captures. Public pages only; nothing is sent.
    static let userGuideURL = URL(string: "https://github.com/RockxyApp/Tracexy/blob/main/docs/usage.md")
    static let releaseNotesURL = URL(string: "https://github.com/RockxyApp/Tracexy/blob/main/CHANGELOG.md")
    static let issuesURL = URL(string: "https://github.com/RockxyApp/Tracexy/issues")
    static let sampleCapturesURL = URL(string: "https://wiki.wireshark.org/SampleCaptures")

    let coordinator: MainContentCoordinator

    var body: some Commands {
        // Replaces the system "Tracexy Help" item, which has no Help Book to open.
        CommandGroup(replacing: .help) {
            Button("Tracexy User Guide") {
                open(Self.userGuideURL)
            }
            .keyboardShortcut("?", modifiers: .command)
            Button("Release Notes") {
                open(Self.releaseNotesURL)
            }
            Button("Sample Captures") {
                open(Self.sampleCapturesURL)
            }
            Divider()
            Button("Supported Protocols") {
                openWindow(id: TracexyApp.supportedProtocolsWindowID)
            }
            Button("Keyboard Shortcuts") {
                openWindow(id: TracexyApp.keyboardShortcutsWindowID)
            }
            Button("Show Captures Folder") {
                if let folder = coordinator.capturesDirectory() {
                    NSWorkspace.shared.activateFileViewerSelecting([folder])
                }
            }
            .disabled(coordinator.capturesDirectory() == nil)
            Divider()
            Button("Report an Issue") {
                open(Self.issuesURL)
            }
        }
        CommandGroup(replacing: .appSettings) {
            Button("Settings…") {
                openWindow(id: "settings")
            }
            .keyboardShortcut(",", modifiers: .command)
        }
    }

    // MARK: Private

    @Environment(\.openWindow) private var openWindow
    @Environment(\.openURL) private var openURL

    private func open(_ url: URL?) {
        if let url {
            openURL(url)
        }
    }
}
