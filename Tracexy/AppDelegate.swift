import AppKit

/// Holds termination open long enough for the active Project workspace snapshot
/// and any pending catalog write to reach durable storage.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    // MARK: Internal

    weak var coordinator: MainContentCoordinator?

    /// Whether quitting now needs the user's confirmation: a live capture is
    /// running and the General setting asks for one. Sessions held only in memory
    /// do not survive quitting, so an accidental ⌘Q would silently discard them.
    nonisolated static func shouldConfirmQuit(isCapturing: Bool, defaults: UserDefaults) -> Bool {
        guard isCapturing else {
            return false
        }
        // The setting defaults to on; only an explicit false turns it off.
        return defaults.object(forKey: SettingsKeys.confirmQuitWhileCapturing) as? Bool ?? true
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let coordinator else {
            return .terminateNow
        }
        guard !isFlushingProjectState else {
            return .terminateLater
        }
        if Self.shouldConfirmQuit(isCapturing: coordinator.isCapturing, defaults: applicationDefaults) {
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = String(localized: "Quit while capturing?")
            alert.informativeText = String(
                localized: """
                A live capture is still running. Quitting stops it and discards the sessions that have not \
                been saved. Stop the capture and use Save Capture first if you need them.
                """
            )
            alert.addButton(withTitle: String(localized: "Quit"))
            alert.addButton(withTitle: String(localized: "Cancel"))
            guard alert.runModal() == .alertFirstButtonReturn else {
                return .terminateCancel
            }
        }

        isFlushingProjectState = true
        Task {
            await coordinator.flushProjectStateForTermination()
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }

    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        true
    }

    /// No Tracexy scene takes part in AppKit state restoration any more, so a
    /// launch always ends with the workspace window open. Saved state written by
    /// an older version (or a window restored for any other reason) can still
    /// leave SwiftUI believing the launch was a restoration and opening nothing —
    /// a running app with no window. One deferred check reopens the workspace
    /// through the same path a Dock click uses.
    func applicationDidFinishLaunching(_ notification: Notification) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            Self.ensureWorkspaceWindow()
        }
    }

    /// Finder "Open With", a Dock-icon drop, or `open -a`: the capture goes
    /// through the same Library import as ⌘O. When the app was launched by the
    /// file itself the coordinator may not be attached yet, so the request is
    /// held here and forwarded as soon as the main scene attaches it.
    func application(_ application: NSApplication, open urls: [URL]) {
        guard let coordinator else {
            pendingOpenURLs = urls
            return
        }
        coordinator.importExternalCaptures(urls)
    }

    /// Attach the app-level coordinator and forward any file-open request that
    /// arrived before it existed. `applicationDefaults` is the app-wide settings
    /// store (the demo launch composes an isolated one), read only at quit.
    /// The user may have replaced or moved the open capture while another app was
    /// frontmost; re-check on activation so Reload / Locate appear promptly.
    func applicationDidBecomeActive(_ notification: Notification) {
        coordinator?.noteActiveSavedCaptureAvailability()
        coordinator?.refreshRecentCaptures()
    }

    func attach(_ coordinator: MainContentCoordinator, applicationDefaults: UserDefaults = .standard) {
        self.coordinator = coordinator
        self.applicationDefaults = applicationDefaults
        SettingsKeys.removeRetiredKeys(from: applicationDefaults)
        coordinator.refreshRecentCaptures()
        let urls = pendingOpenURLs
        pendingOpenURLs = []
        if !urls.isEmpty {
            coordinator.importExternalCaptures(urls)
        }
    }

    // MARK: Private

    private var isFlushingProjectState = false
    private var pendingOpenURLs: [URL] = []
    private var applicationDefaults: UserDefaults = .standard

    private static func ensureWorkspaceWindow() {
        let hasWorkspaceWindow = NSApp.windows.contains { window in
            window.isVisible && window.canBecomeMain && !(window is NSPanel)
        }
        guard !hasWorkspaceWindow else {
            return
        }
        // The reopen Apple event is exactly what a Dock click sends; SwiftUI
        // answers it by opening the main window group when nothing is visible.
        let event = NSAppleEventDescriptor(
            eventClass: AEEventClass(kCoreEventClass),
            eventID: AEEventID(kAEReopenApplication),
            targetDescriptor: NSAppleEventDescriptor.currentProcess(),
            returnID: AEReturnID(kAutoGenerateReturnID),
            transactionID: AETransactionID(kAnyTransactionID)
        )
        _ = try? event.sendEvent(options: [.noReply], timeout: 1)
    }
}
