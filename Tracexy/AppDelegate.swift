import AppKit

/// Holds termination open long enough for the active Project workspace snapshot
/// and any pending catalog write to reach durable storage.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    // MARK: Internal

    weak var coordinator: MainContentCoordinator?

    /// Retire the preference keys that described an MCP listener, a port and an AI
    /// provider none of which were ever implemented. Leaving stale values behind
    /// would misrepresent what this build does, and nothing reads them.
    func applicationDidFinishLaunching(_: Notification) {
        SettingsKeys.removeRetiredKeys(from: TracexyIdentity.applicationDefaults)
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let coordinator else {
            return .terminateNow
        }
        guard !isFlushingProjectState else {
            return .terminateLater
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

    // MARK: Private

    private var isFlushingProjectState = false
}
