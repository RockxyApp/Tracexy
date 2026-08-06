import AppKit
import Observation

// MARK: - HelperRecoveryPresenter

/// Drives the Settings → Helper recovery flow: the normal force-reset-and-reinstall
/// and, only after that fails, the *manual* Background Items guidance — a copyable
/// Terminal command the user runs themselves, never an action Tracexy elevates.
///
/// Owns just the presentation state (working flag, last summary, whether to offer
/// the manual Background Items guidance). The privileged work and all state truth
/// live on `HelperClient`; this type never runs a privileged operation itself
/// beyond asking the client to force-reset, and it never executes the manual
/// command — it only copies it to the pasteboard.
@MainActor
@Observable
final class HelperRecoveryPresenter {
    // MARK: Lifecycle

    init() {
        helper = .shared
    }

    init(helper: HelperClient) {
        self.helper = helper
    }

    // MARK: Internal

    /// The exact command a user can run manually, in Terminal, to reset macOS
    /// Background Task Management as a global last resort.
    ///
    /// Presentation-only and deliberately confined to this presentation layer:
    /// Tracexy never executes this, feeds it to `osascript`, or spawns it via
    /// `Process` — it is only ever displayed or copied to the pasteboard. Nesting a
    /// global BTM reset inside an already-elevated `osascript` shell was the v0.1.3
    /// regression: the global reset requested `com.apple.auth.admin`, could not
    /// present a second interaction, returned NSOSStatus -60007, and exited *after*
    /// the helper had been unregistered. Keeping the string out of Core/Services
    /// guarantees no privileged executor can ever reach it.
    nonisolated static let manualBackgroundItemsResetCommand = "sudo /usr/bin/sfltool resetbtm"

    private(set) var isWorking = false
    private(set) var summary: ForceResetSummary?

    /// True only once a normal reset has run and failed to recover the helper.
    /// Gates the manual Background Items guidance so the last-resort command is
    /// never an always-visible affordance.
    private(set) var offersManualBackgroundItemsGuidance = false

    /// The exact command shown/copied for the manual, global Background Items
    /// reset. Presentation-only — Tracexy never runs it.
    var manualBackgroundItemsCommand: String {
        Self.manualBackgroundItemsResetCommand
    }

    /// Normal recovery: remove + reinstall. Never touches global Background Items.
    func runNormalReset() async {
        isWorking = true
        defer { isWorking = false }
        let result = await helper.forceResetAndReinstall()
        summary = result
        // Only surface the manual last-resort guidance after a normal attempt
        // didn't recover the helper.
        offersManualBackgroundItemsGuidance = result.suggestsManualBackgroundItemsGuidance
    }

    /// Copies the full success/failure detail to the pasteboard for a bug report.
    func copyDetails() {
        guard let summary else {
            return
        }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(summary.details, forType: .string)
    }

    /// Copies the manual Background Items reset command to the pasteboard. Tracexy
    /// never executes this command; the user pastes it into Terminal themselves.
    func copyManualBackgroundItemsCommand() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(manualBackgroundItemsCommand, forType: .string)
    }

    // MARK: Private

    private let helper: HelperClient
}
