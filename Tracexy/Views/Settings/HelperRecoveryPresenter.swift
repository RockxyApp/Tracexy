import AppKit
import Observation

// MARK: - HelperRecoveryPresenter

/// Drives the Settings → Helper recovery flow: the normal force-reset-and-reinstall
/// and, only after that fails, the heavier `sfltool resetbtm` escalation.
///
/// Owns just the presentation state (working flag, last summary, whether to offer
/// the Background Items escalation). The privileged work and all state truth live
/// on `HelperClient`; this type never runs a privileged operation itself beyond
/// asking the client to.
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

    private(set) var isWorking = false
    private(set) var summary: ForceResetSummary?

    /// True only once a normal (non-BTM) reset has run and failed to recover the
    /// helper. Gates the `sfltool resetbtm` escalation so it is never a casual,
    /// always-visible checkbox.
    private(set) var offersBackgroundItemsReset = false

    /// Normal recovery: remove + reinstall without touching macOS Background Items.
    func runNormalReset() async {
        await run(resetBackgroundItems: false)
    }

    /// Escalated recovery: also runs `sfltool resetbtm`. Only reachable after a
    /// normal reset failed and behind a second explicit confirmation in the UI.
    func runBackgroundItemsReset() async {
        await run(resetBackgroundItems: true)
    }

    /// Copies the full success/failure detail to the pasteboard for a bug report.
    func copyDetails() {
        guard let summary else {
            return
        }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(summary.details, forType: .string)
    }

    // MARK: Private

    private let helper: HelperClient

    private func run(resetBackgroundItems: Bool) async {
        isWorking = true
        defer { isWorking = false }
        let result = await helper.forceResetAndReinstall(resetBackgroundItems: resetBackgroundItems)
        summary = result
        // Only offer the BTM escalation after a *normal* attempt didn't recover;
        // running it a second time offers no new lever, so it drops away.
        offersBackgroundItemsReset = !resetBackgroundItems && result.suggestsBackgroundItemsReset
    }
}
