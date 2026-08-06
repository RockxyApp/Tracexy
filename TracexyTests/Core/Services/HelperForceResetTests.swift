import Foundation
import ServiceManagement
import Testing
@testable import Tracexy

// MARK: - ForceRemoveScriptTests

// The force-reset path is exercised only through its pure builders and result
// types. No test ever runs the privileged script, invokes osascript, or registers
// / unregisters the helper.

@Suite("Force-remove shell script builder")
struct ForceRemoveScriptTests {
    // MARK: Internal

    @Test("Boots out the launchd job and removes the helper binary and launch daemon plist")
    func removesEverything() {
        let script = HelperClient.forceRemoveShellScript(identity: Self.identity)

        #expect(script.contains("/bin/launchctl bootout system/'com.example.helper'"))
        #expect(script.contains("/bin/rm -f '/Library/PrivilegedHelperTools/com.example.helper'"))
        #expect(script.contains("/bin/rm -f '/Library/LaunchDaemons/com.example.helper.plist'"))
    }

    @Test("Terminates the job by its exact service label, ordered before bootout, with no broad pkill")
    func killsByExactServiceLabel() {
        let script = HelperClient.forceRemoveShellScript(identity: Self.identity)

        // The job is killed by its exact `system/<label>` service target.
        #expect(script.contains("/bin/launchctl kill SIGTERM system/'com.example.helper'"))

        // The kill must run before the bootout so the process is signalled while its
        // launchd job still exists.
        let killRange = script.range(of: "launchctl kill SIGTERM system/'com.example.helper'")
        let bootoutRange = script.range(of: "launchctl bootout system/'com.example.helper'")
        #expect(killRange != nil)
        #expect(bootoutRange != nil)
        if let killRange, let bootoutRange {
            #expect(killRange.lowerBound < bootoutRange.lowerBound)
        }

        // The broad, executable-name pkill — which a debug and a production helper
        // share and which could kill a different app's helper — must be gone entirely.
        #expect(!script.contains("pkill"))
        #expect(!script.contains("TracexyCaptureHelper"))
    }

    @Test("Exit guards fail loudly if the job or files remain")
    func exitGuards() {
        let script = HelperClient.forceRemoveShellScript(identity: Self.identity)
        #expect(script.contains("exit 20"))
        #expect(script.contains("exit 21"))
        #expect(script.contains("exit 22"))
    }

    @Test("The privileged script never touches global Background Items")
    func neverResetsBackgroundItems() {
        // The v0.1.3 regression nested `sfltool resetbtm` inside an already-elevated
        // osascript shell (exit 23 guard) after the helper was unregistered. The
        // app-specific cleanup must never contain any of that machinery.
        let script = HelperClient.forceRemoveShellScript(identity: Self.identity)
        #expect(!script.contains("sfltool"))
        #expect(!script.contains("resetbtm"))
        #expect(!script.contains("exit 23"))
    }

    @Test("The completion message describes only what the script verified, not registration removal")
    func completionMessageIsTruthful() {
        let script = HelperClient.forceRemoveShellScript(identity: Self.identity)
        // The script verifies the launchd job and legacy files are gone; it does NOT
        // remove the SMAppService registration (that happens later, in Swift). Its
        // completion echo must not claim registration files were removed.
        #expect(script.contains("Tracexy helper launchd job and legacy files were cleared."))
        #expect(!script.contains("registration files were removed"))
    }

    @Test("The manual Background Items command lives in the presenter, not Core/Services")
    func manualCommandLivesInPresenter() {
        // Presentation-only: this string is displayed/copied, never executed. It now
        // lives on the presenter — the one place `sfltool resetbtm` may appear, and
        // only as guidance text — never beside the privileged executor.
        #expect(HelperRecoveryPresenter.manualBackgroundItemsResetCommand == "sudo /usr/bin/sfltool resetbtm")
        // It must not be wired into the privileged script or any || true swallowing.
        let script = HelperClient.forceRemoveShellScript(identity: Self.identity)
        #expect(!script.contains(HelperRecoveryPresenter.manualBackgroundItemsResetCommand))
    }

    // MARK: Private

    private static let identity = TracexyIdentity(infoDictionary: [
        "TracexyHelperBundleIdentifier": "com.example.helper",
        "TracexyHelperMachServiceName": "com.example.helper",
        "TracexyHelperPlistName": "com.example.helper.plist",
    ])
}

// MARK: - ForceRemoveErrorTests

@Suite("Force-remove error classification")
struct ForceRemoveErrorTests {
    @Test("A cancelled administrator prompt is recognised and does not read as a failure")
    func cancelled() {
        let cancelled = HelperClient.ForceRemoveError.commandFailed(exitCode: 1, output: "User canceled. (-128)")
        #expect(cancelled.isAuthorizationCancelled)
        #expect(cancelled.errorDescription == "The administrator authorization prompt was cancelled.")
    }

    @Test("A tripped exit guard is a real failure, not a cancellation")
    func guardTrip() {
        let tripped = HelperClient.ForceRemoveError.commandFailed(
            exitCode: 20,
            output: "Tracexy helper launchd job is still loaded."
        )
        #expect(!tripped.isAuthorizationCancelled)
        #expect(tripped.errorDescription?.contains("exit code 20") == true)
        #expect(tripped.commandOutput == "Tracexy helper launchd job is still loaded.")
    }

    @Test("A signal termination is described and is not a cancellation")
    func terminated() {
        let terminated = HelperClient.ForceRemoveError.commandTerminated(signal: 15, output: "")
        #expect(!terminated.isAuthorizationCancelled)
        #expect(terminated.errorDescription?.contains("signal 15") == true)
    }
}

// MARK: - PostCleanupRegistrationActionTests

// The decision the reset takes for this app's SMAppService registration *after* the
// privileged cleanup has removed the launchd job and files. Exercised as a pure
// mapping from a real `SMAppService.Status`, so absent-registration semantics are
// covered without registering or unregistering anything live.

@Suite("Post-cleanup SMAppService registration decision")
struct PostCleanupRegistrationActionTests {
    @Test("A live registration is unregistered")
    func liveRegistrationUnregisters() {
        #expect(HelperClient.postCleanupRegistrationAction(for: .enabled) == .unregister)
        #expect(HelperClient.postCleanupRegistrationAction(for: .requiresApproval) == .unregister)
    }

    @Test("An absent registration proceeds to reinstall without unregistering")
    func absentRegistrationProceeds() {
        // The crux: a missing registration is an acceptable end state and must not
        // block the reinstall, so no unregister is attempted.
        #expect(HelperClient.postCleanupRegistrationAction(for: .notRegistered) == .alreadyAbsent)
        #expect(HelperClient.postCleanupRegistrationAction(for: .notFound) == .alreadyAbsent)
    }
}

// MARK: - ForceResetSummaryTests

@Suite("Force-reset result summary")
struct ForceResetSummaryTests {
    @Test("A clean reinstall to a compatible helper is a success and needs no escalation")
    func reinstalledCompatible() {
        let summary = ForceResetSummary(
            phase: .reinstalled,
            removalOutput: "removed",
            finalStatus: .installedCompatible
        )
        #expect(summary.didReinstall)
        #expect(summary.succeeded)
        #expect(!summary.suggestsManualBackgroundItemsGuidance)
        #expect(summary.details.contains("removed"))
        #expect(summary.details.localizedCaseInsensitiveContains("up to date"))
    }

    @Test("Reinstall that only needs Login-Items approval is still a success")
    func reinstalledRequiresApproval() {
        let summary = ForceResetSummary(phase: .reinstalled, removalOutput: "", finalStatus: .requiresApproval)
        #expect(summary.succeeded)
    }

    @Test("Reinstall that lands unreachable is not success and suggests manual guidance")
    func reinstalledUnreachable() {
        let summary = ForceResetSummary(phase: .reinstalled, removalOutput: "", finalStatus: .unreachable)
        #expect(!summary.succeeded)
        #expect(summary.suggestsManualBackgroundItemsGuidance)
    }

    @Test("Reinstall that still reports an outdated helper is not success")
    func reinstalledOutdated() {
        let summary = ForceResetSummary(phase: .reinstalled, removalOutput: "", finalStatus: .installedOutdated)
        #expect(!summary.succeeded)
        #expect(summary.suggestsManualBackgroundItemsGuidance)
    }

    @Test("A failed removal surfaces the re-probed final status and never reads as success")
    func removalFailed() {
        // The re-probed status is authoritative. Because cleanup may have already
        // removed files before a later step failed, the summary must NOT claim the
        // state was left untouched — it reports what the re-probe actually found.
        let summary = ForceResetSummary(
            phase: .removalFailed,
            removalOutput: "Removed the helper files, but couldn’t unregister the launchd service: boom",
            finalStatus: .unreachable
        )
        #expect(!summary.didReinstall)
        #expect(!summary.succeeded)
        #expect(summary.suggestsManualBackgroundItemsGuidance)
        #expect(summary.title == "Force reset failed")
        #expect(summary.details.localizedCaseInsensitiveContains("registered but unreachable"))
        #expect(!summary.details.localizedCaseInsensitiveContains("untouched"))
    }

    @Test("A cancelled removal is not a success and does not push manual guidance")
    func removalCancelled() {
        let summary = ForceResetSummary(phase: .removalCancelled, removalOutput: "cancelled", finalStatus: nil)
        #expect(!summary.succeeded)
        #expect(!summary.suggestsManualBackgroundItemsGuidance)
        #expect(summary.title == "Force reset cancelled")
    }

    @Test("An overlapping lifecycle action does not trigger manual guidance")
    func operationInProgress() {
        let summary = ForceResetSummary(
            phase: .operationInProgress,
            removalOutput: "Another helper operation is already in progress.",
            finalStatus: .installedCompatible
        )
        #expect(!summary.didReinstall)
        #expect(!summary.succeeded)
        #expect(!summary.suggestsManualBackgroundItemsGuidance)
    }
}
