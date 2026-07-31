import Foundation
import Testing
@testable import Tracexy

// MARK: - ForceRemoveScriptTests

// The force-reset path is exercised only through its pure builders and result
// types. No test ever runs the privileged script, invokes osascript, or registers
// / unregisters the helper.

@Suite("Force-remove shell script builder")
struct ForceRemoveScriptTests {
    // MARK: Internal

    @Test("Removes the launchd job, process, helper binary, and launch daemon plist")
    func removesEverything() {
        let script = HelperClient.forceRemoveShellScript(identity: Self.identity, resetBackgroundItems: false)

        #expect(script.contains("/bin/launchctl bootout system/'com.example.helper'"))
        #expect(script.contains("/bin/rm -f '/Library/PrivilegedHelperTools/com.example.helper'"))
        #expect(script.contains("/bin/rm -f '/Library/LaunchDaemons/com.example.helper.plist'"))
    }

    @Test("pkill uses the bracket form so it cannot match itself")
    func bracketedPkill() {
        let script = HelperClient.forceRemoveShellScript(identity: Self.identity, resetBackgroundItems: false)
        #expect(script.contains("/usr/bin/pkill -f '[T]racexyCaptureHelper'"))
        // The naive, self-matching form must not appear.
        #expect(!script.contains("pkill -f 'TracexyCaptureHelper'"))
    }

    @Test("Exit guards fail loudly if the job or files remain")
    func exitGuards() {
        let script = HelperClient.forceRemoveShellScript(identity: Self.identity, resetBackgroundItems: false)
        #expect(script.contains("exit 20"))
        #expect(script.contains("exit 21"))
        #expect(script.contains("exit 22"))
    }

    @Test("sfltool resetbtm is gated behind the flag")
    func sfltoolGated() {
        let without = HelperClient.forceRemoveShellScript(identity: Self.identity, resetBackgroundItems: false)
        let with = HelperClient.forceRemoveShellScript(identity: Self.identity, resetBackgroundItems: true)
        #expect(!without.contains("sfltool resetbtm"))
        #expect(with.contains("/usr/bin/sfltool resetbtm"))
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
        #expect(!summary.suggestsBackgroundItemsReset)
        #expect(summary.details.contains("removed"))
        #expect(summary.details.localizedCaseInsensitiveContains("up to date"))
    }

    @Test("Reinstall that only needs Login-Items approval is still a success")
    func reinstalledRequiresApproval() {
        let summary = ForceResetSummary(phase: .reinstalled, removalOutput: "", finalStatus: .requiresApproval)
        #expect(summary.succeeded)
    }

    @Test("Reinstall that lands unreachable is not success and suggests escalation")
    func reinstalledUnreachable() {
        let summary = ForceResetSummary(phase: .reinstalled, removalOutput: "", finalStatus: .unreachable)
        #expect(!summary.succeeded)
        #expect(summary.suggestsBackgroundItemsReset)
    }

    @Test("Reinstall that still reports an outdated helper is not success")
    func reinstalledOutdated() {
        let summary = ForceResetSummary(phase: .reinstalled, removalOutput: "", finalStatus: .installedOutdated)
        #expect(!summary.succeeded)
        #expect(summary.suggestsBackgroundItemsReset)
    }

    @Test("A failed removal keeps escalation available and never reads as success")
    func removalFailed() {
        let summary = ForceResetSummary(
            phase: .removalFailed,
            removalOutput: "job still loaded",
            finalStatus: .installedCompatible
        )
        #expect(!summary.didReinstall)
        #expect(!summary.succeeded)
        #expect(summary.suggestsBackgroundItemsReset)
        #expect(summary.title == "Force reset failed")
    }

    @Test("A cancelled removal is not a success and does not push escalation")
    func removalCancelled() {
        let summary = ForceResetSummary(phase: .removalCancelled, removalOutput: "cancelled", finalStatus: nil)
        #expect(!summary.succeeded)
        #expect(!summary.suggestsBackgroundItemsReset)
        #expect(summary.title == "Force reset cancelled")
    }

    @Test("An overlapping lifecycle action does not trigger destructive escalation")
    func operationInProgress() {
        let summary = ForceResetSummary(
            phase: .operationInProgress,
            removalOutput: "Another helper operation is already in progress.",
            finalStatus: .installedCompatible
        )
        #expect(!summary.didReinstall)
        #expect(!summary.succeeded)
        #expect(!summary.suggestsBackgroundItemsReset)
    }
}
