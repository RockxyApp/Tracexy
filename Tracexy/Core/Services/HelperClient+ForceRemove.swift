import Foundation
import ServiceManagement

// Hard-recovery paths for the helper daemon. Used when SMAppService unregister
// can't get the app back to an observable state (BTM/launchd drift).

extension HelperClient {
    // MARK: Internal

    enum ForceRemoveError: LocalizedError, Equatable {
        case commandFailed(exitCode: Int32, output: String)
        case commandTerminated(signal: Int32, output: String)

        // MARK: Internal

        /// The raw merged stdout/stderr from the privileged script, regardless of
        /// how it terminated.
        var commandOutput: String {
            switch self {
            case let .commandFailed(_, output),
                 let .commandTerminated(_, output):
                output
            }
        }

        /// Whether the failure is the user cancelling the administrator prompt
        /// (osascript reports error `-128` / "User canceled") rather than a real
        /// removal failure. A cancelled prompt must abort without reinstalling.
        var isAuthorizationCancelled: Bool {
            guard case let .commandFailed(_, output) = self else {
                return false
            }
            return output.localizedCaseInsensitiveContains("User canceled")
                || output.localizedCaseInsensitiveContains("User cancelled")
                || output.contains("-128")
        }

        var errorDescription: String? {
            switch self {
            case let .commandFailed(exitCode, output):
                if isAuthorizationCancelled {
                    return "The administrator authorization prompt was cancelled."
                }
                return output.isEmpty
                    ? "Force reset failed with exit code \(exitCode)."
                    : "Force reset failed with exit code \(exitCode): \(output)"
            case let .commandTerminated(signal, output):
                return output.isEmpty
                    ? "Force reset was interrupted by signal \(signal)."
                    : "Force reset was interrupted by signal \(signal): \(output)"
            }
        }
    }

    // MARK: Shell scripting (osascript "with administrator privileges")

    nonisolated static func forceRemoveShellScript(
        identity: TracexyIdentity,
        resetBackgroundItems: Bool
    )
        -> String
    {
        let label = shellQuote(identity.helperMachServiceName)
        let helperPath = shellQuote("/Library/PrivilegedHelperTools/\(identity.helperBundleIdentifier)")
        let launchDaemonPath = shellQuote("/Library/LaunchDaemons/\(identity.helperPlistName)")
        let processPattern = shellQuote("[T]racexyCaptureHelper")

        var commands = [
            "/bin/launchctl bootout system/\(label) 2>/dev/null || true",
            "/usr/bin/pkill -f \(processPattern) 2>/dev/null || true",
            "/bin/rm -f \(helperPath)",
            "/bin/rm -f \(launchDaemonPath)",
        ]

        if resetBackgroundItems {
            commands.append("/usr/bin/sfltool resetbtm 2>/dev/null || true")
        }

        commands.append(contentsOf: [
            "if /bin/launchctl print system/\(label) >/dev/null 2>&1; then " +
                "echo 'Tracexy helper launchd job is still loaded.' >&2; exit 20; fi",
            "if [ -e \(helperPath) ]; then echo 'Tracexy helper binary still exists.' >&2; exit 21; fi",
            "if [ -e \(launchDaemonPath) ]; then echo 'Tracexy launch daemon plist still exists.' >&2; exit 22; fi",
            "echo 'Tracexy helper registration files were removed.'",
        ])

        return commands.joined(separator: "; ")
    }

    nonisolated static func runPrivilegedShellScript(_ shellScript: String) async throws -> String {
        let appleScript = privilegedAppleScript(for: shellScript)

        return try await Task.detached(priority: .userInitiated) {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            process.arguments = ["-e", appleScript]

            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe

            try process.run()
            process.waitUntilExit()

            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            guard process.terminationStatus == 0 else {
                if process.terminationReason == .uncaughtSignal {
                    throw ForceRemoveError.commandTerminated(signal: process.terminationStatus, output: output)
                }
                throw ForceRemoveError.commandFailed(exitCode: process.terminationStatus, output: output)
            }
            return output
        }.value
    }

    // MARK: Private

    nonisolated private static func privilegedAppleScript(for shellScript: String) -> String {
        let escaped = shellScript
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return "do shell script \"\(escaped)\" with administrator privileges"
    }

    nonisolated private static func shellQuote(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }
}

// MARK: - ForceResetSummary

/// The verified outcome of `forceResetAndReinstall`. Never self-asserts success:
/// the `finalStatus` is snapshotted from a real re-probe, so the summary reflects
/// what actually happened rather than what was attempted.
struct ForceResetSummary: Equatable {
    // MARK: Internal

    enum Phase: Equatable {
        /// A lifecycle action was already running, so no reset was attempted.
        case operationInProgress
        /// The administrator prompt was cancelled; nothing was removed or reinstalled.
        case removalCancelled
        /// The privileged removal failed (nonzero exit / exit-guard tripped);
        /// state was left untouched and no reinstall was attempted.
        case removalFailed
        /// Removal succeeded (script exit 0) and a reinstall was attempted;
        /// `finalStatus` carries the real post-reinstall state.
        case reinstalled
    }

    let phase: Phase
    /// Merged stdout/stderr from the privileged script (or the error text).
    let removalOutput: String
    /// The helper status after the operation, re-probed. `nil` only if never set.
    let finalStatus: HelperClient.Status?

    var didReinstall: Bool {
        phase == .reinstalled
    }

    /// True only when removal *and* reinstall landed the bundled helper in the
    /// expected state, or registration succeeded and only macOS approval remains.
    /// An outdated helper after reinstall indicates stale state and is not success.
    var succeeded: Bool {
        guard phase == .reinstalled else {
            return false
        }
        switch finalStatus {
        case .installedCompatible,
             .requiresApproval:
            return true
        default:
            return false
        }
    }

    /// Whether to offer the heavier `sfltool resetbtm` escalation next. Only after
    /// a normal (non-BTM) attempt failed to recover — never after a user-initiated
    /// cancel.
    var suggestsBackgroundItemsReset: Bool {
        switch phase {
        case .operationInProgress:
            false
        case .removalFailed:
            true
        case .reinstalled:
            !succeeded
        case .removalCancelled:
            false
        }
    }

    /// A short, user-facing headline for the result.
    var title: String {
        switch phase {
        case .operationInProgress:
            "Helper operation already in progress"
        case .removalCancelled:
            "Force reset cancelled"
        case .removalFailed:
            "Force reset failed"
        case .reinstalled:
            switch finalStatus {
            case .installedCompatible?: "Helper reset and reinstalled"
            case .installedOutdated?: "Helper reinstalled — update available"
            case .requiresApproval?: "Helper reinstalled — approval needed in Login Items"
            case .unreachable?: "Helper reinstalled but not responding"
            case .signingMismatch?: "Helper reinstalled but signature mismatched"
            case .installedIncompatible?: "Helper reinstalled but incompatible"
            case let .failed(reason)?: "Helper reinstall failed: \(reason)"
            case .notInstalled?,
                 .none: "Helper removed but reinstall didn’t complete"
            }
        }
    }

    /// Multi-line detail suitable for a Copy Details action.
    var details: String {
        var lines = [title]
        let trimmed = removalOutput.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty {
            lines.append(trimmed)
        }
        if let finalStatus {
            lines.append("Final helper status: \(Self.describe(finalStatus))")
        }
        return lines.joined(separator: "\n")
    }

    // MARK: Private

    private static func describe(_ status: HelperClient.Status) -> String {
        switch status {
        case .notInstalled: "not installed"
        case .requiresApproval: "awaiting approval in Login Items"
        case .installedCompatible: "installed and up to date"
        case .installedOutdated: "installed, update available"
        case .installedIncompatible: "installed, incompatible protocol"
        case .unreachable: "registered but unreachable"
        case .signingMismatch: "signing mismatch"
        case let .failed(reason): "failed — \(reason)"
        }
    }
}
