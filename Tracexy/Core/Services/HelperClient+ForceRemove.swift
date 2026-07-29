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

        var errorDescription: String? {
            switch self {
            case let .commandFailed(exitCode, output):
                if output.localizedCaseInsensitiveContains("User canceled") {
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
