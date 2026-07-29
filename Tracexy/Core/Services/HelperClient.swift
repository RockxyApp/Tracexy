import Foundation
import OSLog
import ServiceManagement

// MARK: - HelperClient

/// Manages the lifecycle of the Tracexy privileged capture helper via SMAppService.
///
/// Registers the launch daemon, probes the installed helper's version over XPC,
/// and classifies it as compatible / outdated / incompatible so the UI can offer
/// Install / Update / Reinstall.
@MainActor
@Observable
final class HelperClient {
    // MARK: Internal

    /// Installation + compatibility state of the helper daemon.
    enum Status: Equatable {
        case notInstalled
        case requiresApproval
        case installedCompatible
        case installedOutdated
        case installedIncompatible
        case unreachable
        case signingMismatch
        case failed(String)
    }

    /// The specific signing problem when `status == .signingMismatch` (sibling-app parity).
    enum SigningIssue: Equatable {
        case appSignatureInvalid(detail: String)
        case identityMismatch(appSigner: String, helperSigner: String)
    }

    static let shared = HelperClient()

    /// Where the embedded helper binary lives inside the app bundle.
    static let bundledHelperBinaryRelativePath = "Contents/Library/HelperTools/TracexyCaptureHelper"

    private(set) var status: Status = .notInstalled
    private(set) var signingIssue: SigningIssue?
    /// Version/build/protocol reported by the installed helper, when reachable.
    private(set) var installedInfo: HelperInfo?
    private(set) var isBusy = false

    // MARK: Bundled (shipped) versions — what this app build embeds

    /// The build the embedded helper was compiled at. App and helper share the
    /// project version, so the app's own `CFBundleVersion` is the bundled build.
    var bundledHelperBuild: Int {
        Int(Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "0") ?? 0
    }

    var bundledHelperVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0"
    }

    var expectedProtocolVersion: Int {
        HelperProtocolVersion.current
    }

    /// A short, user-facing action label for the current status (sibling-app parity).
    var actionLabel: String? {
        switch status {
        case .installedCompatible: nil
        case .installedOutdated,
             .installedIncompatible: "Update"
        case .notInstalled: "Install"
        case .requiresApproval: "Open Settings"
        case .unreachable: "Retry"
        case .signingMismatch:
            // An invalid app signature can't be fixed by reinstalling the helper.
            if case .appSignatureInvalid = signingIssue {
                nil
            } else {
                "Reinstall"
            }
        case .failed: "Reinstall"
        }
    }

    // MARK: Capture quick-path

    /// Registers the daemon if needed and returns true when it's enabled and
    /// reachable enough to start a capture. Refreshes the version status in the
    /// background. Kept synchronous for the capture Start path.
    @discardableResult
    func ensureInstalled() -> Bool {
        let service = SMAppService.daemon(plistName: Self.plistName)
        switch service.status {
        case .enabled:
            refreshStatusInBackground()
            return true
        case .requiresApproval:
            status = .requiresApproval
            SMAppService.openSystemSettingsLoginItems()
            return false
        case .notRegistered,
             .notFound:
            do {
                try service.register()
                if service.status == .enabled {
                    refreshStatusInBackground()
                    return true
                }
                status = .requiresApproval
                SMAppService.openSystemSettingsLoginItems()
                return false
            } catch {
                handleRegisterError(error, serviceStatus: service.status)
                return status == .requiresApproval ? false : false
            }
        @unknown default:
            status = .failed("unknown SMAppService status")
            return false
        }
    }

    /// The XPC proxy to the helper, opening the privileged connection if needed.
    func proxy() throws -> TracexyHelperProtocol {
        let connection = openConnectionIfNeeded()
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
            Self.logger.error("XPC error: \(error.localizedDescription, privacy: .public)")
        }) as? TracexyHelperProtocol else {
            throw NSError(domain: "Tracexy", code: 1, userInfo: [NSLocalizedDescriptionKey: "helper unreachable"])
        }
        return proxy
    }

    func disconnect() {
        connection?.invalidate()
        connection = nil
    }

    // MARK: Lifecycle management (sibling-app parity)

    /// Register the helper daemon, prompting for Login Items approval if needed.
    func install() async {
        await runBusy { await self.performInstall() }
    }

    /// Uninstall (delete) the helper: tell it to stop, then unregister from launchd.
    func uninstall() async {
        await runBusy {
            self.disconnect()
            do {
                try await SMAppService.daemon(plistName: Self.plistName).unregister()
                self.status = .notInstalled
                self.installedInfo = nil
                Self.logger.info("helper uninstalled")
            } catch {
                self.status = .failed(error.localizedDescription)
                Self.logger.error("helper unregister failed: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    /// Update the helper: unregister the old daemon, then register the new one.
    /// Re-registration may require Login Items approval again.
    func update() async {
        await runBusy {
            self.disconnect()
            try? await SMAppService.daemon(plistName: Self.plistName).unregister()
            try? await Task.sleep(nanoseconds: 500_000_000)
            let service = SMAppService.daemon(plistName: Self.plistName)
            do {
                try service.register()
                if service.status == .requiresApproval {
                    self.status = .requiresApproval
                    SMAppService.openSystemSettingsLoginItems()
                } else {
                    await self.performCheckStatus()
                }
            } catch {
                self.handleRegisterError(error, serviceStatus: service.status)
            }
        }
    }

    /// Probe the installed helper and classify its compatibility.
    func checkStatus() async {
        await runBusy { await self.performCheckStatus() }
    }

    /// Hard-remove the helper from launchd and the privileged-helper location,
    /// then reinstall from the current app bundle (the recovery path).
    /// Returns a user-facing summary of the privileged command output.
    @discardableResult
    func forceResetAndReinstall(resetBackgroundItems: Bool) async -> String {
        var summary = ""
        await runBusy {
            if let proxy = try? self.proxy() {
                proxy.stopCapture {}
            }
            self.disconnect()
            try? await SMAppService.daemon(plistName: Self.plistName).unregister()

            let script = Self.forceRemoveShellScript(
                identity: TracexyIdentity.current,
                resetBackgroundItems: resetBackgroundItems
            )
            do {
                let output = try await Self.runPrivilegedShellScript(script)
                summary = output.isEmpty ? "Removed stale helper files and launchd registration." : output
            } catch {
                summary = error.localizedDescription
            }

            self.status = .notInstalled
            self.installedInfo = nil
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            await self.performInstall()
        }
        return summary
    }

    // MARK: Compatibility

    /// Classify a probed helper: protocol mismatch is incompatible; an older
    /// build than what we ship is outdated; otherwise compatible (sibling-app logic).
    func evaluateCompatibility(_ info: HelperInfo) -> Status {
        if info.protocolVersion != expectedProtocolVersion {
            return .installedIncompatible
        }
        return info.buildNumber >= bundledHelperBuild ? .installedCompatible : .installedOutdated
    }

    // MARK: Private

    private static let logger = Logger(subsystem: TracexyIdentity.current.logSubsystem, category: "HelperClient")
    private static let plistName = TracexyIdentity.current.helperPlistName

    private var connection: NSXPCConnection?

    private func openConnectionIfNeeded() -> NSXPCConnection {
        if let connection {
            return connection
        }
        let new = NSXPCConnection(
            machServiceName: TracexyIdentity.current.helperMachServiceName,
            options: .privileged
        )
        new.remoteObjectInterface = NSXPCInterface(with: TracexyHelperProtocol.self)
        new.invalidationHandler = { [weak self] in Task { @MainActor in self?.connection = nil } }
        new.interruptionHandler = { [weak self] in Task { @MainActor in self?.connection = nil } }
        new.resume()
        connection = new
        return new
    }

    private func runBusy(_ work: () async -> Void) async {
        isBusy = true
        await work()
        isBusy = false
    }

    private func refreshStatusInBackground() {
        Task { @MainActor in await performCheckStatus() }
    }

    private func performInstall() async {
        let service = SMAppService.daemon(plistName: Self.plistName)
        switch service.status {
        case .enabled:
            await performCheckStatus()
        case .requiresApproval:
            status = .requiresApproval
            SMAppService.openSystemSettingsLoginItems()
        case .notRegistered,
             .notFound:
            do {
                try service.register()
                if service.status == .requiresApproval {
                    status = .requiresApproval
                    SMAppService.openSystemSettingsLoginItems()
                } else {
                    await performCheckStatus()
                }
            } catch {
                handleRegisterError(error, serviceStatus: service.status)
            }
        @unknown default:
            status = .failed("unknown SMAppService status")
        }
    }

    private func performCheckStatus() async {
        signingIssue = nil
        let service = SMAppService.daemon(plistName: Self.plistName)
        switch service.status {
        case .enabled:
            // Signing preflight first: a signature/identity mismatch is surfaced
            // immediately and must not be "fixed" by re-registration (sibling-app logic).
            switch SigningDiagnostics.diagnose() {
            case let .appSignatureInvalid(detail):
                signingIssue = .appSignatureInvalid(detail: detail)
                installedInfo = nil
                status = .signingMismatch
                return
            case let .signingIdentityMismatch(appSigner, helperSigner):
                signingIssue = .identityMismatch(appSigner: appSigner, helperSigner: helperSigner)
                installedInfo = nil
                status = .signingMismatch
                return
            case .healthy,
                 .helperBinaryNotFound,
                 .certificateChainUnavailable,
                 .diagnosticError:
                break
            }
            do {
                let info = try await fetchHelperInfo()
                installedInfo = info
                status = evaluateCompatibility(info)
                Self.logger.info(
                    "helper enabled: build=\(info.buildNumber) proto=\(info.protocolVersion) → \(String(describing: self.status))"
                )
            } catch {
                installedInfo = nil
                status = .unreachable
                Self.logger.warning("helper enabled but unreachable: \(error.localizedDescription, privacy: .public)")
            }
        case .requiresApproval:
            status = .requiresApproval
        case .notRegistered,
             .notFound:
            status = .notInstalled
            installedInfo = nil
        @unknown default:
            status = .notInstalled
            installedInfo = nil
        }
    }

    /// One XPC round-trip to `getHelperInfo`, resilient to the connection failing
    /// (the error handler resumes the continuation instead of hanging forever).
    private func fetchHelperInfo() async throws -> HelperInfo {
        let connection = openConnectionIfNeeded()
        return try await withCheckedThrowingContinuation { continuation in
            let once = ResumeOnce(continuation)
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
                once.resume(throwing: error)
            }) as? TracexyHelperProtocol else {
                once.resume(throwing: NSError(
                    domain: "Tracexy", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "helper unreachable"]
                ))
                return
            }
            proxy.getHelperInfo { version, build, proto in
                once.resume(returning: HelperInfo(
                    binaryVersion: version, buildNumber: build, protocolVersion: proto
                ))
            }
        }
    }

    private func handleRegisterError(_ error: Error, serviceStatus: SMAppService.Status) {
        let nsError = error as NSError
        if serviceStatus == .requiresApproval || nsError.code == kSMErrorLaunchDeniedByUser {
            status = .requiresApproval
            SMAppService.openSystemSettingsLoginItems()
        } else {
            status = .failed(error.localizedDescription)
            Self.logger.error("helper register failed: \(error.localizedDescription, privacy: .public)")
        }
    }
}

// MARK: - ResumeOnce

/// Guards `fetchHelperInfo`'s checked continuation so it resumes exactly once,
/// even though the XPC reply block and the error handler can race on different
/// threads.
///
/// Deliberately non-generic (specialized to `HelperInfo`): a generic version
/// crashed the Swift 6.2 SIL optimizer (EarlyPerfInliner, in the synthesized
/// deallocating destructor) under Release `-O -whole-module-optimization`. The
/// concrete layout sidesteps that. The lock only guards the one-shot `claim`;
/// the continuation is resumed outside the lock so no continuation work runs
/// while the lock is held.
private final class ResumeOnce: @unchecked Sendable {
    // MARK: Lifecycle

    init(_ continuation: CheckedContinuation<HelperInfo, Error>) {
        self.continuation = continuation
    }

    // MARK: Internal

    func resume(returning value: HelperInfo) {
        guard claim() else {
            return
        }
        continuation.resume(returning: value)
    }

    func resume(throwing error: Error) {
        guard claim() else {
            return
        }
        continuation.resume(throwing: error)
    }

    // MARK: Private

    private let continuation: CheckedContinuation<HelperInfo, Error>
    private let lock = NSLock()
    private var done = false

    /// Wins exactly once for the first caller; every later caller loses. The
    /// lock is released before the winner resumes the continuation.
    private func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !done else {
            return false
        }
        done = true
        return true
    }
}
