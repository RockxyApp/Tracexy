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
    nonisolated enum Status: Equatable {
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
    nonisolated enum SigningIssue: Equatable {
        case appSignatureInvalid(detail: String)
        case identityMismatch(appSigner: String, helperSigner: String)
    }

    // MARK: Capture Start availability

    /// Whether the helper can be used to start a capture right now.
    ///
    /// Deliberately richer than `SMAppService.Status.enabled`: "enabled" only
    /// means launchd accepted the registration, not that the installed binary is
    /// the one we trust or that it answers XPC. `.ready` is returned only after
    /// signing + a bounded XPC probe agree.
    nonisolated enum CaptureAvailability: Equatable {
        /// Enabled, signature matches, protocol-compatible (or merely outdated).
        case ready
        /// Registered but not yet approved in Login Items.
        case requiresApproval
        /// A broken helper the user must recover — never silently hidden. The
        /// string is a user-facing explanation.
        case unavailable(String)
    }

    static let shared = HelperClient()

    /// Where the embedded helper binary lives inside the app bundle.
    nonisolated static let bundledHelperBinaryRelativePath = "Contents/Library/HelperTools/TracexyCaptureHelper"

    private(set) var status: Status = .notInstalled
    private(set) var signingIssue: SigningIssue?
    /// Version/build/protocol reported by the installed helper, when reachable.
    private(set) var installedInfo: HelperInfo?
    private(set) var isBusy = false
    /// The user-facing reason the last XPC probe failed, set when `status` is
    /// `.unreachable` so the UI can explain *why* a registered helper didn't
    /// answer (timed out vs connection error) rather than just "unreachable".
    private(set) var probeFailureDetail: String?

    /// App-level hook fired before any destructive/privileged lifecycle op (force
    /// reset) so the owning coordinator can stop active capture and invalidate its
    /// polling first. Set once at the composition root; `nil` in tests.
    var willBeginDestructiveReset: (@MainActor () -> Void)?

    // MARK: Bundled (shipped) versions — what this app build embeds

    /// The build the embedded helper was compiled at. Read from the
    /// helper-specific `Info.plist` keys (populated from `Versions.xcconfig`),
    /// never the app's own `CFBundleVersion`, so the two never get conflated.
    var bundledHelperBuild: Int {
        BundledHelperMetadata.bundled.build
    }

    var bundledHelperVersion: String {
        BundledHelperMetadata.bundled.version
    }

    var expectedProtocolVersion: Int {
        BundledHelperMetadata.bundled.protocolVersion
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

    /// Pure mapping from a probed `Status` to Start availability. Kept separate so
    /// the decision is unit-testable without SMAppService or XPC.
    nonisolated static func captureAvailability(
        for status: Status,
        unreachableDetail: String?
    )
        -> CaptureAvailability
    {
        switch status {
        case .installedCompatible,
             .installedOutdated:
            // Outdated shares the current protocol, so it still captures.
            .ready
        case .requiresApproval:
            .requiresApproval
        case .installedIncompatible:
            .unavailable("the installed helper uses an incompatible protocol. Update it in Settings → Helper.")
        case .signingMismatch:
            .unavailable(
                "the installed helper’s code signature doesn’t match this app. Reinstall it in Settings → Helper."
            )
        case .unreachable:
            .unavailable(unreachableDetail
                ?? "the helper is registered but isn’t responding. Recover it in Settings → Helper.")
        case .notInstalled:
            .unavailable("the capture helper isn’t installed. Install it in Settings → Helper.")
        case let .failed(reason):
            .unavailable(reason)
        }
    }

    /// Pure compatibility decision, testable without a live bundle. Protocol
    /// mismatch is incompatible; an older build than we ship is outdated;
    /// otherwise compatible.
    nonisolated static func classifyCompatibility(
        _ info: HelperInfo,
        expectedProtocolVersion: Int,
        bundledBuild: Int
    )
        -> Status
    {
        if info.protocolVersion != expectedProtocolVersion {
            return .installedIncompatible
        }
        return info.buildNumber >= bundledBuild ? .installedCompatible : .installedOutdated
    }

    /// Whether a registration error means the user must approve the helper in
    /// Login Items, rather than a genuine failure. Three triggers, matching the
    /// sibling app: SMAppService already reports `.requiresApproval`; the error is
    /// `kSMErrorLaunchDeniedByUser`; or it's the OSStatus "operation not permitted"
    /// early-block (`NSOSStatusErrorDomain` code `1`). Constraining that last case
    /// to `NSOSStatusErrorDomain` avoids sweeping in unrelated code-`1` errors
    /// (e.g. a POSIX `EPERM`).
    nonisolated static func isApprovalRequired(serviceStatus: SMAppService.Status, error: NSError) -> Bool {
        if serviceStatus == .requiresApproval {
            return true
        }
        if error.code == kSMErrorLaunchDeniedByUser {
            return true
        }
        if error.domain == NSOSStatusErrorDomain, error.code == 1 {
            return true
        }
        return false
    }

    /// Registers the daemon if needed, then verifies signing + XPC reachability
    /// before reporting whether capture can start. Never blocks indefinitely:
    /// the probe is timeout-bounded, so a wedged helper resolves to `.unavailable`
    /// rather than leaving the Start path spinning.
    func prepareForCaptureViaHelper() async -> CaptureAvailability {
        guard !isBusy else {
            return .unavailable("another helper operation is already in progress. Wait for it to finish and try again.")
        }
        return await runBusyReturning { () async -> CaptureAvailability in
            let service = SMAppService.daemon(plistName: Self.plistName)
            switch service.status {
            case .enabled:
                break
            case .requiresApproval:
                self.status = .requiresApproval
                SMAppService.openSystemSettingsLoginItems()
                return .requiresApproval
            case .notRegistered,
                 .notFound:
                if case let .incomplete(reason) = BundledHelperPackage.validateBundled(
                    identity: TracexyIdentity.current
                ) {
                    self.status = .failed("Helper package is incomplete: \(reason)")
                    return .unavailable("the helper package is incomplete: \(reason)")
                }
                do {
                    try service.register()
                    if service.status == .requiresApproval {
                        self.status = .requiresApproval
                        SMAppService.openSystemSettingsLoginItems()
                        return .requiresApproval
                    }
                } catch {
                    self.handleRegisterError(error, serviceStatus: service.status)
                    return self.status == .requiresApproval
                        ? .requiresApproval
                        : .unavailable(error.localizedDescription)
                }
            @unknown default:
                self.status = .failed("unknown SMAppService status")
                return .unavailable("unknown helper registration status")
            }
            // Enabled (or freshly registered): never trust that alone. Probe
            // signing + XPC compatibility before handing the Start path a proxy.
            await self.performCheckStatus()
            return Self.captureAvailability(for: self.status, unreachableDetail: self.probeFailureDetail)
        }
    }

    /// The XPC proxy to the helper, opening the privileged connection if needed.
    func proxy() throws -> TracexyHelperProtocol {
        let connection = openConnectionIfNeeded()
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ [weak self] error in
            Self.logger.error("XPC error: \(error.localizedDescription, privacy: .public)")
            Task { @MainActor in
                self?.recordRuntimeConnectionFailure(error.localizedDescription)
            }
        }) as? TracexyHelperProtocol else {
            throw NSError(domain: "Tracexy", code: 1, userInfo: [NSLocalizedDescriptionKey: "helper unreachable"])
        }
        return proxy
    }

    func disconnect() {
        resetConnection()
    }

    // MARK: Lifecycle management (sibling-app parity)

    /// Register the helper daemon, prompting for Login Items approval if needed.
    func install() async {
        guard !isBusy else {
            return
        }
        await runBusy { await self.performInstall() }
    }

    /// Uninstall (delete) the helper: stop its capture best-effort, then unregister
    /// from launchd. A failed unregister is surfaced, never reported as success.
    func uninstall() async {
        guard !isBusy else {
            return
        }
        await runBusy {
            if let proxy = try? self.proxy() {
                proxy.stopCapture {}
            }
            self.disconnect()
            do {
                try await SMAppService.daemon(plistName: Self.plistName).unregister()
                self.status = .notInstalled
                self.installedInfo = nil
                self.probeFailureDetail = nil
                Self.logger.info("helper uninstalled")
            } catch {
                self.status = .failed(error.localizedDescription)
                Self.logger.error("helper unregister failed: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    /// Update the helper: remove the old daemon, then register the new one.
    ///
    /// A replacement is **never** registered over a helper we failed to remove — a
    /// failed unregister aborts and surfaces the failure. Removal is only required
    /// when the daemon is actually present; a `.notRegistered`/`.notFound` start
    /// state proceeds straight to registration (this doubles as the reinstall
    /// path for a `.failed`/signing-mismatch helper). Re-registration may require
    /// Login Items approval again.
    func update() async {
        guard !isBusy else {
            return
        }
        await runBusy {
            if let proxy = try? self.proxy() {
                proxy.stopCapture {}
            }
            self.disconnect()

            let existing = SMAppService.daemon(plistName: Self.plistName)
            if existing.status == .enabled || existing.status == .requiresApproval {
                do {
                    try await existing.unregister()
                } catch {
                    self.status = .failed("Couldn’t remove the existing helper: \(error.localizedDescription)")
                    Self.logger.error(
                        "helper update aborted — unregister failed: \(error.localizedDescription, privacy: .public)"
                    )
                    return
                }
                try? await Task.sleep(nanoseconds: 500_000_000)
            }

            await self.performInstall()
        }
    }

    /// Probe the installed helper and classify its compatibility.
    func checkStatus() async {
        guard !isBusy else {
            return
        }
        await runBusy { await self.performCheckStatus() }
    }

    /// Surface a helper connection that failed after an earlier successful probe,
    /// such as a daemon that exits or wedges during an active capture.
    func recordRuntimeConnectionFailure(_ detail: String) {
        resetConnection()
        installedInfo = nil
        probeFailureDetail = detail
        status = .unreachable
    }

    /// Hard-remove the helper from launchd and the privileged-helper location,
    /// then reinstall from the current app bundle (the recovery path).
    ///
    /// Returns a structured, verified summary. Removal is authoritative: if the
    /// administrator prompt is cancelled, the privileged script exits nonzero, or
    /// its exit guards detect a still-loaded launchd job / leftover files, the
    /// method aborts **without clearing state and without reinstalling**, then
    /// re-probes so `finalStatus` reflects reality. Only a clean removal (script
    /// exit 0) proceeds to reinstall, after which the summary carries the actual
    /// post-reinstall status.
    @discardableResult
    func forceResetAndReinstall(resetBackgroundItems: Bool) async -> ForceResetSummary {
        guard !isBusy else {
            return ForceResetSummary(
                phase: .operationInProgress,
                removalOutput: "Another helper operation is already in progress.",
                finalStatus: status
            )
        }
        var summary = ForceResetSummary(phase: .removalFailed, removalOutput: "", finalStatus: nil)
        await runBusy {
            // App-level: stop active capture + invalidate polling before anything
            // privileged runs.
            self.willBeginDestructiveReset?()

            if let proxy = try? self.proxy() {
                proxy.stopCapture {}
            }
            self.disconnect()
            // Best-effort de-registration; the privileged script is the authority.
            try? await SMAppService.daemon(plistName: Self.plistName).unregister()

            let script = Self.forceRemoveShellScript(
                identity: TracexyIdentity.current,
                resetBackgroundItems: resetBackgroundItems
            )
            let removalOutput: String
            do {
                removalOutput = try await Self.runPrivilegedShellScript(script)
            } catch let error as ForceRemoveError {
                // Abort: do not clear state, do not reinstall. Re-probe for truth.
                await self.performCheckStatus()
                summary = ForceResetSummary(
                    phase: error.isAuthorizationCancelled ? .removalCancelled : .removalFailed,
                    removalOutput: error.errorDescription ?? error.commandOutput,
                    finalStatus: self.status
                )
                Self.logger.error("force reset removal failed: \(error.commandOutput, privacy: .public)")
                return
            } catch {
                await self.performCheckStatus()
                summary = ForceResetSummary(
                    phase: .removalFailed,
                    removalOutput: error.localizedDescription,
                    finalStatus: self.status
                )
                return
            }

            // Removal verified by the script's exit guards (exit 0). Reinstall.
            self.status = .notInstalled
            self.installedInfo = nil
            self.probeFailureDetail = nil
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            await self.performInstall()
            summary = ForceResetSummary(
                phase: .reinstalled,
                removalOutput: removalOutput.isEmpty
                    ? "Removed stale helper files and launchd registration."
                    : removalOutput,
                finalStatus: self.status
            )
        }
        return summary
    }

    // MARK: Compatibility

    /// Classify a probed helper: protocol mismatch is incompatible; an older
    /// build than what we ship is outdated; otherwise compatible (sibling-app logic).
    func evaluateCompatibility(_ info: HelperInfo) -> Status {
        Self.classifyCompatibility(
            info,
            expectedProtocolVersion: expectedProtocolVersion,
            bundledBuild: bundledHelperBuild
        )
    }

    // MARK: Private

    private static let logger = Logger(subsystem: TracexyIdentity.current.logSubsystem, category: "HelperClient")
    private static let plistName = TracexyIdentity.current.helperPlistName

    // MARK: Probe tuning + approval classification

    /// Deterministic worst case ≈ `probeMaxAttempts × probeTimeout` plus the
    /// inter-attempt delays: 3 × 3s + 2 × 750ms.
    private static let probeTimeoutNanoseconds: UInt64 = 3_000_000_000
    private static let probeMaxAttempts = 3
    private static let probeRetryDelayNanoseconds: UInt64 = 750_000_000

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
        defer { isBusy = false }
        await work()
    }

    private func runBusyReturning<T>(_ work: () async -> T) async -> T {
        isBusy = true
        defer { isBusy = false }
        return await work()
    }

    /// Invalidate and drop the XPC connection so the next probe reconnects fresh.
    /// Called between probe attempts and after a timeout/interruption: a wedged
    /// connection is discarded rather than reused.
    private func resetConnection() {
        connection?.invalidate()
        connection = nil
    }

    private func performInstall() async {
        // Local, deterministic package preflight before touching launchd: a broken
        // app bundle never attempts registration; it fails with a clear reason.
        if case let .incomplete(reason) = BundledHelperPackage.validateBundled(identity: TracexyIdentity.current) {
            status = .failed("Helper package is incomplete: \(reason)")
            Self.logger.error("bundled helper package incomplete: \(reason, privacy: .public)")
            return
        }
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
            switch await probeHelperInfoWithRetry() {
            case let .success(info):
                installedInfo = info
                probeFailureDetail = nil
                status = evaluateCompatibility(info)
                Self.logger.info(
                    "helper enabled: build=\(info.buildNumber) proto=\(info.protocolVersion) → \(String(describing: self.status))"
                )
            case let .failure(error):
                installedInfo = nil
                probeFailureDetail = error.detail
                status = .unreachable
                Self.logger.warning("helper enabled but unreachable: \(error.detail, privacy: .public)")
            }
        case .requiresApproval:
            status = .requiresApproval
            probeFailureDetail = nil
        case .notRegistered,
             .notFound:
            status = .notInstalled
            installedInfo = nil
            probeFailureDetail = nil
        @unknown default:
            status = .notInstalled
            installedInfo = nil
            probeFailureDetail = nil
        }
    }

    /// Probe `getHelperInfo` with a deterministic per-attempt timeout, a bounded
    /// number of attempts, and a fresh connection between attempts. Never hangs:
    /// a registered-but-wedged helper resolves to `.failure` within the bounded
    /// worst case rather than blocking forever.
    private func probeHelperInfoWithRetry() async -> Result<HelperInfo, HelperProbeError> {
        var lastError = HelperProbeError.unreachable("The helper did not respond.")
        for attempt in 1 ... Self.probeMaxAttempts {
            do {
                let info = try await fetchHelperInfo(timeoutNanoseconds: Self.probeTimeoutNanoseconds)
                return .success(info)
            } catch let error as HelperProbeError {
                lastError = error
            } catch {
                lastError = .unreachable(error.localizedDescription)
            }
            // Discard the (possibly wedged) connection before the next attempt.
            resetConnection()
            if attempt < Self.probeMaxAttempts {
                try? await Task.sleep(nanoseconds: Self.probeRetryDelayNanoseconds)
            }
        }
        return .failure(lastError)
    }

    /// One timeout-bounded XPC round-trip to `getHelperInfo`. The reply block, the
    /// remote-object error handler, and a cancellable deadline task all race to
    /// resume a single one-shot continuation gate (`ResumeOnce`); whichever fires
    /// first wins and the rest are no-ops. The deadline task is cancelled once the
    /// continuation resumes, so a prompt reply never waits out the timeout.
    private func fetchHelperInfo(timeoutNanoseconds: UInt64) async throws -> HelperInfo {
        let connection = openConnectionIfNeeded()
        let deadline = DeadlineBox()
        defer { deadline.cancel() }
        return try await withCheckedThrowingContinuation { continuation in
            let once = ResumeOnce(continuation)
            deadline.task = Task {
                try? await Task.sleep(nanoseconds: timeoutNanoseconds)
                once.resume(throwing: HelperProbeError.timedOut)
            }
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
                once.resume(throwing: HelperProbeError.unreachable(error.localizedDescription))
            }) as? TracexyHelperProtocol else {
                once.resume(throwing: HelperProbeError.unreachable("The helper is unreachable."))
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
        if Self.isApprovalRequired(serviceStatus: serviceStatus, error: error as NSError) {
            status = .requiresApproval
            SMAppService.openSystemSettingsLoginItems()
        } else {
            status = .failed(error.localizedDescription)
            Self.logger.error("helper register failed: \(error.localizedDescription, privacy: .public)")
        }
    }
}

// MARK: - OneShotGuard

/// A lock-backed "first caller wins" gate. `claim()` returns `true` exactly once —
/// for the first caller across any threads — and `false` forever after. The lock
/// guards only the flag flip; callers do their one-shot work (resuming a
/// continuation, cancelling a task) outside the lock so nothing runs while held.
///
/// Extracted from `ResumeOnce` so the race can be unit-tested without a live XPC
/// continuation.
final class OneShotGuard: @unchecked Sendable {
    // MARK: Internal

    /// Wins exactly once for the first caller; every later caller loses.
    func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !claimed else {
            return false
        }
        claimed = true
        return true
    }

    // MARK: Private

    private let lock = NSLock()
    private var claimed = false
}

// MARK: - HelperProbeError

/// Why an XPC probe of the installed helper failed, carrying a user-facing detail
/// so `.unreachable` can explain *why* a registered helper didn't answer.
enum HelperProbeError: Error, Equatable {
    case timedOut
    case unreachable(String)

    // MARK: Internal

    var detail: String {
        switch self {
        case .timedOut: "The helper didn’t respond within the timeout."
        case let .unreachable(message): message
        }
    }
}

// MARK: - DeadlineBox

/// Holds the cancellable deadline task for a single timeout-bounded probe so the
/// awaiting call can cancel it once the continuation resumes. Reference type: the
/// task is assigned synchronously inside the continuation body (before the first
/// suspension) and cancelled later from the caller's `defer`.
private final class DeadlineBox {
    var task: Task<Void, Never>?

    func cancel() {
        task?.cancel()
    }
}

// MARK: - ResumeOnce

/// Guards `fetchHelperInfo`'s checked continuation so it resumes exactly once,
/// even though the XPC reply block, the error handler, and the deadline task can
/// race on different threads. Backed by `OneShotGuard`.
///
/// Deliberately non-generic (specialized to `HelperInfo`): a generic version
/// crashed the Swift 6.2 SIL optimizer (EarlyPerfInliner, in the synthesized
/// deallocating destructor) under Release `-O -whole-module-optimization`. The
/// concrete layout sidesteps that. The continuation is resumed outside the gate's
/// lock so no continuation work runs while the lock is held.
private final class ResumeOnce: @unchecked Sendable {
    // MARK: Lifecycle

    init(_ continuation: CheckedContinuation<HelperInfo, Error>) {
        self.continuation = continuation
    }

    // MARK: Internal

    func resume(returning value: HelperInfo) {
        guard gate.claim() else {
            return
        }
        continuation.resume(returning: value)
    }

    func resume(throwing error: Error) {
        guard gate.claim() else {
            return
        }
        continuation.resume(throwing: error)
    }

    // MARK: Private

    private let continuation: CheckedContinuation<HelperInfo, Error>
    private let gate = OneShotGuard()
}

// MARK: - BundledHelperPackage

/// Deterministic, local preflight of the shipped helper package before it is
/// registered with launchd. Split into a pure validator over an already-parsed
/// launchd plist (unit-testable with synthetic dictionaries) and a thin live
/// orchestrator that reads the app bundle.
nonisolated enum BundledHelperPackage {
    // MARK: Internal

    /// What the bundled launchd plist must declare for this app build.
    struct Requirements: Equatable {
        let expectedLabel: String
        let expectedBundleProgram: String
        let expectedMachServiceName: String
        let expectedAssociatedBundleIdentifiers: [String]
    }

    enum Validation: Equatable {
        case ok
        /// The package is missing or inconsistent; the string is user-facing.
        case incomplete(reason: String)
    }

    /// Pure validation of a parsed launchd plist against the requirements. Checks
    /// `Label`, `BundleProgram`, that the Mach service is present *and* enabled,
    /// and that the app's bundle identifier is among `AssociatedBundleIdentifiers`.
    static func validateLaunchdPlist(_ plist: [String: Any], requirements: Requirements) -> Validation {
        guard let label = plist["Label"] as? String, !label.isEmpty else {
            return .incomplete(reason: "the launch daemon plist is missing its Label.")
        }
        guard label == requirements.expectedLabel else {
            return .incomplete(reason: "the launch daemon Label “\(label)” doesn’t match the expected helper identity.")
        }
        guard let program = plist["BundleProgram"] as? String, !program.isEmpty else {
            return .incomplete(reason: "the launch daemon plist is missing its BundleProgram path.")
        }
        guard program == requirements.expectedBundleProgram else {
            return .incomplete(
                reason: "the launch daemon BundleProgram “\(program)” doesn’t point at the bundled helper."
            )
        }
        guard let machServices = plist["MachServices"] as? [String: Any] else {
            return .incomplete(reason: "the launch daemon plist declares no MachServices.")
        }
        switch machServices[requirements.expectedMachServiceName] {
        case let flag as Bool where flag:
            break
        case let number as NSNumber where number.boolValue:
            break
        case .none:
            return .incomplete(
                reason: "the launch daemon plist doesn’t vend the “\(requirements.expectedMachServiceName)” Mach service."
            )
        default:
            return .incomplete(
                reason: "the “\(requirements.expectedMachServiceName)” Mach service is disabled in the launch daemon plist."
            )
        }
        guard let associated = plist["AssociatedBundleIdentifiers"] as? [String], !associated.isEmpty else {
            return .incomplete(reason: "the launch daemon plist is missing AssociatedBundleIdentifiers.")
        }
        let normalizedAssociated = normalizedIdentifiers(associated)
        let normalizedExpected = normalizedIdentifiers(requirements.expectedAssociatedBundleIdentifiers)
        guard normalizedAssociated == normalizedExpected else {
            return .incomplete(
                reason: "the launch daemon plist has unexpected AssociatedBundleIdentifiers."
            )
        }
        return .ok
    }

    /// Live orchestrator: verifies the helper executable is a runnable regular
    /// file and the launchd plist parses, then delegates to `validateLaunchdPlist`.
    static func validateBundled(
        identity: TracexyIdentity,
        bundle: Bundle = .main,
        fileManager: FileManager = .default
    )
        -> Validation
    {
        let helperBinary = bundle.bundleURL
            .appendingPathComponent(HelperClient.bundledHelperBinaryRelativePath, isDirectory: false)
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: helperBinary.path, isDirectory: &isDirectory),
              !isDirectory.boolValue else
        {
            return .incomplete(reason: "the bundled helper executable is missing.")
        }
        guard fileManager.isExecutableFile(atPath: helperBinary.path) else {
            return .incomplete(reason: "the bundled helper executable isn’t runnable.")
        }
        let plistURL = bundle.bundleURL
            .appendingPathComponent("Contents/Library/LaunchDaemons/\(identity.helperPlistName)", isDirectory: false)
        guard let data = try? Data(contentsOf: plistURL),
              let raw = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let plist = raw as? [String: Any] else
        {
            return .incomplete(reason: "the bundled launch daemon plist is missing or unreadable.")
        }
        return validateLaunchdPlist(plist, requirements: Requirements(
            expectedLabel: identity.helperMachServiceName,
            expectedBundleProgram: HelperClient.bundledHelperBinaryRelativePath,
            expectedMachServiceName: identity.helperMachServiceName,
            expectedAssociatedBundleIdentifiers: identity.allowedCallerIdentifiers
        ))
    }

    // MARK: Private

    private static func normalizedIdentifiers(_ identifiers: [String]) -> [String] {
        Array(
            Set(
                identifiers
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .filter { !$0.isEmpty }
            )
        )
        .sorted()
    }
}
