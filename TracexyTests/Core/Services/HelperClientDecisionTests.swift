import Foundation
import ServiceManagement
import Testing
@testable import Tracexy

// MARK: - OneShotGuardTests

// Pure, deterministic coverage for the helper-lifecycle decision points that must
// never touch real XPC, registration, or privileged commands.

@Suite("Helper one-shot resume gate")
struct OneShotGuardTests {
    @Test("Admits exactly one claimant under heavy contention")
    func admitsExactlyOne() {
        let gate = OneShotGuard()
        let winners = LockedCounter()

        // Many threads race to claim; the gate must let exactly one through — this
        // is the invariant that keeps the probe continuation resumed exactly once
        // when reply / error / timeout fire together.
        DispatchQueue.concurrentPerform(iterations: 4_000) { _ in
            if gate.claim() {
                winners.increment()
            }
        }

        #expect(winners.value == 1)
    }

    @Test("A second sequential claim always loses")
    func secondClaimLoses() {
        let gate = OneShotGuard()
        #expect(gate.claim())
        #expect(!gate.claim())
        #expect(!gate.claim())
    }
}

// MARK: - LockedCounter

private final class LockedCounter: @unchecked Sendable {
    // MARK: Internal

    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return count
    }

    func increment() {
        lock.lock()
        defer { lock.unlock() }
        count += 1
    }

    // MARK: Private

    private let lock = NSLock()
    private var count = 0
}

// MARK: - HelperCompatibilityTests

@Suite("Helper compatibility classification")
struct HelperCompatibilityTests {
    @Test("Same protocol and at-or-above the bundled build is compatible")
    func compatible() {
        let atBuild = HelperClient.classifyCompatibility(
            HelperInfo(binaryVersion: "1.0.0", buildNumber: 10, protocolVersion: 3),
            expectedProtocolVersion: 3,
            bundledBuild: 10
        )
        let aboveBuild = HelperClient.classifyCompatibility(
            HelperInfo(binaryVersion: "1.0.1", buildNumber: 11, protocolVersion: 3),
            expectedProtocolVersion: 3,
            bundledBuild: 10
        )
        #expect(atBuild == .installedCompatible)
        #expect(aboveBuild == .installedCompatible)
    }

    @Test("Same protocol but an older build is outdated")
    func outdated() {
        let result = HelperClient.classifyCompatibility(
            HelperInfo(binaryVersion: "0.9.0", buildNumber: 9, protocolVersion: 3),
            expectedProtocolVersion: 3,
            bundledBuild: 10
        )
        #expect(result == .installedOutdated)
    }

    @Test("A different protocol is incompatible regardless of build")
    func incompatible() {
        let older = HelperClient.classifyCompatibility(
            HelperInfo(binaryVersion: "1.0.0", buildNumber: 100, protocolVersion: 2),
            expectedProtocolVersion: 3,
            bundledBuild: 10
        )
        #expect(older == .installedIncompatible)
    }

    @Test("A pre-v3 helper is incompatible against the current v3 protocol; v3 is fine")
    func protocolV3AgainstOlder() {
        // The typed-CaptureConfiguration start surface bumped the protocol to 3. A
        // previously installed v2 helper — even a newer build — must be classified
        // incompatible so Start stays gated (no downgraded start request) and the
        // old helper must be reinstalled, while a matching v3 helper at the shipped
        // build is compatible.
        let legacyV2 = HelperClient.classifyCompatibility(
            HelperInfo(binaryVersion: "0.1.2", buildNumber: 99, protocolVersion: 2),
            expectedProtocolVersion: 3,
            bundledBuild: 4
        )
        let currentV3 = HelperClient.classifyCompatibility(
            HelperInfo(binaryVersion: "0.1.3", buildNumber: 4, protocolVersion: 3),
            expectedProtocolVersion: 3,
            bundledBuild: 4
        )

        #expect(legacyV2 == .installedIncompatible)
        #expect(currentV3 == .installedCompatible)
        // An incompatible helper maps Start to a clear, gated message, not ready.
        #expect(
            HelperClient.captureAvailability(for: legacyV2, unreachableDetail: nil)
                == .unavailable("the installed helper uses an incompatible protocol. Update it in Settings → Helper.")
        )
    }
}

// MARK: - CaptureAvailabilityTests

@Suite("Capture Start availability mapping")
struct CaptureAvailabilityTests {
    @Test("Compatible and outdated are both ready to capture")
    func ready() {
        #expect(HelperClient.captureAvailability(for: .installedCompatible, unreachableDetail: nil) == .ready)
        #expect(HelperClient.captureAvailability(for: .installedOutdated, unreachableDetail: nil) == .ready)
    }

    @Test("Approval maps through, not to ready")
    func approval() {
        #expect(HelperClient.captureAvailability(for: .requiresApproval, unreachableDetail: nil) == .requiresApproval)
    }

    @Test("Broken helpers are surfaced as unavailable, never ready")
    func unavailable() {
        for status in [
            HelperClient.Status.installedIncompatible,
            .signingMismatch,
            .notInstalled,
            .failed("boom"),
        ] {
            let availability = HelperClient.captureAvailability(for: status, unreachableDetail: nil)
            guard case .unavailable = availability else {
                Issue.record("expected .unavailable for \(status)")
                continue
            }
        }
    }

    @Test("Unreachable carries the probe detail so the user learns why")
    func unreachableDetail() {
        let availability = HelperClient.captureAvailability(
            for: .unreachable,
            unreachableDetail: "The helper didn’t respond within the timeout."
        )
        guard case let .unavailable(detail) = availability else {
            Issue.record("expected .unavailable")
            return
        }
        #expect(detail == "The helper didn’t respond within the timeout.")
    }
}

// MARK: - HelperRegistrationRepairTests

@Suite("Registration-repair availability")
struct HelperRegistrationRepairTests {
    @Test("Only a registered-but-unreachable helper offers registration repair")
    func onlyUnreachable() {
        #expect(HelperClient.offersRegistrationRepair(for: .unreachable))
    }

    @Test("Every other status routes to its own specific action, not repair")
    func everythingElseDoesNot() {
        for status in [
            HelperClient.Status.notInstalled,
            .requiresApproval,
            .installedCompatible,
            .installedOutdated,
            .installedIncompatible,
            .signingMismatch,
            .failed("boom"),
        ] {
            #expect(!HelperClient.offersRegistrationRepair(for: status))
        }
    }
}

// MARK: - HelperApprovalClassificationTests

@Suite("Helper approval-error classification")
struct HelperApprovalClassificationTests {
    @Test("SMAppService already reporting requiresApproval is approval")
    func statusRequiresApproval() {
        let unrelated = NSError(domain: NSCocoaErrorDomain, code: NSFileNoSuchFileError)
        #expect(HelperClient.isApprovalRequired(serviceStatus: .requiresApproval, error: unrelated))
    }

    @Test("kSMErrorLaunchDeniedByUser is approval")
    func launchDeniedByUser() {
        let error = NSError(domain: NSOSStatusErrorDomain, code: kSMErrorLaunchDeniedByUser)
        #expect(HelperClient.isApprovalRequired(serviceStatus: .enabled, error: error))
    }

    @Test("The OSStatus operation-not-permitted early block is approval")
    func operationNotPermitted() {
        let error = NSError(domain: NSOSStatusErrorDomain, code: 1)
        #expect(HelperClient.isApprovalRequired(serviceStatus: .enabled, error: error))
    }

    @Test("Unrelated errors are not misclassified as approval")
    func doesNotMisclassify() {
        let cocoa = NSError(domain: NSCocoaErrorDomain, code: NSFileNoSuchFileError)
        // A POSIX EPERM (code 1) in a different domain must not trip the OSStatus rule.
        let posix = NSError(domain: NSPOSIXErrorDomain, code: 1)
        #expect(!HelperClient.isApprovalRequired(serviceStatus: .enabled, error: cocoa))
        #expect(!HelperClient.isApprovalRequired(serviceStatus: .enabled, error: posix))
    }
}

// MARK: - HelperProbeErrorTests

@Suite("Helper probe error detail")
struct HelperProbeErrorTests {
    @Test("Timeout describes the timeout; unreachable passes its message through")
    func detail() {
        #expect(HelperProbeError.timedOut.detail.localizedCaseInsensitiveContains("timeout"))
        #expect(HelperProbeError.unreachable("connection invalid").detail == "connection invalid")
    }
}
