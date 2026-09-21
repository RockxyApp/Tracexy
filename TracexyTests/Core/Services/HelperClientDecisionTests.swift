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
            HelperInfo(binaryVersion: "2.2.0", buildNumber: 8, protocolVersion: 5),
            expectedProtocolVersion: 5,
            bundledBuild: 8
        )
        let aboveBuild = HelperClient.classifyCompatibility(
            HelperInfo(binaryVersion: "2.2.1", buildNumber: 9, protocolVersion: 5),
            expectedProtocolVersion: 5,
            bundledBuild: 8
        )
        #expect(atBuild == .installedCompatible)
        #expect(aboveBuild == .installedCompatible)
    }

    @Test("Same protocol but an older build is outdated")
    func outdated() {
        let result = HelperClient.classifyCompatibility(
            HelperInfo(binaryVersion: "2.1.0", buildNumber: 7, protocolVersion: 5),
            expectedProtocolVersion: 5,
            bundledBuild: 8
        )
        #expect(result == .installedOutdated)
    }

    @Test("A different protocol is incompatible regardless of build")
    func incompatible() {
        let older = HelperClient.classifyCompatibility(
            HelperInfo(binaryVersion: "9.0.0", buildNumber: 100, protocolVersion: 6),
            expectedProtocolVersion: 5,
            bundledBuild: 8
        )
        #expect(older == .installedIncompatible)
    }

    @Test("Protocol v4 stays capture-compatible but is outdated against v5")
    func protocolV4AgainstV5() {
        // Protocol v5 adds maintenance selectors without changing v4's typed
        // capture commands, so v4 can still capture while awaiting one explicit
        // migration.
        let legacyV4 = HelperClient.classifyCompatibility(
            HelperInfo(binaryVersion: "2.1.0", buildNumber: 99, protocolVersion: 4),
            expectedProtocolVersion: 5,
            bundledBuild: 8
        )
        let currentV5 = HelperClient.classifyCompatibility(
            HelperInfo(binaryVersion: "2.2.0", buildNumber: 8, protocolVersion: 5),
            expectedProtocolVersion: 5,
            bundledBuild: 8
        )

        #expect(legacyV4 == .installedOutdated)
        #expect(currentV5 == .installedCompatible)
        #expect(HelperClient.captureAvailability(for: legacyV4, unreachableDetail: nil) == .ready)
    }
}

// MARK: - HelperUpdatePlanTests

@Suite("Helper executable update planning")
struct HelperUpdatePlanTests {
    // MARK: Internal

    @Test("Exact v5 metadata and executable identity are up to date")
    func upToDate() {
        let info = HelperInfo(binaryVersion: "2.2.0", buildNumber: 8, protocolVersion: 5)
        let identity = HelperExecutableIdentity(
            executableDigest: digest,
            launchIdentity: UUID().uuidString,
            processIdentifier: 42,
            executablePath: "/Applications/Tracexy.app/helper",
            buildNumber: 8,
            protocolVersion: 5
        )
        #expect(HelperClient.updatePlan(
            status: .installedCompatible,
            installedInfo: info,
            installedIdentity: identity,
            expectedProtocolVersion: 5,
            bundledBuildNumber: 8,
            candidateDigest: digest
        ) == .upToDate)
    }

    @Test("Matching version numbers cannot hide different executable bytes")
    func digestDriftRefreshes() {
        let info = HelperInfo(binaryVersion: "2.2.0", buildNumber: 8, protocolVersion: 5)
        let identity = HelperExecutableIdentity(
            executableDigest: String(repeating: "b", count: 64),
            launchIdentity: UUID().uuidString,
            processIdentifier: 42,
            executablePath: "/Applications/Tracexy.app/helper",
            buildNumber: 8,
            protocolVersion: 5
        )
        #expect(HelperClient.updatePlan(
            status: .installedCompatible,
            installedInfo: info,
            installedIdentity: identity,
            expectedProtocolVersion: 5,
            bundledBuildNumber: 8,
            candidateDigest: digest
        ) == .approvalPreservingRefresh)
    }

    @Test("Only known v4 uses the explicit legacy migration")
    func legacyProtocols() {
        let v4 = HelperClient.updatePlan(
            status: .installedOutdated,
            installedInfo: HelperInfo(binaryVersion: "2.1.0", buildNumber: 7, protocolVersion: 4),
            installedIdentity: nil,
            expectedProtocolVersion: 5,
            bundledBuildNumber: 8,
            candidateDigest: digest
        )
        let v3 = HelperClient.updatePlan(
            status: .installedIncompatible,
            installedInfo: HelperInfo(binaryVersion: "1.9.0", buildNumber: 6, protocolVersion: 3),
            installedIdentity: nil,
            expectedProtocolVersion: 5,
            bundledBuildNumber: 8,
            candidateDigest: digest
        )
        #expect(v4 == .legacyManualMigration)
        #expect(v3 == .blocked(.incompatibleProtocol))
    }

    @Test("A newer installed helper is never downgraded")
    func noDowngrade() {
        #expect(HelperClient.updatePlan(
            status: .installedIncompatible,
            installedInfo: HelperInfo(binaryVersion: "2.3.0", buildNumber: 9, protocolVersion: 5),
            installedIdentity: nil,
            expectedProtocolVersion: 5,
            bundledBuildNumber: 8,
            candidateDigest: digest
        ) == .blocked(.downgradeRefused))
    }

    // MARK: Private

    private let digest = String(repeating: "a", count: 64)
}

// MARK: - CaptureAvailabilityTests

@Suite("Capture Start availability mapping")
struct CaptureAvailabilityTests {
    @Test("Compatible and outdated are both ready to capture")
    func ready() {
        #expect(HelperClient.captureAvailability(for: .installedCompatible, unreachableDetail: nil) == .ready)
        #expect(HelperClient.captureAvailability(for: .installedOutdated, unreachableDetail: nil) == .ready)
    }

    @Test("v5 capture requires exact executable convergence")
    func v5RequiresExecutableConvergence() {
        let info = HelperInfo(binaryVersion: "2.2.0", buildNumber: 8, protocolVersion: 5)
        let driftedIdentity = HelperExecutableIdentity(
            executableDigest: String(repeating: "b", count: 64),
            launchIdentity: UUID().uuidString,
            processIdentifier: 42,
            executablePath: "/Applications/Tracexy.app/helper",
            buildNumber: 8,
            protocolVersion: 5
        )

        let availability = HelperClient.captureAvailability(
            for: .installedCompatible,
            installedInfo: info,
            installedIdentity: driftedIdentity,
            expectedProtocolVersion: 5,
            bundledBuildNumber: 8,
            candidateDigest: String(repeating: "a", count: 64),
            unreachableDetail: nil
        )

        guard case let .unavailable(detail) = availability else {
            Issue.record("expected v5 drift to block capture")
            return
        }
        #expect(detail.localizedCaseInsensitiveContains("verification"))
    }

    @Test("Known v4 remains capture-ready while awaiting explicit migration")
    func v4MigrationCanStillCapture() {
        let availability = HelperClient.captureAvailability(
            for: .installedOutdated,
            installedInfo: HelperInfo(binaryVersion: "2.1.0", buildNumber: 7, protocolVersion: 4),
            installedIdentity: nil,
            expectedProtocolVersion: 5,
            bundledBuildNumber: 8,
            candidateDigest: String(repeating: "a", count: 64),
            unreachableDetail: nil
        )

        #expect(availability == .ready)
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
