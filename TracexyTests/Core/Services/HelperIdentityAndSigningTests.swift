import Foundation
import Testing
@testable import Tracexy

// MARK: - SigningDiagnosticsPathTests

@Suite("Signing diagnostics helper-path selection")
struct SigningDiagnosticsPathTests {
    @Test("Diagnostics target the bundled helper launchd actually executes")
    func bundledOnly() {
        let bundled = URL(fileURLWithPath: "/Applications/Tracexy.app")
            .appendingPathComponent(HelperClient.bundledHelperBinaryRelativePath, isDirectory: false)

        let candidates = SigningDiagnostics.helperExecutableCandidates(bundledHelperURL: bundled)

        #expect(candidates == [bundled])
    }

    @Test("The stale legacy /Library/PrivilegedHelperTools artifact is never considered")
    func noLegacyPrivilegedHelperTools() {
        let bundled = URL(fileURLWithPath: "/Applications/Tracexy.app")
            .appendingPathComponent(HelperClient.bundledHelperBinaryRelativePath, isDirectory: false)

        let candidates = SigningDiagnostics.helperExecutableCandidates(bundledHelperURL: bundled)

        #expect(!candidates.contains { $0.path.contains("/Library/PrivilegedHelperTools") })
    }
}

// MARK: - HelperIdentityConsistencyTests

/// Local-dev and production identities are derived from the same bundle-driven
/// keys, so the launchd plist filename, Mach service, and caller allowlist always
/// move together. These tests pin that isolation: a dev-namespaced build can never
/// resolve to the production helper label / plist that launchd keys BTM on.
@Suite("Local-dev vs production helper identity")
struct HelperIdentityConsistencyTests {
    @Test("Production Community identity is exactly the shipping helper label/plist")
    func production() {
        let production = TracexyIdentity(infoDictionary: [
            "CFBundleIdentifier": "com.amunx.tracexy.community",
            "TracexyFamilyNamespace": "com.amunx.tracexy",
            "TracexyHelperBundleIdentifier": "com.amunx.tracexy.helper",
            "TracexyHelperMachServiceName": "com.amunx.tracexy.helper",
            "TracexyHelperPlistName": "com.amunx.tracexy.helper.plist",
            "TracexyAllowedCallerIdentifiers": "com.amunx.tracexy.community com.amunx.tracexy",
        ])

        #expect(production.helperBundleIdentifier == "com.amunx.tracexy.helper")
        #expect(production.helperMachServiceName == "com.amunx.tracexy.helper")
        #expect(production.helperPlistName == "com.amunx.tracexy.helper.plist")
        #expect(production.allowedCallerIdentifiers.contains("com.amunx.tracexy.community"))
    }

    @Test("Local-dev identity is fully isolated from the production helper label/plist")
    func localDevIsolated() {
        let dev = TracexyIdentity(infoDictionary: [
            "CFBundleIdentifier": "com.amunx.tracexy.dev",
            "TracexyFamilyNamespace": "com.amunx.tracexy",
            "TracexyHelperBundleIdentifier": "com.amunx.tracexy.dev.helper",
            "TracexyHelperMachServiceName": "com.amunx.tracexy.dev.helper",
            "TracexyHelperPlistName": "com.amunx.tracexy.dev.helper.plist",
            "TracexyAllowedCallerIdentifiers": "com.amunx.tracexy.dev",
        ])
        let production = "com.amunx.tracexy.helper"

        #expect(dev.helperBundleIdentifier != production)
        #expect(dev.helperMachServiceName != production)
        #expect(dev.helperPlistName != "\(production).plist")
        #expect(dev.helperPlistName == "\(dev.helperMachServiceName).plist")
        // Only the dev app is a trusted caller of the dev helper.
        #expect(dev.allowedCallerIdentifiers == ["com.amunx.tracexy.dev"])
    }

    @Test("The launchd plist filename always follows the Mach-service identity")
    func plistFollowsMachService() {
        for machService in ["com.amunx.tracexy.helper", "com.amunx.tracexy.dev.helper"] {
            let identity = TracexyIdentity(infoDictionary: [
                "TracexyHelperMachServiceName": machService,
                "TracexyHelperPlistName": "\(machService).plist",
            ])
            #expect(identity.helperPlistName == "\(identity.helperMachServiceName).plist")
        }
    }
}
