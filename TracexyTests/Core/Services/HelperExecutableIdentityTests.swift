import CryptoKit
import Foundation
import Testing
@testable import Tracexy

// MARK: - HelperExecutableIdentityTests

@Suite("Helper executable identity")
struct HelperExecutableIdentityTests {
    @Test("Digest is exact, lowercase, and bounded")
    func digest() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let executable = directory.appendingPathComponent("helper")
        let bytes = Data("tracexy-helper".utf8)
        try bytes.write(to: executable)

        let expected = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        let actual = try HelperExecutableDigest.sha256Hex(atPath: executable.path)

        #expect(actual == expected)
        #expect(HelperExecutableDigest.isWellFormedDigest(actual))
        #expect(!HelperExecutableDigest.isWellFormedDigest(String(repeating: "A", count: 64)))
        #expect(!HelperExecutableDigest.isWellFormedDigest(String(repeating: "ａ", count: 64)))
        #expect(throws: HelperExecutableDigest.Failure.tooLarge(path: executable.path)) {
            try HelperExecutableDigest.sha256Hex(atPath: executable.path, maximumByteCount: bytes.count - 1)
        }
    }

    @Test("Identity rejects missing provenance")
    func malformedIdentity() {
        #expect(!HelperExecutableIdentity(
            executableDigest: "",
            launchIdentity: "",
            processIdentifier: 0,
            executablePath: "",
            buildNumber: 0,
            protocolVersion: 0
        ).isWellFormed)
    }
}

// MARK: - HelperLaunchSigningSnapshotTests

@Suite("Helper launch signing snapshot")
struct HelperLaunchSigningSnapshotTests {
    @Test("Signing authority decisions use profiles, not executable paths")
    func profileComparison() {
        let helper = CallerValidation.CodeSigningProfile(
            identifier: "com.example.helper",
            teamIdentifier: "TEAM123",
            certificateDERs: [],
            executablePath: "/old/App.app/helper"
        )
        let caller = CallerValidation.CodeSigningProfile(
            identifier: "com.example.app",
            teamIdentifier: "TEAM123",
            certificateDERs: [],
            executablePath: "/new/App.app/app"
        )

        #expect(CallerValidation.signingAuthoritiesMatch(helper: helper, caller: caller))
        #expect(!CallerValidation.signingAuthoritiesMatch(helper: helper, caller: nil))
    }
}
