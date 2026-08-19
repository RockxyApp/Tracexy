import Foundation
import Security
import Testing
@testable import Tracexy

// MARK: - ConnectionValidatorAuditTokenTests

/// Pins the audit-token-first authorization contract of the privileged-helper XPC entrypoint:
/// authorization derives from the connection's audit token, both validation layers evaluate the
/// same audit-token-derived `SecCode`, and every audit-token problem fails closed. The caller's
/// PID is logging context only and can never authorize a connection on its own.
@Suite("Audit-token caller authorization")
struct ConnectionValidatorAuditTokenTests {
    // MARK: Internal

    @Test("A missing audit token is rejected (fails closed)")
    func missingTokenFailsClosed() {
        // PID is deliberately the current process, which the diagnostic PID path would accept —
        // proving the entrypoint never authorizes on PID when the token is absent.
        let ownPid = ProcessInfo.processInfo.processIdentifier
        #expect(ConnectionValidator.validateCaller(auditTokenData: nil, pid: ownPid) == false)
    }

    @Test("Never accept because PID validation would pass when the audit token is absent")
    func pidPassButTokenAbsentIsRejected() throws {
        let token = try #require(CallerValidation.currentProcessAuditToken())
        let code = try #require(CallerValidation.secCodeFromAuditToken(token))
        let ownIdentifier = try #require(CallerValidation.signingIdentifier(of: code))
        let ownPid = ProcessInfo.processInfo.processIdentifier

        // The diagnostics-only PID path authorizes this host against its own identifier...
        #expect(CallerValidation.validateCaller(pid: ownPid, allowedIdentifiers: [ownIdentifier]))
        // ...but the production entrypoint still fails closed with no audit token.
        #expect(ConnectionValidator.validateCaller(auditTokenData: nil, pid: ownPid) == false)
    }

    @Test("A wrong-sized audit token cannot resolve to a SecCode and is rejected")
    func wrongSizedTokenFailsClosed() {
        let ownPid = ProcessInfo.processInfo.processIdentifier
        let undersized = Data(count: 8) // audit_token_t is 32 bytes
        #expect(CallerValidation.secCodeFromAuditToken(undersized) == nil)
        #expect(ConnectionValidator.validateCaller(auditTokenData: undersized, pid: ownPid) == false)
    }

    @Test("A correctly-sized but unresolvable audit token is rejected")
    func unresolvableTokenFailsClosed() {
        let ownPid = ProcessInfo.processInfo.processIdentifier
        // Correctly sized (32 bytes) but filled with a pattern that maps to no live guest.
        let bogus = Data(repeating: 0xFF, count: MemoryLayout<audit_token_t>.size)
        // The security-relevant invariant: whether Security resolves it or not, it is never us,
        // so the caller is rejected and never authorized on the accompanying PID.
        #expect(ConnectionValidator.validateCaller(auditTokenData: bogus, pid: ownPid) == false)
    }

    @Test("A resolvable token whose identifier is not on the allowlist is rejected")
    func allowedIdentifierMismatchIsRejected() throws {
        let token = try #require(CallerValidation.currentProcessAuditToken())
        let code = try #require(CallerValidation.secCodeFromAuditToken(token))
        // Layer 1 (signing-authority match) passes for self, but layer 2 (bundle identity) must
        // fail because the running host's identifier is not on this allowlist.
        #expect(CallerValidation.validateCallerCode(code, allowedIdentifiers: notAllowedIdentifiers) == false)
    }

    @Test("The current process's own audit token passes full two-layer validation")
    func currentProcessTokenPassesWhenAllowed() throws {
        // Holds under the supported signing contexts: local Xcode DerivedData ad-hoc builds and
        // Apple-anchored (Developer ID) release builds. Both the token and its SecCode must exist
        // in this macOS test environment, so they are required rather than expected.
        let token = try #require(CallerValidation.currentProcessAuditToken())
        let code = try #require(CallerValidation.secCodeFromAuditToken(token))
        let ownIdentifier = try #require(CallerValidation.signingIdentifier(of: code))

        #expect(CallerValidation.validateCallerCode(code, allowedIdentifiers: [ownIdentifier]))
    }

    // MARK: Private

    private let notAllowedIdentifiers = ["com.example.definitely.not.a.tracexy.caller"]
}
