import Foundation
import os
import Security

/// XPC Caller Validation Model (audit-token-first, two-layer defense-in-depth):
///
/// Authorization is derived entirely from the connection's **audit token**. The token is
/// resolved to a single caller `SecCode`, and BOTH of the following layers are evaluated
/// against that one code. The caller's PID is used only as logging context — never as
/// authorization evidence — which eliminates the PID-recycling TOCTOU window and the old
/// permissive "PID passed, token absent" fallback. Validation fails closed on any audit-token
/// problem (unavailable, wrong-sized, or unresolvable to a `SecCode`).
///
/// 1. **Signing-authority match**: requires the caller and this process to share the same Apple
///    TeamIdentifier, keeping one canonical helper usable across Apple Development Xcode builds
///    and Developer ID release builds. When a TeamIdentifier is unavailable, validation falls
///    back to exact certificate-chain comparison, then to the local Xcode ad-hoc DerivedData
///    pairing.
///
/// 2. **Bundle identity requirement** (Apple SecRequirement pattern): validates the caller
///    matches one of the configured Tracexy app bundle identifiers, not just any app sharing
///    the same developer certificate, by checking the audit-token-derived `SecCode` against a
///    `SecRequirement` for each allowed identifier.
///
/// Both checks must pass for a connection to be accepted.
///
/// References:
/// - Pearcleaner `CodesignCheck.swift` for certificate chain comparison
/// - smjobbless `XPCServer.swift` for `SecRequirement`-based audit token validation
/// - Apple `SecCodeCheckValidity` / `SecRequirementCreateWithString` documentation
///
enum ConnectionValidator {
    // MARK: Internal

    // MARK: - Public API

    /// Production entrypoint: validates a real incoming XPC connection.
    ///
    /// Fails closed when the audit token cannot be extracted; the PID is logged for diagnostics
    /// only and never authorizes the caller on its own.
    static func isValidCaller(_ connection: NSXPCConnection) -> Bool {
        let pid = connection.processIdentifier
        guard let auditTokenData = extractAuditTokenData(from: connection) else {
            logger.error("SECURITY: rejecting caller (pid \(pid)) — audit token unavailable; failing closed")
            return false
        }
        return validateCaller(auditTokenData: auditTokenData, pid: pid)
    }

    /// Testable entrypoint: authorizes a caller solely from its audit token data.
    /// The production `isValidCaller(_:)` delegates here after extracting the token; the `pid`
    /// argument is logging context only and does not participate in the authorization decision.
    ///
    /// Rejects (fails closed) when the token is missing, the wrong size, or cannot be resolved to
    /// a `SecCode`. On a resolvable token, the derived caller code must satisfy the full two-layer
    /// validation (signing-authority match AND bundle-identity allowlist).
    static func validateCaller(auditTokenData: Data?, pid: pid_t) -> Bool {
        guard let tokenData = auditTokenData else {
            logger.error("SECURITY: rejecting caller (pid \(pid)) — audit token missing; failing closed")
            return false
        }

        guard let callerCode = CallerValidation.secCodeFromAuditToken(tokenData) else {
            logger.error(
                "SECURITY: rejecting caller (pid \(pid)) — audit token malformed or unresolvable; failing closed"
            )
            return false
        }

        guard CallerValidation.validateCallerCode(
            callerCode,
            allowedIdentifiers: allowedCallerIdentifiers
        ) else {
            logger.error("SECURITY: audit-token two-layer validation failed for caller (pid \(pid))")
            return false
        }

        logger.info("SECURITY: audit-token two-layer validation passed for caller (pid \(pid))")
        return true
    }

    /// Extracts raw audit token data from an NSXPCConnection via KVC.
    /// Returns `nil` if the token is unavailable (client-side connections,
    /// KVC failure, or unexpected runtime type).
    static func extractAuditTokenData(from connection: NSXPCConnection) -> Data? {
        guard let tokenValue = connection.value(forKey: "auditToken") else {
            logger.debug("SECURITY: auditToken KVC returned nil")
            return nil
        }

        if let data = tokenValue as? Data {
            return data
        }

        var token = audit_token_t()
        let expectedSize = MemoryLayout<audit_token_t>.size
        guard let nsValue = tokenValue as? NSValue else {
            logger.debug("SECURITY: auditToken KVC returned unexpected type: \(type(of: tokenValue))")
            return nil
        }
        nsValue.getValue(&token, size: expectedSize)
        return Data(bytes: &token, count: expectedSize)
    }

    // MARK: Private

    private static let logger = Logger(
        subsystem: TracexyIdentity.current.logSubsystem,
        category: "ConnectionValidator"
    )

    private static let allowedCallerIdentifiers = TracexyIdentity.current.allowedCallerIdentifiers
}
