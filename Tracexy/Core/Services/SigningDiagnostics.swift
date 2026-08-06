import Foundation
import OSLog
import Security

/// App-side signing diagnostics that detect certificate mismatches between the
/// running app and the installed helper binary BEFORE attempting XPC.
///
/// Two layers for testability:
/// 1. `Environment` abstracts the Security framework calls.
/// 2. `classify(_:)` is a pure function mapping observations to a result.
enum SigningDiagnostics {
    // MARK: Internal

    enum Result: Equatable {
        /// App signature valid, helper exists, certificate chains match.
        case healthy
        /// App bundle code signature is invalid (e.g. a stale Xcode build).
        case appSignatureInvalid(detail: String)
        /// App is valid, helper binary exists, but signing identities differ.
        case signingIdentityMismatch(appSigner: String, helperSigner: String)
        /// App is valid, but no helper binary exists at the expected path.
        case helperBinaryNotFound
        /// At least one binary is signed without an extractable certificate chain
        /// (common for local ad-hoc helper repair paths).
        case certificateChainUnavailable
        /// An unexpected error occurred during diagnosis.
        case diagnosticError(detail: String)
    }

    protocol Environment {
        func validateAppSignature() -> String?
        func helperBinaryExists() -> Bool
        func appSignerSummary() -> String?
        func helperSignerSummary() -> String?
        func appCertificateChain() -> [Data]?
        func helperCertificateChain() -> [Data]?
    }

    // MARK: - Live Environment

    struct LiveEnvironment: Environment {
        // MARK: Internal

        func validateAppSignature() -> String? {
            var code: SecCode?
            guard SecCodeCopySelf([], &code) == errSecSuccess, let selfCode = code else {
                return "SecCodeCopySelf failed"
            }
            var staticCode: SecStaticCode?
            guard SecCodeCopyStaticCode(selfCode, [], &staticCode) == errSecSuccess,
                  let selfStatic = staticCode else
            {
                return "SecCodeCopyStaticCode failed"
            }
            let status = SecStaticCodeCheckValidity(selfStatic, SecCSFlags([]), nil)
            if status != errSecSuccess {
                let desc = SecCopyErrorMessageString(status, nil) as String? ?? "unknown"
                return "Code signature invalid: OSStatus \(status) (\(desc))"
            }
            return nil
        }

        func helperBinaryExists() -> Bool {
            resolvedHelperExecutableURL != nil
        }

        func appSignerSummary() -> String? {
            guard let chain = appCertificateChain(), let leafDER = chain.first else {
                return nil
            }
            return summaryFromDER(leafDER)
        }

        func helperSignerSummary() -> String? {
            guard let chain = helperCertificateChain(), let leafDER = chain.first else {
                return nil
            }
            return summaryFromDER(leafDER)
        }

        func appCertificateChain() -> [Data]? {
            certificateChainForSelf()
        }

        func helperCertificateChain() -> [Data]? {
            guard let helperURL = resolvedHelperExecutableURL else {
                return nil
            }
            return certificateChainForURL(helperURL)
        }

        // MARK: Private

        private var resolvedHelperExecutableURL: URL? {
            SigningDiagnostics.helperExecutableCandidates().first { candidateURL in
                FileManager.default.isExecutableFile(atPath: candidateURL.path)
            }
        }

        private func certificateChainForSelf() -> [Data]? {
            var code: SecCode?
            guard SecCodeCopySelf([], &code) == errSecSuccess, let selfCode = code else {
                return nil
            }
            var staticCode: SecStaticCode?
            guard SecCodeCopyStaticCode(selfCode, [], &staticCode) == errSecSuccess,
                  let staticCode else
            {
                return nil
            }
            return extractCertificateDERs(from: staticCode)
        }

        private func certificateChainForURL(_ url: URL) -> [Data]? {
            var staticCode: SecStaticCode?
            guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess,
                  let staticCode else
            {
                return nil
            }
            return extractCertificateDERs(from: staticCode)
        }

        private func extractCertificateDERs(from staticCode: SecStaticCode) -> [Data]? {
            var info: CFDictionary?
            guard SecCodeCopySigningInformation(
                staticCode,
                SecCSFlags(rawValue: kSecCSSigningInformation),
                &info
            ) == errSecSuccess,
                let dict = info as? [String: Any],
                let certs = dict[kSecCodeInfoCertificates as String] as? [SecCertificate],
                !certs.isEmpty else
            {
                return nil
            }
            return certs.map { SecCertificateCopyData($0) as Data }
        }

        private func summaryFromDER(_ der: Data) -> String? {
            guard let cert = SecCertificateCreateWithData(nil, der as CFData) else {
                return nil
            }
            return SecCertificateCopySubjectSummary(cert) as String?
        }
    }

    /// The helper binary launchd actually executes for an SMAppService daemon:
    /// the one embedded in the app bundle at `Contents/Library/HelperTools`.
    ///
    /// Deliberately does NOT consider `/Library/PrivilegedHelperTools/…`. That
    /// legacy `SMJobBless` location is never written by Tracexy — SMAppService
    /// runs the bundled binary in place — so comparing the app against a stale
    /// artifact there would diagnose a helper we never launch and mask (or
    /// invent) a signing mismatch against the real one.
    static func helperExecutableCandidates(
        bundledHelperURL: URL = Bundle.main.bundleURL
            .appendingPathComponent(HelperClient.bundledHelperBinaryRelativePath, isDirectory: false)
    )
        -> [URL]
    {
        [bundledHelperURL]
    }

    // MARK: - Classification

    /// Pure decision function — maps environment observations to a result.
    static func classify(_ environment: some Environment) -> Result {
        if let invalidReason = environment.validateAppSignature() {
            return .appSignatureInvalid(detail: invalidReason)
        }
        guard environment.helperBinaryExists() else {
            return .helperBinaryNotFound
        }
        guard let appChain = environment.appCertificateChain(),
              let helperChain = environment.helperCertificateChain() else
        {
            return .certificateChainUnavailable
        }

        let appSigner = environment.appSignerSummary() ?? "unknown"
        let helperSigner = environment.helperSignerSummary() ?? "unknown"

        guard appChain.count == helperChain.count else {
            return .signingIdentityMismatch(appSigner: appSigner, helperSigner: helperSigner)
        }
        for index in appChain.indices where appChain[index] != helperChain[index] {
            return .signingIdentityMismatch(appSigner: appSigner, helperSigner: helperSigner)
        }
        return .healthy
    }

    /// Run diagnostics using the live Security framework environment.
    static func diagnose() -> Result {
        let result = classify(LiveEnvironment())
        switch result {
        case .healthy:
            logger.debug("Signing diagnostics: healthy")
        case let .appSignatureInvalid(detail):
            logger.warning("Signing diagnostics: app signature invalid — \(detail, privacy: .public)")
        case let .signingIdentityMismatch(app, helper):
            logger
                .warning(
                    "Signing diagnostics: identity mismatch — app=\(app, privacy: .public) helper=\(helper, privacy: .public)"
                )
        case .helperBinaryNotFound:
            logger.debug("Signing diagnostics: helper binary not found")
        case .certificateChainUnavailable:
            logger.debug("Signing diagnostics: certificate chain unavailable")
        case let .diagnosticError(detail):
            logger.error("Signing diagnostics: error — \(detail, privacy: .public)")
        }
        return result
    }

    // MARK: Private

    private static let logger = Logger(
        subsystem: TracexyIdentity.current.logSubsystem,
        category: "SigningDiagnostics"
    )
}
