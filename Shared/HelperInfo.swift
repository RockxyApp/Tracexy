import Foundation

// MARK: - HelperInfo

/// Structured helper information returned by the `getHelperInfo` XPC method.
/// Replaces the single version string from the legacy `getHelperVersion`.
struct HelperInfo: Equatable {
    let binaryVersion: String
    let buildNumber: Int
    let protocolVersion: Int
}

// MARK: - HelperProtocolVersion

/// Single source of truth for the XPC protocol version, compiled into **both**
/// the app and the helper (this file is shared). Bump this whenever the
/// `TracexyHelperProtocol` interface changes in a backward-incompatible way:
/// the app then reports the installed helper as `installedIncompatible` and
/// offers an Update.
enum HelperProtocolVersion {
    static let current = 1
}
