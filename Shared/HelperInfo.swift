import CryptoKit
import Foundation
import MachO

// MARK: - HelperInfo

/// Structured helper information returned by the `getHelperInfo` XPC method.
/// Replaces the single version string from the legacy `getHelperVersion`.
nonisolated struct HelperInfo: Equatable {
    let binaryVersion: String
    let buildNumber: Int
    let protocolVersion: Int
}

// MARK: - HelperCompatibilityDecision

/// Capability and compatibility decisions are protocol-first. A build number
/// identifies a revision of one protocol; it never proves that an XPC selector
/// exists.
nonisolated enum HelperCompatibilityDecision: Equatable {
    case compatible
    case outdated
    case incompatible
}

// MARK: - HelperCompatibilityPolicy

nonisolated enum HelperCompatibilityPolicy {
    // MARK: Internal

    /// Protocol v5 added the maintenance selectors without changing the v4
    /// capture commands, so a v4 helper can still capture while awaiting update.
    static let executableRefreshProtocolVersion = 5
    static let executableIdentityProtocolVersion = 5

    static func classify(
        installedProtocolVersion: Int,
        installedBuildNumber: Int,
        expectedProtocolVersion: Int,
        bundledBuildNumber: Int
    )
        -> HelperCompatibilityDecision
    {
        guard knownProtocolVersions.contains(installedProtocolVersion),
              knownProtocolVersions.contains(expectedProtocolVersion),
              installedBuildNumber > 0,
              bundledBuildNumber > 0,
              installedProtocolVersion <= expectedProtocolVersion else
        {
            return .incompatible
        }
        if installedProtocolVersion < expectedProtocolVersion {
            return backwardCompatibleProtocolVersions.contains(installedProtocolVersion)
                ? .outdated
                : .incompatible
        }
        return installedBuildNumber >= bundledBuildNumber ? .compatible : .outdated
    }

    static func supportsExecutableRefresh(protocolVersion: Int) -> Bool {
        protocolVersion == executableRefreshProtocolVersion
    }

    static func supportsExecutableIdentity(protocolVersion: Int) -> Bool {
        protocolVersion == executableIdentityProtocolVersion
    }

    static func requiresLegacyDestructiveMigration(protocolVersion: Int) -> Bool {
        legacyMigrationProtocolVersions.contains(protocolVersion)
    }

    // MARK: Private

    private static let knownProtocolVersions: Set<Int> = [4, 5]
    private static let backwardCompatibleProtocolVersions: Set<Int> = [4]
    private static let legacyMigrationProtocolVersions: Set<Int> = [4]
}

// MARK: - HelperExecutableIdentity

/// Evidence about the executable a live helper process actually launched from.
/// Version/build metadata alone cannot prove that an in-place app update replaced
/// the running daemon.
nonisolated struct HelperExecutableIdentity: Equatable, Sendable {
    let executableDigest: String
    let launchIdentity: String
    let processIdentifier: Int32
    let executablePath: String
    let buildNumber: Int
    let protocolVersion: Int

    var isWellFormed: Bool {
        HelperExecutableDigest.isWellFormedDigest(executableDigest)
            && !launchIdentity.isEmpty
            && processIdentifier > 0
            && buildNumber > 0
            && protocolVersion > 0
    }
}

// MARK: - HelperExecutableDigest

nonisolated enum HelperExecutableDigest {
    enum Failure: Error, Equatable {
        case unreadable(path: String)
        case tooLarge(path: String)
    }

    static let maximumExecutableByteCount = 256 * 1_024 * 1_024

    static func sha256Hex(
        atPath path: String,
        maximumByteCount: Int = maximumExecutableByteCount
    )
        throws -> String
    {
        guard !path.isEmpty, let handle = FileHandle(forReadingAtPath: path) else {
            throw Failure.unreadable(path: path)
        }
        defer { try? handle.close() }

        var hasher = SHA256()
        var totalByteCount = 0
        while true {
            let chunk: Data?
            do {
                chunk = try handle.read(upToCount: 1 << 20)
            } catch {
                throw Failure.unreadable(path: path)
            }
            guard let chunk, !chunk.isEmpty else {
                break
            }
            totalByteCount += chunk.count
            guard totalByteCount <= maximumByteCount else {
                throw Failure.tooLarge(path: path)
            }
            hasher.update(data: chunk)
        }
        guard totalByteCount > 0 else {
            throw Failure.unreadable(path: path)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    static func isWellFormedDigest(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        return bytes.count == 64 && bytes.allSatisfy {
            (UInt8(ascii: "0") ... UInt8(ascii: "9")).contains($0)
                || (UInt8(ascii: "a") ... UInt8(ascii: "f")).contains($0)
        }
    }

    static func canonicalPath(_ path: String) -> String {
        guard !path.isEmpty else {
            return path
        }
        return URL(fileURLWithPath: path)
            .resolvingSymlinksInPath()
            .standardizedFileURL
            .path
    }
}

// MARK: - HelperExecutableLocation

nonisolated enum HelperExecutableLocation {
    static func currentProcessExecutablePath() -> String {
        var bufferSize = UInt32(PATH_MAX) * 4
        var buffer = [CChar](repeating: 0, count: Int(bufferSize) + 1)
        if _NSGetExecutablePath(&buffer, &bufferSize) == 0 {
            let resolved = String(cString: buffer)
            if !resolved.isEmpty {
                return HelperExecutableDigest.canonicalPath(resolved)
            }
        }
        if let executablePath = Bundle.main.executablePath, !executablePath.isEmpty {
            return HelperExecutableDigest.canonicalPath(executablePath)
        }
        return HelperExecutableDigest.canonicalPath(CommandLine.arguments.first ?? "")
    }
}

// MARK: - HelperProtocolVersion

/// XPC protocol version embedded into both the app and helper bundles from
/// `Configuration/Versions.xcconfig`.
nonisolated enum HelperProtocolVersion {
    static let infoDictionaryKey = "TracexyHelperProtocolVersion"

    static var current: Int {
        value(in: Bundle.main.infoDictionary)
    }

    static func value(in infoDictionary: [String: Any]?) -> Int {
        BundledHelperMetadata.parsePositiveInt(infoDictionary?[infoDictionaryKey])
    }
}

// MARK: - BundledHelperMetadata

/// The helper version/build/protocol this app build ships, as embedded in the
/// app's `Info.plist` from the `TRACEXY_*` xcconfig values (see
/// `Configuration/Versions.xcconfig`, the sole source of truth).
///
/// These are *helper-specific* keys — distinct from the app's own
/// `CFBundleShortVersionString`/`CFBundleVersion` — so the app never conflates
/// its marketing/build number with what the bundled helper actually reports.
///
/// Parsing is deliberately small and total: every value **fails closed**.
/// Malformed, missing, or non-positive numeric values become `0`; a missing or
/// blank version string becomes `"0.0.0"`. Nothing here traps or force-unwraps.
nonisolated struct BundledHelperMetadata: Equatable {
    // MARK: Lifecycle

    init(version: String, build: Int, protocolVersion: Int) {
        self.version = version
        self.build = build
        self.protocolVersion = protocolVersion
    }

    /// Parse from an injected info dictionary (nil-safe and testable). Reads the
    /// helper-specific keys only; never the app's `CFBundle*` values.
    init(infoDictionary: [String: Any]?) {
        version = BundledHelperMetadata.parseVersion(infoDictionary?[Key.version])
        build = BundledHelperMetadata.parsePositiveInt(infoDictionary?[Key.build])
        protocolVersion = BundledHelperMetadata.parsePositiveInt(infoDictionary?[Key.protocolVersion])
    }

    // MARK: Internal

    /// Info.plist keys populated from the `TRACEXY_HELPER_*` xcconfig variables.
    enum Key {
        static let version = "TracexyBundledHelperVersion"
        static let build = "TracexyBundledHelperBuild"
        static let protocolVersion = HelperProtocolVersion.infoDictionaryKey
    }

    /// Runtime convenience: read the app's own bundle. Prefer the injectable
    /// initializer in tests.
    static var bundled: BundledHelperMetadata {
        BundledHelperMetadata(infoDictionary: Bundle.main.infoDictionary)
    }

    let version: String
    let build: Int
    let protocolVersion: Int

    // MARK: Fileprivate

    /// A strictly-positive integer from a `String`, `Int`, or `NSNumber`.
    /// Anything else — missing, malformed, zero, or negative — fails closed to `0`.
    fileprivate static func parsePositiveInt(_ raw: Any?) -> Int {
        let value: Int? = switch raw {
        case let intValue as Int:
            intValue
        case let stringValue as String:
            Int(stringValue.trimmingCharacters(in: .whitespacesAndNewlines))
        case let numberValue as NSNumber:
            numberValue.intValue
        default:
            nil
        }
        guard let value, value > 0 else {
            return 0
        }
        return value
    }

    // MARK: Private

    /// A version string, trimmed. Missing, non-string, or blank → `"0.0.0"`.
    private static func parseVersion(_ raw: Any?) -> String {
        guard let value = raw as? String else {
            return "0.0.0"
        }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "0.0.0" : trimmed
    }
}
