import Foundation

// MARK: - HelperInfo

/// Structured helper information returned by the `getHelperInfo` XPC method.
/// Replaces the single version string from the legacy `getHelperVersion`.
nonisolated struct HelperInfo: Equatable {
    let binaryVersion: String
    let buildNumber: Int
    let protocolVersion: Int
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
