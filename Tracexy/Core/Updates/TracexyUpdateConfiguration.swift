import Foundation

/// Bundle-driven Sparkle configuration. Missing, malformed, or placeholder
/// values fail closed so local and test builds never schedule accidental checks.
struct TracexyUpdateConfiguration {
    // MARK: Lifecycle

    init(bundle: Bundle) {
        self.init(infoDictionary: bundle.infoDictionary ?? [:])
    }

    init(infoDictionary info: [String: Any]) {
        updatesEnabled = Self.bool(named: "TracexyUpdatesEnabled", in: info)

        let feedValue = Self.normalized(Self.string(named: "SUFeedURL", in: info))
        if let feedValue,
           let candidate = URL(string: feedValue),
           candidate.scheme?.lowercased() == "https",
           candidate.host != nil
        {
            feedURL = candidate
        } else {
            feedURL = nil
        }

        let keyValue = Self.normalized(Self.string(named: "SUPublicEDKey", in: info))
        if let keyValue,
           let keyData = Data(base64Encoded: keyValue),
           keyData.count == 32
        {
            publicEDKey = keyValue
        } else {
            publicEDKey = ""
        }

        appVersion = Self.normalized(
            Self.string(named: "CFBundleShortVersionString", in: info)
        ) ?? "0"
        buildNumber = Self.normalized(
            Self.string(named: "CFBundleVersion", in: info)
        ) ?? "0"
    }

    // MARK: Internal

    static let current = TracexyUpdateConfiguration(bundle: .main)

    let updatesEnabled: Bool
    let feedURL: URL?
    let publicEDKey: String
    let appVersion: String
    let buildNumber: String

    var supportsUserInitiatedChecks: Bool {
        feedURL != nil && !publicEDKey.isEmpty
    }

    var supportsAutomaticChecks: Bool {
        updatesEnabled && supportsUserInitiatedChecks
    }

    // MARK: Private

    private static func string(named key: String, in info: [String: Any]) -> String {
        (info[key] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }

    private static func bool(named key: String, in info: [String: Any]) -> Bool {
        if let value = info[key] as? Bool {
            return value
        }

        switch string(named: key, in: info).lowercased() {
        case "1",
             "true",
             "yes":
            return true
        default:
            return false
        }
    }

    private static func normalized(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              !trimmed.contains("__PENDING__"),
              !trimmed.localizedCaseInsensitiveContains("placeholder") else
        {
            return nil
        }
        return trimmed
    }
}
