import Foundation
import SwiftUI

// MARK: - SettingsKeys

/// Namespaced `UserDefaults` keys for every persisted preference. Never hardcode
/// a defaults key — everything derives from the family namespace via
/// `TracexyIdentity.defaultsKey` (see the identity abstraction rule).
enum SettingsKeys {
    // MARK: Internal

    static let selectedSettingsTab = key("settings.selectedTab")
    static let appearance = key("settings.appearance")
    static let defaultView = key("settings.defaultView")
    static let byteUnits = key("settings.byteUnits")
    static let confirmQuitWhileCapturing = key("settings.confirmQuitWhileCapturing")
    static let restoreWorkspace = key("settings.restoreWorkspace")

    static let defaultInterface = key("settings.defaultInterface")
    static let autoStartCapture = key("settings.autoStartCapture")
    static let captureFilterMode = key("settings.captureFilterMode")
    static let bpfExpression = key("settings.bpfExpression")
    static let snapLength = key("settings.snapLength")
    static let promiscuous = key("settings.promiscuous")
    static let retainPackets = key("settings.retainPackets")

    static let redactBodies = key("settings.redactBodies")
    static let stripCredentials = key("settings.stripCredentials")
    static let maskIPs = key("settings.maskIPs")
    static let localOnly = key("settings.localOnly")
    static let autoClear = key("settings.autoClear")
    static let shareAnalytics = key("settings.shareAnalytics")

    static let mcpEnabled = key("settings.mcpEnabled")
    static let mcpPort = key("settings.mcpPort")
    static let mcpExposeSessions = key("settings.mcpExposeSessions")
    static let aiInsights = key("settings.aiInsights")
    static let aiProvider = key("settings.aiProvider")

    // MARK: Private

    private static func key(_ suffix: String) -> String {
        TracexyIdentity.current.defaultsKey(suffix)
    }
}

// MARK: - SettingsTab

enum SettingsTab: String, CaseIterable {
    case general
    case capture
    case helper
    case privacy
    case mcp
    case updates
}

// MARK: - AppAppearance

/// The user's appearance preference, applied app-wide via `.preferredColorScheme`.
enum AppAppearance: String, CaseIterable, Identifiable {
    case system
    case light
    case dark

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .system: String(localized: "System")
        case .light: String(localized: "Light")
        case .dark: String(localized: "Dark")
        }
    }

    var systemImage: String {
        switch self {
        case .system: "circle.lefthalf.filled"
        case .light: "sun.max.fill"
        case .dark: "moon.fill"
        }
    }

    var detail: String {
        switch self {
        case .system: String(localized: "Matches macOS")
        case .light: String(localized: "Always light")
        case .dark: String(localized: "Always dark")
        }
    }

    /// `nil` follows the system; otherwise forces light/dark.
    var colorScheme: ColorScheme? {
        switch self {
        case .system: nil
        case .light: .light
        case .dark: .dark
        }
    }
}

// MARK: - DefaultView

/// Which surface a fresh workspace lands on. Backs the General → "Default view" pref.
enum DefaultView: String, CaseIterable, Identifiable {
    case sessions
    case overview

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .sessions: String(localized: "Sessions")
        case .overview: String(localized: "Overview")
        }
    }

    var sidebarItem: SidebarItem {
        switch self {
        case .sessions: .sessions
        case .overview: .overview
        }
    }
}

// MARK: - ByteUnits

/// Binary (KiB) vs decimal (KB) byte formatting preference.
enum ByteUnits: String, CaseIterable, Identifiable {
    case binary
    case decimal

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .binary: String(localized: "Binary — KiB")
        case .decimal: String(localized: "Decimal — KB")
        }
    }

    var countStyle: ByteCountFormatter.CountStyle {
        switch self {
        case .binary: .binary
        case .decimal: .decimal
        }
    }
}

// MARK: - CaptureFilterMode

enum CaptureFilterMode: String, CaseIterable, Identifiable {
    case all
    case custom

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .all: String(localized: "All traffic")
        case .custom: String(localized: "Custom (BPF)")
        }
    }
}

// MARK: - CaptureSettingsResolver

/// Turns persisted Capture-Settings preferences into validated, bounded capture
/// inputs, read fresh at each capture start. Pure and deterministic so the
/// mapping (and the clamping of invalid persisted values to a safe default) is
/// unit-testable without a live capture or `UserDefaults`.
enum CaptureSettingsResolver {
    /// The retention-window sizes the UI offers, and the safe fallback used when a
    /// persisted value is none of them. These make the existing 8k/20k/50k picker
    /// behavioral: the chosen value becomes the in-memory save/export capacity.
    static let retainPacketsChoices = [8_000, 20_000, 50_000]
    static let defaultRetainPackets = 8_000

    /// Clamp a persisted snap length into the supported range (delegating to the
    /// shared bound), so a corrupt or out-of-range value can never open an
    /// oversized or too-small capture buffer.
    static func resolvedSnapLength(_ raw: Int) -> Int {
        CaptureConfiguration.clampedSnapLength(raw)
    }

    /// Map a persisted retention choice to an allowed capacity; anything not in the
    /// offered set clamps to the safe default rather than sizing the window blindly.
    static func resolvedRetainPackets(_ raw: Int) -> Int {
        retainPacketsChoices.contains(raw) ? raw : defaultRetainPackets
    }

    /// Map the persisted filter mode + expression to a BPF string: `.all` → no
    /// filter (`nil`); `.custom` → the trimmed expression, or `nil` when it is
    /// blank so an empty custom filter is never sent as a (meaningless) expression.
    static func resolvedBPF(filterMode: String, expression: String) -> String? {
        guard filterMode == CaptureFilterMode.custom.rawValue else {
            return nil
        }
        let trimmed = expression.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Assemble a capture configuration from the current preferences. Reads the
    /// snap length, promiscuous flag, filter mode, and BPF expression fresh, so a
    /// settings change since the last capture takes effect at the next start.
    /// `defaults` is injectable so the whole mapping is testable without touching
    /// the shared store.
    static func configuration(interface: String, defaults: UserDefaults = .standard) -> CaptureConfiguration {
        CaptureConfiguration(
            interface: interface,
            snapLength: resolvedSnapLength(defaults.integer(forKey: SettingsKeys.snapLength)),
            promiscuous: defaults.bool(forKey: SettingsKeys.promiscuous),
            bpf: resolvedBPF(
                filterMode: defaults.string(forKey: SettingsKeys.captureFilterMode) ?? CaptureFilterMode.all.rawValue,
                expression: defaults.string(forKey: SettingsKeys.bpfExpression) ?? ""
            )
        )
    }

    /// Resolve the configured retention-window capacity from the current
    /// preferences, clamping an invalid persisted value to the safe default.
    static func retainCapacity(defaults: UserDefaults = .standard) -> Int {
        resolvedRetainPackets(defaults.integer(forKey: SettingsKeys.retainPackets))
    }
}

// MARK: - PrivacySettingsResolver

/// Resolves export protections from persisted preferences without treating an
/// unset `UserDefaults` key as `false`. The Privacy pane's shipped defaults are
/// protective, so a fresh install must apply them before the user has opened
/// Settings or caused `@AppStorage` to materialize the keys.
enum PrivacySettingsResolver {
    // MARK: Internal

    static func exportPolicy(defaults: UserDefaults = .standard) -> SessionExportPrivacyPolicy {
        SessionExportPrivacyPolicy(
            redactPayloadBodies: resolvedBool(
                forKey: SettingsKeys.redactBodies,
                defaultValue: true,
                defaults: defaults
            ),
            stripCredentials: resolvedBool(
                forKey: SettingsKeys.stripCredentials,
                defaultValue: true,
                defaults: defaults
            ),
            maskIPAddresses: resolvedBool(
                forKey: SettingsKeys.maskIPs,
                defaultValue: false,
                defaults: defaults
            )
        )
    }

    // MARK: Private

    private static func resolvedBool(
        forKey key: String,
        defaultValue: Bool,
        defaults: UserDefaults
    )
        -> Bool
    {
        (defaults.object(forKey: key) as? Bool) ?? defaultValue
    }
}

// MARK: - AutoClear

enum AutoClear: String, CaseIterable, Identifiable {
    case never
    case minutes15
    case hour1
    case hours24

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .never: String(localized: "Never")
        case .minutes15: String(localized: "After 15 minutes")
        case .hour1: String(localized: "After 1 hour")
        case .hours24: String(localized: "After 24 hours")
        }
    }
}

// MARK: - AppInfo

/// Read-only app identity for the Updates pane. Real values from the bundle —
/// never invented.
enum AppInfo {
    static var versionString: String {
        let short = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"
        return "\(short) (build \(build))"
    }
}
