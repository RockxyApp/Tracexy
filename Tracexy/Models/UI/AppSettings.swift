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
