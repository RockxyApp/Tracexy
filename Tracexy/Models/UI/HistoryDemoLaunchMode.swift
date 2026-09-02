import Foundation

// MARK: - HistoryDemoLaunchMode

/// Development-only composition policy for the synthetic History walkthrough.
///
/// The launch flag never grants access to production History. The app composes an
/// in-memory ``SessionStore`` separately and this type supplies a dedicated defaults
/// suite so changing Auto-clear during a demo cannot mutate the user's real settings.
enum HistoryDemoLaunchMode {
    /// Keep the user-requested spelling as the canonical script contract. The
    /// clearer alias is accepted for discoverability without breaking that contract.
    static let launchArguments = ["--dum-data", "--demo-data"]

    static func isEnabled(arguments: [String] = CommandLine.arguments) -> Bool {
        launchArguments.contains { arguments.contains($0) }
    }

    static func settingsSuiteName(identity: TracexyIdentity = .current) -> String {
        "\(identity.defaultsPrefix).history-demo"
    }

    /// Reset only the isolated demo suite. Never fall back to `.standard`: callers
    /// must fail the demo composition closed if this suite cannot be created.
    static func freshSettingsDefaults(identity: TracexyIdentity = .current) -> UserDefaults? {
        let suiteName = settingsSuiteName(identity: identity)
        guard let defaults = UserDefaults(suiteName: suiteName) else {
            return nil
        }
        defaults.removePersistentDomain(forName: suiteName)
        defaults.set(AutoClear.never.rawValue, forKey: SettingsKeys.autoClear)
        defaults.set(SettingsTab.privacy.rawValue, forKey: SettingsKeys.selectedSettingsTab)
        return defaults
    }
}
