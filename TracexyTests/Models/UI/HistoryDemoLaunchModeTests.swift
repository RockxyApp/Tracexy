import Foundation
import Testing
@testable import Tracexy

@MainActor
@Suite("Synthetic History launch mode")
struct HistoryDemoLaunchModeTests {
    @Test("The requested flag and descriptive alias enable demo mode")
    func launchArguments() {
        #expect(HistoryDemoLaunchMode.isEnabled(arguments: ["Tracexy", "--dum-data"]))
        #expect(HistoryDemoLaunchMode.isEnabled(arguments: ["Tracexy", "--demo-data"]))
        #expect(!HistoryDemoLaunchMode.isEnabled(arguments: ["Tracexy", "--direct-capture"]))
    }

    @Test("Fresh demo settings are isolated and start on Privacy with Auto-clear Never")
    func settingsIsolation() throws {
        let prefix = "HistoryDemoLaunchModeTests.\(UUID().uuidString)"
        let identity = TracexyIdentity(infoDictionary: ["TracexyDefaultsPrefix": prefix])
        let suiteName = HistoryDemoLaunchMode.settingsSuiteName(identity: identity)
        let existing = try #require(UserDefaults(suiteName: suiteName))
        defer { existing.removePersistentDomain(forName: suiteName) }
        existing.set(AutoClear.hours24.rawValue, forKey: SettingsKeys.autoClear)
        existing.set(SettingsTab.general.rawValue, forKey: SettingsKeys.selectedSettingsTab)

        let defaults = try #require(HistoryDemoLaunchMode.freshSettingsDefaults(identity: identity))

        #expect(HistoryRetentionSettingsResolver.autoClear(defaults: defaults) == .never)
        #expect(defaults.string(forKey: SettingsKeys.selectedSettingsTab) == SettingsTab.privacy.rawValue)
        #expect(suiteName.hasSuffix(".history-demo"))
    }
}
