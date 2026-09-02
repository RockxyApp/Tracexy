import Foundation
import Testing
@testable import Tracexy

@Suite("Privacy settings")
struct PrivacySettingsTests {
    // MARK: Internal

    @Test("Fresh defaults resolve to protective session export settings")
    func protectiveDefaults() throws {
        let defaults = try scratchDefaults()

        let policy = PrivacySettingsResolver.exportPolicy(defaults: defaults)

        #expect(policy.redactPayloadBodies)
        #expect(policy.stripCredentials)
        #expect(!policy.maskIPAddresses)
    }

    @Test("Persisted privacy choices override every shipped default")
    func persistedChoices() throws {
        let defaults = try scratchDefaults()
        defaults.set(false, forKey: SettingsKeys.redactBodies)
        defaults.set(false, forKey: SettingsKeys.stripCredentials)
        defaults.set(true, forKey: SettingsKeys.maskIPs)

        let policy = PrivacySettingsResolver.exportPolicy(defaults: defaults)

        #expect(!policy.redactPayloadBodies)
        #expect(!policy.stripCredentials)
        #expect(policy.maskIPAddresses)
    }

    // MARK: Internal — History Auto-clear resolution

    @Test("Absent Auto-clear key resolves to Never so stale defaults cannot delete")
    func autoClearDefaultsToNever() throws {
        let defaults = try scratchDefaults()

        #expect(HistoryRetentionSettingsResolver.autoClear(defaults: defaults) == .never)
    }

    @Test("Every persisted Auto-clear choice resolves to its own case")
    func autoClearValidChoicesResolve() throws {
        for choice in AutoClear.allCases {
            let defaults = try scratchDefaults()
            defaults.set(choice.rawValue, forKey: SettingsKeys.autoClear)

            #expect(HistoryRetentionSettingsResolver.autoClear(defaults: defaults) == choice)
        }
    }

    @Test("An unknown persisted Auto-clear value fails closed to Never")
    func autoClearUnknownValueFailsClosed() throws {
        let defaults = try scratchDefaults()
        defaults.set("after-3-fortnights", forKey: SettingsKeys.autoClear)

        #expect(HistoryRetentionSettingsResolver.autoClear(defaults: defaults) == .never)
    }

    @Test("Auto-clear choices map to their retention intervals in seconds")
    func autoClearRetentionIntervals() {
        #expect(AutoClear.never.retentionInterval == nil)
        #expect(AutoClear.minutes15.retentionInterval == 900)
        #expect(AutoClear.hour1.retentionInterval == 3_600)
        #expect(AutoClear.hours24.retentionInterval == 86_400)
    }

    // MARK: Private

    private func scratchDefaults() throws -> UserDefaults {
        let suiteName = "PrivacySettingsTests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        defaults.removePersistentDomain(forName: suiteName)
        return defaults
    }
}
