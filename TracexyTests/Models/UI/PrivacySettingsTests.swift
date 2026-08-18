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

    // MARK: Private

    private func scratchDefaults() throws -> UserDefaults {
        let suiteName = "PrivacySettingsTests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        defaults.removePersistentDomain(forName: suiteName)
        return defaults
    }
}
