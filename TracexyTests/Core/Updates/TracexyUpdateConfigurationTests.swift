import Foundation
import Testing
@testable import Tracexy

@Suite("Tracexy update configuration")
struct TracexyUpdateConfigurationTests {
    // MARK: Internal

    @Test("Production configuration enables manual and automatic checks")
    func productionConfiguration() {
        let configuration = TracexyUpdateConfiguration(infoDictionary: [
            "TracexyUpdatesEnabled": "YES",
            "SUFeedURL": "https://raw.githubusercontent.com/RockxyApp/Tracexy/main/appcast.xml",
            "SUPublicEDKey": validKey,
            "CFBundleShortVersionString": "1.2.3",
            "CFBundleVersion": "42",
        ])

        #expect(configuration.supportsUserInitiatedChecks)
        #expect(configuration.supportsAutomaticChecks)
        #expect(configuration.appVersion == "1.2.3")
        #expect(configuration.buildNumber == "42")
    }

    @Test("Local configuration keeps manual checks but disables scheduled checks")
    func localConfiguration() {
        let configuration = TracexyUpdateConfiguration(infoDictionary: [
            "TracexyUpdatesEnabled": false,
            "SUFeedURL": "https://raw.githubusercontent.com/RockxyApp/Tracexy/main/appcast.xml",
            "SUPublicEDKey": validKey,
        ])

        #expect(configuration.supportsUserInitiatedChecks)
        #expect(!configuration.supportsAutomaticChecks)
    }

    @Test(
        "Unsafe or incomplete configuration fails closed",
        arguments: [
            // Non-HTTPS feed URL.
            [
                "TracexyUpdatesEnabled": "YES",
                "SUFeedURL": "http://example.com/appcast.xml",
                "SUPublicEDKey": Data(repeating: 1, count: 32).base64EncodedString(),
            ],
            // Placeholder public key.
            [
                "TracexyUpdatesEnabled": "YES",
                "SUFeedURL": "https://example.com/appcast.xml",
                "SUPublicEDKey": "__PENDING_TRACEXY_SPARKLE_PUBLIC_ED_KEY__",
            ],
            // Public key is not valid base64.
            [
                "TracexyUpdatesEnabled": "YES",
                "SUFeedURL": "https://example.com/appcast.xml",
                "SUPublicEDKey": "not-a-public-key",
            ],
            // Feed URL absent entirely (valid key present).
            [
                "TracexyUpdatesEnabled": "YES",
                "SUPublicEDKey": Data(repeating: 7, count: 32).base64EncodedString(),
            ],
            // Feed URL present but blank.
            [
                "TracexyUpdatesEnabled": "YES",
                "SUFeedURL": "   ",
                "SUPublicEDKey": Data(repeating: 7, count: 32).base64EncodedString(),
            ],
            // Public key absent entirely (valid feed present).
            [
                "TracexyUpdatesEnabled": "YES",
                "SUFeedURL": "https://example.com/appcast.xml",
            ],
            // Public key present but blank.
            [
                "TracexyUpdatesEnabled": "YES",
                "SUFeedURL": "https://example.com/appcast.xml",
                "SUPublicEDKey": "",
            ],
            // Valid base64 but the decoded key is too short (31 bytes, not 32).
            [
                "TracexyUpdatesEnabled": "YES",
                "SUFeedURL": "https://example.com/appcast.xml",
                "SUPublicEDKey": Data(repeating: 9, count: 31).base64EncodedString(),
            ],
            // Valid base64 but the decoded key is too long (64 bytes, not 32).
            [
                "TracexyUpdatesEnabled": "YES",
                "SUFeedURL": "https://example.com/appcast.xml",
                "SUPublicEDKey": Data(repeating: 9, count: 64).base64EncodedString(),
            ],
        ]
    )
    func invalidConfiguration(info: [String: Any]) {
        let configuration = TracexyUpdateConfiguration(infoDictionary: info)

        #expect(!configuration.supportsUserInitiatedChecks)
        #expect(!configuration.supportsAutomaticChecks)
    }

    // MARK: Private

    private let validKey = Data(repeating: 7, count: 32).base64EncodedString()
}
