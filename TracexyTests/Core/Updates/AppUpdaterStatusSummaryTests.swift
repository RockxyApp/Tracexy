import Foundation
import Testing
@testable import Tracexy

@MainActor
@Suite("App updater status summary")
struct AppUpdaterStatusSummaryTests {
    // MARK: Internal

    @Test("Newer release creates the toolbar badge summary")
    func updateFoundCreatesSummary() {
        let updater = AppUpdater(configuration: configuration(appVersion: "0.12.0"))

        updater.recordUpdateFound(latestVersion: "0.17.0", fetchVersionsBehind: false)

        #expect(updater.updateStatusSummary?.title == "Update Available")
        #expect(updater.updateStatusSummary?.versionLine == "v0.12.0 -> v0.17.0")
        #expect(updater.updateStatusSummary?.versionsBehind == 5)
        #expect(updater.updateStatusSummary?.badgeTitle == "5 New Updates")
    }

    @Test("Same or older release hides the badge")
    func currentOrOlderReleaseHidesSummary() {
        #expect(AppUpdater.makeUpdateStatusSummary(
            currentVersion: "0.17.0",
            latestVersion: "0.17.0"
        ) == nil)
        #expect(AppUpdater.makeUpdateStatusSummary(
            currentVersion: "0.17.0",
            latestVersion: "0.12.0"
        ) == nil)
    }

    @Test("Cross-major update uses generic copy without release history")
    func crossMajorUsesGenericBadge() {
        let summary = AppUpdater.makeUpdateStatusSummary(
            currentVersion: "0.25.0",
            latestVersion: "1.0.0"
        )

        #expect(summary?.versionsBehind == nil)
        #expect(summary?.badgeTitle == "Update Available")
    }

    @Test("Appcast derives the latest release and deduplicated update count")
    func appcastSummary() {
        let data = Data(
            """
            <rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
              <channel>
                <item sparkle:shortVersionString="0.21.1"><enclosure sparkle:shortVersionString="0.21.1" /></item>
                <item><enclosure sparkle:shortVersionString="0.21.0" /></item>
                <item><enclosure sparkle:shortVersionString="0.21.0" /></item>
                <item><enclosure sparkle:shortVersionString="0.20.1" /></item>
                <item><enclosure sparkle:shortVersionString="0.20.0" /></item>
              </channel>
            </rss>
            """.utf8
        )

        let summary = AppUpdater.makeUpdateStatusSummary(
            currentVersion: "0.20.0",
            appcastData: data
        )

        #expect(summary?.latestVersion == "0.21.1")
        #expect(summary?.versionsBehind == 3)
        #expect(summary?.badgeTitle == "3 New Updates")
    }

    @Test("Single release uses singular badge copy")
    func singleUpdateUsesSingularCopy() {
        let summary = AppUpdater.makeUpdateStatusSummary(
            currentVersion: "0.16.0",
            latestVersion: "0.17.0"
        )

        #expect(summary?.badgeTitle == "1 New Update")
        #expect(summary?.countLine == "1 version behind")
    }

    @Test("Clearing update state removes the badge summary")
    func clearRemovesSummary() {
        let updater = AppUpdater(configuration: configuration(appVersion: "0.12.0"))
        updater.recordUpdateFound(latestVersion: "0.13.0", fetchVersionsBehind: false)

        updater.clearUpdateStatusSummary()

        #expect(updater.updateStatusSummary == nil)
    }

    #if DEBUG
    @Test("Explicit Debug preview renders the requested badge count")
    func debugPreviewInstallsRequestedCount() {
        let updater = AppUpdater(configuration: configuration(appVersion: "0.1.4"))

        let installed = updater.installUpdateBadgePreview(environment: [
            "TRACEXY_UPDATE_BADGE_PREVIEW_COUNT": "15",
        ])

        #expect(installed)
        #expect(updater.updateStatusSummary?.latestVersion == "0.1.19")
        #expect(updater.updateStatusSummary?.badgeTitle == "15 New Updates")
    }
    #endif

    // MARK: Private

    private func configuration(appVersion: String) -> TracexyUpdateConfiguration {
        TracexyUpdateConfiguration(infoDictionary: [
            "TracexyUpdatesEnabled": false,
            "SUFeedURL": "https://example.com/appcast.xml",
            "SUPublicEDKey": Data(repeating: 7, count: 32).base64EncodedString(),
            "CFBundleShortVersionString": appVersion,
            "CFBundleVersion": "1",
        ])
    }
}
