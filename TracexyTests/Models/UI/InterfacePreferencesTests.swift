import Foundation
import Testing
@testable import Tracexy

/// Capture ▸ Manage Interfaces hides interfaces from the capture menus, names
/// them and keeps a note, app-wide; the interface in use always stays listed.
@MainActor
struct InterfacePreferencesTests {
    // MARK: Internal

    @Test
    func menusLeaveOutHiddenInterfacesButKeepTheOneInUse() {
        var settings = InterfaceSettings()
        settings.hidden = ["awdl0", "utun3"]
        settings.friendlyNames = ["en0": "Office Wi-Fi"]
        let listed = NetworkInterfaces.applying(settings, to: interfaces, keeping: "utun3")
        #expect(listed.map(\.id) == ["en0", "utun3", "lo0"])
        #expect(listed.first?.menuLabel == "Office Wi-Fi (en0)")
        #expect(listed.first?.category == .wifi)
        #expect(NetworkInterfaces.applying(settings, to: interfaces, keeping: nil).map(\.id) == ["en0", "lo0"])
    }

    @Test
    func editsPersistAndClean() throws {
        let suite = "interface-preferences-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }

        let preferences = InterfacePreferences(defaults: defaults)
        preferences.setShown(false, for: "awdl0")
        preferences.setFriendlyName("  Desk  Dock \n", for: "en5")
        preferences.setComment(String(repeating: "x", count: 500), for: "en5")
        preferences.setFriendlyName("   ", for: "en7")

        let reloaded = InterfacePreferences(defaults: defaults)
        #expect(reloaded.settings.hidden == ["awdl0"])
        #expect(reloaded.settings.friendlyNames == ["en5": "Desk  Dock"])
        #expect(reloaded.settings.comments["en5"]?.count == InterfaceSettings.maximumCommentLength)

        reloaded.setFriendlyName("", for: "en5")
        reloaded.showAll()
        let cleared = InterfacePreferences(defaults: defaults)
        #expect(cleared.settings.friendlyNames.isEmpty)
        #expect(cleared.settings.hidden.isEmpty)
    }

    @Test
    func unreadableStoredSettingsStartEmpty() throws {
        let suite = "interface-preferences-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        defaults.set(Data("not json".utf8), forKey: SettingsKeys.interfaceSettings)
        #expect(InterfacePreferences(defaults: defaults).settings == InterfaceSettings())
    }

    // MARK: Private

    private let interfaces = [
        NetworkInterface(
            id: "en0",
            displayName: "Wi-Fi",
            category: .wifi,
            ipv4: "192.0.2.4",
            isUp: true,
            isLoopback: false
        ),
        NetworkInterface(id: "awdl0", displayName: "awdl0", category: .wifi, ipv4: nil, isUp: true, isLoopback: false),
        NetworkInterface(
            id: "utun3",
            displayName: "utun3",
            category: .tunnels,
            ipv4: nil,
            isUp: true,
            isLoopback: false
        ),
        NetworkInterface(
            id: "lo0",
            displayName: "Loopback",
            category: .loopback,
            ipv4: "127.0.0.1",
            isUp: true,
            isLoopback: true
        ),
    ]
}
