import Foundation
import Testing
@testable import Tracexy

/// Address names are the investigator's labels: shown only where a session's host
/// is a bare address, never over a name the capture supplied, and kept per Project.
@MainActor
struct AddressNameBookTests {
    // MARK: Internal

    @Test
    func namesBareAddressHostsOnlyAndPersists() throws {
        let suite = "com.amunx.tracexy.tests.names.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let book = AddressNameBook()
        book.bind(to: defaults)

        #expect(book.setName("  NAS  ", for: "192.0.2.5"))
        #expect(!book.setName("Not an address", for: "nas.local"))
        #expect(book.setName("Router", for: "2001:DB8::1"))
        #expect(book.name(for: "2001:db8::1") == "Router")

        #expect(book.displayHost(for: session(host: "192.0.2.5")) == "NAS (192.0.2.5)")
        // A name the capture supplied is never replaced.
        #expect(book.displayHost(for: session(host: "files.example.test")) == "files.example.test")
        #expect(book.displayHost(for: session(host: "192.0.2.6")) == "192.0.2.6")

        let reloaded = AddressNameBook()
        reloaded.bind(to: defaults)
        #expect(reloaded.name(for: "192.0.2.5") == "NAS")
        #expect(reloaded.setName(" ", for: "192.0.2.5"))
        #expect(reloaded.name(for: "192.0.2.5") == nil)
        #expect(String(repeating: "x", count: 80).prefix(AddressNameBook.maximumNameCharacters).count == 60)
    }

    @Test
    func keepsConflictingIPv6AliasesUntilExplicitResolution() throws {
        let suite = "com.amunx.tracexy.tests.names.ipv6-migration.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let key = ProjectScopedSettingsKeys.addressNames
        let expanded = "2001:db8:0:0:0:0:0:1"
        let originalNames = [expanded: "NAS", "2001:db8::1": "Canonical NAS"]
        let originalData = try JSONEncoder().encode(originalNames)
        defaults.set(originalData, forKey: key)

        let book = AddressNameBook()
        book.bind(to: defaults)
        #expect(book.name(for: "2001:DB8:0000:0000:0000:0000:0000:0001") == "Canonical NAS")
        #expect(book.conflictingNames(for: expanded) == ["Canonical NAS", "NAS"])
        #expect(defaults.data(forKey: key) == originalData)

        // An unrelated save must retain both conflicting aliases verbatim.
        #expect(book.setName("Gateway", for: "192.0.2.1"))
        let afterUnrelatedSave = try #require(defaults.data(forKey: key))
        #expect(try JSONDecoder().decode([String: String].self, from: afterUnrelatedSave)
            == [expanded: "NAS", "2001:db8::1": "Canonical NAS", "192.0.2.1": "Gateway"])

        let reloaded = AddressNameBook()
        reloaded.bind(to: defaults)
        #expect(reloaded.name(for: "2001:db8::1") == "Canonical NAS")
        #expect(reloaded.conflictingNames(for: expanded) == ["Canonical NAS", "NAS"])
        #expect(reloaded.setName("Resolved NAS", for: expanded))
        #expect(reloaded.name(for: "2001:db8::1") == "Resolved NAS")
        let resolved = try #require(defaults.data(forKey: key))
        #expect(try JSONDecoder().decode([String: String].self, from: resolved)
            == ["192.0.2.1": "Gateway", "2001:db8::1": "Resolved NAS"])
        #expect(reloaded.setName("", for: "2001:db8::1"))
        #expect(reloaded.name(for: expanded) == nil)
    }

    @Test
    func unreadableAddressNamesRemainUntouchedAndDisableEditing() throws {
        let suite = "com.amunx.tracexy.tests.names.corrupt.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let key = ProjectScopedSettingsKeys.addressNames
        let corruptData = Data([0xFF, 0x00, 0x13])
        defaults.set(corruptData, forKey: key)

        let book = AddressNameBook()
        book.bind(to: defaults)
        #expect(!book.canEditNames)
        #expect(!book.setName("NAS", for: "192.0.2.1"))
        #expect(defaults.data(forKey: key) == corruptData)

        let rebound = AddressNameBook()
        rebound.bind(to: defaults)
        #expect(!rebound.canEditNames)
        #expect(defaults.data(forKey: key) == corruptData)
    }

    // MARK: Private

    private func session(host: String) -> SessionSummary {
        SessionSummary(
            id: UUID(), startTime: nil, duration: nil, processName: nil, host: host,
            sourceEndpoint: "192.0.2.1:1", destinationEndpoint: "\(host):443",
            protocolStack: [.tcp], status: .ok, latencyMilliseconds: nil, bytesUp: 0, bytesDown: 0
        )
    }
}
