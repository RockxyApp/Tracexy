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
        defer { defaults.removePersistentDomain(forName: suite) }
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

    // MARK: Private

    private func session(host: String) -> SessionSummary {
        SessionSummary(
            id: UUID(), startTime: nil, duration: nil, processName: nil, host: host,
            sourceEndpoint: "192.0.2.1:1", destinationEndpoint: "\(host):443",
            protocolStack: [.tcp], status: .ok, latencyMilliseconds: nil, bytesUp: 0, bytesDown: 0
        )
    }
}
