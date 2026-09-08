import Foundation
import Testing
@testable import Tracexy

@Suite("Exact IP scope")
struct SessionIPAddressScopeTests {
    // MARK: Internal

    @Test("Selecting an IPv4 address never includes a longer address or port substring")
    func exactIPv4() {
        let session = makeSession(source: "192.0.2.10", destination: "198.51.100.20")
        #expect(matches(session, "192.0.2.10"))
        #expect(matches(session, "198.51.100.20"))
        #expect(!matches(session, "192.0.2.1"))
        #expect(!matches(session, "198.51.100.2"))
        #expect(!matches(session, "443"))
    }

    @Test("Equivalent IPv6 spellings match both endpoint and DNS evidence")
    func equivalentIPv6() {
        var session = makeSession(source: "2001:db8::1", destination: "2001:db8::10")
        #expect(matches(session, "2001:0DB8:0:0:0:0:0:1"))
        #expect(!matches(session, "2001:db8::2"))
        session.dnsAnswers = ["2001:db8::abcd"]
        #expect(matches(session, "2001:0db8:0000:0000:0000:0000:0000:abcd"))
    }

    @Test("DNS answers remain eligible but names and absent typed endpoints are not invented addresses")
    func dnsAndUnknown() {
        var session = makeSession(source: "192.0.2.10", destination: "198.51.100.20")
        session.dnsAnswers = ["203.0.113.9", "cdn.example.test"]
        #expect(matches(session, "203.0.113.9"))
        #expect(!matches(session, "cdn.example.test"))
        session.sourceEndpointValue = nil
        session.destinationEndpointValue = nil
        #expect(!matches(session, "192.0.2.10"))
        #expect(!matches(session, ""))
        #expect(!matches(session, "192.0.2.10\0other"))
    }

    // MARK: Private

    private func matches(_ session: SessionSummary, _ address: String) -> Bool {
        MainContentCoordinator.session(session, matchesAddress: IPAddressValue(parsing: address))
    }

    private func makeSession(source: String, destination: String) -> SessionSummary {
        SessionSummary(
            id: UUID(), startTime: Date(timeIntervalSince1970: 1), duration: 0,
            host: "example.test", sourceEndpoint: "\(source):443", destinationEndpoint: "\(destination):443",
            sourceEndpointValue: IPEndpoint(ip: source, port: 443),
            destinationEndpointValue: IPEndpoint(ip: destination, port: 443),
            protocolStack: [.tcp], status: .ok, bytesUp: 1, bytesDown: 1
        )
    }
}
