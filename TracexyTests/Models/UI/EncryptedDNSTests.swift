import Foundation
import Testing
@testable import Tracexy

/// "is my DNS encrypted?" — DoT and DoQ by port 853, DoH only by a well-known
/// resolver name, plain unicast DNS counted beside them, multicast DNS left out.
struct EncryptedDNSTests {
    // MARK: Internal

    @Test
    func classifiesByPortOrServerName() {
        #expect(EncryptedDNS.classify(Self.session(port: 853, stack: [.tcp, .tls]))?.transport == .tls)
        #expect(EncryptedDNS.classify(Self.session(port: 853, stack: [.udp, .quic]))?.transport == .quic)
        let doh = EncryptedDNS.classify(Self.session(port: 443, stack: [.tcp, .tls], sni: "dns.google"))
        #expect(doh?.transport == .https)
        #expect(doh?.basis == "server name")
        #expect(EncryptedDNS.classify(Self.session(port: 443, stack: [.tcp, .tls], sni: "abc123.dns.nextdns.io"))?
            .transport == .https)
        // Any other HTTPS server is ordinary web traffic, not guessed to be DNS.
        #expect(EncryptedDNS.classify(Self.session(port: 443, stack: [.tcp, .tls], sni: "example.com")) == nil)
        #expect(EncryptedDNS.classify(Self.session(port: 53, stack: [.udp, .dns])) == nil)
    }

    @Test
    func rowsAndSummary() {
        let sessions = [
            Self.session(port: 443, stack: [.tcp, .tls], sni: "dns.google"),
            Self.session(port: 443, stack: [.tcp, .tls], sni: "dns.google", clientPort: 50_001),
            Self.session(port: 853, stack: [.tcp, .tls], sni: "dns.quad9.net"),
            Self.session(port: 53, stack: [.udp, .dns]),
            Self.session(port: 5_353, stack: [.udp, .mdns, .dns]),
        ]
        let rows = EncryptedDNS.rows(of: sessions)
        #expect(rows.map(\.server) == ["dns.google", "dns.quad9.net"])
        #expect(rows.first?.sessionCount == 2)
        #expect(EncryptedDNS.summary(of: sessions)
            == "1 plain DNS session, 3 encrypted (DNS over TLS 1, DNS over HTTPS 2)")
        #expect(EncryptedDNS.summary(of: [sessions[3]]) == "1 plain DNS session, no encrypted DNS recognized")
    }

    // MARK: Private

    private static func session(
        port: UInt16,
        stack: [ProtocolKind],
        sni: String? = nil,
        clientPort: UInt16 = 50_000
    )
        -> SessionSummary
    {
        let client = IPEndpoint(ip: "192.0.2.10", port: clientPort)
        let server = IPEndpoint(ip: "198.51.100.8", port: port)
        var session = SessionSummary(
            id: SessionBuilder.stableID("dns-\(port)-\(sni ?? "")-\(clientPort)-\(stack.count)"),
            startTime: Date(timeIntervalSince1970: 1_800_000_000), duration: 1, processName: nil,
            host: sni ?? server.ip, sourceEndpoint: client.display, destinationEndpoint: server.display,
            sourceEndpointValue: client, destinationEndpointValue: server, protocolStack: stack, status: .ok,
            latencyMilliseconds: nil, bytesUp: 100, bytesDown: 200
        )
        session.sni = sni
        return session
    }
}
