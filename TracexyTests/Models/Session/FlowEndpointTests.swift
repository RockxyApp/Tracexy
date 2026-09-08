import Foundation
import Testing
@testable import Tracexy

/// Flow's address rows are grouped by the *typed* destination endpoint the fold
/// published, never by re-splitting the rendered `"ip:port"` string. Every
/// fixture here therefore supplies a real `IPEndpoint`, because a summary
/// carrying only display text is exactly the case the grouping now excludes —
/// and counts as an explicit omission rather than a silent row.
@Suite("Flow endpoints")
struct FlowEndpointTests {
    // MARK: Internal

    @Test("Conversations to one address collapse into one row that sums them")
    func conversationsCollapsePerAddress() {
        let endpoints = FlowEndpoint.endpoints(from: [
            session(ip: "93.184.16.34", port: 443, host: "api.example.com", bytes: 100),
            session(ip: "93.184.16.34", port: 8_443, host: "api.example.com", bytes: 50),
            session(ip: "104.18.32.7", port: 443, host: "cdn.fastly.net", bytes: 20),
        ])

        #expect(endpoints.count == 2)
        // Heaviest first, so the list opens on what matters.
        #expect(endpoints[0].address == "93.184.16.34")
        #expect(endpoints[0].bytes == 150)
        #expect(endpoints[0].sessionCount == 2)
        #expect(FlowEndpoint.omittedSessionCount(in: []) == 0)
    }

    @Test("Every name an address answered to is kept, most-seen first")
    func competingNamesAreAllKept() {
        let endpoints = FlowEndpoint.endpoints(from: [
            session(ip: "104.18.32.7", port: 443, host: "edge.quic.cloud", bytes: 10),
            session(ip: "104.18.32.7", port: 443, host: "edge.quic.cloud", bytes: 10),
            session(ip: "104.18.32.7", port: 443, host: "assets.quic.cloud", bytes: 10),
        ])

        // A shared CDN address is the normal case, and picking one name would
        // hide exactly the ambiguity the user needs to see.
        #expect(endpoints[0].names == ["edge.quic.cloud", "assets.quic.cloud"])
        #expect(endpoints[0].displayName == "edge.quic.cloud")
    }

    @Test("An unresolved address falls back to itself and is never invented a name")
    func unresolvedAddressKeepsItself() {
        let endpoints = FlowEndpoint.endpoints(from: [
            session(ip: "203.0.113.9", port: 443, host: "203.0.113.9", bytes: 10),
        ])

        #expect(endpoints[0].names.isEmpty)
        #expect(endpoints[0].displayName == "203.0.113.9")
    }

    @Test("Private and loopback addresses stay listed but are marked unmappable")
    func localTrafficIsListedNotDropped() {
        let endpoints = FlowEndpoint.endpoints(from: [
            session(ip: "192.168.1.10", port: 445, host: "nas.local", bytes: 10),
            session(ip: "93.184.16.34", port: 443, host: "api.example.com", bytes: 10),
        ])

        // Dropping them would make the surface's totals disagree with the
        // session list, which is worse than an honest "not on the map".
        #expect(endpoints.count == 2)
        let local = try? #require(endpoints.first { $0.address == "192.168.1.10" })
        #expect(local?.isMappable == false)
        #expect(endpoints.first { $0.address == "93.184.16.34" }?.isMappable == true)
    }

    @Test("A failed conversation makes the whole address read as failed")
    func worstStatusWins() {
        let endpoints = FlowEndpoint.endpoints(from: [
            session(ip: "93.184.16.34", port: 443, host: "api.example.com", bytes: 10, status: .ok),
            session(ip: "93.184.16.34", port: 443, host: "api.example.com", bytes: 10, status: .error),
        ])

        #expect(endpoints[0].status == .error)
    }

    @Test("Equivalent IPv6 spellings are one row with one deterministic address")
    func equivalentIPv6SpellingsCollapse() throws {
        let endpoints = FlowEndpoint.endpoints(from: [
            session(ip: "2001:db8::1", port: 443, host: "v6.example.com", bytes: 10),
            session(ip: "2001:0db8:0000:0000:0000:0000:0000:0001", port: 443, host: "v6.example.com", bytes: 5),
        ])

        // Binary identity, so two spellings of one address are one destination.
        #expect(endpoints.count == 1)
        let row = try #require(endpoints.first)
        #expect(row.sessionCount == 2)
        #expect(row.bytes == 15)
        // Whichever spelling wins, it wins the same way every run.
        #expect(row.address == FlowEndpoint.endpoints(from: [
            session(ip: "2001:0db8:0000:0000:0000:0000:0000:0001", port: 443, host: "v6.example.com", bytes: 5),
            session(ip: "2001:db8::1", port: 443, host: "v6.example.com", bytes: 10),
        ]).first?.address)
        // A host that is only the address in another spelling is a fallback, not
        // a resolved name.
        #expect(row.names == ["v6.example.com"])
    }

    @Test("A host that is just the address in another spelling is not a resolved name")
    func addressSpelledAsHostIsNotAName() throws {
        let endpoints = FlowEndpoint.endpoints(from: [
            session(ip: "2001:db8::1", port: 443, host: "2001:0db8::1", bytes: 10),
        ])

        #expect(try #require(endpoints.first).names.isEmpty)
    }

    @Test("A session with no usable typed destination is omitted and counted, never guessed")
    func missingTypedDestinationIsOmittedAndCounted() {
        var displayOnly = session(ip: "93.184.16.34", port: 443, host: "api.example.com", bytes: 10)
        displayOnly.destinationEndpointValue = nil
        var invalid = session(ip: "93.184.16.34", port: 443, host: "broken.example", bytes: 10)
        invalid.destinationEndpointValue = IPEndpoint(ip: "not-an-address", port: 443)
        let listed = session(ip: "104.18.32.7", port: 443, host: "cdn.fastly.net", bytes: 20)
        let sessions = [displayOnly, invalid, listed]

        let endpoints = FlowEndpoint.endpoints(from: sessions)

        // The rendered endpoint string is still there and still says
        // "93.184.16.34:443" — and is deliberately not parsed back into a row.
        #expect(endpoints.count == 1)
        #expect(endpoints[0].address == "104.18.32.7")
        #expect(endpoints[0].sessionCount == 1)
        #expect(FlowEndpoint.omittedSessionCount(in: sessions) == 2)
    }

    // MARK: Private

    private func session(
        ip: String,
        port: UInt16,
        host: String,
        bytes: Int,
        status: SessionStatus = .ok
    )
        -> SessionSummary
    {
        SessionSummary(
            id: UUID(),
            startTime: Date(timeIntervalSince1970: 0),
            duration: 0.1,
            processName: "MyApp",
            host: host,
            sourceEndpoint: "192.168.1.2:52000",
            destinationEndpoint: "\(ip):\(port)",
            sourceEndpointValue: IPEndpoint(ip: "192.168.1.2", port: 52_000),
            destinationEndpointValue: IPEndpoint(ip: ip, port: port),
            protocolStack: [.tcp],
            status: status,
            latencyMilliseconds: 10,
            bytesUp: bytes,
            bytesDown: 0
        )
    }
}
