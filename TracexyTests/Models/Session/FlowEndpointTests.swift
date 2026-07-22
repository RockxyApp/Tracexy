import Foundation
import Testing
@testable import Tracexy

@Suite("Flow endpoints")
struct FlowEndpointTests {
    // MARK: Internal

    @Test("Conversations to one address collapse into one row that sums them")
    func conversationsCollapsePerAddress() {
        let endpoints = FlowEndpoint.endpoints(from: [
            session(destination: "93.184.16.34:443", host: "api.example.com", bytes: 100),
            session(destination: "93.184.16.34:8443", host: "api.example.com", bytes: 50),
            session(destination: "104.18.32.7:443", host: "cdn.fastly.net", bytes: 20)
        ])

        #expect(endpoints.count == 2)
        // Heaviest first, so the list opens on what matters.
        #expect(endpoints[0].address == "93.184.16.34")
        #expect(endpoints[0].bytes == 150)
        #expect(endpoints[0].sessionCount == 2)
    }

    @Test("Every name an address answered to is kept, most-seen first")
    func competingNamesAreAllKept() {
        let endpoints = FlowEndpoint.endpoints(from: [
            session(destination: "104.18.32.7:443", host: "edge.quic.cloud", bytes: 10),
            session(destination: "104.18.32.7:443", host: "edge.quic.cloud", bytes: 10),
            session(destination: "104.18.32.7:443", host: "assets.quic.cloud", bytes: 10)
        ])

        // A shared CDN address is the normal case, and picking one name would
        // hide exactly the ambiguity the user needs to see.
        #expect(endpoints[0].names == ["edge.quic.cloud", "assets.quic.cloud"])
        #expect(endpoints[0].displayName == "edge.quic.cloud")
    }

    @Test("An unresolved address falls back to itself and is never invented a name")
    func unresolvedAddressKeepsItself() {
        let endpoints = FlowEndpoint.endpoints(from: [
            session(destination: "203.0.113.9:443", host: "203.0.113.9", bytes: 10)
        ])

        #expect(endpoints[0].names.isEmpty)
        #expect(endpoints[0].displayName == "203.0.113.9")
    }

    @Test("Private and loopback addresses stay listed but are marked unmappable")
    func localTrafficIsListedNotDropped() {
        let endpoints = FlowEndpoint.endpoints(from: [
            session(destination: "192.168.1.10:445", host: "nas.local", bytes: 10),
            session(destination: "93.184.16.34:443", host: "api.example.com", bytes: 10)
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
            session(destination: "93.184.16.34:443", host: "api.example.com", bytes: 10, status: .ok),
            session(destination: "93.184.16.34:443", host: "api.example.com", bytes: 10, status: .error)
        ])

        #expect(endpoints[0].status == .error)
    }

    // MARK: Private

    private func session(
        destination: String,
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
            destinationEndpoint: destination,
            protocolStack: [.tcp],
            status: status,
            latencyMilliseconds: 10,
            bytesUp: bytes,
            bytesDown: 0
        )
    }
}
