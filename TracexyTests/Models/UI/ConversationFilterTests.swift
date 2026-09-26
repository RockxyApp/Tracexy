import Foundation
import Testing
@testable import Tracexy

/// All Frames ▸ Conversation Filter: the Ethernet, IP and TCP or UDP terms for a
/// frame's session each find that session and not a neighbour sharing only part of it.
struct ConversationFilterTests {
    @Test
    func eachLayerFindsItsConversation() throws {
        let frames = [
            PacketBuilder.ethernetIPv4(
                proto: 6, src: "192.0.2.10", dst: "198.51.100.7",
                payload: PacketBuilder.tcp(srcPort: 50_000, dstPort: 443, flags: 0x02, payload: [])
            ),
            PacketBuilder.ethernetIPv4(
                proto: 6, src: "192.0.2.10", dst: "198.51.100.7",
                payload: PacketBuilder.tcp(srcPort: 50_001, dstPort: 80, flags: 0x02, payload: [])
            ),
            PacketBuilder.dnsQueryFrame(name: "a.test", src: "192.0.2.10", dst: "192.0.2.53"),
        ]
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("conv-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames.enumerated().map {
            CapturedFrame(
                bytes: $0.element, timestamp: Date(timeIntervalSince1970: 1_800_000_000 + Double($0.offset)),
                originalLength: $0.element.count
            )
        }, to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let loaded = try SavedCaptureStreamLoader(contentsOf: url).load()
        let snapshot = InvestigationSnapshot(
            sessions: loaded.sessions, connections: loaded.connections, datagramEvidence: loaded.datagramEvidence,
            tlsEvidence: loaded.tlsEvidence, segmentSeries: loaded.segmentSeries,
            connectionAnalysis: loaded.connectionAnalysis, datagramAnalysis: loaded.datagramAnalysis,
            tlsAnalysis: loaded.tlsAnalysis, trafficTimeline: loaded.trafficTimeline
        )
        let engine = InvestigationQueryEngine()
        let matched = { (term: String) in
            try Set(engine.evaluate(engine.compile(SessionQueryParser().parse(term)), over: snapshot).matched.map(\.id))
        }
        let https = try #require(loaded.sessions.first { $0.destinationEndpointValue?.port == 443 })
        let options = ConversationFilter.options(for: https)
        #expect(options.map(\.title) == ["Ethernet", "IPv4", "TCP"])
        let byTitle = Dictionary(uniqueKeysWithValues: options.map { ($0.title, $0.term) })
        #expect(try matched(#require(byTitle["TCP"])) == [https.id])
        #expect(try matched(#require(byTitle["IPv4"])).count == 2, "both TCP sessions share the addresses")
        #expect(try matched(#require(byTitle["Ethernet"])).count == 3, "every frame shares the two MACs")

        let dns = try #require(loaded.sessions.first { $0.protocolStack.contains(.dns) })
        #expect(ConversationFilter.options(for: dns).map(\.title) == ["Ethernet", "IPv4", "UDP"])
        #expect(try matched(#require(ConversationFilter.options(for: dns).last?.term)) == [dns.id])
    }
}
