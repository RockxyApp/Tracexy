import Foundation
import Testing
@testable import Tracexy

/// Statistics ▸ Conversations and Endpoints: sums of the sessions' own per-direction
/// frame and byte tallies, keyed by address (IPv4/IPv6) or address and port (TCP/UDP).
struct TrafficStatisticsTests {
    // MARK: Internal

    @Test
    func conversationsSumBothDirectionsAndKeepTheFirstInitiatorAsA() throws {
        let sessions = [
            Self.session(
                "a",
                client: ("10.0.0.5", 50_000),
                server: ("192.0.2.1", 443),
                up: (3, 300),
                down: (5, 5_000),
                start: 10,
                duration: 2
            ),
            // Started from the other side: its "up" is B → A.
            Self.session(
                "b",
                client: ("192.0.2.1", 5_353),
                server: ("10.0.0.5", 5_353),
                up: (1, 100),
                down: (2, 200),
                start: 11,
                duration: 4,
                proto: .udp
            ),
        ]
        let rows = TrafficStatistics.conversations(of: sessions, kind: .ipv4)
        #expect(rows.count == 1)
        let row = try #require(rows.first)
        #expect(row.addressA == "10.0.0.5")
        #expect(row.sessionCount == 2)
        #expect(row.packetsAToB == 3 + 2)
        #expect(row.bytesAToB == 300 + 200)
        #expect(row.packetsBToA == 5 + 1)
        #expect(row.bytesBToA == 5_000 + 100)
        #expect(row.duration == 5)
        #expect(row.bitsPerSecondAToB == 800.0)
        #expect(row.term == "ip == 10.0.0.5 and ip == 192.0.2.1")

        let tcp = TrafficStatistics.conversations(of: sessions, kind: .tcp)
        #expect(tcp.count == 1)
        #expect(tcp.first?.term == "ip == 10.0.0.5 and ip == 192.0.2.1 and port == 50000 and port == 443")
        #expect(TrafficStatistics.conversations(of: sessions, kind: .udp).first?.term
            == "ip == 192.0.2.1 and ip == 10.0.0.5 and port == 5353")
        #expect(TrafficStatistics.conversations(of: sessions, kind: .ipv6).isEmpty)

        let arp = Self.session(
            "arp",
            client: ("10.0.0.5", 0),
            server: ("10.0.0.1", 0),
            up: (1, 42),
            down: (1, 42),
            proto: .arp
        )
        #expect(TrafficStatistics.conversations(of: [arp], kind: .ipv4).isEmpty, "ARP is not carried over IPv4")
    }

    @Test
    func endpointsSplitTxAndRx() throws {
        let sessions = [
            Self.session("a", client: ("10.0.0.5", 50_000), server: ("192.0.2.1", 443), up: (3, 300), down: (5, 5_000)),
            Self.session("b", client: ("10.0.0.5", 50_001), server: ("198.51.100.7", 443), up: (2, 20), down: (2, 40)),
        ]
        let rows = TrafficStatistics.endpoints(of: sessions, kind: .ipv4)
        let client = try #require(rows.first { $0.address == "10.0.0.5" })
        #expect(client.sessionCount == 2)
        #expect(client.txPackets == 5)
        #expect(client.txBytes == 320)
        #expect(client.rxPackets == 7)
        #expect(client.rxBytes == 5_040)
        let server = try #require(rows.first { $0.address == "192.0.2.1" })
        #expect(server.txBytes == 5_000)
        #expect(server.rxBytes == 300)
        #expect(rows.first?.address == "10.0.0.5", "largest first")
        #expect(TrafficStatistics.endpoints(of: sessions, kind: .tcp).count == 4)
        #expect(TrafficStatistics.endpointCounts(of: sessions)[.ipv4] == 3)
    }

    @Test
    func ipv6LabelsAndTermsParse() throws {
        let sessions = [
            Self.session(
                "v6",
                client: ("2001:db8::5", 50_000),
                server: ("2001:db8::1", 443),
                up: (1, 10),
                down: (1, 10)
            ),
        ]
        let endpoint = try #require(TrafficStatistics.endpoints(of: sessions, kind: .tcp).first)
        #expect(endpoint.label.hasPrefix("[2001:db8::"))
        let conversation = try #require(TrafficStatistics.conversations(of: sessions, kind: .ipv6).first)
        let parser = SessionQueryParser()
        _ = try parser.parse(conversation.term)
        _ = try parser.parse(endpoint.term)
    }

    @Test
    func csvHasAHeaderAndOneLinePerRow() {
        let sessions = [
            Self.session("a", client: ("10.0.0.5", 50_000), server: ("192.0.2.1", 443), up: (3, 300), down: (5, 5_000)),
        ]
        let csv = TrafficStatistics.csv(TrafficStatistics.endpoints(of: sessions, kind: .ipv4))
        let lines = csv.split(separator: "\n")
        #expect(lines.count == 3)
        #expect(lines[1] == "10.0.0.5,,1,8,5300,3,300,5,5000")
    }

    @Test
    func theFoldCountsFramesPerDirectionLikeTshark() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("traffic-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("conv.pcap")
        let frames = ReplayCorpus.conversationCapturedFrames()
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)

        let loaded = try SavedCaptureStreamLoader(contentsOf: url).load()
        let packets = loaded.sessions.reduce(0) { $0 + $1.packetsUp + $1.packetsDown }
        #expect(packets == frames.count)
        // The corpus's DNS exchange is the conversation with frames in both directions.
        let session = try #require(loaded.sessions.first { $0.dnsQuery == "one.example" })
        #expect(session.packetsUp > 0)
        #expect(session.packetsDown > 0)

        if WiresharkOracle.isAvailable {
            // Frames sent by the session's client, as tshark counts them.
            let client = try #require(session.sourceEndpointValue)
            let rows = try WiresharkOracle.tsharkFields(
                url, fields: ["frame.number"], filter: "ip.src == \(client.ip) && udp.srcport == \(client.port)"
            )
            #expect(rows.count == session.packetsUp)
        }
    }

    // MARK: Private

    private static func session(
        _ seed: String,
        client: (String, UInt16),
        server: (String, UInt16),
        up: (Int, Int),
        down: (Int, Int),
        start: TimeInterval? = nil,
        duration: TimeInterval? = nil,
        proto: ProtocolKind = .tcp
    )
        -> SessionSummary
    {
        let source = IPEndpoint(ip: client.0, port: client.1)
        let destination = IPEndpoint(ip: server.0, port: server.1)
        return SessionSummary(
            id: SessionBuilder.stableID("traffic-\(seed)"),
            startTime: start.map { Date(timeIntervalSince1970: 1_700_000_000 + $0) },
            duration: duration,
            processName: nil,
            host: seed,
            sourceEndpoint: source.display,
            destinationEndpoint: destination.display,
            sourceEndpointValue: source,
            destinationEndpointValue: destination,
            protocolStack: [proto],
            status: .ok,
            latencyMilliseconds: nil,
            bytesUp: up.1,
            bytesDown: down.1,
            packetsUp: up.0,
            packetsDown: down.0
        )
    }
}
