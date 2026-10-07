import Foundation
import Testing
@testable import Tracexy

/// Ethernet conversations and endpoints, and the `mac` Session Expression
/// field that narrows to them (Wireshark's `eth.addr`).
struct EthernetStatisticsTests {
    // MARK: Internal

    @Test
    func macFieldParsesValidatesAndMatches() throws {
        #expect(SessionSummary.normalizedMAC("0A-0b-0C-0d-0E-0f") == "0a:0b:0c:0d:0e:0f")
        #expect(SessionSummary.normalizedMAC("0a:0b:0c:0d:0e") == nil)
        #expect(SessionSummary.normalizedMAC("0a:0b:0c:0d:0e:zz") == nil)

        let sessions = Self.sessions()
        let web = try #require(sessions.first { $0.protocolStack.contains(.tcp) })
        let pair = try #require(web.macAddresses)
        #expect(pair.client == Self.clientMAC && pair.server == Self.gatewayMAC)

        let parser = SessionQueryParser()
        let engine = InvestigationQueryEngine()
        let snapshot = InvestigationSnapshot(
            fold: SessionFoldSnapshot(
                sessions: sessions, connections: .empty, datagramEvidence: .empty, tlsEvidence: .empty,
                segmentSeries: .empty
            ),
            connectionAssessor: ConnectionAssessor(),
            datagramAssessor: DatagramAssessor()
        )
        for (text, expected) in [
            ("mac == \(Self.clientMAC)", 2),
            ("source.mac == \(Self.clientMAC)", 2),
            ("destination.mac == \(Self.clientMAC)", 0),
            ("mac in {\(Self.otherMAC), \(Self.gatewayMAC.uppercased())}", 2),
        ] {
            let result = try engine.evaluate(engine.compile(parser.parse(text)), over: snapshot)
            #expect(result.matched.count == expected, "\(text)")
        }
        #expect(throws: SessionQueryParseError.self) { try parser.parse("mac == 12:34") }

        #expect(DisplayFilterTranslator.translate("eth.src == \(Self.clientMAC.uppercased())")
            == .translated("source.mac == \(Self.clientMAC)", approximate: false))
    }

    @Test
    func ethernetConversationsMatchWireshark() throws {
        let sessions = Self.sessions()
        let conversations = TrafficStatistics.conversations(of: sessions, kind: .ethernet)
        #expect(conversations.count == 1)
        let row = try #require(conversations.first)
        #expect(row.addressA == Self.clientMAC && row.addressB == Self.gatewayMAC)
        #expect(row.term == "mac == \(Self.clientMAC) and mac == \(Self.gatewayMAC)")
        _ = try SessionQueryParser().parse(row.term)
        let endpoints = TrafficStatistics.endpoints(of: sessions, kind: .ethernet)
        #expect(Set(endpoints.map(\.address)) == [Self.clientMAC, Self.gatewayMAC])

        guard WiresharkOracle.isAvailable else {
            return
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("eth-\(UUID().uuidString).pcap")
        let records = Self.frames().enumerated().map {
            ReplayCorpus.Frame(bytes: $0.element, offsetSeconds: $0.offset, linkType: LinkType.ethernet)
        }
        try Data(ReplayCorpus.classicPcapBytes(records)).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let totals = try WiresharkOracle.tsharkFields(url, fields: ["frame.len"])
            .compactMap { Int($0[0]) }
        #expect(row.packets == totals.count)
        #expect(row.bytes == totals.reduce(0, +))
        let pairs = try WiresharkOracle.tsharkFields(url, fields: ["eth.src", "eth.dst"])
        #expect(Set(pairs.flatMap { $0 }) == [Self.clientMAC, Self.gatewayMAC])
    }

    // MARK: Private

    private static let clientMAC = "0a:00:27:00:00:01"
    private static let gatewayMAC = "0a:00:27:00:00:fe"
    private static let otherMAC = "0a:00:27:00:00:99"

    /// A web request and its answer, and a DNS query, all between the client and
    /// its gateway: the server side of each frame is the gateway's MAC.
    private static func frames() -> [[UInt8]] {
        let request = PacketBuilder.httpRequestFrame(host: "a.test", path: "/", src: "192.0.2.10", dst: "198.51.100.7")
        let answer = PacketBuilder.ethernetIPv4(
            proto: 6, src: "198.51.100.7", dst: "192.0.2.10",
            payload: PacketBuilder.tcp(
                srcPort: 80, dstPort: 52_100, flags: 0x18, payload: Array("HTTP/1.1 200 OK\r\n\r\n".utf8)
            )
        )
        let dns = PacketBuilder.dnsQueryFrame(name: "a.test", src: "192.0.2.10", dst: "192.0.2.1")
        return [
            macs(request, source: clientMAC, destination: gatewayMAC),
            macs(answer, source: gatewayMAC, destination: clientMAC),
            macs(dns, source: clientMAC, destination: gatewayMAC),
        ]
    }

    private static func sessions() -> [SessionSummary] {
        let captured = frames().enumerated().map { index, bytes in
            CapturedFrame(
                bytes: bytes, timestamp: Date(timeIntervalSince1970: 1_700_000_000 + Double(index)),
                originalLength: bytes.count, capturedLength: bytes.count, linkType: LinkType.ethernet
            )
        }
        return SessionBuilder.build(from: captured, linkType: LinkType.ethernet)
    }

    private static func macs(_ frame: [UInt8], source: String, destination: String) -> [UInt8] {
        var copy = frame
        let bytes = { (mac: String) in mac.split(separator: ":").compactMap { UInt8($0, radix: 16) } }
        copy.replaceSubrange(0 ..< 6, with: bytes(destination))
        copy.replaceSubrange(6 ..< 12, with: bytes(source))
        return copy
    }
}
