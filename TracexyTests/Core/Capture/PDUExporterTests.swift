import Foundation
import Testing
@testable import Tracexy

/// File ▸ Export PDUs writes each recognized application payload — UDP
/// datagrams and reassembled TCP turns — as a Wireshark Upper PDU packet (link type
/// 252), and Wireshark dissects the same messages from it.
struct PDUExporterTests {
    // MARK: Internal

    @Test
    func upperPDUTagsFollowWireshark() {
        let bytes = PDUExporter.packet(
            name: "http", source: IPEndpoint(ip: "10.0.0.5", port: 50_000),
            destination: IPEndpoint(ip: "203.0.113.9", port: 80), tcp: true, payload: [0xAA]
        )
        // Tag 12, length 4, "http"; IPv4 source/destination; port type TCP (2); ports; end.
        #expect(Array(bytes.prefix(8)) == [0, 12, 0, 4] + Array("http".utf8))
        #expect(Array(bytes[8 ..< 16]) == [0, 20, 0, 4, 10, 0, 0, 5])
        #expect(Array(bytes[24 ..< 32]) == [0, 24, 0, 4, 0, 0, 0, 2])
        #expect(Array(bytes.suffix(5)) == [0, 0, 0, 0, 0xAA])
        let sip = PDUExporter.packet(
            name: "sip", source: IPEndpoint(ip: "10.0.0.5", port: 1), destination: IPEndpoint(ip: "10.0.0.6", port: 2),
            tcp: false, payload: []
        )
        // A name is padded with NUL to 4 bytes, and the length counts the padding.
        #expect(Array(sip.prefix(8)) == [0, 12, 0, 4, 0x73, 0x69, 0x70, 0])
    }

    @Test
    func exportedPDUsDissectLikeTheOriginal() throws {
        let source = FileManager.default.temporaryDirectory.appendingPathComponent("pdu-in-\(UUID().uuidString).pcap")
        let output = FileManager.default.temporaryDirectory.appendingPathComponent("pdu-\(UUID().uuidString).pcapng")
        defer {
            try? FileManager.default.removeItem(at: source)
            try? FileManager.default.removeItem(at: output)
        }
        try Data(ReplayCorpus.classicPcapBytes(Self.frames().enumerated().map {
            ReplayCorpus.Frame(bytes: $0.element, offsetSeconds: $0.offset, linkType: LinkType.ethernet)
        })).write(to: source)
        let identity = try CaptureStreamReader(contentsOf: source).identity
        let http = FiveTuple(
            proto: .tcp, source: IPEndpoint(ip: "10.0.0.5", port: 50_000),
            destination: IPEndpoint(ip: "203.0.113.9", port: 80)
        )
        let dns = FiveTuple(
            proto: .udp, source: IPEndpoint(ip: "10.0.0.5", port: 53_000),
            destination: IPEndpoint(ip: "192.0.2.53", port: 53)
        )
        let sip = FiveTuple(
            proto: .udp, source: IPEndpoint(ip: "10.0.0.5", port: 5_060),
            destination: IPEndpoint(ip: "198.51.100.7", port: 5_060)
        )
        let summary = try PDUExporter.export(
            from: source, expectedIdentity: identity, streams: [PDUExporter.Stream(tuple: http, kind: .http)],
            datagramSessions: [SessionBuilder.sessionID(for: dns), SessionBuilder.sessionID(for: sip)], to: output
        )
        // Two HTTP turns each way, one DNS query, one SIP INVITE.
        #expect(summary.pduCount == 6)
        #expect(summary.streamCount == 1)

        guard WiresharkOracle.isAvailable else {
            return
        }
        #expect(try WiresharkOracle.tsharkFields(
            output, fields: ["http.request.method", "http.request.uri"], filter: "http.request"
        ) == [["GET", "/a.txt"], ["GET", "/b.txt"]])
        #expect(try WiresharkOracle.tsharkFields(output, fields: ["http.response.code"], filter: "http.response")
            == [["200"], ["200"]])
        #expect(try WiresharkOracle.tsharkFields(output, fields: ["dns.qry.name"], filter: "dns") == [["t.test"]])
        #expect(try WiresharkOracle.tsharkFields(output, fields: ["sip.Method"], filter: "sip") == [["INVITE"]])
        #expect(try WiresharkOracle.tsharkFields(output, fields: ["exported_pdu.ipv4_dst"], filter: "sip")
            == [["198.51.100.7"]])
    }

    // MARK: Private

    private static func frames() -> [[UInt8]] {
        let first = Array("GET /a.txt HTTP/1.1\r\nHost: t.test\r\n\r\n".utf8)
        let second = Array("GET /b.txt HTTP/1.1\r\nHost: t.test\r\n\r\n".utf8)
        let reply = Array("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok".utf8)
        func tcp(_ client: Bool, _ sequence: UInt32, _ payload: [UInt8]) -> [UInt8] {
            PacketBuilder.ethernetIPv4(
                proto: 6, src: client ? "10.0.0.5" : "203.0.113.9", dst: client ? "203.0.113.9" : "10.0.0.5",
                payload: PacketBuilder.tcp(
                    srcPort: client ? 50_000 : 80, dstPort: client ? 80 : 50_000, flags: 0x18, payload: payload,
                    sequence: sequence
                )
            )
        }
        // A standard query for t.test, type A.
        let query: [UInt8] = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0x74, 4] + Array("test".utf8)
            + [0, 0, 1, 0, 1]
        let invite = Array((
            "INVITE sip:bob@example.test SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bK1\r\n"
                + "From: <sip:alice@example.test>;tag=a1\r\nTo: <sip:bob@example.test>\r\nCall-ID: c1\r\n"
                + "CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        ).utf8)
        return [
            tcp(true, 1_000, first),
            tcp(false, 5_000, reply),
            PacketBuilder.ethernetIPv4(
                proto: 17, src: "10.0.0.5", dst: "192.0.2.53",
                payload: PacketBuilder.udp(srcPort: 53_000, dstPort: 53, payload: query)
            ),
            tcp(true, 1_000 + UInt32(first.count), second),
            tcp(false, 5_000 + UInt32(reply.count), reply),
            PacketBuilder.ethernetIPv4(
                proto: 17, src: "10.0.0.5", dst: "198.51.100.7",
                payload: PacketBuilder.udp(srcPort: 5_060, dstPort: 5_060, payload: invite)
            ),
        ]
    }
}
