import Foundation
import Testing
@testable import Tracexy

/// VoIP Calls ▸ Flow Sequence: a call's SIP messages, and each RTP stream sent to a
/// media address its SDP offered — once, with its packet count — while an unrelated
/// stream stays out; the SDP address and port read as tshark reads them.
struct SIPCallFlowTests {
    // MARK: Internal

    @Test
    func aCallsFlowIsItsSignallingAndItsMedia() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let rows = try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID()).scan()
            .rows
        #expect(rows.compactMap { $0.sip?.media?.display } == ["192.0.2.10:40000", "198.51.100.7:40002"])
        let flow = SIPCallFlow.rows(callID: "call-1@example.test", in: rows)
        #expect(flow.filter { $0.protocolName == "RTP" }.map(\.info) == ["(g711U), 3 packets", "(g711U), 3 packets"])
        #expect(flow.filter { $0.sip != nil }.count == 4)
        #expect(!flow.contains { $0.source == "203.0.113.9" })
        #expect(CaptureFlowGraph(rows: flow).lanes == ["192.0.2.10", "198.51.100.7"])

        guard WiresharkOracle.isAvailable else {
            return
        }
        #expect(try WiresharkOracle.tsharkFields(
            url, fields: ["sdp.connection_info.address", "sdp.media.port"], filter: "sdp"
        ) == [["192.0.2.10", "40000"], ["198.51.100.7", "40002"]])
    }

    // MARK: Private

    private static let alice = "192.0.2.10"
    private static let bob = "198.51.100.7"

    private static func sip(_ firstLine: String, cseq: String, sdp: (String, Int)? = nil) -> [UInt8] {
        let body = sdp.map { address, port in
            "v=0\r\no=- 1 1 IN IP4 \(address)\r\ns=-\r\nc=IN IP4 \(address)\r\nt=0 0\r\n"
                + "m=audio \(port) RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
        } ?? ""
        let headers = "\(firstLine)\r\nVia: SIP/2.0/UDP \(alice):5060;branch=z9hG4bK1\r\n"
            + "From: <sip:alice@example.test>;tag=a1\r\nTo: <sip:bob@example.test>\r\n"
            + "Call-ID: call-1@example.test\r\nCSeq: \(cseq)\r\n"
            + (body.isEmpty ? "" : "Content-Type: application/sdp\r\n") + "Content-Length: \(body.utf8.count)\r\n\r\n"
        return Array((headers + body).utf8)
    }

    private static func udp(
        _ source: (String, UInt16),
        _ destination: (String, UInt16),
        _ payload: [UInt8]
    )
        -> [UInt8]
    {
        PacketBuilder.ethernetIPv4(
            proto: 17, src: source.0, dst: destination.0,
            payload: PacketBuilder.udp(srcPort: source.1, dstPort: destination.1, payload: payload)
        )
    }

    private static func rtp(sequence: UInt16, ssrc: UInt32) -> [UInt8] {
        [
            0x80,
            0x00,
            UInt8(sequence >> 8),
            UInt8(sequence & 0xFF),
            0,
            0,
            0,
            UInt8(sequence),
            UInt8(ssrc >> 24),
            UInt8(ssrc >> 16 & 0xFF),
            UInt8(ssrc >> 8 & 0xFF),
            UInt8(ssrc & 0xFF)
        ] + [UInt8](repeating: 0xFF, count: 160)
    }

    private static func capture() throws -> URL {
        var frames = [
            udp(
                (alice, 5_060),
                (bob, 5_060),
                sip("INVITE sip:bob@example.test SIP/2.0", cseq: "1 INVITE", sdp: (alice, 40_000))
            ),
            udp((bob, 5_060), (alice, 5_060), sip("SIP/2.0 200 OK", cseq: "1 INVITE", sdp: (bob, 40_002))),
            udp((alice, 5_060), (bob, 5_060), sip("ACK sip:bob@example.test SIP/2.0", cseq: "1 ACK")),
        ]
        for sequence in 1 ... 3 {
            frames.append(udp((alice, 40_000), (bob, 40_002), rtp(sequence: UInt16(sequence), ssrc: 0x11111111)))
            frames.append(udp((bob, 40_002), (alice, 40_000), rtp(sequence: UInt16(sequence), ssrc: 0x22222222)))
            frames.append(udp(
                ("203.0.113.9", 50_000),
                ("203.0.113.8", 50_002),
                rtp(sequence: UInt16(sequence), ssrc: 7)
            ))
        }
        frames.append(udp((alice, 5_060), (bob, 5_060), sip("BYE sip:bob@example.test SIP/2.0", cseq: "2 BYE")))
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("callflow-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames.enumerated().map {
            CapturedFrame(
                bytes: $0.element, timestamp: Date(timeIntervalSince1970: 1_800_000_000 + Double($0.offset) / 50),
                originalLength: $0.element.count
            )
        }, to: url)
        return url
    }
}
