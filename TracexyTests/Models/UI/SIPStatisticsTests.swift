import Foundation
import Testing
@testable import Tracexy

/// SIP is recognized and Statistics ▸ SIP counts what
/// `tshark -z sip,stat` counts — messages, resent messages, status codes, request
/// methods and setup time.
struct SIPStatisticsTests {
    // MARK: Internal

    @Test
    func decodesTheStartLineAndDialogHeaders() throws {
        let invite = Self.frame(0, true, Self.request("INVITE", 1))
        let packet = SessionBuilder.decodePacket(
            CapturedFrame(bytes: invite.1, timestamp: nil, originalLength: invite.1.count), linkType: LinkType.ethernet
        )
        #expect(packet.appProtocol == .sip)
        #expect(packet.sip?.method == "INVITE")
        #expect(packet.sip?.callID == "call-1@example.test")
        #expect(packet.sip?.cseqNumber == 1)
        #expect(packet.layers.last?.summary == "Request: INVITE sip:bob@example.test")
        #expect(try SessionQueryParser().parse("sip") == .leaf(.protocolStackContains(.sip)))
    }

    @Test
    func statisticsMatchWireshark() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let rows = try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID()).scan()
            .rows
        let tree = SIPStatistics.tree(rows: rows)
        let byID = Dictionary(uniqueKeysWithValues: flatten(tree).map { ($0.id, $0) })
        #expect(byID["messages"]?.count == 11)
        #expect(byID["resent"]?.count == 2)
        #expect(byID["codes/200"]?.title == "200 OK")
        #expect(byID["setup"]?.average == 2_020)

        guard WiresharkOracle.isAvailable, let tshark = WiresharkOracle.tsharkURL else {
            return
        }
        let process = Process()
        let pipe = Pipe()
        process.executableURL = tshark
        process.arguments = ["-r", url.path, "-q", "-z", "sip,stat"]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let text = String(bytes: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        process.waitUntilExit()
        func number(after prefix: String) -> Int? {
            text.split(separator: "\n").first { $0.hasPrefix(prefix) }
                .flatMap { Int($0.dropFirst(prefix.count).trimmingCharacters(in: .whitespaces)) }
        }
        #expect(number(after: "Number of SIP messages:") == byID["messages"]?.count)
        #expect(number(after: "Number of resent SIP messages:") == byID["resent"]?.count)
        // "  SIP 200 OK  :   3 Packets" and "  INVITE  :   2 Packets", in hash order.
        var theirs: [String: Int] = [:]
        for line in text.split(separator: "\n") where line.contains("Packets") {
            let parts = line.split(separator: ":")
            let name = parts[0].trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "SIP ", with: "")
            theirs[name] = Int(parts[1].split(separator: " ")[0])
        }
        let ours = Dictionary(uniqueKeysWithValues: flatten(tree)
            .filter { $0.id.hasPrefix("codes/") || $0.id.hasPrefix("methods/") }
            .map { ($0.title, $0.count) })
        #expect(ours == theirs)
        #expect(text.contains("Average setup time \(Int(byID["setup"]?.average ?? 0)) ms"))
    }

    @Test
    func callsFollowTheirState() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let rows = try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID()).scan()
            .rows
        let calls = SIPCalls.calls(rows: rows)
        #expect(calls.count == 1)
        let call = try #require(calls.first)
        #expect(call.state == .completed)
        #expect(call.from == "sip:alice@example.test")
        #expect(call.to == "sip:bob@example.test")
        // Grouped by Call-ID, as Wireshark's VoIP Calls: the fixture's OPTIONS shares it.
        #expect(call.messages == 11)
        #expect(call.duration.map { ($0 * 1_000).rounded() } == 13_040)
        #expect(SIPMessageFacts.address("\"Bob\" <sip:bob@x.test>;tag=9") == "sip:bob@x.test")

        func facts(_ method: String?, _ code: Int?, _ cseqMethod: String) -> SIPMessageFacts {
            SIPMessageFacts(
                method: method, statusCode: code, reason: nil, callID: "c", cseqNumber: 1, cseqMethod: cseqMethod
            )
        }
        #expect(SIPCalls.next(.setup, facts(nil, 486, "INVITE")) == .rejected(486))
        #expect(SIPCalls.next(.ringing, facts("CANCEL", nil, "CANCEL")) == .cancelled)
        #expect(SIPCalls.next(.ringing, facts(nil, 487, "INVITE")) == .cancelled)
        #expect(SIPCalls.next(.inCall, facts(nil, 486, "INVITE")) == .inCall)
    }

    // MARK: Private

    private static let alice = "192.0.2.10"
    private static let bob = "198.51.100.7"

    private static func request(_ method: String, _ cseq: Int, toTag: Bool = false) -> String {
        "\(method) sip:bob@example.test SIP/2.0\r\nVia: SIP/2.0/UDP \(alice):5060;branch=z9hG4bK\(cseq)\(method)\r\n"
            + "From: <sip:alice@example.test>;tag=a1\r\nTo: <sip:bob@example.test>\(toTag ? ";tag=b2" : "")\r\n"
            + "Call-ID: call-1@example.test\r\nCSeq: \(cseq) \(method)\r\nContent-Length: 0\r\n\r\n"
    }

    private static func response(_ status: String, _ cseq: Int, _ method: String) -> String {
        "SIP/2.0 \(status)\r\nVia: SIP/2.0/UDP \(alice):5060;branch=z9hG4bK\(cseq)\(method)\r\n"
            + "From: <sip:alice@example.test>;tag=a1\r\nTo: <sip:bob@example.test>;tag=b2\r\n"
            + "Call-ID: call-1@example.test\r\nCSeq: \(cseq) \(method)\r\nContent-Length: 0\r\n\r\n"
    }

    private static func frame(_ time: Double, _ fromAlice: Bool, _ text: String) -> (Double, [UInt8]) {
        (time, PacketBuilder.ethernetIPv4(
            proto: 17, src: fromAlice ? alice : bob, dst: fromAlice ? bob : alice,
            payload: PacketBuilder.udp(srcPort: 5_060, dstPort: 5_060, payload: Array(text.utf8))
        ))
    }

    /// A call with a resent INVITE and a resent 200 OK, then an OPTIONS answered 404.
    private static func capture() throws -> URL {
        let frames = [
            frame(0, true, request("INVITE", 1)),
            frame(0.5, true, request("INVITE", 1)),
            frame(0.55, false, response("100 Trying", 1, "INVITE")),
            frame(0.8, false, response("180 Ringing", 1, "INVITE")),
            frame(2.0, false, response("200 OK", 1, "INVITE")),
            frame(2.01, false, response("200 OK", 1, "INVITE")),
            frame(2.02, true, request("ACK", 1, toTag: true)),
            frame(12.0, true, request("BYE", 2, toTag: true)),
            frame(12.05, false, response("200 OK", 2, "BYE")),
            frame(13.0, true, request("OPTIONS", 3)),
            frame(13.04, false, response("404 Not Found", 3, "OPTIONS")),
        ]
        func le32(_ value: UInt32) -> [UInt8] {
            (0 ..< 4).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
        }
        var bytes = le32(0xA1B2C3D4) + [2, 0, 4, 0] + le32(0) + le32(0) + le32(65_535) + le32(1)
        for (offset, frame) in frames {
            let micros = UInt64((offset * 1_000_000).rounded())
            bytes += le32(1_790_000_000 + UInt32(micros / 1_000_000)) + le32(UInt32(micros % 1_000_000))
            bytes += le32(UInt32(frame.count)) + le32(UInt32(frame.count)) + frame
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("sip-\(UUID().uuidString).pcap")
        try Data(bytes).write(to: url)
        return url
    }

    private func flatten(_ nodes: [StatsTreeNode]) -> [StatsTreeNode] {
        nodes.flatMap { [$0] + flatten($0.children ?? []) }
    }
}
