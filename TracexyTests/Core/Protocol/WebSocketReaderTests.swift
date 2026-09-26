import Foundation
import Testing
@testable import Tracexy

// MARK: - WebSocketReaderTests

/// WebSocket frames and messages after an HTTP/1.1 upgrade, on the bytes pinned below:
/// masking,
/// permessage-deflate with a shared context, fragmentation with an interleaved
/// ping, close codes, honest stops, and agreement with tshark.
struct WebSocketReaderTests {
    // MARK: Internal

    @Test("Messages are unmasked, inflated and reassembled")
    func messages() throws {
        let conversation = try #require(WebSocketReader.read(aToB: Self.client, bToA: Self.server))
        #expect(conversation.clientIsAToB)
        #expect(conversation.deflate)
        let client = conversation.messages.filter(\.fromClient)
        let server = conversation.messages.filter { !$0.fromClient }
        #expect(client.map(\.opcode) == [.text, .binary, .ping, .close])
        #expect(client[0].text == "hello server")
        #expect(client[1].payload == [0, 1, 2, 3])
        #expect(client[1].frameCount == 2)
        #expect(client[3].closeCode == 1_000)
        #expect(client[3].closeReason == "bye")
        #expect(server.map(\.opcode) == [.text, .text, .pong, .close])
        // The second compressed message is only 5 bytes: it refers back into the first.
        #expect(server[0].text == Self.longText)
        #expect(server[1].text == Self.longText)
        #expect(server.map(\.compressed) == [true, true, false, false])
        #expect(server[1].wireSize == 5)
        #expect(server[1].size == 52)
        #expect(conversation.clientStop == nil)
        #expect(conversation.serverStop == nil)
        #expect(!conversation.clientInflateFailed && !conversation.serverInflateFailed)
        #expect(conversation.frames.count == 9)
    }

    @Test("A stream with no WebSocket upgrade is not read")
    func recognition() {
        let plain = Array("GET / HTTP/1.1\r\nHost: a\r\n\r\n".utf8)
        let ok = Array("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".utf8)
        #expect(WebSocketReader.read(aToB: plain, bToA: ok) == nil)
        #expect(WebSocketReader.read(aToB: [], bToA: []) == nil)
    }

    @Test("Reading stops honestly: cut short, broken framing, lost compression context")
    func honestStops() throws {
        let cut = try #require(WebSocketReader.read(aToB: Array(Self.client.dropLast(2)), bToA: Self.server))
        #expect(cut.clientStop == .cutShort)

        // A fragmented ping is not allowed (§5.5).
        let broken = Self.requestBytes + [0x09, 0x80, 1, 2, 3, 4]
        let malformed = try #require(WebSocketReader.read(aToB: broken, bToA: Self.responseBytes))
        #expect(malformed.clientStop == .malformed)

        // Without the first compressed message, the second cannot be inflated.
        let second = Self.hex("c105ca20430f00")
        let lost = try #require(WebSocketReader.read(aToB: Self.requestBytes, bToA: Self.responseBytes + second))
        #expect(lost.serverInflateFailed)
        #expect(lost.messages.first?.payload == nil)
        #expect(lost.messages.first?.wireSize == 5)
    }

    @Test("The followed stream lists messages in capture order with their frames")
    func followedStreamPresentation() throws {
        try Self.withCapture { url, identity in
            let result = try FollowStreamReader(contentsOf: url, expectedIdentity: identity, tuple: Self.tuple).read()
            let webSocket = try #require(FollowWebSocketPresentation(result: result))
            #expect(webSocket.messages.map(\.kind) == [
                "Text", "Text", "Text", "Binary", "Ping", "Pong", "Close", "Close",
            ])
            #expect(webSocket.messages.map(\.fromClient) == [true, false, false, true, true, false, true, false])
            #expect(webSocket.messages.map(\.content) == [
                "hello server", Self.longText, Self.longText, "00 01 02 03", "70", "70",
                "1000 normal closure bye", "1000 normal closure",
            ])
            #expect(webSocket.messages.map(\.size) == [
                "12 bytes", "52 bytes", "52 bytes", "4 bytes", "1 byte", "1 byte", "5 bytes", "2 bytes",
            ])
            #expect(webSocket.messages.map { $0.frame?.ordinal.rawValue } == [3, 4, 5, 6, 6, 7, 8, 9])
            #expect(webSocket.frameCount == 9)
            #expect(webSocket.notes.isEmpty)
            // The HTTP/1 section still lists the upgrade itself.
            #expect(FollowHTTPPresentation(result: result)?.rows.map(\.status) == ["101 Switching Protocols"])
        }
    }

    @Test(.enabled(if: WiresharkOracle.isAvailable, "Wireshark is not installed on this machine"))
    func tsharkAgrees() throws {
        try Self.withCapture { url, identity in
            let rows = try WiresharkOracle.tsharkFields(
                url,
                fields: ["frame.number", "websocket.opcode", "websocket.payload_length", "websocket.mask"],
                filter: "websocket"
            )
            let result = try FollowStreamReader(contentsOf: url, expectedIdentity: identity, tuple: Self.tuple).read()
            let webSocket = try #require(FollowWebSocketPresentation(result: result))
            var ours: [String: [FollowWebSocketFrameRow]] = [:]
            for frame in webSocket.frames {
                ours["\(frame.frame?.ordinal.rawValue ?? 0)", default: []].append(frame)
            }
            #expect(rows.count == 7)
            let codes = ["Continuation": "0", "Text": "1", "Binary": "2", "Close": "8", "Ping": "9", "Pong": "10"]
            for row in rows {
                let frames = ours[row[0]] ?? []
                #expect(frames.map { codes[$0.opcode] ?? "?" }.joined(separator: ",") == row[1], "frame \(row[0])")
                #expect(frames.map { "\($0.length)" }.joined(separator: ",") == row[2], "frame \(row[0])")
                #expect(frames.map { $0.masked ? "True" : "False" }.joined(separator: ",") == row[3], "frame \(row[0])")
            }
            let texts = try WiresharkOracle.tsharkFields(
                url,
                fields: ["websocket.payload.text"],
                filter: "websocket.payload.text"
            )
            #expect(texts.map { $0[0] } == ["hello server", Self.longText, Self.longText])
            let close = try WiresharkOracle.tsharkFields(
                url, fields: ["websocket.payload.close.status_code"], filter: "websocket.opcode == 8"
            )
            #expect(close.map { $0[0] } == ["1000", "1000"])
        }
    }

    // MARK: Private

    private static let longText = "hello client, this is a longer reply from the server"

    private static let requestBytes = Array((
        "GET /chat HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
            + "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n"
    ).utf8)

    private static let responseBytes = Array((
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            + "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
    ).utf8)

    /// The fixture's nine segments in capture order, with their times in microseconds.
    private static let segments: [(client: Bool, microseconds: UInt32, bytes: [UInt8])] = [
        (true, 0, requestBytes),
        (false, 10_000, responseBytes),
        (true, 20_000, hex("818c37fa213d5f9f4d5158da5258458c444f")),
        (
            false,
            30_000,
            hex(
                "c133ca48cdc9c95748cec94ccd2bd15128c9c82c5600a244859cfcbcf4d42285a2d4829c4a85b4a2fc5ca05caa42716a51596a1100"
            )
        ),
        (false, 40_000, hex("c105ca20430f00")),
        (true, 50_000, hex("02820102030401038981a1b2c3d4d180820ff05aa50df3")),
        (false, 60_000, hex("8a0170")),
        (true, 70_000, hex("88851122334412ca513d74")),
        (false, 80_000, hex("880203e8")),
    ]

    private static let tuple = FiveTuple(
        proto: .tcp,
        source: IPEndpoint(ip: "192.0.2.10", port: 51_000),
        destination: IPEndpoint(ip: "198.51.100.80", port: 80)
    )

    private static var client: [UInt8] {
        segments.filter(\.client).flatMap(\.bytes)
    }

    private static var server: [UInt8] {
        segments.filter { !$0.client }.flatMap(\.bytes)
    }

    private static func hex(_ text: String) -> [UInt8] {
        let digits = Array(text)
        return stride(from: 0, to: digits.count - 1, by: 2)
            .compactMap { UInt8(String(digits[$0 ... $0 + 1]), radix: 16) }
    }

    private static func withCapture(_ body: (URL, PcapFileIdentity) throws -> Void) throws {
        func le32(_ value: UInt32) -> [UInt8] {
            withUnsafeBytes(of: value.littleEndian) { Array($0) }
        }
        var clientSeq: UInt32 = 1_000
        var serverSeq: UInt32 = 5_000
        var file: [UInt8] = [0xD4, 0xC3, 0xB2, 0xA1, 2, 0, 4, 0] + le32(0) + le32(0) + le32(65_535)
        file += le32(LinkType.ethernet)
        for segment in segments {
            let tcp = PacketBuilder.tcp(
                srcPort: segment.client ? 51_000 : 80, dstPort: segment.client ? 80 : 51_000, flags: 0x18,
                payload: segment.bytes, sequence: segment.client ? clientSeq : serverSeq
            )
            let packet = PacketBuilder.ethernetIPv4(
                proto: 6,
                src: segment.client ? "192.0.2.10" : "198.51.100.80",
                dst: segment.client ? "198.51.100.80" : "192.0.2.10",
                payload: tcp
            )
            if segment.client {
                clientSeq += UInt32(segment.bytes.count)
            } else {
                serverSeq += UInt32(segment.bytes.count)
            }
            file += le32(1_800_000_000) + le32(segment.microseconds)
            file += le32(UInt32(packet.count)) + le32(UInt32(packet.count)) + packet
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("websocket-\(UUID().uuidString).pcap")
        try Data(file).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        try body(url, CaptureStreamReader(contentsOf: url).identity)
    }
}
