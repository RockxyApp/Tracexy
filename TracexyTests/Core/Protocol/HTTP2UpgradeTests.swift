import Foundation
import Testing
@testable import Tracexy

/// HTTP/2 reached by an HTTP/1.1 `Upgrade: h2c` exchange (RFC 7540 §3.2): stream 1
/// is the upgraded request, the client's frames follow its preface after the
/// request, and the server's follow its `101 Switching Protocols`.
struct HTTP2UpgradeTests {
    // MARK: Internal

    @Test("An h2c upgrade is read as HTTP/2 with the HTTP/1.1 request on stream 1")
    func upgradedConnection() throws {
        let conversation = try #require(HTTP2ConnectionReader.read(aToB: Self.client, bToA: Self.server))
        #expect(conversation.clientIsAToB)
        let upgrade = try #require(conversation.upgrade)
        #expect(upgrade.requestOffset == 0)
        #expect(upgrade.responseOffset == 0)
        #expect(upgrade.clientStart == Self.request.count)
        #expect(upgrade.serverStart == Self.switching.count)

        #expect(conversation.streams.map(\.id) == [1, 3])
        let first = conversation.streams[0]
        #expect(first.method == "GET")
        #expect(first.path == "/index")
        #expect(first.authority == "example.test")
        #expect(first.status == 200)
        #expect(first.requestEnded)
        #expect(first.responseEnded)
        #expect(first.responseDataBytes == 5)
        #expect(first.requestOffset == 0)
        // Only the request's own headers are kept; the switch's are not part of it.
        let names = first.requestHeaders.map(\.name)
        #expect(names == [":method", ":path", ":scheme", ":authority", "accept"])
        #expect(conversation.streams[1].path == "/")
        #expect(conversation.streams[1].status == 404)

        // The client's SETTINGS frame is empty, so its settings are the header's.
        #expect(conversation.clientSettings.map(\.name) == ["MAX_CONCURRENT_STREAMS", "INITIAL_WINDOW_SIZE"])
        #expect(conversation.clientSettings.map(\.value) == [100, 65_535])
        #expect(conversation.serverSettings.map(\.value) == [100])
        #expect(conversation.frames.filter(\.fromClient).map(\.typeName) == ["SETTINGS", "HEADERS"])
        #expect(conversation.frames.filter { !$0.fromClient }.map(\.typeName) == [
            "SETTINGS", "HEADERS", "DATA", "HEADERS",
        ])
        #expect(conversation.frames.first?.offset == Self.request.count + HTTP2ConnectionReader.preface.count)
        #expect(conversation.clientStop == nil)
        #expect(conversation.serverStop == nil)

        let swapped = try #require(HTTP2ConnectionReader.read(aToB: Self.server, bToA: Self.client))
        #expect(!swapped.clientIsAToB)
        #expect(swapped.streams.map(\.id) == [1, 3])
    }

    @Test("Only a 101 that switches to h2c, followed by the preface, is HTTP/2")
    func recognition() {
        // Declined: the server answered 200 and stayed on HTTP/1.1.
        let declined = Array("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".utf8)
        #expect(HTTP2ConnectionReader.read(aToB: Self.request, bToA: declined) == nil)
        // A WebSocket upgrade is not HTTP/2.
        let webSocket = Array(
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".utf8
        )
        #expect(HTTP2ConnectionReader.read(aToB: Self.request, bToA: webSocket) == nil)
        // After the switch the client must send the preface, not more HTTP/1.1.
        let notPreface = Self.request + Array("GET /again HTTP/1.1\r\n\r\n".utf8)
        #expect(HTTP2ConnectionReader.read(aToB: notPreface, bToA: Self.server) == nil)
    }

    @Test("A capture that ends before the preface keeps stream 1 and says the client side was cut")
    func prefaceNotRetained() throws {
        let conversation = try #require(HTTP2ConnectionReader.read(aToB: Self.request, bToA: Self.server))
        #expect(conversation.clientStop == .cutShort)
        #expect(conversation.streams.first?.status == 200)
        let partial = Self.request + HTTP2ConnectionReader.preface.prefix(10)
        let cut = try #require(HTTP2ConnectionReader.read(aToB: partial, bToA: Self.server))
        #expect(cut.clientStop == .cutShort)
    }

    @Test("HTTP2-Settings is base64url; anything that is not whole entries is ignored")
    func upgradeSettings() {
        #expect(HTTP2ConnectionReader.upgradeSettings("AAMAAABkAAQAAP__").map(\.value) == [100, 65_535])
        #expect(HTTP2ConnectionReader.upgradeSettings("").isEmpty)
        #expect(HTTP2ConnectionReader.upgradeSettings("AAMAAA").isEmpty)
        #expect(HTTP2ConnectionReader.upgradeSettings("%%%").isEmpty)
    }

    @Test("The 101 that switches to h2c marks the session HTTP/2; a 101 to WebSocket does not")
    func decoderRecognizesTheSwitch() {
        let h2c = Self.decode(Self.switching)
        #expect(h2c.negotiatedApplication == .http2)
        #expect(h2c.appProtocol == .http)
        let ws = Self.decode(Array(
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".utf8
        ))
        #expect(ws.negotiatedApplication == .websocket)
        // The request alone only asks; the session is not HTTP/2 until the server agrees.
        #expect(Self.decode(Self.request, client: true).negotiatedApplication == nil)
    }

    @Test("A followed h2c connection shows both the upgrade and the HTTP/2 streams, timed from their frames")
    func followedUpgrade() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let loaded = try SavedCaptureStreamLoader(contentsOf: url).load()
        #expect(loaded.sessions.first?.protocolStack.last == .http2)

        let identity = try CaptureStreamReader(contentsOf: url).identity
        let result = try FollowStreamReader(
            contentsOf: url, expectedIdentity: identity, tuple: Self.tuple, sourceToken: UUID()
        ).read()
        let http = try #require(FollowHTTPPresentation(result: result))
        #expect(http.rows.map(\.status).first?.hasPrefix("101") == true)
        let http2 = try #require(FollowHTTP2Presentation(result: result))
        #expect(http2.streams.map(\.request) == ["GET /index", "GET /"])
        #expect(http2.streams.map(\.status) == ["200", "404"])
        #expect(http2.streams.map { $0.requestFrame?.ordinal.rawValue } == [1, 3])
        #expect(http2.streams.map { $0.responseFrame?.ordinal.rawValue } == [2, 4])
        #expect(http2.streams.first?.elapsed == "10.0 ms")
        #expect(http2.notes.first?.contains("Upgrade: h2c") == true)
    }

    // MARK: Private

    private static let tuple = FiveTuple(
        proto: .tcp,
        source: IPEndpoint(ip: "192.0.2.10", port: 51_000),
        destination: IPEndpoint(ip: "198.51.100.80", port: 80)
    )

    private static let request = Array((
        "GET /index HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade, HTTP2-Settings\r\n"
            + "Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\nAccept: */*\r\n\r\n"
    ).utf8)

    private static let switching = Array(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n".utf8
    )

    /// `:method GET`, `:scheme http`, `:path /`, `:authority example.test` (literal, indexed name).
    private static let secondRequestBlock: [UInt8] = [0x82, 0x86, 0x84, 0x41, 0x0C] + Array("example.test".utf8)

    /// The request; then the preface, an empty SETTINGS and a second request.
    private static let clientSegments: [[UInt8]] = [
        request,
        HTTP2ConnectionReader.preface + frame(4, flags: 0, stream: 0, [])
            + frame(1, flags: 5, stream: 3, secondRequestBlock),
    ]

    /// The 101 with the server's SETTINGS and stream 1's response; then stream 3's.
    private static let serverSegments: [[UInt8]] = [
        switching + frame(4, flags: 0, stream: 0, [0, 3, 0, 0, 0, 100])
            + frame(1, flags: 4, stream: 1, [0x88]) + frame(0, flags: 1, stream: 1, Array("hello".utf8)),
        frame(1, flags: 5, stream: 3, [0x8D]),
    ]

    private static var client: [UInt8] {
        clientSegments.flatMap(\.self)
    }

    private static var server: [UInt8] {
        serverSegments.flatMap(\.self)
    }

    private static func frame(_ type: UInt8, flags: UInt8, stream: UInt32, _ payload: [UInt8]) -> [UInt8] {
        let length = UInt32(payload.count)
        return [UInt8(length >> 16 & 0xFF), UInt8(length >> 8 & 0xFF), UInt8(length & 0xFF), type, flags]
            + withUnsafeBytes(of: stream.bigEndian) { Array($0) } + payload
    }

    private static func segment(client: Bool, seq: UInt32, _ payload: [UInt8]) -> [UInt8] {
        let tcp = PacketBuilder.tcp(
            srcPort: client ? 51_000 : 80, dstPort: client ? 80 : 51_000, flags: 0x18,
            payload: payload, sequence: seq
        )
        return PacketBuilder.ethernetIPv4(
            proto: 6, src: client ? "192.0.2.10" : "198.51.100.80", dst: client ? "198.51.100.80" : "192.0.2.10",
            payload: tcp
        )
    }

    private static func decode(_ payload: [UInt8], client: Bool = false) -> DecodedPacket {
        SessionBuilder.decodePacket(
            CapturedFrame(bytes: segment(client: client, seq: 1, payload), timestamp: nil, originalLength: 0),
            linkType: LinkType.ethernet
        )
    }

    /// Four segments: client request, server switch + response, client preface +
    /// second request, server second response.
    private static func capture() throws -> URL {
        let order: [(client: Bool, index: Int, microseconds: UInt32)] = [
            (true, 0, 0), (false, 0, 10_000), (true, 1, 20_000), (false, 1, 30_000),
        ]
        var clientSeq: UInt32 = 1_000
        var serverSeq: UInt32 = 5_000
        func le32(_ value: UInt32) -> [UInt8] {
            withUnsafeBytes(of: value.littleEndian) { Array($0) }
        }
        var file: [UInt8] = [0xD4, 0xC3, 0xB2, 0xA1, 2, 0, 4, 0] + le32(0) + le32(0) + le32(65_535)
        file += le32(LinkType.ethernet)
        for step in order {
            let payload = step.client ? clientSegments[step.index] : serverSegments[step.index]
            let packet = segment(client: step.client, seq: step.client ? clientSeq : serverSeq, payload)
            if step.client {
                clientSeq += UInt32(payload.count)
            } else {
                serverSeq += UInt32(payload.count)
            }
            file += le32(1_800_000_000) + le32(step.microseconds)
            file += le32(UInt32(packet.count)) + le32(UInt32(packet.count)) + packet
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("h2c-\(UUID().uuidString).pcap")
        try Data(file).write(to: url)
        return url
    }
}
