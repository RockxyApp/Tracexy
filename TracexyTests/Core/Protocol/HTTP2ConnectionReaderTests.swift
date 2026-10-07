import Foundation
import Testing
@testable import Tracexy

// MARK: - HPACKDecoderTests

/// HPACK (RFC 7541): the Appendix C examples, eviction, and honest failures. Every
/// expected list was also decoded by Go's independent HPACK implementation.
struct HPACKDecoderTests {
    // MARK: Internal

    @Test("C.2.1: a literal with indexing enters the dynamic table")
    func literalWithIndexing() throws {
        var decoder = HPACKDecoder()
        let fields = try decoder.decode(Self.hex("400a637573746f6d2d6b65790d637573746f6d2d686561646572"))
        #expect(fields == [HPACKHeader(name: "custom-key", value: "custom-header")])
        #expect(decoder.dynamicTableSize == 55)
    }

    @Test("C.4: three Huffman-coded requests share one dynamic table")
    func huffmanRequests() throws {
        var decoder = HPACKDecoder()
        let first = try decoder.decode(Self.hex("828684418cf1e3c2e5f23a6ba0ab90f4ff"))
        #expect(first == Self.pairs([
            (":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com"),
        ]))
        #expect(decoder.dynamicTableSize == 57)
        let second = try decoder.decode(Self.hex("828684be5886a8eb10649cbf"))
        #expect(second.last == HPACKHeader(name: "cache-control", value: "no-cache"))
        #expect(decoder.dynamicTableSize == 110)
        let third = try decoder.decode(Self.hex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"))
        #expect(third == Self.pairs([
            (":method", "GET"), (":scheme", "https"), (":path", "/index.html"),
            (":authority", "www.example.com"), ("custom-key", "custom-value"),
        ]))
        #expect(decoder.dynamicTableSize == 164)
    }

    @Test("C.6: responses in a 256-byte table evict the oldest entries")
    func huffmanResponsesWithEviction() throws {
        var decoder = HPACKDecoder(maximumTableSize: 256)
        _ = try decoder.decode(Self.hex(
            "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3"
        ))
        #expect(decoder.dynamicTableSize == 222)
        let second = try decoder.decode(Self.hex("4883640effc1c0bf"))
        #expect(second.first == HPACKHeader(name: ":status", value: "307"))
        #expect(decoder.dynamicTableSize == 222)
        let third = try decoder.decode(Self.hex(
            "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af"
                + "27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007"
        ))
        #expect(third == Self.pairs([
            (":status", "200"), ("cache-control", "private"), ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
            ("location", "https://www.example.com"), ("content-encoding", "gzip"),
            ("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"),
        ]))
        #expect(decoder.dynamicTableSize == 215)
        #expect(decoder.dynamicTable.count == 3)
    }

    @Test("Bad blocks fail closed instead of guessing")
    func failures() {
        func error(_ hex: String) -> HPACKError? {
            var decoder = HPACKDecoder()
            do {
                _ = try decoder.decode(Self.hex(hex))
                return nil
            } catch {
                return error
            }
        }
        #expect(error("80") == .invalidIndex(0))
        #expect(error("be") == .invalidIndex(62))
        #expect(error("418c f1e3") == .truncated)
        // A Huffman string of one full byte of 1s: 8 bits of padding.
        #expect(error("4081ff0161") == .invalidHuffman)
        // A size update after a field.
        #expect(error("823f e11f") == .invalidTableSizeUpdate(4_096))
        #expect(error("3fe1ff") == .truncated)
    }

    // MARK: Fileprivate

    fileprivate static func hex(_ text: String) -> [UInt8] {
        let digits = Array(text.filter(\.isHexDigit))
        return stride(from: 0, to: digits.count - 1, by: 2)
            .compactMap { UInt8(String(digits[$0 ... $0 + 1]), radix: 16) }
    }

    fileprivate static func pairs(_ list: [(String, String)]) -> [HPACKHeader] {
        list.map { HPACKHeader(name: $0.0, value: $0.1) }
    }
}

// MARK: - HTTP2ConnectionReaderTests

/// HTTP/2 frames and streams over a followed TCP stream, on the bytes pinned below:
/// header blocks from Go's HPACK encoder, PADDED + PRIORITY + CONTINUATION, an
/// interim 103, a client reset, and agreement with tshark.
struct HTTP2ConnectionReaderTests {
    // MARK: Internal

    @Test("Streams pair request and response heads, data sizes and resets")
    func streams() throws {
        let conversation = try #require(HTTP2ConnectionReader.read(aToB: Self.client, bToA: Self.server))
        #expect(conversation.clientIsAToB)
        #expect(conversation.streams.map(\.id) == [1, 3, 5])
        #expect(conversation.streams.map(\.method) == ["GET", "POST", "GET"])
        #expect(conversation.streams.map(\.path) == ["/a", "/upload", "/slow"])
        #expect(conversation.streams.map(\.authority) == ["example.test", "example.test", "example.test"])
        #expect(conversation.streams.map(\.status) == [200, 404, nil])
        #expect(conversation.streams[1].informationalStatuses == [103])
        #expect(conversation.streams[0].responseDataBytes == 5)
        #expect(conversation.streams[1].requestDataBytes == 7)
        #expect(conversation.streams[1].responseHeaders.last == HPACKHeader(name: "server", value: "h2-fixture"))
        #expect(conversation.streams[2].resetCode == 8)
        #expect(conversation.streams[2].resetByClient)
        // swiftformat:disable:next preferKeyPath
        #expect(conversation.streams.allSatisfy { $0.requestEnded })
        #expect(conversation.clientSettings.map(\.name) == ["ENABLE_PUSH", "INITIAL_WINDOW_SIZE"])
        #expect(conversation.serverSettings.map(\.value) == [100])
        #expect(conversation.clientStop == nil)
        #expect(conversation.serverStop == nil)
    }

    @Test("Frames are read with their types, streams and details")
    func frames() throws {
        let conversation = try #require(HTTP2ConnectionReader.read(aToB: Self.client, bToA: Self.server))
        #expect(conversation.frames.filter(\.fromClient).map(\.typeName) == [
            "SETTINGS", "HEADERS", "HEADERS", "CONTINUATION", "DATA", "SETTINGS", "HEADERS", "RST_STREAM",
        ])
        #expect(conversation.frames.filter { !$0.fromClient }.map(\.typeName) == [
            "SETTINGS", "SETTINGS", "HEADERS", "DATA", "HEADERS", "HEADERS", "DATA", "WINDOW_UPDATE", "GOAWAY",
        ])
        let details = conversation.frames.map(\.detail)
        #expect(details.contains("CANCEL"))
        #expect(details.contains("Last stream 5, NO_ERROR"))
        #expect(details.contains("Increment 1000"))
        #expect(details.contains("ENABLE_PUSH 0, INITIAL_WINDOW_SIZE 65535"))
    }

    @Test("The server side may be a → b; a stream without the preface is not HTTP/2")
    func directionAndRecognition() throws {
        let swapped = try #require(HTTP2ConnectionReader.read(aToB: Self.server, bToA: Self.client))
        #expect(!swapped.clientIsAToB)
        #expect(swapped.streams.count == 3)
        #expect(HTTP2ConnectionReader.read(aToB: Array("GET / HTTP/1.1\r\n\r\n".utf8), bToA: []) == nil)
        #expect(HTTP2ConnectionReader.read(aToB: [], bToA: []) == nil)
    }

    @Test("Reading stops honestly: cut short, broken framing, lost header state")
    func honestStops() throws {
        let cut = try #require(HTTP2ConnectionReader.read(aToB: Array(Self.client.dropLast(3)), bToA: Self.server))
        #expect(cut.clientStop == .cutShort)
        #expect(cut.streams.count == 3)

        // A DATA frame in the middle of a header block.
        let broken = HTTP2ConnectionReader.preface + Self.frame(1, flags: 0, stream: 1, Self.clientBlock1)
            + Self.frame(0, flags: 1, stream: 1, [])
        let malformed = try #require(HTTP2ConnectionReader.read(aToB: broken, bToA: []))
        #expect(malformed.clientStop == .malformed)

        // The server's third block refers to dynamic entries its first block made;
        // without the first block the reference cannot be resolved.
        let orphan = Self.frame(1, flags: 4, stream: 3, Self.serverBlock3)
        let lost = try #require(HTTP2ConnectionReader.read(aToB: HTTP2ConnectionReader.preface, bToA: orphan))
        #expect(lost.serverStop == .headerCompression)
        // The frame is still listed; only its headers cannot be read.
        #expect(lost.frames.map(\.typeName) == ["HEADERS"])
        #expect(lost.streams.isEmpty)
    }

    @Test("A followed stream is timed from the frames that carried each head")
    func followedStreamPresentation() throws {
        try Self.withCapture { url, identity in
            let token = UUID()
            let result = try FollowStreamReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple, sourceToken: token
            ).read()
            let http2 = try #require(FollowHTTP2Presentation(result: result))
            #expect(FollowHTTPPresentation(result: result) == nil)
            #expect(http2.streams.map(\.request) == ["GET /a", "POST /upload", "GET /slow"])
            #expect(http2.streams.map(\.status) == ["200", "404", "Reset by client, CANCEL"])
            #expect(http2.streams.map(\.isError) == [false, true, true])
            #expect(http2.streams.map(\.elapsed) == ["20 ms", "50 ms", nil])
            #expect(http2.streams.map { $0.requestFrame?.ordinal.rawValue } == [1, 3, 6])
            #expect(http2.streams.map { $0.responseFrame?.ordinal.rawValue } == [2, 5, nil])
            #expect(http2.streams.allSatisfy { $0.requestFrame?.locator?.sourceToken == token })
            #expect(http2.frameCount == 17)
            // Capture order: every frame's captured frame number never decreases.
            let ordinals = http2.frames.compactMap { $0.frame?.ordinal.rawValue }
            #expect(ordinals.count == 17)
            #expect(ordinals == ordinals.sorted())
            #expect(http2.notes.isEmpty)
        }
    }

    @Test(.enabled(if: WiresharkOracle.isAvailable, "Wireshark is not installed on this machine"))
    func tsharkAgrees() throws {
        try Self.withCapture { url, identity in
            let rows = try WiresharkOracle.tsharkFields(
                url, fields: ["frame.number", "http2.type", "http2.streamid"], filter: "http2"
            )
            let result = try FollowStreamReader(contentsOf: url, expectedIdentity: identity, tuple: Self.tuple).read()
            let http2 = try #require(FollowHTTP2Presentation(result: result))
            // Per captured frame: the HTTP/2 frame types and stream identifiers, in order.
            var ours: [String: ([String], [String])] = [:]
            for frame in http2.frames {
                let number = "\(frame.frame?.ordinal.rawValue ?? 0)"
                let type = Self.typeCodes[frame.type] ?? "?"
                ours[number, default: ([], [])].0.append(type)
                ours[number, default: ([], [])].1.append("\(frame.streamID)")
            }
            #expect(rows.count == 7)
            for row in rows {
                let entry = ours[row[0]]
                #expect(entry?.0.joined(separator: ",") == row[1], "frame \(row[0])")
                #expect(entry?.1.joined(separator: ",") == row[2], "frame \(row[0])")
            }
            let statuses = try WiresharkOracle.tsharkFields(
                url,
                fields: ["http2.headers.status"],
                filter: "http2.headers.status"
            )
            #expect(statuses.map { $0[0] } == ["200", "103", "404"])
        }
    }

    // MARK: Private

    private static let typeCodes = [
        "DATA": "0", "HEADERS": "1", "PRIORITY": "2", "RST_STREAM": "3", "SETTINGS": "4",
        "PUSH_PROMISE": "5", "PING": "6", "GOAWAY": "7", "WINDOW_UPDATE": "8", "CONTINUATION": "9",
    ]

    private static let clientBlock1 = HPACKDecoderTests.hex("828645022f6141892f91d35d055d25427f7a894d83217cfa5925427f")
    private static let clientBlock2 = HPACKDecoderTests.hex("8386458562dae838e4c05f8b1d75d0620d263d4c7441ea")
    private static let clientBlock3 = HPACKDecoderTests.hex("8286458461141fc7c2")
    private static let serverBlock1 = HPACKDecoderTests.hex("885f87497ca58ae819aa76889c4b4a6f29b6c2ff")
    private static let serverBlock2 = HPACKDecoderTests.hex("4e8208196d94fff8c213ea82ae4423fefed4b0b4415d85a0e393")
    private static let serverBlock3 = HPACKDecoderTests.hex("8dc1c0")

    private static let tuple = FiveTuple(
        proto: .tcp,
        source: IPEndpoint(ip: "192.0.2.10", port: 51_000),
        destination: IPEndpoint(ip: "198.51.100.80", port: 80)
    )

    /// The client's bytes in the order of the fixture's three client segments.
    private static let clientSegments: [[UInt8]] = [
        HTTP2ConnectionReader.preface
            + frame(4, flags: 0, stream: 0, [0, 2, 0, 0, 0, 0, 0, 4, 0, 0, 0xFF, 0xFF])
            + frame(1, flags: 5, stream: 1, clientBlock1),
        frame(1, flags: 0x28, stream: 3, [2, 0, 0, 0, 0, 15] + clientBlock2.prefix(10) + [0, 0])
            + frame(9, flags: 4, stream: 3, Array(clientBlock2.dropFirst(10)))
            + frame(0, flags: 1, stream: 3, Array("{\"a\":1}".utf8))
            + frame(4, flags: 1, stream: 0, []),
        frame(1, flags: 5, stream: 5, clientBlock3) + frame(3, flags: 0, stream: 5, [0, 0, 0, 8]),
    ]

    private static let serverSegments: [[UInt8]] = [
        frame(4, flags: 0, stream: 0, [0, 3, 0, 0, 0, 100]) + frame(4, flags: 1, stream: 0, [])
            + frame(1, flags: 4, stream: 1, serverBlock1) + frame(0, flags: 1, stream: 1, Array("hello".utf8)),
        frame(1, flags: 4, stream: 3, serverBlock2),
        frame(1, flags: 4, stream: 3, serverBlock3) + frame(0, flags: 1, stream: 3, []),
        frame(8, flags: 0, stream: 0, [0, 0, 0x03, 0xE8]) + frame(7, flags: 0, stream: 0, [0, 0, 0, 5, 0, 0, 0, 0]),
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

    /// The fixture's seven segments: client, server, client, server, server, client, server.
    private static func withCapture(_ body: (URL, PcapFileIdentity) throws -> Void) throws {
        let order: [(client: Bool, index: Int, microseconds: UInt32)] = [
            (true, 0, 0), (false, 0, 20_000), (true, 1, 30_000), (false, 1, 40_000),
            (false, 2, 80_000), (true, 2, 90_000), (false, 3, 100_000),
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
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("http2-\(UUID().uuidString).pcap")
        try Data(file).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        try body(url, CaptureStreamReader(contentsOf: url).identity)
    }
}
