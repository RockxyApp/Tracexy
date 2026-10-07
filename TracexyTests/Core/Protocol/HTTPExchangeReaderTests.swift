import Foundation
import Testing
@testable import Tracexy

// MARK: - HTTPExchangeReaderTests

/// HTTP/1 request/response pairing over a followed TCP stream: RFC 9112 body
/// framing, interim responses, bounds, fail-closed stops, frame timing from the
/// follow reader's first-delivery marks, and agreement with tshark.
struct HTTPExchangeReaderTests {
    // MARK: Internal

    @Test
    func keepAliveRequestsPairInOrder() throws {
        let client = Self
            .bytes("GET /a HTTP/1.1\r\nHost: example.test\r\n\r\nGET /b HTTP/1.1\r\nHost: example.test\r\n\r\n")
        let server = Self.bytes(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"
                + "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
        )
        let conversation = try #require(HTTPExchangeReader.read(aToB: client, bToA: server))
        #expect(conversation.clientIsAToB)
        #expect(conversation.stop == nil)
        #expect(conversation.exchanges.map(\.target) == ["/a", "/b"])
        #expect(conversation.exchanges.map(\.status) == [200, 404])
        let first = conversation.exchanges[0]
        #expect(first.host == "example.test")
        #expect(first.response?.bodyLength == 5)
        #expect(first.response?.contentType == "text/plain")
        #expect(conversation.exchanges[1].request.offset == 39)
        #expect(conversation.exchanges[1].response?.offset == first.response.map { $0.offset + ($0.length ?? 0) })
    }

    @Test
    func chunkedBodiesAndTrailersAreFramed() throws {
        let client = Self.bytes(
            "POST /up HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\nGET /next HTTP/1.1\r\n\r\n"
        )
        let server = Self.bytes(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n3;ext=1\r\nabc\r\nA\r\n0123456789\r\n0\r\n"
                + "Trailer-Field: x\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"
        )
        let conversation = try #require(HTTPExchangeReader.read(aToB: client, bToA: server))
        #expect(conversation.exchanges.count == 2)
        #expect(conversation.exchanges[0].request.bodyLength == 4)
        #expect(conversation.exchanges[0].response?.framing == .chunked)
        #expect(conversation.exchanges[0].response?.bodyLength == 13)
        #expect(conversation.exchanges[1].status == 204)
        #expect(conversation.stop == nil)
    }

    @Test
    func interimAndBodilessResponsesDoNotShiftPairing() throws {
        let client = Self.bytes(
            "PUT /f HTTP/1.1\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\nokHEAD /f HTTP/1.1\r\n\r\n"
                + "GET /f HTTP/1.1\r\nIf-None-Match: \"x\"\r\n\r\n"
        )
        let server = Self.bytes(
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"
                + "HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n"
                + "HTTP/1.1 304 Not Modified\r\nContent-Length: 999\r\n\r\n"
        )
        let conversation = try #require(HTTPExchangeReader.read(aToB: client, bToA: server))
        #expect(conversation.exchanges.map(\.status) == [201, 200, 304])
        #expect(conversation.exchanges[0].interimStatuses == [100])
        // HEAD and 304 carry no body whatever Content-Length says.
        #expect(conversation.exchanges[1].response?.bodyLength == 0)
        #expect(conversation.exchanges[2].response?.isComplete == true)
        #expect(conversation.stop == nil)
    }

    @Test
    func theServerSideMayBeAToB() throws {
        let conversation = try #require(HTTPExchangeReader.read(
            aToB: Self.bytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
            bToA: Self.bytes("GET / HTTP/1.0\r\n\r\n")
        ))
        #expect(!conversation.clientIsAToB)
        #expect(conversation.exchanges.first?.status == 200)
    }

    @Test
    func readingStopsHonestly() throws {
        // A response framed by connection close cannot be proven complete.
        let untilClose = try #require(HTTPExchangeReader.read(
            aToB: Self.bytes("GET / HTTP/1.0\r\n\r\n"),
            bToA: Self.bytes("HTTP/1.0 200 OK\r\n\r\n<html>")
        ))
        #expect(untilClose.exchanges.first?.response?.isComplete == false)
        #expect(untilClose.stop == .responseCutShort)

        // A request whose body the retained bytes cut short.
        let cut = try #require(HTTPExchangeReader.read(
            aToB: Self.bytes("POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc"), bToA: []
        ))
        #expect(cut.exchanges.first?.request.isComplete == false)
        #expect(cut.stop == .requestCutShort)

        // Conflicting Content-Length values are not trusted.
        let conflicting = try #require(HTTPExchangeReader.read(
            aToB: Self.bytes("POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab"), bToA: []
        ))
        #expect(conflicting.stop == .malformed)

        // After 101 Switching Protocols the bytes are no longer HTTP/1.
        let upgrade = try #require(HTTPExchangeReader.read(
            aToB: Self.bytes("GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n\u{81}\u{05}hello"),
            bToA: Self.bytes("HTTP/1.1 101 Switching Protocols\r\n\r\n\u{81}\u{02}hi")
        ))
        #expect(upgrade.exchanges.count == 1)
        #expect(upgrade.exchanges.first?.status == 101)
        #expect(upgrade.stop == .notHTTP)
    }

    @Test
    func nonHTTPStreamsAreNotRead() {
        #expect(HTTPExchangeReader.read(aToB: [0x16, 0x03, 0x01, 0x00, 0x05], bToA: []) == nil)
        #expect(HTTPExchangeReader.read(aToB: Self.bytes("SSH-2.0-OpenSSH\r\n"), bToA: []) == nil)
        #expect(HTTPExchangeReader.read(aToB: Self.bytes("get / HTTP/1.1\r\n\r\n"), bToA: []) == nil)
        #expect(HTTPExchangeReader.read(aToB: [], bToA: []) == nil)
    }

    @Test
    func theExchangeCountIsBounded() throws {
        let many = String(repeating: "GET / HTTP/1.1\r\n\r\n", count: HTTPExchangeReader.maximumExchanges + 5)
        let conversation = try #require(HTTPExchangeReader.read(aToB: Self.bytes(many), bToA: []))
        #expect(conversation.exchanges.count == HTTPExchangeReader.maximumExchanges)
        #expect(conversation.stop == .exchangeLimit)
        #expect(conversation.exchanges.allSatisfy { $0.status == nil })
    }

    @Test
    func followedStreamIsTimedFromTheFramesThatCarriedEachMessage() throws {
        try Self.withCapture(Self.conversationFrames) { url, identity in
            let token = UUID()
            let result = try FollowStreamReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple, sourceToken: token
            ).read()
            let http = try #require(FollowHTTPPresentation(result: result))
            #expect(http.rows.map(\.request) == ["GET /a", "GET /b"])
            #expect(http.rows.map(\.status) == ["200 OK", "404 Not Found"])
            #expect(http.rows.map(\.isError) == [false, true])
            // Request frame → first response byte: 20 ms, then 50 ms.
            #expect(http.rows.map(\.elapsed) == ["20 ms", "50 ms"])
            #expect(http.rows[0].size == ByteUnits.string(5))
            // An empty body shows no size rather than "zero".
            #expect(http.rows[1].size == nil)
            #expect(http.rows.map { $0.requestFrame?.ordinal.rawValue } == [1, 4])
            #expect(http.rows.map { $0.responseFrame?.ordinal.rawValue } == [2, 5])
            #expect(http.rows.allSatisfy { $0.requestFrame?.locator?.sourceToken == token })
            #expect(http.notes.isEmpty)
        }
    }

    @Test
    func aNonHTTPStreamHasNoSection() throws {
        let frames: [(bytes: [UInt8], microseconds: UInt32)] = [
            (Self.segment(client: true, seq: 1_000, "SSH-2.0-OpenSSH_9.6\r\n"), 0),
        ]
        try Self.withCapture(frames) { url, identity in
            let result = try FollowStreamReader(contentsOf: url, expectedIdentity: identity, tuple: Self.tuple).read()
            #expect(FollowHTTPPresentation(result: result) == nil)
        }
    }

    @Test
    func marksNameTheFrameThatFirstDeliveredEachByte() throws {
        // A retransmission that extends the first segment marks only its new bytes.
        let frames: [(bytes: [UInt8], microseconds: UInt32)] = [
            (Self.segment(client: true, seq: 1_000, "abcd"), 0),
            (Self.segment(client: true, seq: 1_000, "abcdefgh"), 10_000),
            (Self.segment(client: true, seq: 1_008, "ij"), 20_000),
        ]
        try Self.withCapture(frames) { url, identity in
            let result = try FollowStreamReader(contentsOf: url, expectedIdentity: identity, tuple: Self.tuple).read()
            let run = try #require(result.aToB.runs.first)
            #expect(String(bytes: run.bytes, encoding: .ascii) == "abcdefghij")
            #expect(result.aToB.segmentMarks.map(\.offset) == [0, 4, 8])
            #expect(result.aToB.firstFrame(ofByte: 3, in: run)?.ordinal.rawValue == 1)
            #expect(result.aToB.firstFrame(ofByte: 4, in: run)?.ordinal.rawValue == 2)
            #expect(result.aToB.firstFrame(ofByte: 9, in: run)?.ordinal.rawValue == 3)
        }
    }

    @Test(.enabled(if: WiresharkOracle.isAvailable, "Wireshark is not installed on this machine"))
    func tsharkAgrees() throws {
        try Self.withCapture(Self.conversationFrames) { url, identity in
            // Status and the request each response answered, by frame number.
            let responses = try WiresharkOracle.tsharkFields(
                url, fields: ["http.response.code", "http.request_in"], filter: "http.response"
            )
            #expect(responses == [["200", "1"], ["404", "4"]])
            let result = try FollowStreamReader(contentsOf: url, expectedIdentity: identity, tuple: Self.tuple).read()
            let http = try #require(FollowHTTPPresentation(result: result))
            #expect(http.rows.map { $0.status.prefix(3) } == ["200", "404"])
            #expect(http.rows.map { $0.requestFrame.map { "\($0.ordinal.rawValue)" } } == ["1", "4"])
            // A single-segment exchange: tshark's http.time is the same interval.
            let times = try WiresharkOracle.tsharkFields(
                url,
                fields: ["http.time"],
                filter: "http.response.code == 404"
            )
            #expect(times.first?.first.flatMap(Double.init).map { abs($0 - 0.05) < 0.0005 } == true)
        }
    }

    @Test
    func bodiesAreReadBackWithoutChunkFraming() throws {
        let server = Self.bytes(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}"
                + "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"
                + "3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n"
                + "HTTP/1.1 204 No Content\r\n\r\n"
        )
        let client = Self.bytes("GET /api/item?id=4 HTTP/1.1\r\n\r\nGET /a%2Fb HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n")
        let conversation = try #require(HTTPExchangeReader.read(aToB: client, bToA: server))
        let first = try #require(conversation.exchanges[0].response)
        let second = try #require(conversation.exchanges[1].response)
        #expect(HTTPExchangeReader.body(of: first, in: server)
            .flatMap { String(bytes: $0, encoding: .utf8) } == "{\"a\":1}")
        #expect(HTTPExchangeReader.body(of: second, in: server)
            .flatMap { String(bytes: $0, encoding: .utf8) } == "abcde")
        #expect(second.contentEncoding == "gzip")
        // No body, nothing to save.
        #expect(conversation.exchanges[2].response.flatMap { HTTPExchangeReader.body(of: $0, in: server) } == nil)

        #expect(HTTPBodyFileName.suggested(
            target: "/api/item?id=4",
            contentType: "application/json; charset=utf-8",
            contentEncoding: nil
        ) == "item.json")
        #expect(HTTPBodyFileName.suggested(target: "/a%2Fb", contentType: nil, contentEncoding: "gzip") == "a_b.gz")
        #expect(HTTPBodyFileName
            .suggested(target: "/", contentType: "text/html", contentEncoding: nil) == "response.html")
        #expect(HTTPBodyFileName.suggested(target: "/.env", contentType: nil, contentEncoding: "br") == "response.br")
        #expect(HTTPBodyFileName
            .suggested(target: "/logo.png", contentType: "image/png", contentEncoding: nil) == "logo.png")
    }

    @Test
    func onlyCompleteBodiesAreOfferedForSaving() throws {
        try Self.withCapture(Self.conversationFrames) { url, identity in
            let result = try FollowStreamReader(contentsOf: url, expectedIdentity: identity, tuple: Self.tuple).read()
            let http = try #require(FollowHTTPPresentation(result: result))
            // GET /a carried "hello" across two segments; GET /b's 404 had no body.
            #expect(http.rows[0].bodyFileName == "a")
            #expect(http.responseBody(of: http.rows[0], in: result)
                .flatMap { String(bytes: $0, encoding: .utf8) } == "hello")
            #expect(http.rows[1].bodyFileName == nil)
            #expect(http.responseBody(of: http.rows[1], in: result) == nil)
        }
    }

    @Test
    func blankLinesBetweenRequestsAreIgnored() throws {
        let conversation = try #require(HTTPExchangeReader.read(
            aToB: Self.bytes("POST /a HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi\r\nGET /b HTTP/1.1\r\n\r\n\r\n"),
            bToA: Self.bytes(
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"
            )
        ))
        #expect(conversation.exchanges.map(\.target) == ["/a", "/b"])
        #expect(conversation.exchanges.map(\.status) == [200, 204])
        #expect(conversation.stop == nil)
    }

    @Test
    func aCaptureThatBeganMidExchangeSkipsTheOrphanResponse() throws {
        // Frame 1: the response to a request sent before the capture began.
        // Frame 2: the next request. Frame 3: its response.
        let orphan = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nold"
        let frames: [(bytes: [UInt8], microseconds: UInt32)] = [
            (Self.segment(client: false, seq: 7_000, orphan), 0),
            (Self.segment(client: true, seq: 1_000, "GET /next HTTP/1.1\r\n\r\n"), 10_000),
            (Self.segment(
                client: false, seq: 7_000 + UInt32(orphan.utf8.count),
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
            ), 30_000),
        ]
        try Self.withCapture(frames) { url, identity in
            let result = try FollowStreamReader(contentsOf: url, expectedIdentity: identity, tuple: Self.tuple).read()
            let http = try #require(FollowHTTPPresentation(result: result))
            #expect(http.rows.map(\.request) == ["GET /next"])
            #expect(http.rows.map(\.status) == ["404 Not Found"])
            #expect(http.rows.map(\.elapsed) == ["20 ms"])
            #expect(http.notes.contains("The capture began after one request was sent; its response is not listed."))
        }
    }

    @Test
    func aSegmentBridgingAHoleMarksEveryPieceItDelivered() throws {
        let frames: [(bytes: [UInt8], microseconds: UInt32)] = [
            (Self.segment(client: true, seq: 1_000, "abcd"), 0),
            (Self.segment(client: true, seq: 1_008, "ijkl"), 10_000),
            (Self.segment(client: true, seq: 1_004, "efghIJKLmnop"), 20_000),
        ]
        try Self.withCapture(frames) { url, identity in
            let result = try FollowStreamReader(contentsOf: url, expectedIdentity: identity, tuple: Self.tuple).read()
            let run = try #require(result.aToB.runs.first)
            #expect(String(bytes: run.bytes, encoding: .ascii) == "abcdefghijklmnop")
            #expect(result.aToB.segmentMarks.map(\.offset) == [0, 4, 8, 12])
            #expect(result.aToB.firstFrame(ofByte: 9, in: run)?.ordinal.rawValue == 2)
            #expect(result.aToB.firstFrame(ofByte: 13, in: run)?.ordinal.rawValue == 3)
        }
    }

    @Test
    func secondReviewFixesHold() throws {
        // An unreadable chunk size is malformed, not cut short.
        let badChunk = try #require(HTTPExchangeReader.read(
            aToB: Self.bytes("GET / HTTP/1.1\r\n\r\n"),
            bToA: Self.bytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n0\r\n\r\n")
        ))
        #expect(badChunk.stop == .malformed)

        // A leftover 100 Continue and its final response are skipped as one response.
        let orphan = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"
        let frames: [(bytes: [UInt8], microseconds: UInt32)] = [
            (Self.segment(client: false, seq: 7_000, orphan), 0),
            (Self.segment(client: true, seq: 1_000, "GET /x HTTP/1.1\r\n\r\n"), 10_000),
            (Self.segment(
                client: false, seq: 7_000 + UInt32(orphan.utf8.count), "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
            ), 20_000),
        ]
        try Self.withCapture(frames) { url, identity in
            let result = try FollowStreamReader(contentsOf: url, expectedIdentity: identity, tuple: Self.tuple).read()
            let http = try #require(FollowHTTPPresentation(result: result))
            #expect(http.rows.map(\.status) == ["200 OK"])
            #expect(http.notes.contains("The capture began after one request was sent; its response is not listed."))
        }
    }

    @Test
    func marksAreWithdrawnForBytesThatWereNotKept() throws {
        let frames: [(bytes: [UInt8], microseconds: UInt32)] = [
            (Self.segment(client: true, seq: 1_000, "abcd"), 0),
            (Self.segment(client: true, seq: 1_004, "efgh"), 10_000),
        ]
        try Self.withCapture(frames) { url, identity in
            let result = try FollowStreamReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple,
                configuration: .init(maxRetainedBytesPerDirection: 4)
            ).read()
            #expect(result.aToB.retainedByteCount == 4)
            #expect(result.aToB.segmentMarks.map(\.offset) == [0])
            #expect(result.aToB.segmentMarksDroppedFrom == nil)
        }
    }

    // MARK: Private

    /// 192.0.2.10:51000 ↔ 198.51.100.80:80; the client sorts first, so it is `a`.
    private static let tuple = FiveTuple(
        proto: .tcp,
        source: IPEndpoint(ip: "192.0.2.10", port: 51_000),
        destination: IPEndpoint(ip: "198.51.100.80", port: 80)
    )

    private static var conversationFrames: [(bytes: [UInt8], microseconds: UInt32)] {
        let requestA = "GET /a HTTP/1.1\r\nHost: example.test\r\n\r\n"
        let responseHead = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel"
        return [
            (segment(client: true, seq: 1_000, requestA), 0),
            (segment(client: false, seq: 5_000, responseHead), 20_000),
            (segment(client: false, seq: 5_000 + UInt32(responseHead.utf8.count), "lo"), 21_000),
            (
                segment(
                    client: true,
                    seq: 1_000 + UInt32(requestA.utf8.count),
                    "GET /b HTTP/1.1\r\nHost: example.test\r\n\r\n"
                ),
                100_000
            ),
            (segment(
                client: false, seq: 5_000 + UInt32(responseHead.utf8.count) + 2,
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
            ), 150_000),
        ]
    }

    private static func bytes(_ text: String) -> [UInt8] {
        Array(text.utf8)
    }

    private static func segment(client: Bool, seq: UInt32, _ text: String) -> [UInt8] {
        let tcp = PacketBuilder.tcp(
            srcPort: client ? 51_000 : 80, dstPort: client ? 80 : 51_000, flags: 0x18,
            payload: Array(text.utf8), sequence: seq
        )
        return PacketBuilder.ethernetIPv4(
            proto: 6, src: client ? "192.0.2.10" : "198.51.100.80", dst: client ? "198.51.100.80" : "192.0.2.10",
            payload: tcp
        )
    }

    /// A classic little-endian pcap whose records carry explicit microsecond times.
    private static func withCapture(
        _ frames: [(bytes: [UInt8], microseconds: UInt32)],
        _ body: (URL, PcapFileIdentity) throws -> Void
    )
        throws
    {
        func le32(_ value: UInt32) -> [UInt8] {
            withUnsafeBytes(of: value.littleEndian) { Array($0) }
        }
        var file: [UInt8] = [0xD4, 0xC3, 0xB2, 0xA1, 2, 0, 4, 0] + le32(0) + le32(0) + le32(65_535)
        file += le32(LinkType.ethernet)
        for frame in frames {
            file += le32(1_800_000_000) + le32(frame.microseconds)
            file += le32(UInt32(frame.bytes.count)) + le32(UInt32(frame.bytes.count)) + frame.bytes
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("http-\(UUID().uuidString).pcap")
        try Data(file).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        try body(url, CaptureStreamReader(contentsOf: url).identity)
    }
}
