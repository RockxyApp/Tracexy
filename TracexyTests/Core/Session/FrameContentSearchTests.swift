import Foundation
import Testing
@testable import Tracexy

/// Find Packet: a string, hex bytes or regular expression in each
/// frame's bytes or details — byte searches agree with tshark's `frame contains` and
/// `frame matches`.
struct FrameContentSearchTests {
    // MARK: Internal

    @Test
    func hexReadsTheUsualSpellings() {
        #expect(FrameSearchQuery.hexBytes("16 03 01") == [0x16, 0x03, 0x01])
        #expect(FrameSearchQuery.hexBytes("de:ad:BE:ef") == [0xDE, 0xAD, 0xBE, 0xEF])
        #expect(FrameSearchQuery.hexBytes("abc") == nil)
        #expect(FrameSearchQuery.hexBytes("zz") == nil)
    }

    @Test
    func findsInBytesAsTsharkDoes() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        func frames(_ kind: FrameSearchQuery.Kind, _ text: String, caseSensitive: Bool = false) throws -> [UInt64] {
            try FrameContentSearch.matches(in: url, query: FrameSearchQuery(
                kind: kind, target: .bytes, text: text, caseSensitive: caseSensitive
            ))
        }
        #expect(try frames(.string, "get /b") == [3])
        #expect(try frames(.string, "get /b", caseSensitive: true).isEmpty)
        #expect(try frames(.hex, "48 54 54 50 2f 31 2e 31 20 32 30 30") == [2, 4])
        #expect(try frames(.regex, "GET /[ab]\\.txt") == [1, 3])

        guard WiresharkOracle.isAvailable else {
            return
        }
        func tshark(_ filter: String) throws -> [UInt64] {
            try WiresharkOracle.tsharkFields(url, fields: ["frame.number"], filter: filter).compactMap { UInt64($0[0]) }
        }
        #expect(try tshark("frame contains \"GET /b\"") == [3])
        #expect(try tshark("frame contains 48:54:54:50:2f:31:2e:31:20:32:30:30") == [2, 4])
        #expect(try tshark("frame matches \"GET /[ab]\\\\.txt\"") == [1, 3])
    }

    @Test
    func findsInDetails() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let found = try FrameContentSearch.matches(in: url, query: FrameSearchQuery(
            kind: .string, target: .details, text: "Destination Port: 80"
        ))
        #expect(found == [1, 3])
        #expect(throws: FrameSearchQuery.Invalid.self) {
            try FrameSearchQuery(kind: .hex, target: .details, text: "00").matcher()
        }
        #expect(throws: FrameSearchQuery.Invalid.self) {
            try FrameSearchQuery(kind: .regex, target: .bytes, text: "([").matcher()
        }
    }

    @Test
    func adjacentSearchWrapsWithoutRetainingEveryMatch() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let query = FrameSearchQuery(kind: .hex, target: .bytes, text: "48 54 54 50 2f 31 2e 31 20 32 30 30")
        let first = try FrameContentSearch.adjacentMatch(in: url, query: query, after: nil, forward: true)
        let next = try FrameContentSearch.adjacentMatch(in: url, query: query, after: 2, forward: true)
        let wrapped = try FrameContentSearch.adjacentMatch(in: url, query: query, after: 4, forward: true)
        let previous = try FrameContentSearch.adjacentMatch(in: url, query: query, after: 4, forward: false)
        let reverseWrapped = try FrameContentSearch.adjacentMatch(
            in: url, query: query, after: 2, forward: false
        )
        #expect(first == .init(ordinal: 2, matchCount: 2, completeness: .complete))
        #expect(next == .init(ordinal: 4, matchCount: 2, completeness: .complete))
        #expect(wrapped == .init(ordinal: 2, matchCount: 2, completeness: .complete))
        #expect(previous == .init(ordinal: 2, matchCount: 2, completeness: .complete))
        #expect(reverseWrapped == .init(ordinal: 4, matchCount: 2, completeness: .complete))
    }

    @Test
    func adjacentSearchReportsTruncatedTailAfterCompleteMatches() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let handle = try FileHandle(forWritingTo: url)
        _ = try handle.seekToEnd()
        try handle.write(contentsOf: Data([0x01]))
        try handle.close()
        let query = FrameSearchQuery(kind: .hex, target: .bytes, text: "48 54 54 50 2f 31 2e 31 20 32 30 30")
        let result = try FrameContentSearch.adjacentMatch(in: url, query: query, after: nil, forward: true)
        #expect(result == .init(ordinal: 2, matchCount: 2, completeness: .incompleteTruncatedTail(.partialHeader)))
    }

    @Test
    func frameExpressionNavigationWrapsInCaptureOrder() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let identity = try CaptureStreamReader(contentsOf: url).identity
        var parser = FrameExpressionParser()
        let expression = try parser.parse("tcp.port == 80")
        func find(_ after: UInt64?, forward: Bool) throws -> FrameExpressionSearch.NavigationResult {
            try FrameExpressionSearch.adjacentMatch(
                in: url, expectedIdentity: identity, sourceToken: UUID(), expression: expression,
                after: after, forward: forward
            )
        }
        #expect(try find(nil, forward: true).ordinal == 1)
        #expect(try find(1, forward: true).ordinal == 2)
        #expect(try find(4, forward: true).ordinal == 1)
        #expect(try find(1, forward: false).ordinal == 4)
        #expect(try find(4, forward: false).ordinal == 3)
        #expect(try find(4, forward: true).matchCount == 4)
    }

    @Test
    func frameExpressionFindUsesCaptureDirectionAndReportsUnknown() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("frame-find-direction-\(UUID().uuidString).pcapng")
        defer { try? FileManager.default.removeItem(at: url) }
        try PcapngWriter.write(defaultLinkType: LinkType.ethernet, frames: [
            CapturedFrame(
                bytes: [1],
                timestamp: Date(timeIntervalSince1970: 1),
                originalLength: 1,
                direction: .inbound
            ),
            CapturedFrame(bytes: [2], timestamp: Date(timeIntervalSince1970: 2), originalLength: 1),
        ], to: url)
        let identity = try CaptureStreamReader(contentsOf: url).identity
        var parser = FrameExpressionParser()
        let expression = try parser.parse("frame.capture_direction == inbound")
        let result = try FrameExpressionSearch.adjacentMatch(
            in: url, expectedIdentity: identity, sourceToken: UUID(), expression: expression,
            after: nil, forward: true
        )

        #expect(result.ordinal == 1)
        #expect(result.matchCount == 1)
        #expect(result.unknownCount == 1)
        #expect(result.completeness == .complete)
    }

    @Test
    func frameExpressionNavigationReportsUnknownAndTruncatedTail() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let identity = try CaptureStreamReader(contentsOf: url).identity
        var parser = FrameExpressionParser()
        let unknownExpression = try parser.parse("dns.response")
        let unknown = try FrameExpressionSearch.adjacentMatch(
            in: url, expectedIdentity: identity, sourceToken: UUID(), expression: unknownExpression,
            after: nil, forward: true
        )
        #expect(unknown.ordinal == nil)
        #expect(unknown.unknownCount == 1)

        let handle = try FileHandle(forWritingTo: url)
        _ = try handle.seekToEnd()
        try handle.write(contentsOf: Data([0x01]))
        try handle.close()
        let truncatedIdentity = try CaptureStreamReader(contentsOf: url).identity
        let expression = try parser.parse("tcp.port == 80")
        let truncated = try FrameExpressionSearch.adjacentMatch(
            in: url, expectedIdentity: truncatedIdentity, sourceToken: UUID(), expression: expression,
            after: nil, forward: true
        )
        #expect(truncated.matchCount == 4)
        #expect(truncated.completeness == .incompleteTruncatedTail(.partialHeader))
    }

    // MARK: Private

    private static func capture() throws -> URL {
        let texts = [
            (true, "GET /a.txt HTTP/1.1\r\nHost: t.test\r\n\r\n"), (false, "HTTP/1.1 200 OK\r\n\r\n"),
            (true, "GET /b.txt HTTP/1.1\r\nHost: t.test\r\n\r\n"), (false, "HTTP/1.1 200 OK\r\n\r\n"),
        ]
        var client: UInt32 = 1_000
        var server: UInt32 = 5_000
        let frames = texts.enumerated().map { index, item in
            let (isClient, text) = item
            let bytes = PacketBuilder.ethernetIPv4(
                proto: 6, src: isClient ? "192.0.2.10" : "198.51.100.80",
                dst: isClient ? "198.51.100.80" : "192.0.2.10",
                payload: PacketBuilder.tcp(
                    srcPort: isClient ? 50_000 : 80, dstPort: isClient ? 80 : 50_000, flags: 0x18,
                    payload: Array(text.utf8), sequence: isClient ? client : server
                )
            )
            if isClient {
                client += UInt32(text.utf8.count)
            } else {
                server += UInt32(text.utf8.count)
            }
            return CapturedFrame(
                bytes: bytes, timestamp: Date(timeIntervalSince1970: 1_800_000_000 + Double(index)),
                originalLength: bytes.count
            )
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("find-\(UUID().uuidString).pcap")
        let malformed = CapturedFrame(
            bytes: [0x01], timestamp: Date(timeIntervalSince1970: 1_800_000_004), originalLength: 1
        )
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames + [malformed], to: url)
        return url
    }
}
