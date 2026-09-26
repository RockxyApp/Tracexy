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
    func nextAndPreviousWrapAroundTheShownMatches() {
        let rows = [1, 2, 3, 5, 8].map(Self.row)
        let matches: Set<UInt64> = [2, 5, 9]
        #expect(FrameFindBar.step(from: nil, forward: true, matches: matches, rows: rows) == 2)
        #expect(FrameFindBar.step(from: 2, forward: true, matches: matches, rows: rows) == 5)
        #expect(FrameFindBar.step(from: 5, forward: true, matches: matches, rows: rows) == 2)
        #expect(FrameFindBar.step(from: 2, forward: false, matches: matches, rows: rows) == 5)
        #expect(FrameFindBar.step(from: nil, forward: true, matches: [9], rows: rows) == nil)
    }

    // MARK: Private

    private static func row(_ ordinal: UInt64) -> CaptureFrameRow {
        CaptureFrameRow(
            provenance: SessionFrameProvenance(
                ordinal: FrameOrdinal(rawValue: ordinal), timestamp: nil, capturedLength: 0, originalLength: 0,
                linkType: LinkType.ethernet, locator: SessionEvidenceLocator(sourceToken: UUID(), offset: 0)
            ),
            source: "", destination: "", protocolName: "", info: "", sessionID: nil, interfaceID: 0, hasComment: false
        )
    }

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
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        return url
    }
}
