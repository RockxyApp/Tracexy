import Foundation
import Testing
@testable import Tracexy

/// File ▸ Export Objects ▸ HTTP lists every complete response body in
/// the capture, gzip decoded as Wireshark does; the saved bytes match
/// `tshark --export-objects http`.
struct CaptureObjectScannerTests {
    // MARK: Internal

    @Test
    func listsBodiesLikeWireshark() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("objects-\(UUID().uuidString).pcap")
        let records = Self.frames().enumerated().map {
            ReplayCorpus.Frame(bytes: $0.element, offsetSeconds: $0.offset, linkType: LinkType.ethernet)
        }
        try Data(ReplayCorpus.classicPcapBytes(records)).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let identity = try CaptureStreamReader(contentsOf: url).identity
        let tuple = FiveTuple(
            proto: .tcp, source: IPEndpoint(ip: "10.0.0.5", port: 50_000),
            destination: IPEndpoint(ip: "203.0.113.9", port: 80)
        )
        let list = try CaptureObjectScanner.scan(
            .http, contentsOf: url, expectedIdentity: identity,
            streams: [CaptureObjectScanner.Stream(tuple: tuple, sessionID: SessionBuilder.sessionID(for: tuple))]
        )
        #expect(list.objects.map(\.fileName) == ["a.txt", "b.txt"])
        #expect(list.objects.map(\.host) == ["t.test", "t.test"])
        #expect(list.objects.map { String(bytes: $0.body, encoding: .utf8) }
            == ["hello", "hello from a gzip body"])
        #expect(list.objects.map(\.frameOrdinal) == [2, 4])
        #expect(CaptureObjectScanner.uniqueName("a.txt", taken: ["a.txt", "a.txt(1)"]) == "a.txt(2)")
        // macOS volumes usually ignore case, so `A.TXT` already takes `a.txt`.
        #expect(CaptureObjectScanner.uniqueName("a.txt", taken: ["A.TXT"]) == "a.txt(1)")
        // A name too long for a file keeps its extension and fits with a `(n)` added.
        let long = CaptureObjectScanner.savableName(String(repeating: "é", count: 300) + ".docx")
        #expect(long.hasSuffix(".docx"))
        #expect(long.utf8.count <= CaptureObjectScanner.maximumSavableNameBytes)
        #expect(CaptureObjectScanner.uniqueName(long, taken: [long]).utf8.count <= 255)

        guard WiresharkOracle.isAvailable, let tshark = WiresharkOracle.tsharkURL else {
            return
        }
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("objects-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let process = Process()
        process.executableURL = tshark
        process.arguments = ["-r", url.path, "-q", "--export-objects", "http,\(folder.path)"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        let theirs = try FileManager.default.contentsOfDirectory(atPath: folder.path).map { name in
            try [UInt8](Data(contentsOf: folder.appendingPathComponent(name)))
        }
        #expect(Set(theirs) == Set(list.objects.map(\.body)))
    }

    // MARK: Private

    private static let gzipBody: [UInt8] = [
        0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFF, 0xCB, 0x48, 0xCD, 0xC9, 0xC9, 0x57, 0x48, 0x2B,
        0xCA, 0xCF, 0x55, 0x48, 0x54, 0x48, 0xAF, 0xCA, 0x2C, 0x50, 0x48, 0xCA, 0x4F, 0xA9, 0x04, 0x00, 0x9E, 0xD1,
        0xC8, 0x4F, 0x16, 0x00, 0x00, 0x00,
    ]

    /// Two requests on one connection and their responses: plain text, then gzip.
    private static func frames() -> [[UInt8]] {
        let first = Array("GET /a.txt HTTP/1.1\r\nHost: t.test\r\n\r\n".utf8)
        let second = Array("GET /b.txt HTTP/1.1\r\nHost: t.test\r\n\r\n".utf8)
        let plain = Array("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello".utf8)
        let coded = Array((
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\n"
                + "Content-Length: \(gzipBody.count)\r\n\r\n"
        ).utf8) + gzipBody
        return [
            segment(client: true, seq: 1_000, first),
            segment(client: false, seq: 5_000, plain),
            segment(client: true, seq: 1_000 + UInt32(first.count), second),
            segment(client: false, seq: 5_000 + UInt32(plain.count), coded),
        ]
    }

    private static func segment(client: Bool, seq: UInt32, _ payload: [UInt8]) -> [UInt8] {
        PacketBuilder.ethernetIPv4(
            proto: 6, src: client ? "10.0.0.5" : "203.0.113.9", dst: client ? "203.0.113.9" : "10.0.0.5",
            payload: PacketBuilder.tcp(
                srcPort: client ? 50_000 : 80, dstPort: client ? 80 : 50_000, flags: 0x18, payload: payload,
                sequence: seq
            )
        )
    }
}
