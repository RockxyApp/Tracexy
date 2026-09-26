import Foundation
import Testing
@testable import Tracexy

/// `tracexy glossary` lists every name a script can use — and every listed tap parses;
/// `tracexy frames --column Protocol:Field` adds decode-tree fields as columns.
struct CommandLineGlossaryTests {
    @Test
    func glossaryNamesParse() throws {
        var json = ""
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "glossary", "--format", "json"], output: { json += $0 }, errors: { _ in }
        ) == 0)
        let object = try #require(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: [String]])
        #expect(Set(object.keys) == ["terms", "protocols", "findings", "taps", "objectTypes"])
        for tap in object["taps"] ?? [] {
            #expect(StatisticsTap(tap) != nil, "\(tap)")
        }
        for finding in object["findings"] ?? [] {
            #expect((try? SessionQueryParser().parse("finding == \(finding)")) != nil, "\(finding)")
        }
        #expect(object["objectTypes"] == ["ftp-data", "http", "imf", "tftp", "x509af"])
        #expect(throws: TracexyCommandLine.UsageError.self) {
            try TracexyCommandLine.parse(["glossary", "--format", "csv"])
        }
    }

    @Test
    func framesTakeFieldColumns() throws {
        let frame = PacketBuilder.dnsQueryFrame(name: "a.test", src: "192.0.2.10", dst: "192.0.2.53")
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("cols-\(UUID().uuidString).pcap")
        try PcapWriter.write(
            linkType: LinkType.ethernet,
            frames: [CapturedFrame(
                bytes: frame,
                timestamp: Date(timeIntervalSince1970: 1_800_000_000),
                originalLength: frame.count
            )],
            to: url
        )
        defer { try? FileManager.default.removeItem(at: url) }
        var csv = ""
        #expect(TracexyCommandLine.runIfRequested(
            [
                "Tracexy",
                "frames",
                url.path,
                "--column",
                "udp:Destination Port",
                "--column",
                "IPv4:TTL",
                "--format",
                "csv"
            ],
            output: { csv += $0 }, errors: { _ in }
        ) == 0)
        let lines = csv.split(separator: "\n")
        #expect(lines.first?.hasSuffix(",UDP:Destination Port,IPv4:TTL") == true)
        #expect(lines.dropFirst().first?.hasSuffix(",53,64") == true)
        #expect(throws: TracexyCommandLine.UsageError.self) {
            try TracexyCommandLine.parse(["frames", "a.pcap", "--column", "nope:Field"])
        }
    }
}
