import Foundation
import Testing
@testable import Tracexy

/// File ▸ Export Packet Dissections and `tracexy frames --details` write every
/// frame's decode tree as text (tshark `-V` layout) or JSON.
struct DissectionExporterTests {
    // MARK: Internal

    @Test
    func textListsEachFramesLayersAndFields() throws {
        let url = try Self.capture(ports: [53, 443])
        defer { try? FileManager.default.removeItem(at: url) }
        var data = Data()
        let summary = try DissectionExporter.export(from: url, format: .text) { data += $0 }
        #expect(summary == DissectionExporter.Summary(writtenFrameCount: 2, scannedFrameCount: 2))
        let text = try #require(String(bytes: data, encoding: .utf8))
        #expect(text
            .hasPrefix("Frame 1: 46 bytes on wire, 46 bytes captured, 2027-01-15T08:00:00.000000Z\nEthernet II"))
        #expect(text.contains("\n    Destination Port: 443\n"))
        #expect(text.components(separatedBy: "\nFrame ").count == 2)
    }

    @Test
    func jsonIsOneObjectPerFrame() throws {
        let url = try Self.capture(ports: [53, 443, 80])
        defer { try? FileManager.default.removeItem(at: url) }
        let dns = SessionBuilder.sessionID(for: FiveTuple(
            proto: .udp, source: IPEndpoint(ip: "192.0.2.10", port: 40_000),
            destination: IPEndpoint(ip: "198.51.100.7", port: 53)
        ))
        var data = Data()
        let summary = try DissectionExporter.export(from: url, sessions: [dns], format: .json) { data += $0 }
        #expect(summary.writtenFrameCount == 1)
        #expect(summary.scannedFrameCount == 3)
        let frames = try #require(try JSONSerialization.jsonObject(with: data) as? [[String: Any]])
        #expect(frames.count == 1)
        #expect(frames[0]["frame"] as? Int == 1)
        #expect(frames[0]["session"] as? String == dns.uuidString)
        let layers = try #require(frames[0]["layers"] as? [[String: Any]])
        #expect(layers.compactMap { $0["protocol"] as? String }.prefix(3) == ["ETH", "IPv4", "UDP"])
        var empty = Data()
        _ = try DissectionExporter.export(from: url, sessions: [], format: .json) { empty += $0 }
        #expect(try JSONSerialization.jsonObject(with: empty) is [Any])
    }

    @Test
    func timesAreUTCWithMicroseconds() {
        #expect(DissectionExporter
            .stamp(Date(timeIntervalSince1970: 1_790_167_957.626342)) == "2026-09-23T12:52:37.626342Z")
        #expect(DissectionExporter.stamp(Date(timeIntervalSince1970: 0.9999999)) == "1970-01-01T00:00:01.000000Z")
    }

    @Test
    func commandLinePrintsDetails() throws {
        let url = try Self.capture(ports: [53])
        defer { try? FileManager.default.removeItem(at: url) }
        var data = Data()
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "frames", url.path, "--details"], output: { _ in }, errors: { _ in }, data: { data += $0 }
        ) == 0)
        #expect(String(bytes: data, encoding: .utf8)?.hasPrefix("Frame 1: ") == true)
        var message = ""
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "frames", url.path, "--details", "--format", "csv"], output: { _ in },
            errors: { message += $0 }
        ) == 2)
        #expect(message.contains("text or json"))
    }

    // MARK: Private

    private static func capture(ports: [UInt16]) throws -> URL {
        let frames = ports.enumerated().map { index, port in
            CapturedFrame(
                bytes: PacketBuilder.ethernetIPv4(
                    proto: 17, src: "192.0.2.10", dst: "198.51.100.7",
                    payload: PacketBuilder.udp(srcPort: 40_000, dstPort: port, payload: [0, 1, 2, 3])
                ),
                timestamp: Date(timeIntervalSince1970: 1_800_000_000 + Double(index)),
                originalLength: 46
            )
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("dissect-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        return url
    }
}
