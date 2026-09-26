import Foundation
import Testing
@testable import Tracexy

/// Export Frames can carry the capture's address names inside the PCAPNG file
/// (a Name Resolution Block), so Wireshark shows the same names without resolving.
struct FrameExportNameResolutionTests {
    @Test
    func namesTravelInsideThePcapng() throws {
        let frame = PacketBuilder.httpRequestFrame(
            host: "web.example.test", path: "/", src: "192.0.2.10", dst: "198.51.100.7"
        )
        let source = FileManager.default.temporaryDirectory.appendingPathComponent("nrb-in-\(UUID().uuidString).pcap")
        try Data(ReplayCorpus.classicPcapBytes([
            ReplayCorpus.Frame(bytes: frame, offsetSeconds: 0, linkType: LinkType.ethernet),
        ])).write(to: source)
        defer { try? FileManager.default.removeItem(at: source) }
        let output = FileManager.default.temporaryDirectory.appendingPathComponent("nrb-\(UUID().uuidString).pcapng")
        defer { try? FileManager.default.removeItem(at: output) }

        var options = FrameExportOptions(format: .pcapng)
        options.nameRecords = [
            FrameExportNameRecord(address: "198.51.100.7", name: "web.example.test"),
            FrameExportNameRecord(address: "2001:db8::1", name: "v6.example.test"),
            FrameExportNameRecord(address: "not-an-address", name: "skipped.test"),
            FrameExportNameRecord(address: "192.0.2.10", name: ""),
        ]
        let summary = try CaptureFrameExporter.export(from: source, scope: .wholeCapture, options: options, to: output)
        #expect(summary.writtenNameCount == 2)
        #expect(summary.writtenFrameCount == 1)
        // Tracexy reads its own file back: the block is skipped, the frame kept.
        let reader = try CaptureStreamReader(contentsOf: output)
        guard case let .frame(event) = try reader.next() else {
            Issue.record("the exported frame should read back")
            return
        }
        #expect(event.bytes == frame)

        // Replacing addresses leaves the names out, since they would name the hosts.
        let anonymized = FileManager.default.temporaryDirectory
            .appendingPathComponent("nrb-anon-\(UUID().uuidString).pcapng")
        defer { try? FileManager.default.removeItem(at: anonymized) }
        options.anonymizesAddresses = true
        let quiet = try CaptureFrameExporter.export(
            from: source, scope: .wholeCapture, options: options, to: anonymized
        )
        #expect(quiet.writtenNameCount == 0)

        guard WiresharkOracle.isAvailable else {
            return
        }
        let rows = try WiresharkOracle.tsharkFields(output, fields: ["ip.dst_host"], extraArguments: ["-N", "n"])
        #expect(rows == [["web.example.test"]])
    }
}
