import Foundation
import Testing
@testable import Tracexy

/// Export Frames can leave out exact duplicates of a recent frame and
/// keep only the first bytes of each frame, as `editcap -d` and `editcap -s` do.
struct FrameExportTrimTests {
    // MARK: Internal

    @Test
    func removesDuplicatesAndTruncatesLikeEditcap() throws {
        let a = PacketBuilder.httpRequestFrame(host: "a.test", path: "/one", src: "192.0.2.10", dst: "198.51.100.7")
        let b = PacketBuilder.httpRequestFrame(host: "b.test", path: "/two", src: "192.0.2.10", dst: "198.51.100.8")
        let c = PacketBuilder.dnsQueryFrame(name: "example.com", src: "192.0.2.10", dst: "192.0.2.1")
        // a, a (dup), b, a (dup within 5), c, b (dup), then a again after 6 others would not be.
        let frames = [a, a, b, a, c, b, c, c]
        let source = try Self.write(frames)
        defer { try? FileManager.default.removeItem(at: source) }

        let output = Self.temporaryURL()
        defer { try? FileManager.default.removeItem(at: output) }
        let summary = try CaptureFrameExporter.export(
            from: source, scope: .wholeCapture,
            options: FrameExportOptions(format: .pcap, removesDuplicates: true, truncatesTo: 64), to: output
        )
        #expect(summary.removedDuplicateCount == 5)
        #expect(summary.writtenFrameCount == 3)
        #expect(summary.truncatedFrameCount == 3)
        let written = try Self.frames(output)
        #expect(written.map(\.reference.capturedLength) == [64, 64, 64])
        #expect(written.map(\.reference.originalLength) == [a.count, b.count, c.count])
        #expect(written[0].bytes == Array(a.prefix(64)))

        guard let editcap = WiresharkOracle.capinfosURL?.deletingLastPathComponent().appendingPathComponent("editcap"),
              FileManager.default.isExecutableFile(atPath: editcap.path) else
        {
            return
        }
        let reference = Self.temporaryURL()
        defer { try? FileManager.default.removeItem(at: reference) }
        try Self.run(editcap, ["-d", "-s", "64", "-F", "pcap", source.path, reference.path])
        let theirs = try WiresharkOracle.tsharkFields(reference, fields: ["frame.cap_len", "frame.len"])
        let ours = try WiresharkOracle.tsharkFields(output, fields: ["frame.cap_len", "frame.len"])
        #expect(ours == theirs)
    }

    // MARK: Private

    private static func temporaryURL() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("trim-\(UUID().uuidString).pcap")
    }

    private static func write(_ frames: [[UInt8]]) throws -> URL {
        let url = temporaryURL()
        let records = frames.enumerated().map {
            ReplayCorpus.Frame(bytes: $0.element, offsetSeconds: $0.offset, linkType: LinkType.ethernet)
        }
        try Data(ReplayCorpus.classicPcapBytes(records)).write(to: url)
        return url
    }

    private static func frames(_ url: URL) throws -> [CaptureFrameEvent] {
        let reader = try CaptureStreamReader(contentsOf: url)
        var events: [CaptureFrameEvent] = []
        while case let .frame(event) = try reader.next() {
            events.append(event)
        }
        return events
    }

    private static func run(_ tool: URL, _ arguments: [String]) throws {
        let process = Process()
        process.executableURL = tool
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
    }
}
