import Foundation
import Testing
@testable import Tracexy

/// `tracexy info` (capinfos), `select` (editcap's frame selection and
/// duplicate removal) and `merge` (mergecap) — one capture per call, output to
/// standard output only.
struct CommandLineFileVerbsTests {
    // MARK: Internal

    @Test
    func frameListsReadAsEditcapTakesThem() {
        #expect(TracexyCommandLine.frameList("1-3,7") == [1, 2, 3, 7])
        #expect(TracexyCommandLine.frameList("5") == [5])
        #expect(TracexyCommandLine.frameList("0") == nil)
        #expect(TracexyCommandLine.frameList("9-3") == nil)
        #expect(TracexyCommandLine.frameList("a") == nil)
        #expect(TracexyCommandLine.frameList("1-99999999") == nil)
    }

    @Test
    func infoReportsWhatCapinfosDoes() throws {
        let url = try Self.capture(ports: [53, 80, 443], name: "info")
        defer { try? FileManager.default.removeItem(at: url) }
        var text = ""
        #expect(TracexyCommandLine.runIfRequested(["Tracexy", "info", url.path], output: { text += $0 }) == 0)
        #expect(text.contains("Frames: 3"))
        let digests = try CaptureHasher.digests(of: url)
        #expect(text.contains("SHA-256: \(digests.sha256)"))
        var json = ""
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "info", url.path, "--format", "json"], output: { json += $0 }
        ) == 0)
        let pairs = try #require(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [[String: String]])
        #expect(pairs.contains { $0["key"] == "Frames" && $0["value"] == "3" })
    }

    @Test
    func selectWritesTheChosenFrames() throws {
        let url = try Self.capture(ports: [53, 80, 443, 443], name: "select")
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(try Self.frames(of: ["select", url.path, "--frames", "1,3-4"]).map(\.port) == [53, 443, 443])
        #expect(try Self.frames(of: ["select", url.path, "--expression", "port == 443"]).count == 2)
        // Frames 3 and 4 are byte-identical, so the second goes.
        #expect(try Self.frames(of: ["select", url.path, "--dedupe"]).map(\.port) == [53, 80, 443])
    }

    @Test
    func selectTruncatesAndComments() throws {
        let url = try Self.capture(ports: [53], name: "snap")
        defer { try? FileManager.default.removeItem(at: url) }
        var bytes = Data()
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "select", url.path, "--snaplen", "34", "--comment", "from the CLI"],
            output: { _ in }, errors: { _ in }, data: { bytes += $0 }
        ) == 0)
        let out = FileManager.default.temporaryDirectory.appendingPathComponent("snap-\(UUID().uuidString).pcapng")
        try bytes.write(to: out)
        defer { try? FileManager.default.removeItem(at: out) }
        let reader = try CaptureStreamReader(contentsOf: out)
        guard case let .frame(event) = try reader.next() else {
            Issue.record("no frame")
            return
        }
        #expect(event.bytes.count == 34)
        #expect(event.reference.originalLength == 46)
        #expect(bytes.range(of: Data("from the CLI".utf8)) != nil)
        var message = ""
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "select", url.path, "--snaplen", "5"], output: { _ in }, errors: { message += $0 }
        ) == 2)
        #expect(message.contains("14 to 262144"))
    }

    /// editcap -t: every time moves, the frames chosen stay the same.
    @Test
    func selectShiftsTimes() throws {
        let url = try Self.capture(ports: [53, 80], name: "shift")
        defer { try? FileManager.default.removeItem(at: url) }
        let shifted = try Self.frames(of: ["select", url.path, "--time-shift", "-3600.25"])
        #expect(shifted.map(\.time) == [
            Date(timeIntervalSince1970: 1_800_000_000 - 3_600.25),
            Date(timeIntervalSince1970: 1_800_000_000.5 - 3_600.25),
        ])
        var message = ""
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "select", url.path, "--time-shift", "soon"], output: { _ in }, errors: { message += $0 }
        ) == 2)
        #expect(message.contains("--time-shift takes seconds"))
    }

    @Test
    func mergeInterleavesByTime() throws {
        let first = try Self.capture(ports: [1, 3], name: "merge-a", start: 0)
        let second = try Self.capture(ports: [2], name: "merge-b", start: 0.25)
        defer {
            try? FileManager.default.removeItem(at: first)
            try? FileManager.default.removeItem(at: second)
        }
        #expect(try Self.frames(of: ["merge", first.path, second.path]).map(\.port) == [1, 2, 3])
    }

    @Test
    func usageErrorsExplainThemselves() {
        var message = ""
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "merge", "/tmp/only-one.pcap"], output: { _ in }, errors: { message += $0 }
        ) == 2)
        #expect(message.contains("two or more"))
        message = ""
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "select", "/tmp/x.pcap", "--frames", "1", "--expression", "tcp"], output: { _ in },
            errors: { message += $0 }
        ) == 2)
        #expect(message.contains("not both"))
    }

    // MARK: Private

    /// Runs the command and reads the PCAPNG it printed: each frame's UDP destination port.
    private static func frames(of arguments: [String]) throws -> [(port: UInt16, time: Date?)] {
        var bytes = Data()
        let status = TracexyCommandLine.runIfRequested(
            ["Tracexy"] + arguments, output: { _ in }, errors: { _ in }, data: { bytes += $0 }
        )
        try #require(status == 0)
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("cli-out-\(UUID().uuidString).pcapng")
        try bytes.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let reader = try CaptureStreamReader(contentsOf: url)
        var ports: [(UInt16, Date?)] = []
        while case let .frame(event) = try reader.next() {
            let packet = SessionBuilder.decodePacket(
                CapturedFrame(
                    bytes: event.bytes,
                    timestamp: event.reference.timestamp,
                    originalLength: event.bytes.count
                ),
                linkType: event.reference.linkType
            )
            ports.append((packet.destinationEndpoint?.port ?? 0, event.reference.timestamp))
        }
        return ports
    }

    private static func capture(ports: [UInt16], name: String, start: Double = 0) throws -> URL {
        let frames = ports.enumerated().map { index, port in
            CapturedFrame(
                bytes: PacketBuilder.ethernetIPv4(
                    proto: 17, src: "192.0.2.10", dst: "198.51.100.7",
                    payload: PacketBuilder.udp(srcPort: 40_000, dstPort: port, payload: [1, 2, 3, 4])
                ),
                // Equal ports are sent at the same instant, so identical frames stay identical.
                timestamp: Date(timeIntervalSince1970: 1_800_000_000 + start + Double(index) * 0.5
                    - (index > 0 && ports[index - 1] == port ? 0.5 : 0)),
                originalLength: 46
            )
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("cli-\(name)-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        return url
    }
}
