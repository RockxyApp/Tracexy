import Foundation
import Testing
@testable import Tracexy

/// The read-only command line in the app binary — argument parsing, the exit
/// statuses, and output produced by the same analysis and export code as the window.
@MainActor
struct TracexyCommandLineTests {
    @Test
    func aNormalLaunchIsNotTheCommandLine() {
        #expect(TracexyCommandLine.runIfRequested(["/Applications/Tracexy.app/Contents/MacOS/Tracexy"]) == nil)
        #expect(TracexyCommandLine.runIfRequested(["Tracexy", "--direct-capture"]) == nil)
        #expect(TracexyCommandLine.runIfRequested(["Tracexy", "-NSDocumentRevisionsDebugMode", "YES"]) == nil)
    }

    @Test
    func parsingAcceptsOnlyWhatEachCommandTakes() throws {
        let parsed = try TracexyCommandLine.parse([
            "findings",
            "a.pcap",
            "-e",
            "tcp",
            "--format",
            "json",
            "--fail-on",
            "warning"
        ])
        #expect(parsed.command == .findings)
        #expect(parsed.file?.lastPathComponent == "a.pcap")
        #expect(parsed.expression == "tcp")
        #expect(parsed.format == .json)
        #expect(parsed.failOn == .warning)
        for bad in [
            ["sessions"],
            ["summary", "a.pcap", "--format", "csv"],
            ["summary", "a.pcap", "-e", "tcp"],
            ["sessions", "a.pcap", "--fail-on", "note"],
            ["sessions", "a.pcap", "b.pcap"],
            ["sessions", "a.pcap", "--format", "xml"],
            ["findings", "a.pcap", "--fail-on"],
        ] {
            #expect(throws: TracexyCommandLine.UsageError.self, "\(bad)") { try TracexyCommandLine.parse(bad) }
        }
    }

    @Test
    func commandsReadACaptureAndReturnTheirStatus() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("cli-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("refused.pcap")
        // A SYN answered by a reset from the server: one "connection refused" warning.
        let frames = [
            PacketBuilder.ethernetIPv4(
                proto: 6, src: "192.0.2.10", dst: "203.0.113.5",
                payload: PacketBuilder.tcp(srcPort: 50_000, dstPort: 8_080, flags: 0x02, payload: [])
            ),
            PacketBuilder.ethernetIPv4(
                proto: 6, src: "203.0.113.5", dst: "192.0.2.10",
                payload: PacketBuilder.tcp(srcPort: 8_080, dstPort: 50_000, flags: 0x14, payload: [])
            ),
        ]
        try PcapWriter.write(
            linkType: LinkType.ethernet,
            frames: frames.enumerated().map { index, bytes in
                CapturedFrame(
                    bytes: bytes, timestamp: Date(timeIntervalSince1970: 1_800_000_000 + Double(index)),
                    originalLength: bytes.count
                )
            },
            to: url
        )
        var out = ""
        var err = ""
        func run(_ arguments: [String]) -> Int32? {
            out = ""
            err = ""
            return TracexyCommandLine.runIfRequested(
                ["tracexy"] + arguments, output: { out += $0 }, errors: { err += $0 }
            )
        }

        #expect(run(["summary", url.path]) == 0)
        #expect(out.contains("Sessions: 1"))
        #expect(out.contains("Connection refused by peer (warning)"))
        #expect(run(["summary", url.path, "--json"]) == 0)
        #expect(out.contains("\"findings\" : 1"))

        #expect(run(["findings", url.path, "--fail-on", "warning"]) == 3)
        #expect(out.hasPrefix(InvestigationExport.findingHeader.joined(separator: ",")))
        #expect(run(["findings", url.path, "-e", "port == 443", "--fail-on", "warning"]) == 0)

        #expect(run(["sessions", url.path, "-e", "finding == connectionRefused", "--format", "json"]) == 0)
        let json = try #require(try JSONSerialization.jsonObject(with: Data(out.utf8)) as? [String: Any])
        #expect((json["sessions"] as? [Any])?.count == 1)

        #expect(run(["sessions", url.path, "-e", "port =="]) == 2)
        #expect(err.contains("A value is expected here."))
        #expect(run(["sessions", directory.appendingPathComponent("missing.pcap").path]) == 1)
        #expect(run(["help"]) == 0)
        #expect(out.contains("Usage:"))
    }

    @Test
    func statsTapsParseWithTsharkSpellings() throws {
        let parsed = try TracexyCommandLine.parse([
            "stats",
            "a.pcap",
            "-z",
            "conv,ip",
            "--tap",
            "io,phs",
            "--tap",
            "plen,tree"
        ])
        #expect(parsed.taps == [.conversations(.ipv4), .protocolHierarchy, .packetLengths])
        #expect(parsed.format == .text, "stats print text unless a format is named")
        #expect(throws: TracexyCommandLine.UsageError.self) { try TracexyCommandLine.parse(["stats", "a.pcap"]) }
        #expect(throws: TracexyCommandLine.UsageError.self) {
            try TracexyCommandLine.parse(["stats", "a.pcap", "--tap", "conv,sctp"])
        }
        #expect(try TracexyCommandLine.parse([
            "stats",
            "a.pcap",
            "-z",
            "smb2,srt",
            "-z",
            "ldap,srt",
            "-z",
            "kerberos,srt"
        ])
        .taps == [.serviceResponseTime(.smb2), .serviceResponseTime(.ldap), .serviceResponseTime(.kerberos)])
        #expect(try TracexyCommandLine.parse(["stats", "a.pcap", "-z", "icmp,srt", "-z", "icmpv6,srt"]).taps
            == [.serviceResponseTime(.icmp), .serviceResponseTime(.icmpv6)])
        #expect(throws: TracexyCommandLine.UsageError.self) {
            try TracexyCommandLine.parse(["stats", "a.pcap", "--tap", "smb2"])
        }
        #expect(throws: TracexyCommandLine.UsageError.self) {
            try TracexyCommandLine.parse(["sessions", "a.pcap", "--format", "text"])
        }
    }

    @Test
    func statsPrintTheWindowsModels() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("cli-stats-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("conv.pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: ReplayCorpus.conversationCapturedFrames(), to: url)

        var printed = ""
        let status = TracexyCommandLine.runIfRequested(
            ["Tracexy", "stats", url.path, "--tap", "plen", "--tap", "endpoints,udp", "--format", "csv"],
            output: { printed += $0 }, errors: { _ in }
        )
        #expect(status == 0)
        let lines = printed.split(separator: "\n").map(String.init)
        #expect(lines.first == "range,count,average,min,max,percent")
        #expect(lines.contains { $0.hasPrefix("all,\(ReplayCorpus.conversationCapturedFrames().count),") })
        #expect(lines.contains("address,port,sessions,frames,bytes,tx_frames,tx_bytes,rx_frames,rx_bytes"))

        printed = ""
        _ = TracexyCommandLine.runIfRequested(
            ["Tracexy", "stats", url.path, "-z", "phs", "--format", "json"],
            output: { printed += $0 },
            errors: { _ in }
        )
        let json = try #require(try JSONSerialization.jsonObject(with: Data(printed.utf8)) as? [[String: Any]])
        #expect(json.first?["statistic"] as? String == "Protocol Hierarchy")
    }

    @Test
    func csvCellsAreGuarded() {
        let table = StatisticsTable(title: "t", columns: ["a"], rows: [["=cmd()"], ["-5"], ["x,y"]])
        #expect(table.csv == "a\n'=cmd()\n-5\n\"x,y\"\n")
    }

    @Test
    func framesListEveryFrameAndHonourTheExpression() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("cli-frames-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("conv.pcap")
        let frames = ReplayCorpus.conversationCapturedFrames()
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)

        var printed = ""
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "frames", url.path, "--format", "csv"], output: { printed += $0 }, errors: { _ in }
        ) == 0)
        let lines = printed.split(separator: "\n")
        #expect(lines.first == "number,time_s,source,destination,protocol,length,info,session")
        #expect(lines.count == frames.count + 1)

        printed = ""
        _ = TracexyCommandLine.runIfRequested(
            ["Tracexy", "frames", url.path, "-e", "dns", "--format", "csv"], output: { printed += $0 }, errors: { _ in }
        )
        let dnsLines = printed.split(separator: "\n").dropFirst()
        #expect(!dnsLines.isEmpty && dnsLines.count < frames.count)
        #expect(dnsLines.allSatisfy { $0.contains("DNS") || $0.contains("mDNS") })
        #expect(try TracexyCommandLine.parse(["frames", "a.pcap"]).format == .text)
    }
}
