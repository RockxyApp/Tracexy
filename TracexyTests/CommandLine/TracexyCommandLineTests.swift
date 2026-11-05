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
    func decodeAsRulesAreValidatedAndInvocationScoped() throws {
        let parsed = try TracexyCommandLine.parse([
            "frames", "a.pcap", "--decode-as", "udp:5300:dns", "--decode-as", "tcp:8888:http"
        ])
        #expect(parsed.decodeAsRules.map(\.decode) == [.dns, .http])
        #expect(try TracexyCommandLine.parse([
            "summary", "a.pcap", "--decode-as", "udp:5300:dns",
        ]).decodeAsRules.map(\.port) == [5_300])
        for bad in [
            ["info", "a.pcap", "--decode-as", "udp:5300:dns"],
            ["frames", "a.pcap", "--decode-as", "udp:0:dns"],
            ["frames", "a.pcap", "--decode-as", "udp:65536:dns"],
            ["frames", "a.pcap", "--decode-as", "tcp:5300:quic"],
            ["frames", "a.pcap", "--decode-as", "udp:5300:unknown"],
            ["frames", "a.pcap", "--decode-as", "udp:5300:dns", "--decode-as", "udp:5300:http"],
        ] {
            #expect(throws: TracexyCommandLine.UsageError.self, "\(bad)") {
                try TracexyCommandLine.parse(bad)
            }
        }
        let ruleArgs = (1 ... 64).flatMap { ["--decode-as", "udp:\($0):dns"] }
        #expect(try TracexyCommandLine.parse(["frames", "a.pcap"] + ruleArgs).decodeAsRules.count == 64)
        #expect(throws: TracexyCommandLine.UsageError.self) {
            try TracexyCommandLine.parse(["frames", "a.pcap"] + ruleArgs + ["--decode-as", "udp:65:dns"])
        }

        let frame = PacketBuilder.ethernetIPv4(
            proto: 17, src: "192.0.2.10", dst: "192.0.2.53",
            payload: PacketBuilder.udp(
                srcPort: 40_000, dstPort: 5_300,
                payload: PacketBuilder.dnsQuery(name: "cli-decode.example")
            )
        )
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("cli-decode-as-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: [
            CapturedFrame(
                bytes: frame,
                timestamp: Date(timeIntervalSince1970: 1_800_000_000),
                originalLength: frame.count
            )
        ], to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        func run(_ args: [String]) -> String {
            var output = ""
            _ = TracexyCommandLine.runIfRequested(["tracexy"] + args, output: { output += $0 }, errors: { _ in })
            return output
        }
        let plainFrames = run(["frames", url.path, "--format", "csv"])
        let forcedFrames = run(["frames", url.path, "--format", "csv", "--decode-as", "udp:5300:dns"])
        #expect(plainFrames.contains(",UDP,"))
        #expect(forcedFrames.contains(",DNS,"))
        let forcedDNS = run(["stats", url.path, "--tap", "dns", "--decode-as", "udp:5300:dns"])
        #expect(forcedDNS.contains("cli-decode.example"))
        let compressedURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("cli-decode-as-\(UUID().uuidString).pcap.gz")
        _ = try CaptureFrameExporter.export(
            from: url, scope: .wholeCapture, options: .init(compressesWithGzip: true), to: compressedURL
        )
        defer { try? FileManager.default.removeItem(at: compressedURL) }
        let compressedDNS = run(["stats", compressedURL.path, "--tap", "dns", "--decode-as", "udp:5300:dns"])
        #expect(compressedDNS.contains("cli-decode.example"))
        let subsequentDNS = run(["stats", url.path, "--tap", "dns"])
        #expect(!subsequentDNS.contains("cli-decode.example"), "A later invocation must not inherit CLI rules")
    }

    @Test
    func frameListRejectsOversizedAndEmptyRangesWithoutTrapping() throws {
        #expect(TracexyCommandLine.frameList("2,5-7") == Set<UInt64>([2, 5, 6, 7]))
        #expect(TracexyCommandLine.frameList("18446744073709551614-18446744073709551615") ==
            Set<UInt64>([UInt64.max - 1, UInt64.max]))
        for text in ["", "-", "1-18446744073709551615", "1-10000001", "1,", ",1", "1,,2", "2-1"] {
            #expect(TracexyCommandLine.frameList(text) == nil, "\(text)")
            #expect(throws: TracexyCommandLine.UsageError.self) {
                try TracexyCommandLine.parse(["frames", "a.pcap", "--details", "--frames", text])
            }
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
    func frameRowsRejectAnIncompleteRetainedPrefix() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("cli-frame-limit-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: ReplayCorpus.conversationCapturedFrames(), to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        do {
            _ = try TracexyCommandLine.frameRows(file: url, sessions: [], limited: false, maxRetainedFrames: 2)
            Issue.record("The frame table must not silently omit later frames")
        } catch let error as TracexyCommandLine.FrameRowsIncompleteError {
            #expect(error.scannedFrameCount == ReplayCorpus.conversationCapturedFrames().count)
            #expect(error.retainedFrameCount == 2)
        }
    }

    @Test
    func frameRowsRejectATruncatedFinalRecord() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("cli-frame-truncated-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: ReplayCorpus.conversationCapturedFrames(), to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let writer = try FileHandle(forWritingTo: url)
        try writer.seekToEnd()
        try writer.write(contentsOf: Data([0x01, 0x02]))
        try writer.close()

        do {
            _ = try TracexyCommandLine.frameRows(file: url, sessions: [], limited: false)
            Issue.record("The frame table must not present a truncated capture as complete")
        } catch let error as TracexyCommandLine.FrameRowsTruncatedError {
            #expect(error.scannedFrameCount == ReplayCorpus.conversationCapturedFrames().count)
        }

        var printed = ""
        #expect(throws: TracexyCommandLine.FrameRowsTruncatedError.self) {
            try TracexyCommandLine.streamFrames(
                file: url, sessions: [], limited: false, columns: [], format: .csv,
                output: { printed += $0 }
            )
        }
        #expect(printed.isEmpty, "No frame table should escape before validation finishes")
    }

    @Test
    func streamingFramesIncludeRowsPastTheScannerRetentionLimit() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("cli-frame-stream-\(UUID().uuidString).pcap")
        let frames = ReplayCorpus.conversationCapturedFrames()
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        var csv = ""
        try TracexyCommandLine.streamFrames(
            file: url, sessions: [], limited: false, columns: [], format: .csv,
            output: { csv += $0 }
        )
        let expected = try TracexyCommandLine.framesTable(file: url, sessions: [], limited: false)
        #expect(csv == expected.csv)
        #expect(csv.split(separator: "\n").count == frames.count + 1)
        #expect(csv.contains("\n\(frames.count),"))

        var text = ""
        try TracexyCommandLine.streamFrames(
            file: url, sessions: [], limited: false, columns: [], format: .text,
            output: { text += $0 }
        )
        #expect(text == expected.text)

        var json = ""
        try TracexyCommandLine.streamFrames(
            file: url, sessions: [], limited: false, columns: [], format: .json,
            output: { json += $0 }
        )
        let object = try #require(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        #expect((object["rows"] as? [[String: String]])?.count == frames.count)

        let window = try #require(TracexyCommandLine.fieldKey("TCP:Window"))
        var custom = ""
        try TracexyCommandLine.streamFrames(
            file: url, sessions: [], limited: false, columns: [window], format: .csv,
            output: { custom += $0 }
        )
        let expectedCustom = try TracexyCommandLine.framesTable(
            file: url, sessions: [], limited: false, columns: [window]
        )
        #expect(custom == expectedCustom.csv)

        var repeatedJSON = ""
        try TracexyCommandLine.streamFrames(
            file: url, sessions: [], limited: false, columns: [window, window], format: .json,
            output: { repeatedJSON += $0 }
        )
        let repeatedObject = try #require(
            JSONSerialization.jsonObject(with: Data(repeatedJSON.utf8)) as? [String: Any]
        )
        #expect((repeatedObject["rows"] as? [[String: String]])?.count == frames.count)
        #expect((repeatedObject["rows"] as? [[String: String]])?.first?["TCP:Window"] != nil)
        let repeatedTable = try TracexyCommandLine.framesTable(
            file: url, sessions: [], limited: false, columns: [window, window]
        )
        #expect((repeatedTable.jsonObject["rows"] as? [[String: String]])?.count == frames.count)
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
        // SCTP folds into sessions, so its conversation and endpoint taps are
        // named like the other transports. A link-layer tap is still refused,
        // because Tracexy does not fold Ethernet conversations.
        #expect(try TracexyCommandLine.parse([
            "stats", "a.pcap", "--tap", "conv,sctp"
        ]).taps == [.conversations(.sctp)])
        #expect(try TracexyCommandLine.parse([
            "stats", "a.pcap", "-z", "endpoints,sctp"
        ]).taps == [.endpoints(.sctp)])
        #expect(throws: TracexyCommandLine.UsageError.self) {
            try TracexyCommandLine.parse(["stats", "a.pcap", "--tap", "conv,eth"])
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

        printed = ""
        let srtStatus = TracexyCommandLine.runIfRequested(
            ["Tracexy", "stats", url.path, "--tap", "smb2,srt", "--format", "csv"],
            output: { printed += $0 }, errors: { _ in }
        )
        #expect(srtStatus == 0)
        #expect(printed == "index,command,calls,min_srt_s,max_srt_s,avg_srt_s,sum_srt_s\n")

        printed = ""
        let combinedSRTStatus = TracexyCommandLine.runIfRequested(
            ["Tracexy", "stats", url.path, "--tap", "smb2,srt", "--tap", "conv,ipv4", "--format", "json"],
            output: { printed += $0 }, errors: { _ in }
        )
        #expect(combinedSRTStatus == 0)
        let combinedStats = try #require(try JSONSerialization.jsonObject(with: Data(printed.utf8)) as? [[String: Any]])
        #expect(combinedStats.compactMap { $0["statistic"] as? String }
            == ["SMB2 SRT Statistics", "IPv4 Conversations"])

        for (tap, expectedTitle) in [("ldap,srt", "LDAP SRT Statistics"), ("kerberos,srt", "Kerberos SRT Statistics")] {
            printed = ""
            let status = TracexyCommandLine.runIfRequested(
                ["Tracexy", "stats", url.path, "--tap", tap, "--format", "json"],
                output: { printed += $0 }, errors: { _ in }
            )
            #expect(status == 0)
            let standalone = try #require(try JSONSerialization
                .jsonObject(with: Data(printed.utf8)) as? [[String: Any]])
            #expect(standalone.first?["statistic"] as? String == expectedTitle)

            printed = ""
            let mixedStatus = TracexyCommandLine.runIfRequested(
                ["Tracexy", "stats", url.path, "--tap", tap, "--tap", "conv,ipv4", "--format", "json"],
                output: { printed += $0 }, errors: { _ in }
            )
            #expect(mixedStatus == 0)
            let mixed = try #require(try JSONSerialization.jsonObject(with: Data(printed.utf8)) as? [[String: Any]])
            #expect(mixed.compactMap { $0["statistic"] as? String } == [expectedTitle, "IPv4 Conversations"])
        }
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
        #expect(lines.first == "number,time_s,source,destination,protocol,capture_direction,length,info,session")
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

    @Test
    func frameTableAndStreamingOutputPreserveCaptureInterfaceDirection() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("cli-frame-direction-\(UUID().uuidString).pcapng")
        defer { try? FileManager.default.removeItem(at: url) }
        let frames: [CapturedFrame] = [
            CapturedFrame(
                bytes: [0, 1],
                timestamp: Date(timeIntervalSince1970: 1_800_000_000),
                originalLength: 2,
                direction: .inbound
            ),
            CapturedFrame(
                bytes: [2, 3],
                timestamp: Date(timeIntervalSince1970: 1_800_000_001),
                originalLength: 2,
                direction: .outbound
            ),
            CapturedFrame(bytes: [4, 5], timestamp: nil, originalLength: 2),
        ]
        try PcapngWriter.write(defaultLinkType: LinkType.ethernet, frames: frames, to: url)

        let table = try TracexyCommandLine.framesTable(file: url, sessions: [], limited: false)
        let directionIndex = try #require(table.columns.firstIndex(of: "capture_direction"))
        #expect(table.rows.map { $0[directionIndex] } == ["inbound", "outbound", "unknown"])

        var json = ""
        try TracexyCommandLine.streamFrames(
            file: url, sessions: [], limited: false, columns: [], format: .json,
            output: { json += $0 }
        )
        let object = try #require(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        let rows = try #require(object["rows"] as? [[String: String]])
        #expect(rows.map { $0["capture_direction"] } == ["inbound", "outbound", "unknown"])

        var csv = ""
        try TracexyCommandLine.streamFrames(
            file: url, sessions: [], limited: false, columns: [], format: .csv,
            output: { csv += $0 }
        )
        #expect(csv == table.csv)
    }
}
