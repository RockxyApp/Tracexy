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
    func appliedFrameExpressionExportsMatchingCaptureOrdinals() throws {
        let url = try Self.capture(ports: [53, 443, 80, 53])
        defer { try? FileManager.default.removeItem(at: url) }
        let expression = try Self.expression("udp.port == 53")
        var data = Data()
        let summary = try DissectionExporter.export(
            from: url, frameExpression: expression, format: .json
        ) { data += $0 }

        #expect(summary == .init(writtenFrameCount: 2, scannedFrameCount: 4))
        let objects = try #require(JSONSerialization.jsonObject(with: data) as? [[String: Any]])
        #expect(objects.compactMap { $0["frame"] as? Int } == [1, 4])
    }

    @Test("Dissection export filters by retained PCAPNG capture direction")
    func captureDirectionExpressionExportsOnlyKnownInboundFrames() throws {
        let source = FileManager.default.temporaryDirectory
            .appendingPathComponent("dissect-direction-\(UUID().uuidString).pcapng")
        defer { try? FileManager.default.removeItem(at: source) }
        try PcapngWriter.write(defaultLinkType: LinkType.ethernet, frames: [
            CapturedFrame(
                bytes: [1],
                timestamp: Date(timeIntervalSince1970: 1),
                originalLength: 1,
                direction: .inbound
            ),
            CapturedFrame(
                bytes: [2],
                timestamp: Date(timeIntervalSince1970: 2),
                originalLength: 1,
                direction: .outbound
            ),
            CapturedFrame(bytes: [3], timestamp: Date(timeIntervalSince1970: 3), originalLength: 1),
        ], to: source)
        let expression = try Self.expression("frame.capture_direction == inbound")
        var data = Data()
        let summary = try DissectionExporter.export(
            from: source, frameExpression: expression, excludedFrameOrdinals: [3], format: .json
        ) { data += $0 }
        let objects = try #require(JSONSerialization.jsonObject(with: data) as? [[String: Any]])

        #expect(summary.writtenFrameCount == 1)
        #expect(summary.scannedFrameCount == 3)
        #expect(summary.unknownExpressionFrameCount == 1)
        #expect(summary.excludedIgnoredFrameCount == 0)
        #expect(objects.compactMap { $0["frame"] as? Int } == [1])
    }

    @Test
    func ignoredFramesAreExcludedAfterScopeMatchingAndKeepOriginalOrdinals() throws {
        let url = try Self.capture(ports: [53, 443, 80, 53])
        defer { try? FileManager.default.removeItem(at: url) }
        let expression = try Self.expression("udp.port == 53")
        var data = Data()
        let summary = try DissectionExporter.export(
            from: url, frameExpression: expression, excludedFrameOrdinals: [2, 4], format: .json
        ) { data += $0 }

        #expect(summary.writtenFrameCount == 1)
        #expect(summary.scannedFrameCount == 4)
        #expect(summary.unknownExpressionFrameCount == 0)
        #expect(summary.excludedIgnoredFrameCount == 1)
        let objects = try #require(JSONSerialization.jsonObject(with: data) as? [[String: Any]])
        #expect(objects.compactMap { $0["frame"] as? Int } == [1])
    }

    @Test
    func appliedFrameExpressionPrintsOnlyMatchingSummaryDetailsAndBytes() throws {
        let url = try Self.capture(ports: [53, 443, 80])
        defer { try? FileManager.default.removeItem(at: url) }
        let expression = try Self.expression("udp.port == 53")
        var output = Data()
        let summary = try DissectionExporter.export(
            from: url, frameExpression: expression, format: .text,
            textLayout: [.summary, .details, .bytes]
        ) { output += $0 }

        #expect(summary == .init(writtenFrameCount: 1, scannedFrameCount: 3))
        let text = try #require(String(data: output, encoding: .utf8))
        #expect(text.contains("Frame 1  "))
        #expect(text.contains("UDP  46 bytes"))
        #expect(!text.contains("Frame 2  "))
        #expect(text.contains("Frame 1: 46 bytes on wire, 46 bytes captured"))
        #expect(text.contains("Frame 1: 46 captured bytes"))
        #expect(text.components(separatedBy: "Frame 1:").count == 3)
    }

    @Test
    func frameExpressionUsesEachPcapngInterfaceLinkType() throws {
        let source = FileManager.default.temporaryDirectory
            .appendingPathComponent("dissection-mixed-link-\(UUID().uuidString).pcapng")
        defer { try? FileManager.default.removeItem(at: source) }
        let ethernet = PacketBuilder.ethernetIPv4(
            proto: 17, src: "192.0.2.10", dst: "198.51.100.7",
            payload: PacketBuilder.udp(srcPort: 40_000, dstPort: 53, payload: [1, 2, 3, 4])
        )
        let rawIP = PacketBuilder.ethernetIPv4(
            proto: 17, src: "192.0.2.10", dst: "198.51.100.7",
            payload: PacketBuilder.udp(srcPort: 40_000, dstPort: 443, payload: [1, 2, 3, 4])
        ).dropFirst(14)
        let frames = [
            CapturedFrame(
                bytes: ethernet, timestamp: Date(timeIntervalSince1970: 1_800_000_000),
                originalLength: ethernet.count, linkType: LinkType.ethernet
            ),
            CapturedFrame(
                bytes: Array(rawIP), timestamp: Date(timeIntervalSince1970: 1_800_000_001),
                originalLength: rawIP.count, linkType: LinkType.raw
            ),
        ]
        try PcapngWriter.write(defaultLinkType: LinkType.ethernet, frames: frames, to: source)
        let expression = try Self.expression("udp.dstport == 443")
        var output = Data()
        let summary = try DissectionExporter.export(
            from: source, frameExpression: expression, format: .json
        ) { output += $0 }

        #expect(summary == .init(writtenFrameCount: 1, scannedFrameCount: 2))
        let objects = try #require(JSONSerialization.jsonObject(with: output) as? [[String: Any]])
        #expect(objects.compactMap { $0["frame"] as? Int } == [2])
    }

    @Test
    func frameExpressionCountsUnknownFramesAndStagesMatchingFrames() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dissection-expression-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let source = directory.appendingPathComponent("source.pcap")
        let destination = directory.appendingPathComponent("dissections.json")
        let tcp = PacketBuilder.ethernetIPv4(
            proto: 6, src: "192.0.2.10", dst: "198.51.100.7",
            payload: PacketBuilder.tcp(srcPort: 40_000, dstPort: 443, flags: 0x18, payload: [1, 2, 3, 4])
        )
        let cutTCP = Array(tcp.prefix(14 + 20 + 4))
        let nonmatchingTCP = PacketBuilder.ethernetIPv4(
            proto: 6, src: "192.0.2.10", dst: "198.51.100.7",
            payload: PacketBuilder.tcp(srcPort: 40_000, dstPort: 80, flags: 0x18, payload: [1, 2, 3, 4])
        )
        try PcapWriter.write(linkType: LinkType.ethernet, frames: [
            CapturedFrame(
                bytes: cutTCP, timestamp: Date(timeIntervalSince1970: 1_800_000_000),
                originalLength: tcp.count
            ),
            CapturedFrame(
                bytes: nonmatchingTCP, timestamp: Date(timeIntervalSince1970: 1_800_000_001),
                originalLength: nonmatchingTCP.count
            ),
        ], to: source)
        let expression = try Self.expression("tcp.port == 443")
        var streamed = Data()
        let result = try DissectionExporter.export(
            from: source, frameExpression: expression, format: .json
        ) { streamed += $0 }
        #expect(result == .init(writtenFrameCount: 0, scannedFrameCount: 2, unknownExpressionFrameCount: 1))
        let empty = try #require(JSONSerialization.jsonObject(with: streamed) as? [[String: Any]])
        #expect(empty.isEmpty)

        try Data("previous destination".utf8).write(to: destination)
        #expect(throws: DissectionExporter.ExportError.truncatedTail(completeFrameCount: 2)) {
            let append = try FileHandle(forWritingTo: source)
            try append.seekToEnd()
            try append.write(contentsOf: Data([0x00]))
            try append.close()
            _ = try DissectionExportFileWriter.export(
                from: source, expectedIdentity: nil, sessions: nil, frameExpression: expression,
                format: .json, to: destination
            )
        }
        #expect(try String(contentsOf: destination, encoding: .utf8) == "previous destination")
    }

    @Test
    func frameExpressionScansPastTheRetainedFrameListLimit() throws {
        let url = try Self.capture(ports: Array(repeating: 53, count: 200_000) + [65_535])
        defer { try? FileManager.default.removeItem(at: url) }
        let expression = try Self.expression("udp.dstport == 65535")
        var output = Data()
        let summary = try DissectionExporter.export(
            from: url, frameExpression: expression, format: .json
        ) { output += $0 }

        #expect(summary == .init(writtenFrameCount: 1, scannedFrameCount: 200_001))
        let objects = try #require(JSONSerialization.jsonObject(with: output) as? [[String: Any]])
        #expect(objects.compactMap { $0["frame"] as? Int } == [200_001])
    }

    @Test
    func markedOrdinalsKeepSourceFrameNumbers() throws {
        let url = try Self.capture(ports: [53, 443, 80, 123])
        defer { try? FileManager.default.removeItem(at: url) }
        var data = Data()
        let summary = try DissectionExporter.export(
            from: url, frameOrdinals: [2], format: .text
        ) { data += $0 }
        #expect(summary == DissectionExporter.Summary(writtenFrameCount: 1, scannedFrameCount: 4))
        let text = try #require(String(data: data, encoding: .utf8))
        #expect(text.hasPrefix("Frame 2:"))
        #expect(!text.contains("Frame 1:"))
        #expect(!text.contains("Frame 3:"))
        #expect(!text.contains("Frame 4:"))

        data = Data()
        let ranged = try DissectionExporter.export(
            from: url, frameRange: 1 ... 3, format: .text
        ) { data += $0 }
        #expect(ranged == DissectionExporter.Summary(writtenFrameCount: 3, scannedFrameCount: 4))
        let rangeText = try #require(String(data: data, encoding: .utf8))
        #expect(rangeText.contains("Frame 1:"))
        #expect(rangeText.contains("Frame 2:"))
        #expect(rangeText.contains("Frame 3:"))
        #expect(!rangeText.contains("Frame 4:"))
    }

    @Test
    func summaryPrintLinesKeepOriginalOrdinalsAndDecodedInfo() throws {
        let url = try Self.capture(ports: [53, 443, 80])
        defer { try? FileManager.default.removeItem(at: url) }
        var data = Data()
        let summary = try DissectionExporter.export(
            from: url, frameOrdinals: [2], format: .text, textLayout: .summary
        ) { data += $0 }
        #expect(summary == .init(writtenFrameCount: 1, scannedFrameCount: 3))
        let output = try #require(String(data: data, encoding: .utf8))
        #expect(output.hasPrefix("Frame 2  "))
        #expect(output.contains("192.0.2.10 → 198.51.100.7"))
        #expect(output.contains("UDP"))
        #expect(!output.contains("Frame 1  "))
        #expect(!output.contains("Frame 3  "))
        #expect(!output.contains("Destination Port:"))

        data = Data()
        let ranged = try DissectionExporter.export(
            from: url, frameRange: 2 ... 3, format: .text, textLayout: .summary
        ) { data += $0 }
        #expect(ranged == .init(writtenFrameCount: 2, scannedFrameCount: 3))
        let rangedOutput = try #require(String(data: data, encoding: .utf8))
        #expect(!rangedOutput.contains("Frame 1  "))
        #expect(rangedOutput.contains("Frame 2  "))
        #expect(rangedOutput.contains("Frame 3  "))
    }

    @Test
    func summaryCSVStreamsSelectedFramesWithStableColumns() throws {
        let url = try Self.capture(ports: [53, 443, 80])
        defer { try? FileManager.default.removeItem(at: url) }
        var data = Data()
        let summary = try DissectionExporter.export(
            from: url, frameOrdinals: [2], format: .csv
        ) { data += $0 }
        #expect(summary == .init(writtenFrameCount: 1, scannedFrameCount: 3))
        let csv = try #require(String(data: data, encoding: .utf8))
        let rows = csv.components(separatedBy: "\r\n")
        #expect(rows.count == 3)
        #expect(rows[0] == "\"No.\",\"Time\",\"Source\",\"Destination\",\"Protocol\",\"Length\",\"Info\"")
        #expect(rows[1].hasPrefix("\"2\",\""))
        #expect(rows[2].isEmpty)
    }

    @Test
    func summaryCSVGuardsCaptureDerivedSpreadsheetFormulas() {
        let row = DissectionExporter.csvRow(["=SUM(1,1)", "  @cmd", "plain,\"quoted\"\nvalue"])
        #expect(row == "\"'=SUM(1,1)\",\"'  @cmd\",\"plain,\"\"quoted\"\"\nvalue\"\r\n")
    }

    @Test
    func bytePrintKeepsOriginalOrdinalsAndCapturedBytes() throws {
        let url = try Self.capture(ports: [53, 443, 80])
        defer { try? FileManager.default.removeItem(at: url) }
        var data = Data()
        let result = try DissectionExporter.export(
            from: url, frameOrdinals: [2], format: .text, textLayout: .bytes
        ) { data += $0 }
        #expect(result == .init(writtenFrameCount: 1, scannedFrameCount: 3))
        let output = try #require(String(data: data, encoding: .utf8))
        #expect(output.hasPrefix("Frame 2: 46 captured bytes\n0000  "))
        #expect(output.contains("08 00"))
        #expect(!output.contains("Frame 1:"))
        #expect(!output.contains("Frame 3:"))
    }

    @Test
    func plainTextExportComposesSummaryDetailsAndCapturedBytes() throws {
        let source = try Self.capture(ports: [53, 443])
        defer { try? FileManager.default.removeItem(at: source) }
        var data = Data()
        let summary = try DissectionExporter.export(
            from: source, frameOrdinals: [2], format: .text,
            textLayout: [.summary, .details, .bytes]
        ) { data += $0 }
        #expect(summary == .init(writtenFrameCount: 1, scannedFrameCount: 2))
        let output = try #require(String(data: data, encoding: .utf8))
        let summaryStart = try #require(output.range(of: "Frame 2  "))
        let detailsStart = try #require(output.range(of: "Frame 2: 46 bytes on wire"))
        let bytesStart = try #require(output.range(of: "Frame 2: 46 captured bytes\n0000  "))
        #expect(summaryStart.lowerBound < detailsStart.lowerBound)
        #expect(detailsStart.lowerBound < bytesStart.lowerBound)
        #expect(!output.contains("Frame 1"))
    }

    @Test
    func plainTextExportRejectsEmptySectionSelection() throws {
        let source = try Self.capture(ports: [53])
        defer { try? FileManager.default.removeItem(at: source) }
        var output = Data()
        #expect(throws: DissectionExporter.ExportError.emptyTextLayout) {
            _ = try DissectionExporter.export(
                from: source, format: .text, textLayout: []
            ) { output += $0 }
        }
        #expect(output.isEmpty)
    }

    @Test
    func compactFrameRangeSelectionSupportsOpenEndedAndOverlaps() throws {
        let selection = try #require(FrameOrdinalSelection.parse("5, 10-15, 14-20, 30-"))
        #expect(selection.intervals.count == 3)
        #expect(selection.contains(5))
        #expect(selection.contains(17))
        #expect(!selection.contains(21))
        #expect(selection.contains(UInt64.max))
        #expect(FrameOrdinalSelection.parse("0") == nil)
        #expect(FrameOrdinalSelection.parse("9-4") == nil)
        #expect(FrameOrdinalSelection.parse("1,,2") == nil)
        #expect(FrameOrdinalSelection.parse("18446744073709551616") == nil)
    }

    @Test
    func frameRangeIntervalsMatchEnumeratedMembership() throws {
        var state: UInt64 = 0x8F9DB91D
        func next() -> UInt64 {
            state = state &* 2_862_933_555_777_941_757 &+ 3_037_000_493
            return state
        }
        for _ in 0 ..< 20 {
            var terms: [String] = []
            var expected = Set<UInt64>()
            for _ in 0 ..< 20 {
                let first = next() % 400 + 1
                let last = first + next() % 40
                terms.append("\(first)-\(last)")
                for ordinal in first ... last {
                    expected.insert(ordinal)
                }
            }
            let selection = try #require(FrameOrdinalSelection.parse(terms.joined(separator: ",")))
            for ordinal in UInt64(1) ... 500 {
                #expect(selection.contains(ordinal) == expected.contains(ordinal))
            }
        }
    }

    @Test
    func bytePrintRespectsManualCaptureFrameRange() throws {
        let url = try Self.capture(ports: [53, 443, 80, 123])
        defer { try? FileManager.default.removeItem(at: url) }
        let selection = try #require(FrameOrdinalSelection.parse("2,4-"))
        var data = Data()
        let result = try DissectionExporter.export(
            from: url, frameSelection: selection, format: .text, textLayout: .bytes
        ) { data += $0 }
        #expect(result == .init(writtenFrameCount: 2, scannedFrameCount: 4))
        let output = try #require(String(data: data, encoding: .utf8))
        #expect(output.contains("Frame 2:"))
        #expect(output.contains("Frame 4:"))
        #expect(!output.contains("Frame 1:"))
        #expect(!output.contains("Frame 3:"))
    }

    @Test
    func selectedFrameDissectionKeepsItsOriginalCaptureOrdinal() throws {
        let source = try Self.capture(ports: [53, 443, 80])
        defer { try? FileManager.default.removeItem(at: source) }
        let selection = FrameOrdinalSelection(intervals: [.init(first: 2, last: 2)])
        var output = Data()
        let summary = try DissectionExporter.export(
            from: source, frameSelection: selection, format: .json
        ) { output += $0 }
        #expect(summary == .init(writtenFrameCount: 1, scannedFrameCount: 3))
        let objects = try #require(JSONSerialization.jsonObject(with: output) as? [[String: Any]])
        #expect(objects.map { $0["frame"] as? Int } == [2])
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

    @Test
    func commandLineSelectsDissectionFrameNumbers() throws {
        let url = try Self.capture(ports: [53, 443, 80, 123])
        defer { try? FileManager.default.removeItem(at: url) }
        var data = Data()
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "frames", url.path, "--details", "--frames", "2,4", "--format", "json"],
            data: { data += $0 }
        ) == 0)
        let rows = try #require(try JSONSerialization.jsonObject(with: data) as? [[String: Any]])
        #expect(rows.compactMap { $0["frame"] as? Int } == [2, 4])

        var message = ""
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "frames", url.path, "--frames", "2"], errors: { message += $0 }
        ) == 2)
        #expect(message.contains("requires --details"))
    }

    @Test
    func truncatedTailIsNotPublishedAsCompleteDissections() throws {
        let url = try Self.capture(ports: [53, 443])
        defer { try? FileManager.default.removeItem(at: url) }
        let append = try FileHandle(forWritingTo: url)
        try append.seekToEnd()
        try append.write(contentsOf: Data([0x00]))
        try append.close()

        var data = Data()
        #expect(throws: DissectionExporter.ExportError.truncatedTail(completeFrameCount: 2)) {
            _ = try DissectionExporter.export(from: url, format: .text) { data += $0 }
        }
        #expect(data.isEmpty)

        var message = ""
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "frames", url.path, "--details"], output: { _ in },
            errors: { message += $0 }, data: { data += $0 }
        ) == 1)
        #expect(data.isEmpty)
        #expect(message.contains("incomplete record after 2 complete frames"))
    }

    @Test
    func fileExportPreservesExistingDestinationUntilComplete() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dissection-publish-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let destination = directory.appendingPathComponent("dissections.txt")
        try Data("Existing export".utf8).write(to: destination)

        let truncated = try Self.capture(ports: [53, 443])
        defer { try? FileManager.default.removeItem(at: truncated) }
        let append = try FileHandle(forWritingTo: truncated)
        try append.seekToEnd()
        try append.write(contentsOf: Data([0x00]))
        try append.close()
        #expect(throws: DissectionExporter.ExportError.truncatedTail(completeFrameCount: 2)) {
            _ = try DissectionExportFileWriter.export(
                from: truncated, expectedIdentity: nil, sessions: nil, format: .text, to: destination
            )
        }
        #expect(try Data(contentsOf: destination) == Data("Existing export".utf8))
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == ["dissections.txt"])

        let complete = try Self.capture(ports: [80])
        defer { try? FileManager.default.removeItem(at: complete) }
        let summary = try DissectionExportFileWriter.export(
            from: complete, expectedIdentity: nil, sessions: nil, format: .text, to: destination
        )
        #expect(summary == .init(writtenFrameCount: 1, scannedFrameCount: 1))
        #expect(try String(contentsOf: destination, encoding: .utf8).hasPrefix("Frame 1:"))
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == ["dissections.txt"])
    }

    @Test
    func fileExportRefusesTheSourceAndHardLinksWithoutChangingCaptureBytes() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dissection-source-guard-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let source = directory.appendingPathComponent("capture.pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: ReplayCorpus.conversationCapturedFrames(), to: source)
        let originalBytes = try Data(contentsOf: source)
        let alias = directory.appendingPathComponent("capture-hard-link.pcap")
        try FileManager.default.linkItem(at: source, to: alias)

        for output in [source, alias] {
            #expect(throws: DissectionExportFileWriter.ExportError.destinationIsSource) {
                _ = try DissectionExportFileWriter.export(
                    from: source, expectedIdentity: nil, sessions: nil, format: .text, to: output
                )
            }
            #expect(try Data(contentsOf: source) == originalBytes)
            #expect(try Data(contentsOf: alias) == originalBytes)
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path)
                .sorted() == ["capture-hard-link.pcap", "capture.pcap"])
        }
    }

    @Test
    func fileExportUsesCaptureWideFrameRangeAndOriginalOrdinals() throws {
        let source = try Self.capture(ports: [53, 443, 80])
        defer { try? FileManager.default.removeItem(at: source) }
        let output = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-scoped-dissections-\(UUID().uuidString).csv")
        defer { try? FileManager.default.removeItem(at: output) }
        let selection = try #require(FrameOrdinalSelection.parse("2-"))

        let summary = try DissectionExportFileWriter.export(
            from: source, expectedIdentity: nil, sessions: nil,
            frameSelection: selection, excludedFrameOrdinals: [3], format: .csv, to: output
        )
        #expect(summary == .init(writtenFrameCount: 1, scannedFrameCount: 3, excludedIgnoredFrameCount: 1))
        let lines = try String(contentsOf: output, encoding: .utf8).components(separatedBy: "\r\n")
        #expect(lines.count == 3)
        #expect(lines[0].hasPrefix("\"No.\",\"Time\""))
        #expect(lines[1].hasPrefix("\"2\","))
        #expect(lines[2].isEmpty)
    }

    @Test
    func fileExportUsesMarkedFrameOrdinals() throws {
        let source = try Self.capture(ports: [53, 443, 80])
        defer { try? FileManager.default.removeItem(at: source) }
        let output = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-marked-dissections-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: output) }

        let summary = try DissectionExportFileWriter.export(
            from: source, expectedIdentity: nil, sessions: nil,
            frameOrdinals: [1, 3], format: .json, to: output
        )
        #expect(summary == .init(writtenFrameCount: 2, scannedFrameCount: 3))
        let data = try Data(contentsOf: output)
        let objects = try #require(JSONSerialization.jsonObject(with: data) as? [[String: Any]])
        #expect(objects.map { $0["frame"] as? Int } == [1, 3])
    }

    @Test
    func firstToLastMarkedRangeIncludesUnmarkedFrameBetweenMarks() throws {
        let source = try Self.capture(ports: [53, 443, 80])
        defer { try? FileManager.default.removeItem(at: source) }
        let selection = FrameOrdinalSelection(intervals: [.init(first: 1, last: 3)])
        var output = Data()
        let summary = try DissectionExporter.export(
            from: source, frameSelection: selection, format: .json
        ) { output += $0 }
        #expect(summary == .init(writtenFrameCount: 3, scannedFrameCount: 3))
        let objects = try #require(JSONSerialization.jsonObject(with: output) as? [[String: Any]])
        #expect(objects.map { $0["frame"] as? Int } == [1, 2, 3])
    }

    @Test
    func scopedDissectionsStillRejectTruncatedTail() throws {
        let url = try Self.capture(ports: [53, 443, 80])
        defer { try? FileManager.default.removeItem(at: url) }
        let append = try FileHandle(forWritingTo: url)
        try append.seekToEnd()
        try append.write(contentsOf: Data([0x00]))
        try append.close()

        var output = Data()
        #expect(throws: DissectionExporter.ExportError.truncatedTail(completeFrameCount: 3)) {
            _ = try DissectionExporter.export(
                from: url, frameOrdinals: [1], frameRange: 1 ... 2, format: .text
            ) { output += $0 }
        }
        #expect(output.isEmpty)

        var message = ""
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "frames", url.path, "--details", "--frames", "1"],
            errors: { message += $0 }, data: { output += $0 }
        ) == 1)
        #expect(output.isEmpty)
        #expect(message.contains("incomplete record after 3 complete frames"))
    }

    @Test
    func commandLineStagesLargeDissectionsBeforeStdout() throws {
        let url = try Self.capture(ports: Array(repeating: 53, count: 1_600))
        defer { try? FileManager.default.removeItem(at: url) }
        var complete = Data()
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "frames", url.path, "--details"], data: { complete += $0 }
        ) == 0)
        #expect(complete.count > 256 * 1_024)

        let append = try FileHandle(forWritingTo: url)
        try append.seekToEnd()
        try append.write(contentsOf: Data([0x00]))
        try append.close()
        var rejected = Data()
        var message = ""
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "frames", url.path, "--details"], errors: { message += $0 },
            data: { rejected += $0 }
        ) == 1)
        #expect(rejected.isEmpty)
        #expect(message.contains("incomplete record after 1600 complete frames"))
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

    private static func expression(_ source: String) throws -> FrameExpression {
        var parser = FrameExpressionParser()
        return try parser.parse(source)
    }
}
