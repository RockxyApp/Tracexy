import Foundation
import Testing
@testable import Tracexy

// MARK: - CaptureFrameExporterTests

/// Export Frames…: scopes, formats, metadata preservation, gzip, atomic
/// publication, refusals, and parity with `capinfos` where Wireshark exists.
struct CaptureFrameExporterTests {
    // MARK: Internal

    @Test
    func wholeCaptureToPcapngPreservesSectionInterfaceAndFrameMetadata() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("showcase.pcapng")
            try Data(CaptureContainerFixtures.showcasePcapng()).write(to: source)
            let output = directory.appendingPathComponent("out.pcapng")
            let summary = try CaptureFrameExporter.export(
                from: source, scope: .wholeCapture, options: .init(format: .pcapng, preservesMetadata: true), to: output
            )
            let sourceProperties = try SavedCaptureStreamLoader(contentsOf: source).load().properties
            let loaded = try SavedCaptureStreamLoader(contentsOf: output).load()
            #expect(summary.writtenFrameCount == sourceProperties.totalFrames)
            #expect(summary.unrepresentableFrameCount == 0)
            #expect(summary.omittedFrameOptionCount == 0)
            #expect(loaded.properties.totalFrames == sourceProperties.totalFrames)
            #expect(loaded.properties.commentedFrameCount == sourceProperties.commentedFrameCount)
            let section = try #require(loaded.properties.sections.first)
            #expect(section.hardware?.text == "Mac16,10")
            #expect(section.application?.text == "Tracexy fixture builder")
            #expect(section.comments.values.map(\.text) == ["Section comment one"])
            #expect(section.interfaces.count == 2)
            #expect(section.interfaces[0].name?.text == "en0")
            #expect(section.interfaces[0].interfaceDescription?.text == "Wi-Fi")
            #expect(section.interfaces[0].filter?.text == "tcp or udp")
            #expect(section.interfaces[1].name?.text == "utun4")
            // Sessions are identical after the round trip.
            let sourceSessions = try SavedCaptureStreamLoader(contentsOf: source).load().sessions.map(\.id)
            #expect(loaded.sessions.map(\.id) == sourceSessions)
            #expect(loaded.properties.firstTimestamp == sourceProperties.firstTimestamp)
        }
    }

    @Test
    func sessionScopeKeepsOnlyThoseFrames() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("conv.pcap")
            try Data(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())).write(to: source)
            let sessions = try SavedCaptureStreamLoader(contentsOf: source).load().sessions
            let dns = try #require(sessions.first { $0.protocolStack.contains(.dns) })
            let output = directory.appendingPathComponent("dns.pcap")
            let summary = try CaptureFrameExporter.export(
                from: source, scope: .sessions([dns.id]), options: .init(format: .pcap), to: output
            )
            #expect(summary.writtenFrameCount == 2)
            let loaded = try SavedCaptureStreamLoader(contentsOf: output).load()
            #expect(loaded.sessions.map(\.id) == [dns.id])
            #expect(loaded.format == .pcap)
        }
    }

    @Test
    func timeRangeScopeUsesCaptureClock() throws {
        try withDirectory { directory in
            let frames = ReplayCorpus.conversation()
            let source = directory.appendingPathComponent("conv.pcap")
            try Data(ReplayCorpus.classicPcapBytes(frames)).write(to: source)
            let offsets = frames.map(\.offsetSeconds).sorted()
            let start = ReplayCorpus.epoch.addingTimeInterval(TimeInterval(offsets[1]))
            let end = ReplayCorpus.epoch.addingTimeInterval(TimeInterval(offsets[3]))
            let output = directory.appendingPathComponent("range.pcapng")
            let summary = try CaptureFrameExporter.export(
                from: source, scope: .timeRange(start: start, end: end), options: .init(), to: output
            )
            let expected = frames.filter { $0.timestamp >= start && $0.timestamp <= end }.count
            #expect(summary.writtenFrameCount == expected)
        }
    }

    @Test
    func classicPcapRefusesMixedLinkTypesAndUntimedFramesWithoutLeavingAFile() throws {
        try withDirectory { directory in
            let mixed = directory.appendingPathComponent("mixed.pcapng")
            try Data(ReplayCorpus.pcapngMixedDLTBytes()).write(to: mixed)
            let output = directory.appendingPathComponent("mixed.pcap")
            #expect(throws: FrameExportError.mixedLinkTypesRequirePcapng) {
                try CaptureFrameExporter.export(
                    from: mixed,
                    scope: .wholeCapture,
                    options: .init(format: .pcap),
                    to: output
                )
            }
            #expect(!FileManager.default.fileExists(atPath: output.path))
            let leftovers = try FileManager.default.contentsOfDirectory(atPath: directory.path)
                .filter { $0.hasSuffix(".partial") }
            #expect(leftovers.isEmpty)

            let untimed = directory.appendingPathComponent("untimed.pcapng")
            try Data(ReplayCorpus.pcapngSimplePacketBytes()).write(to: untimed)
            #expect(throws: FrameExportError.untimedFramesRequirePcapng) {
                try CaptureFrameExporter.export(
                    from: untimed,
                    scope: .wholeCapture,
                    options: .init(format: .pcap),
                    to: output
                )
            }
            // PCAPNG keeps the untimed frame untimed.
            let ngOutput = directory.appendingPathComponent("untimed-out.pcapng")
            let summary = try CaptureFrameExporter.export(
                from: untimed,
                scope: .wholeCapture,
                options: .init(),
                to: ngOutput
            )
            #expect(summary.writtenFrameCount == 1)
            #expect(try SavedCaptureStreamLoader(contentsOf: ngOutput).load().properties.untimedFrameCount == 1)
        }
    }

    @Test
    func gzipOutputRoundTripsThroughTheImporter() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("showcase.pcapng")
            try Data(CaptureContainerFixtures.showcasePcapng()).write(to: source)
            let output = directory.appendingPathComponent("out.pcapng.gz")
            let summary = try CaptureFrameExporter.export(
                from: source, scope: .wholeCapture, options: .init(compressesWithGzip: true), to: output
            )
            #expect(summary.writtenByteCount > 0)
            let head = try FileHandle(forReadingFrom: output).read(upToCount: 2)
            #expect(head == Data([0x1F, 0x8B]))
            let library = directory.appendingPathComponent("Library", isDirectory: true)
            try FileManager.default.createDirectory(at: library, withIntermediateDirectories: true)
            let imported = try CaptureImporter.importCapture(from: output, intoDirectory: library)
            let loaded = try SavedCaptureStreamLoader(contentsOf: imported).load()
            #expect(loaded.properties.totalFrames == summary.writtenFrameCount)
            #expect(loaded.properties.sections.first?.interfaces.first?.name?.text == "en0")
        }
    }

    @Test
    func nothingMatchedWritesNoFile() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("conv.pcap")
            try Data(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())).write(to: source)
            let output = directory.appendingPathComponent("none.pcapng")
            #expect(throws: FrameExportError.nothingMatched) {
                try CaptureFrameExporter.export(from: source, scope: .sessions([UUID()]), options: .init(), to: output)
            }
            #expect(!FileManager.default.fileExists(atPath: output.path))
        }
    }

    @Test
    func identityMismatchIsRefused() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("conv.pcap")
            try Data(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())).write(to: source)
            let stale = PcapFileIdentity(size: 3, modifiedAt: nil, device: 0, inode: 0)
            #expect(throws: FrameExportError.identityMismatch) {
                try CaptureFrameExporter.export(
                    from: source, expectedIdentity: stale, scope: .wholeCapture, options: .init(),
                    to: directory.appendingPathComponent("x.pcapng")
                )
            }
        }
    }

    @Test
    func cancellationLeavesNoPartialFile() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("conv.pcap")
            try Data(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())).write(to: source)
            let output = directory.appendingPathComponent("cancelled.pcapng")
            #expect(throws: CancellationError.self) {
                try CaptureFrameExporter.export(
                    from: source, scope: .wholeCapture, options: .init(), to: output, isCancelled: { true }
                )
            }
            #expect(!FileManager.default.fileExists(atPath: output.path))
            let leftovers = try FileManager.default.contentsOfDirectory(atPath: directory.path)
                .filter { $0.hasSuffix(".partial") }
            #expect(leftovers.isEmpty)
        }
    }

    @Test
    func bigEndianSourceDropsPerFrameOptionsButKeepsTypedMetadata() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("be.pcapng")
            try Data(CaptureContainerFixtures.showcasePcapng(little: false)).write(to: source)
            let output = directory.appendingPathComponent("be-out.pcapng")
            let summary = try CaptureFrameExporter.export(
                from: source,
                scope: .wholeCapture,
                options: .init(),
                to: output
            )
            #expect(summary.omittedFrameOptionCount == 1)
            let loaded = try SavedCaptureStreamLoader(contentsOf: output).load()
            #expect(loaded.properties.commentedFrameCount == 0)
            #expect(loaded.properties.sections.first?.interfaces.first?.name?.text == "en0")
        }
    }

    @Test(.enabled(if: WiresharkOracle.isAvailable, "Wireshark is not installed on this machine"))
    func capinfosReadsTheExportedMetadata() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("showcase.pcapng")
            try Data(CaptureContainerFixtures.showcasePcapng()).write(to: source)
            let output = directory.appendingPathComponent("out.pcapng")
            let summary = try CaptureFrameExporter.export(
                from: source,
                scope: .wholeCapture,
                options: .init(),
                to: output
            )
            let report = try WiresharkOracle.capinfos(output)
            #expect(report.int("Number of packets") == summary.writtenFrameCount)
            #expect(report["Capture hardware"] == "Mac16,10")
            #expect(report["Capture comment"] == "Section comment one")
            #expect(report["if0.Name"] == "en0")
            #expect(report["if0.Filter string"] == "tcp or udp")
            #expect(report["if1.Name"] == "utun4")
            #expect(report["Packet 2 Comment"] == "Frame two comment")

            let classic = directory.appendingPathComponent("conv.pcap")
            try Data(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())).write(to: classic)
            let pcapOut = directory.appendingPathComponent("conv-out.pcap")
            let pcapSummary = try CaptureFrameExporter.export(
                from: classic,
                scope: .wholeCapture,
                options: .init(format: .pcap),
                to: pcapOut
            )
            let pcapReport = try WiresharkOracle.capinfos(pcapOut)
            #expect(pcapReport.int("Number of packets") == pcapSummary.writtenFrameCount)
            #expect(pcapReport["File type"]?.contains("pcap") == true)
        }
    }

    // MARK: Private

    private func withDirectory(_ body: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-export-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory)
    }
}
