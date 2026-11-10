import CryptoKit
import Foundation
import Testing
@testable import Tracexy

// MARK: - CaptureFrameExporterTests

/// Export Frames…: scopes, formats, metadata preservation, gzip, atomic
/// publication, refusals, and parity with `capinfos` where Wireshark exists.
struct CaptureFrameExporterTests {
    // MARK: Internal

    @Test
    func packetIDSurvivesPcapngExportAndClassicPcapIsRefused() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("identified.pcapng")
            let frame = CapturedFrame(
                bytes: [0xAA], timestamp: Date(timeIntervalSince1970: 42),
                originalLength: 1, packetID: UInt64.max
            )
            try PcapngWriter.write(defaultLinkType: 1, frames: [frame], to: source)
            for preservesMetadata in [true, false] {
                let output = directory.appendingPathComponent("out-\(preservesMetadata).pcapng")
                _ = try CaptureFrameExporter.export(
                    from: source, scope: .wholeCapture,
                    options: .init(format: .pcapng, preservesMetadata: preservesMetadata), to: output
                )
                #expect(try PcapngReader.read(contentsOf: output).frames.map(\.packetID) == [UInt64.max])
            }
            let classic = directory.appendingPathComponent("out.pcap")
            #expect(throws: FrameExportError.packetIDRequiresPcapng) {
                _ = try CaptureFrameExporter.export(
                    from: source, scope: .wholeCapture,
                    options: .init(format: .pcap), to: classic
                )
            }
            #expect(!FileManager.default.fileExists(atPath: classic.path))
        }
    }

    @Test
    func packetDirectionSurvivesPcapngExportAndClassicPcapIsRefused() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("directed.pcapng")
            let frame = CapturedFrame(
                bytes: [0xAA], timestamp: Date(timeIntervalSince1970: 42),
                originalLength: 1, direction: .inbound
            )
            try PcapngWriter.write(defaultLinkType: 1, frames: [frame], to: source)
            for preservesMetadata in [true, false] {
                let output = directory.appendingPathComponent("out-\(preservesMetadata).pcapng")
                _ = try CaptureFrameExporter.export(
                    from: source, scope: .wholeCapture,
                    options: .init(format: .pcapng, preservesMetadata: preservesMetadata), to: output
                )
                #expect(try PcapngReader.read(contentsOf: output).frames.map(\.direction) == [.inbound])
            }
            let classic = directory.appendingPathComponent("out.pcap")
            #expect(throws: FrameExportError.directionRequiresPcapng) {
                _ = try CaptureFrameExporter.export(
                    from: source, scope: .wholeCapture,
                    options: .init(format: .pcap), to: classic
                )
            }
            #expect(!FileManager.default.fileExists(atPath: classic.path))
        }
    }

    @Test("Frame export scope keeps only known inbound direction and reports unknown")
    func frameExportFiltersCaptureDirection() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("direction-filter.pcapng")
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
            var parser = FrameExpressionParser()
            let expression = try parser.parse("frame.capture_direction == inbound")
            let output = directory.appendingPathComponent("direction-filtered.pcapng")
            let summary = try CaptureFrameExporter.export(
                from: source, scope: .frameExpression(expression),
                options: .init(excludedFrameOrdinals: [3]), to: output
            )

            #expect(summary.scannedFrameCount == 3 && summary.writtenFrameCount == 1)
            #expect((summary.unknownExpressionFrameCount, summary.excludedIgnoredFrameCount) == (1, 0))
            #expect(try PcapngReader.read(contentsOf: output).frames.map(\.direction) == [.inbound])
        }
    }

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

    @Test("Applied Frame Expression export streams matching packets from the complete capture")
    func frameExpressionScopeStreamsMatches() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("conversation.pcap")
            let frames = ReplayCorpus.conversationCapturedFrames()
            try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: source)
            var parser = FrameExpressionParser()
            let expression = try parser.parse("udp.port == 53")
            let output = directory.appendingPathComponent("dns-only.pcapng")

            let summary = try CaptureFrameExporter.export(
                from: source,
                scope: .frameExpression(expression),
                options: .init(),
                to: output
            )

            #expect(summary.scannedFrameCount == frames.count)
            #expect(summary.writtenFrameCount == 4)
            #expect(summary.unknownExpressionFrameCount == 0)
            #expect(try PcapngReader.read(contentsOf: output).frames.count == 4)
        }
    }

    @Test("Ignored ordinals are opt-in and intersect with the chosen scope")
    func ignoredOrdinalsAreExcludedOnlyWhenRequested() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("conversation.pcap")
            let frames = ReplayCorpus.conversationCapturedFrames()
            try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: source)
            let output = directory.appendingPathComponent("without-ignored.pcapng")
            let ignored: Set<UInt64> = [1, 3]

            let summary = try CaptureFrameExporter.export(
                from: source,
                scope: .frames([1, 2, 3]),
                options: .init(excludedFrameOrdinals: ignored),
                to: output
            )

            #expect(summary.excludedIgnoredFrameCount == 2)
            #expect(summary.writtenFrameCount == 1)
            #expect(try PcapngReader.read(contentsOf: output).frames.map(\.bytes) == [frames[1].bytes])

            let defaultOutput = directory.appendingPathComponent("default.pcapng")
            let defaultSummary = try CaptureFrameExporter.export(
                from: source, scope: .frames([1, 2, 3]), options: .init(), to: defaultOutput
            )
            #expect(defaultSummary.excludedIgnoredFrameCount == 0)
            #expect(defaultSummary.writtenFrameCount == 3)
        }
    }

    @Test("Capture-local frame ordinals translate to merged file-set ordinals")
    func frameOrdinalOffsetMapsScopesAndAnnotations() throws {
        let translatedScope = try FrameExportScope.frames([1, 3]).addingFrameOrdinalOffset(2)
        #expect(translatedScope == .frames([3, 5]))

        var options = FrameExportOptions(
            frameComments: [3: "local comment"],
            excludedFrameOrdinals: [1]
        )
        try options.addFrameOrdinalOffset(2)
        #expect(options.excludedFrameOrdinals == [3])
        #expect(options.frameComments == [5: "local comment"])

        #expect(throws: FrameExportError.frameOrdinalOverflow) {
            _ = try FrameExportScope.frames([UInt64.max]).addingFrameOrdinalOffset(1)
        }
    }

    @Test("Ignored frames still advance streaming export progress")
    func ignoredFramesAdvanceProgress() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("many-frames.pcap")
            let frames = (0 ..< 257).map { index in
                CapturedFrame(
                    bytes: [UInt8(index % 251)],
                    timestamp: ReplayCorpus.epoch.addingTimeInterval(Double(index)),
                    originalLength: 1
                )
            }
            try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: source)
            let ignored = Set((1 ... 256).map(UInt64.init))
            var progressUpdates = 0
            let output = directory.appendingPathComponent("last-frame.pcapng")

            let summary = try CaptureFrameExporter.export(
                from: source,
                scope: .wholeCapture,
                options: .init(excludedFrameOrdinals: ignored),
                to: output,
                onProgress: { _ in progressUpdates += 1 }
            )

            #expect(progressUpdates > 0)
            #expect(summary.excludedIgnoredFrameCount == 256)
            #expect(summary.writtenFrameCount == 1)
        }
    }

    @Test("An excluded unknown expression result remains an unknown, not an excluded match")
    func ignoredUnknownExpressionResultIsNotCountedAsExcluded() throws {
        try withDirectory { directory in
            let syn = PacketBuilder.tcpSynFrame(
                src: "192.0.2.10", dst: "198.51.100.7", srcPort: 50_000, dstPort: 443
            )
            let truncated = Array(syn.prefix(42))
            let source = directory.appendingPathComponent("truncated.pcap")
            try PcapWriter.write(linkType: LinkType.ethernet, frames: [
                CapturedFrame(bytes: syn, timestamp: ReplayCorpus.epoch, originalLength: syn.count),
                CapturedFrame(
                    bytes: truncated,
                    timestamp: ReplayCorpus.epoch.addingTimeInterval(1),
                    originalLength: syn.count
                ),
            ], to: source)
            var parser = FrameExpressionParser()
            let expression = try parser.parse("not tcp.rst")
            let output = directory.appendingPathComponent("known.pcapng")

            let summary = try CaptureFrameExporter.export(
                from: source,
                scope: .frameExpression(expression),
                options: .init(excludedFrameOrdinals: [2]),
                to: output
            )

            #expect(summary.writtenFrameCount == 1)
            #expect(summary.unknownExpressionFrameCount == 1)
            #expect(summary.excludedIgnoredFrameCount == 0)
        }
    }

    @Test("Excluding every scoped frame leaves an existing destination untouched")
    func excludingEveryScopedFramePreservesDestination() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("conversation.pcap")
            let frames = ReplayCorpus.conversationCapturedFrames()
            try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: source)
            let output = directory.appendingPathComponent("existing.pcapng")
            let original = Data("existing destination".utf8)
            try original.write(to: output)

            #expect(throws: FrameExportError.ignoredFramesExcludedAll(count: 2)) {
                try CaptureFrameExporter.export(
                    from: source,
                    scope: .frames([1, 2]),
                    options: .init(excludedFrameOrdinals: [1, 2]),
                    to: output
                )
            }
            #expect(try Data(contentsOf: output) == original)
        }
    }

    @Test("Unknown truncated-frame results are excluded and counted during expression export")
    func frameExpressionScopeCountsUnknowns() throws {
        try withDirectory { directory in
            let syn = PacketBuilder.tcpSynFrame(
                src: "192.0.2.10", dst: "198.51.100.7", srcPort: 50_000, dstPort: 443
            )
            let truncated = Array(syn.prefix(42))
            let source = directory.appendingPathComponent("truncated.pcap")
            try PcapWriter.write(linkType: LinkType.ethernet, frames: [
                CapturedFrame(bytes: syn, timestamp: ReplayCorpus.epoch, originalLength: syn.count),
                CapturedFrame(
                    bytes: truncated,
                    timestamp: ReplayCorpus.epoch.addingTimeInterval(1),
                    originalLength: syn.count
                ),
            ], to: source)
            var parser = FrameExpressionParser()
            let expression = try parser.parse("not tcp.rst")
            let output = directory.appendingPathComponent("known-non-rst.pcapng")

            let summary = try CaptureFrameExporter.export(
                from: source,
                scope: .frameExpression(expression),
                options: .init(),
                to: output
            )

            #expect(summary.scannedFrameCount == 2)
            #expect(summary.writtenFrameCount == 1)
            #expect(summary.unknownExpressionFrameCount == 1)
            #expect(try PcapngReader.read(contentsOf: output).frames.count == 1)
        }
    }

    @Test("An all-unknown expression export reports why no file was written")
    func frameExpressionScopeReportsAllUnknown() throws {
        try withDirectory { directory in
            let syn = PacketBuilder.tcpSynFrame(
                src: "192.0.2.10", dst: "198.51.100.7", srcPort: 50_000, dstPort: 443
            )
            let truncated = Array(syn.prefix(42))
            let source = directory.appendingPathComponent("unknown.pcap")
            try PcapWriter.write(linkType: LinkType.ethernet, frames: [
                CapturedFrame(bytes: truncated, timestamp: ReplayCorpus.epoch, originalLength: syn.count),
            ], to: source)
            var parser = FrameExpressionParser()
            let expression = try parser.parse("not tcp.rst")
            let output = directory.appendingPathComponent("unknown-only.pcapng")

            #expect(throws: FrameExportError.expressionExportNoFrames(unknownCount: 1)) {
                try CaptureFrameExporter.export(
                    from: source,
                    scope: .frameExpression(expression),
                    options: .init(),
                    to: output
                )
            }
            #expect(!FileManager.default.fileExists(atPath: output.path))
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
    func bigEndianSourcePreservesPacketCommentsAndKeepsTypedMetadata() throws {
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
            #expect(summary.omittedFrameOptionCount == 0)
            let loaded = try SavedCaptureStreamLoader(contentsOf: output).load()
            #expect(loaded.properties.commentedFrameCount == 1)
            #expect(loaded.properties.sections.first?.interfaces.first?.name?.text == "en0")
            let reader = try CaptureStreamReader(contentsOf: output)
            var commentReference: CaptureFrameCommentReference?
            readFrames: while true {
                switch try reader.next() {
                case let .frame(event):
                    if let reference = event.reference.frameCommentReference {
                        commentReference = reference
                        break readFrames
                    }
                case .end:
                    break readFrames
                }
            }
            guard let reference = commentReference else {
                Issue.record("expected exported packet comment metadata")
                return
            }
            let comments = try CaptureFrameCommentReader.read(
                reference, from: output, expectedIdentity: reader.identity
            )
            #expect(comments.comments.first?.text == "Frame two comment")
        }
    }

    @Test
    func transformedFramePreservesIndependentSourceComments() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("showcase.pcapng")
            try Data(CaptureContainerFixtures.showcasePcapng()).write(to: source)
            let output = directory.appendingPathComponent("truncated.pcapng")
            let summary = try CaptureFrameExporter.export(
                from: source,
                scope: .wholeCapture,
                options: .init(truncatesTo: 14),
                to: output
            )
            #expect(summary.truncatedFrameCount > 0)
            #expect(summary.omittedFrameOptionCount == 0)
            #expect(try SavedCaptureStreamLoader(contentsOf: output).load().properties.commentedFrameCount == 1)
        }
    }

    @Test
    func selectedFrameExportPreservesIndependentCommentsInEitherByteOrder() throws {
        try withDirectory { directory in
            for little in [true, false] {
                let source = directory.appendingPathComponent("showcase-\(little).pcapng")
                try Data(CaptureContainerFixtures.showcasePcapng(little: little)).write(to: source)
                let output = directory.appendingPathComponent("selected-\(little).pcapng")
                let summary = try CaptureFrameExporter.export(
                    from: source,
                    scope: .frames([2]),
                    options: .init(),
                    to: output
                )
                let result = try SavedCaptureStreamLoader(contentsOf: output).load()
                #expect(summary.writtenFrameCount == 1)
                #expect(summary.omittedFrameOptionCount == 0)
                #expect(result.properties.commentedFrameCount == 1)
                let reader = try CaptureStreamReader(contentsOf: output)
                guard case let .frame(event) = try reader.next(),
                      let reference = event.reference.frameCommentReference else
                {
                    Issue.record("expected exported packet comment metadata")
                    return
                }
                let comments = try CaptureFrameCommentReader.read(
                    reference, from: output, expectedIdentity: reader.identity
                )
                #expect(comments.comments.first?.text == "Frame two comment")
            }
        }
    }

    @Test
    func selectedFramePreservesPacketHashOnlyWhenBytesStayUnchanged() throws {
        try withDirectory { directory in
            for little in [true, false] {
                let source = directory.appendingPathComponent("hash-\(little).pcapng")
                let payload = [UInt8](repeating: 0xE5, count: 20)
                let hash = [4] + Array(Insecure.SHA1.hash(data: Data(payload)))
                var bytes = PcapngFixture.sectionHeader(little: little)
                bytes += PcapngFixture.interfaceDescription(little: little)
                bytes += PcapngFixture.enhancedPacket(
                    little: little, ticks: 1, captured: payload,
                    trailingOptions: PcapngFixture.option(code: 3, value: [1] + hash, little: little)
                        + PcapngFixture.option(code: 5, value: PcapngFixture.u64(77, little), little: little)
                        + PcapngFixture.option(code: 0, value: [], little: little)
                )
                try Data(bytes).write(to: source)

                let unchangedOutput = directory.appendingPathComponent("hash-selected-\(little).pcapng")
                let unchangedSummary = try CaptureFrameExporter.export(
                    from: source, scope: .frames([1]), options: .init(), to: unchangedOutput
                )
                #expect(unchangedSummary.omittedFrameOptionCount == 0)
                let unchangedReader = try PcapngStreamReader(contentsOf: unchangedOutput)
                let unchangedEvent = try Self.expectFrame(unchangedReader.next())
                #expect(unchangedEvent.reference.packetID == 77)
                let unchangedHandle = try FileHandle(forReadingFrom: unchangedOutput)
                try unchangedHandle.seek(toOffset: unchangedEvent.reference.optionsRange.lowerBound)
                let copiedOptions = try #require(try unchangedHandle.read(
                    upToCount: Int(unchangedEvent.reference.optionsRange.count)
                ))
                try unchangedHandle.close()
                let expectedOptions = Data(
                    PcapngFixture.option(code: 3, value: [1] + hash, little: true)
                        + PcapngFixture.option(code: 5, value: PcapngFixture.u64(77, true), little: true)
                        + PcapngFixture.option(code: 0, value: [], little: true)
                )
                #expect(copiedOptions == expectedOptions)

                let changedOutput = directory.appendingPathComponent("hash-truncated-\(little).pcapng")
                let changedSummary = try CaptureFrameExporter.export(
                    from: source, scope: .wholeCapture, options: .init(truncatesTo: 14), to: changedOutput
                )
                #expect(changedSummary.omittedFrameOptionCount == 1)
                let changedEvent = try Self.expectFrame(PcapngStreamReader(contentsOf: changedOutput).next())
                #expect(changedEvent.reference.packetID == 77)
                #expect(changedEvent.reference.hasOptions)
                let changedHandle = try FileHandle(forReadingFrom: changedOutput)
                try changedHandle.seek(toOffset: changedEvent.reference.optionsRange.lowerBound)
                let changedOptions = try #require(try changedHandle.read(
                    upToCount: Int(changedEvent.reference.optionsRange.count)
                ))
                try changedHandle.close()
                let expectedChangedOptions = Data(
                    PcapngFixture.option(code: 5, value: PcapngFixture.u64(77, true), little: true)
                        + PcapngFixture.option(code: 0, value: [], little: true)
                )
                #expect(changedOptions == expectedChangedOptions)
            }
        }
    }

    @Test("a big-endian direction flag is reconstructed without an omission warning")
    func bigEndianDirectionFlagSurvivesSelectedFrameExport() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("direction-be.pcapng")
            let packetFlags = PcapngFixture.option(
                code: 2, value: PcapngFixture.u32(1, false), little: false
            ) + PcapngFixture.option(code: 0, value: [], little: false)
            var bytes = PcapngFixture.sectionHeader(little: false)
            bytes += PcapngFixture.interfaceDescription(little: false)
            bytes += PcapngFixture.enhancedPacket(
                little: false, ticks: 1, captured: [UInt8](repeating: 0xA5, count: 20),
                trailingOptions: packetFlags
            )
            try Data(bytes).write(to: source)

            let output = directory.appendingPathComponent("direction-out.pcapng")
            let summary = try CaptureFrameExporter.export(
                from: source, scope: .frames([1]), options: .init(), to: output
            )
            #expect(summary.omittedFrameOptionCount == 0)
            let reader = try PcapngStreamReader(contentsOf: output)
            let event = try Self.expectFrame(reader.next())
            #expect(event.reference.direction == .inbound)
            #expect(event.reference.packetFlags == 1)
            let handle = try FileHandle(forReadingFrom: output)
            try handle.seek(toOffset: event.reference.optionsRange.lowerBound)
            let options = try #require(try handle.read(upToCount: Int(event.reference.optionsRange.count)))
            try handle.close()
            let expected = Data(
                PcapngFixture.option(code: 2, value: PcapngFixture.u32(1, true), little: true)
                    + PcapngFixture.option(code: 0, value: [], little: true)
            )
            #expect(options == expected)
        }
    }

    @Test("Frame export reports interface metadata outside the bounded inventory")
    func reportsInterfaceInventoryOverflow() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("interface-overflow.pcapng")
            var bytes = PcapngFixture.sectionHeader(little: true)
            for index in 0 ..< (CaptureSection.maxInterfaces + 1) {
                let options = CaptureContainerFixtures.InterfaceOptions(
                    name: index == CaptureSection.maxInterfaces ? "overflow-interface" : nil
                )
                bytes += CaptureContainerFixtures.interfaceDescription(little: true, options: options)
            }
            bytes += PcapngFixture.enhancedPacket(
                little: true, interfaceID: UInt32(CaptureSection.maxInterfaces), ticks: 1, captured: [0xA5]
            )
            try Data(bytes).write(to: source)

            let output = directory.appendingPathComponent("interface-overflow-out.pcapng")
            let summary = try CaptureFrameExporter.export(
                from: source, scope: .wholeCapture, options: .init(format: .pcapng), to: output
            )
            #expect(summary.sourceMetadataInventoryTruncated)
            #expect(summary.omittedInterfaceOptionCount == 0)
            #expect(try PcapngReader.read(contentsOf: output).frames.map(\.bytes) == [[0xA5]])

            let withoutMetadata = directory.appendingPathComponent("interface-overflow-minimal.pcapng")
            let minimalSummary = try CaptureFrameExporter.export(
                from: source, scope: .wholeCapture,
                options: .init(format: .pcapng, preservesMetadata: false), to: withoutMetadata
            )
            #expect(!minimalSummary.sourceMetadataInventoryTruncated)
        }
    }

    @Test("Section metadata bounds are surfaced in the frame export summary")
    func reportsBoundedSectionMetadataLoss() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("section-metadata-overflow.pcapng")
            let comments = (0 ..< (CaptureBoundedTextList.maxCount + 2)).map { "section-\($0)" }
            var bytes = CaptureContainerFixtures.sectionHeader(
                little: true, options: .init(comments: comments)
            )
            bytes += PcapngFixture.interfaceDescription(little: true)
            bytes += PcapngFixture.enhancedPacket(little: true, ticks: 1, captured: [0xA5])
            try Data(bytes).write(to: source)

            let output = directory.appendingPathComponent("section-metadata-overflow-out.pcapng")
            let summary = try CaptureFrameExporter.export(
                from: source, scope: .wholeCapture, options: .init(format: .pcapng), to: output
            )
            #expect(summary.omittedSectionOptionCount == 2)
        }
    }

    @Test("Whole-capture export reports metadata from source sections with no emitted frames")
    func reportsMetadataFromEmptySourceSection() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("empty-metadata-section.pcapng")
            var bytes = CaptureContainerFixtures.sectionHeader(
                little: true, options: .init(comments: ["metadata-only-section"])
            )
            bytes += PcapngFixture.sectionHeader(little: true)
            bytes += PcapngFixture.interfaceDescription(little: true)
            bytes += PcapngFixture.enhancedPacket(little: true, ticks: 1, captured: [0xA5])
            try Data(bytes).write(to: source)

            let output = directory.appendingPathComponent("empty-metadata-section-out.pcapng")
            let summary = try CaptureFrameExporter.export(
                from: source, scope: .wholeCapture, options: .init(format: .pcapng), to: output
            )
            #expect(summary.omittedSectionOptionCount == 1)
            #expect(MainContentCoordinator.frameExportWarning(summary)?
                .contains("section option(s) were omitted") == true)
        }
    }

    @Test("Artificial output sections do not recount the same source section omissions")
    func doesNotDoubleCountSectionMetadataAfterRestart() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("restarted-section.pcapng")
            let comments = (0 ..< (CaptureBoundedTextList.maxCount + 2)).map { "section-\($0)" }
            var bytes = CaptureContainerFixtures.sectionHeader(little: true, options: .init(comments: comments))
            bytes += PcapngFixture.interfaceDescription(little: true)
            bytes += PcapngFixture.enhancedPacket(little: true, ticks: 1, captured: [1, 2, 3, 4])
            bytes += PcapngFixture.enhancedPacket(little: true, ticks: 2, captured: [5, 6, 7, 8])
            try Data(bytes).write(to: source)

            let output = directory.appendingPathComponent("restarted-section-out.pcapng")
            let summary = try CaptureFrameExporter.export(
                from: source, scope: .wholeCapture,
                options: .init(format: .pcapng, truncatesTo: 2), to: output
            )
            #expect(summary.omittedSectionOptionCount == 2)
        }
    }

    @Test
    func untimedFrameOnNonzeroOutputInterfaceStartsRepresentableSection() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("mixed-time.pcapng")
            try PcapngWriter.write(defaultLinkType: LinkType.ethernet, frames: [
                CapturedFrame(
                    bytes: [UInt8](repeating: 0, count: 14), timestamp: Date(timeIntervalSince1970: 10),
                    originalLength: 14, linkType: LinkType.ethernet
                ),
                CapturedFrame(
                    bytes: [UInt8](repeating: 0, count: 20), timestamp: nil,
                    originalLength: 20, linkType: LinkType.raw
                ),
            ], to: source)
            let output = directory.appendingPathComponent("mixed-time-out.pcapng")
            let summary = try CaptureFrameExporter.export(
                from: source, scope: .wholeCapture, options: .init(), to: output
            )
            #expect(summary.writtenFrameCount == 2)
            let frames = try PcapngReader.read(contentsOf: output).frames
            #expect(frames.count == 2)
            #expect(frames[0].timestamp != nil)
            #expect(frames[1].timestamp == nil)
            #expect(frames[1].linkType == LinkType.raw)
            #expect(frames[1].bytes.count == 20)
        }
    }

    @Test
    func truncatedSimplePacketAndLargerTimedPacketUseValidInterfaceShapes() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("spb-truncated.pcapng")
            var bytes = PcapngFixture.sectionHeader(little: true)
            bytes += PcapngFixture.interfaceDescription(little: true, snapLength: 14)
            bytes += PcapngFixture.simplePacket(
                little: true, originalLength: 100, captured: Array(repeating: 0xA1, count: 14)
            )
            bytes += PcapngFixture.enhancedPacket(
                little: true, ticks: 1_000_000, captured: Array(repeating: 0xB2, count: 100)
            )
            try Data(bytes).write(to: source)
            let output = directory.appendingPathComponent("spb-truncated-out.pcapng")

            let summary = try CaptureFrameExporter.export(
                from: source, scope: .wholeCapture, options: .init(), to: output
            )
            let frames = try PcapngReader.read(contentsOf: output).frames
            #expect(summary.writtenFrameCount == 2)
            #expect(frames.map(\.bytes.count) == [14, 100])
            #expect(frames[0].timestamp == nil)
            #expect(frames[1].timestamp != nil)
        }
    }

    @Test
    func truncatingUntimedPacketFromUnlimitedInterfaceRewritesSnapLength() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("spb-unlimited.pcapng")
            var bytes = PcapngFixture.sectionHeader(little: true)
            bytes += PcapngFixture.interfaceDescription(little: true, snapLength: 0)
            bytes += PcapngFixture.simplePacket(
                little: true, originalLength: 100, captured: Array(repeating: 0xC3, count: 100)
            )
            try Data(bytes).write(to: source)
            let output = directory.appendingPathComponent("spb-limited-out.pcapng")

            let summary = try CaptureFrameExporter.export(
                from: source, scope: .wholeCapture, options: .init(truncatesTo: 14), to: output
            )
            let frames = try PcapngReader.read(contentsOf: output).frames
            #expect(summary.writtenFrameCount == 1)
            #expect(frames.count == 1)
            #expect(frames[0].bytes.count == 14)
            #expect(frames[0].originalLength == 100)
            #expect(frames[0].timestamp == nil)
        }
    }

    @Test
    func transformedPacketExportOmitsStaleFCSInterfaceMetadata() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("fcs.pcapng")
            var bytes = PcapngFixture.sectionHeader(little: true)
            bytes += CaptureContainerFixtures.interfaceDescription(
                little: true, options: .init(fcsLength: 4)
            )
            bytes += PcapngFixture.enhancedPacket(
                little: true, ticks: 1, captured: Array(repeating: 0xD4, count: 20)
            )
            try Data(bytes).write(to: source)
            let output = directory.appendingPathComponent("fcs-truncated.pcapng")

            let summary = try CaptureFrameExporter.export(
                from: source, scope: .wholeCapture, options: .init(truncatesTo: 14), to: output
            )
            let exported = try SavedCaptureStreamLoader(contentsOf: output).load()
            #expect(summary.writtenFrameCount == 1)
            #expect(summary.omittedInterfaceOptionCount == 1)
            #expect(exported.properties.sections.first?.interfaces.first?.fcsLength == nil)

            let unchangedOutput = directory.appendingPathComponent("fcs-not-truncated.pcapng")
            let unchangedSummary = try CaptureFrameExporter.export(
                from: source, scope: .wholeCapture, options: .init(truncatesTo: 30), to: unchangedOutput
            )
            let unchanged = try SavedCaptureStreamLoader(contentsOf: unchangedOutput).load()
            #expect(unchangedSummary.truncatedFrameCount == 0)
            #expect(unchangedSummary.omittedInterfaceOptionCount == 0)
            #expect(unchanged.properties.sections.first?.interfaces.first?.fcsLength == 4)
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

    @Test("Time correction resolves original anchors even when the output omits those frames")
    func anchoredCorrectionUsesOriginalCaptureScope() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("original.pcapng")
            let times: [Date?] = [10, 20, 30].map { Date(timeIntervalSince1970: $0) } + [nil]
            let frames = times.map { CapturedFrame(bytes: [0xA5], timestamp: $0, originalLength: 1) }
            try PcapngWriter.write(defaultLinkType: 1, frames: frames, to: source)
            let originalBytes = try Data(contentsOf: source)
            let request = CaptureTimeCorrectionRequest.anchors(
                firstFrameOrdinal: 1, firstCorrectedTime: Date(timeIntervalSince1970: 1_000),
                secondFrameOrdinal: 3, secondCorrectedTime: Date(timeIntervalSince1970: 1_200)
            )
            let output = directory.appendingPathComponent("corrected.pcapng")
            let summary = try CaptureFrameExporter.export(
                from: source, scope: .frames([2, 4]),
                options: .init(excludedFrameOrdinals: [1, 3], timeCorrection: request), to: output
            )
            #expect(summary.scannedFrameCount == 4)
            #expect(summary.writtenFrameCount == 2)
            #expect(try PcapngReader.read(contentsOf: output).frames.map(\.timestamp)
                == [Date(timeIntervalSince1970: 1_100), nil])
            #expect(try Data(contentsOf: source) == originalBytes)
        }
    }

    @Test("An in-memory correction scopes by corrected time and survives a derived export")
    func baseCorrectionScopesAndExports() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("original.pcapng")
            let frames = [10.0, 20, 30].map {
                CapturedFrame(bytes: [0xA5], timestamp: Date(timeIntervalSince1970: $0), originalLength: 1)
            }
            try PcapngWriter.write(defaultLinkType: 1, frames: frames, to: source)
            let originalBytes = try Data(contentsOf: source)
            let correction = try CaptureTimeCorrection(shiftBy: 100)
            let output = directory.appendingPathComponent("corrected.pcapng")
            _ = try CaptureFrameExporter.export(
                from: source,
                scope: .timeRange(
                    start: Date(timeIntervalSince1970: 119), end: Date(timeIntervalSince1970: 121)
                ),
                options: .init(baseTimeCorrection: correction),
                to: output
            )
            let loaded = try SavedCaptureStreamLoader(contentsOf: output).load()
            #expect(loaded.properties.totalFrames == 1)
            #expect(loaded.properties.firstTimestamp == Date(timeIntervalSince1970: 120))
            #expect(loaded.metadata.hasTimestampCorrectionMarker)
            #expect(try Data(contentsOf: source) == originalBytes)
        }
    }

    @Test("A later frame can anchor all earlier exported frames")
    func singleAnchorResolvesBeforeWriting() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("original.pcapng")
            let frames = [10.0, 20, 30].map {
                CapturedFrame(bytes: [0xA5], timestamp: Date(timeIntervalSince1970: $0), originalLength: 1)
            }
            try PcapngWriter.write(defaultLinkType: 1, frames: frames, to: source)
            let output = directory.appendingPathComponent("corrected.pcapng")
            _ = try CaptureFrameExporter.export(
                from: source, scope: .wholeCapture,
                options: .init(timeCorrection: .anchor(
                    frameOrdinal: 3, correctedTime: Date(timeIntervalSince1970: 120)
                )), to: output
            )
            #expect(try PcapngReader.read(contentsOf: output).frames.map(\.timestamp)
                == [100.0, 110, 120].map { Date(timeIntervalSince1970: $0) })
        }
    }

    @Test("Missing and untimed anchors refuse export without producing a partial copy")
    func unavailableTimeCorrectionAnchors() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("original.pcapng")
            try PcapngWriter.write(defaultLinkType: 1, frames: [
                CapturedFrame(bytes: [0xA5], timestamp: nil, originalLength: 1),
            ], to: source)
            for (ordinal, expectedError) in [
                (UInt64(1), CaptureTimeCorrection.Error.untimedAnchor(frameOrdinal: 1)),
                (UInt64(2), CaptureTimeCorrection.Error.missingAnchor(frameOrdinal: 2)),
            ] {
                #expect(throws: expectedError) {
                    try CaptureFrameExporter.export(
                        from: source, scope: .wholeCapture,
                        options: .init(timeCorrection: .anchor(
                            frameOrdinal: ordinal, correctedTime: Date(timeIntervalSince1970: 10)
                        )), to: directory.appendingPathComponent("corrected.pcapng")
                    )
                }
            }
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == ["original.pcapng"])
        }
    }

    @Test("A correction failure after writing begins preserves both source and prior destination")
    func correctionFailureDiscardsPartialOutput() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("original.pcapng")
            let frames = [10.0, 0].map {
                CapturedFrame(bytes: [0xA5], timestamp: Date(timeIntervalSince1970: $0), originalLength: 1)
            }
            try PcapngWriter.write(defaultLinkType: 1, frames: frames, to: source)
            let sourceBytes = try Data(contentsOf: source)
            let output = directory.appendingPathComponent("corrected.pcapng")
            let previousBytes = Data("previous destination".utf8)
            try previousBytes.write(to: output)
            #expect(throws: CaptureTimeCorrection.Error.unrepresentableCorrectedTime) {
                try CaptureFrameExporter.export(
                    from: source, scope: .wholeCapture,
                    options: .init(timeCorrection: .anchor(
                        frameOrdinal: 1, correctedTime: Date(timeIntervalSince1970: 1)
                    )), to: output
                )
            }
            #expect(try Data(contentsOf: source) == sourceBytes)
            #expect(try Data(contentsOf: output) == previousBytes)
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
                == ["corrected.pcapng", "original.pcapng"])
        }
    }

    @Test("A corrected copy cannot replace the original directly or through an alias")
    func correctionNeedsDistinctSource() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("original.pcapng")
            try PcapngWriter.write(defaultLinkType: 1, frames: [
                CapturedFrame(bytes: [0xA5], timestamp: Date(timeIntervalSince1970: 10), originalLength: 1),
            ], to: source)
            let symlink = directory.appendingPathComponent("symlink.pcapng")
            let hardlink = directory.appendingPathComponent("hardlink.pcapng")
            try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: source)
            try FileManager.default.linkItem(at: source, to: hardlink)
            let sourceBytes = try Data(contentsOf: source)
            for output in [source, symlink, hardlink] {
                #expect(throws: FrameExportError.timeCorrectionNeedsDistinctDestination) {
                    try CaptureFrameExporter.export(
                        from: source, scope: .wholeCapture, options: .init(timeCorrection: .shiftBy(1)), to: output
                    )
                }
            }
            #expect(try Data(contentsOf: source) == sourceBytes)
        }
    }

    @Test("Correction requests reject classic PCAP and ambiguous combined shifts")
    func correctionOptionConflicts() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("original.pcapng")
            let output = directory.appendingPathComponent("corrected.pcapng")
            #expect(throws: FrameExportError.timeCorrectionRequiresPcapng) {
                try CaptureFrameExporter.export(
                    from: source, scope: .wholeCapture,
                    options: .init(format: .pcap, timeCorrection: .shiftBy(1)), to: output
                )
            }
            #expect(throws: FrameExportError.conflictingTimeCorrections) {
                try CaptureFrameExporter.export(
                    from: source, scope: .wholeCapture,
                    options: .init(shiftsTimeBy: 1, timeCorrection: .shiftBy(1)), to: output
                )
            }
            let contents = try FileManager.default.contentsOfDirectory(atPath: directory.path)
            #expect(contents.isEmpty)
        }
    }

    @Test("Correction option offsets track stopped-spool original frame ordinals")
    func timeCorrectionAnchorOffsets() throws {
        var options = FrameExportOptions(timeCorrection: .anchors(
            firstFrameOrdinal: 1, firstCorrectedTime: Date(timeIntervalSince1970: 10),
            secondFrameOrdinal: 5, secondCorrectedTime: Date(timeIntervalSince1970: 20)
        ))
        try options.addFrameOrdinalOffset(100)
        #expect(options.timeCorrection?.anchorOrdinals == [101, 105])
    }

    @Test("The writing pass rejects an anchor timestamp changed after preflight")
    func correctionRechecksOriginalAnchorTimestamp() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("original.pcapng")
            try PcapngWriter.write(defaultLinkType: 1, frames: [
                CapturedFrame(bytes: [0xA5], timestamp: Date(timeIntervalSince1970: 10), originalLength: 1),
            ], to: source)
            let reader = try CaptureStreamReader(contentsOf: source)
            var correction = try CaptureFrameTimeCorrection(
                options: .init(timeCorrection: .anchor(
                    frameOrdinal: 1,
                    correctedTime: Date(timeIntervalSince1970: 20)
                )),
                source: source, destination: directory.appendingPathComponent("corrected.pcapng"),
                identity: reader.identity, isCancelled: { false }
            )
            guard case let .frame(event) = try reader.next() else {
                Issue.record("Missing original frame")
                return
            }
            #expect(throws: CaptureTimeCorrection.Error.changedAnchor(frameOrdinal: 1)) {
                try correction.validate(CaptureFrameExporter.shifted(event, by: 1), ordinal: 1)
            }
            #expect(throws: CaptureTimeCorrection.Error.missingAnchor(frameOrdinal: 1)) {
                try correction.finish()
            }
            try correction.validate(event, ordinal: 1)
            try correction.finish()
        }
    }

    @Test("Correction preflight respects cancellation before creating an output")
    func correctionPreflightCancellation() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("original.pcapng")
            try PcapngWriter.write(defaultLinkType: 1, frames: [
                CapturedFrame(bytes: [0xA5], timestamp: Date(timeIntervalSince1970: 10), originalLength: 1),
            ], to: source)
            let reader = try CaptureStreamReader(contentsOf: source)
            #expect(throws: CancellationError.self) {
                try CaptureFrameTimeCorrection(
                    options: .init(timeCorrection: .anchor(
                        frameOrdinal: 1, correctedTime: Date(timeIntervalSince1970: 20)
                    )),
                    source: source, destination: directory.appendingPathComponent("corrected.pcapng"),
                    identity: reader.identity, isCancelled: { true }
                )
            }
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == ["original.pcapng"])
        }
    }

    @Test("Fixed correction and the existing time shift retain identical known and unknown timestamps")
    func fixedCorrectionPreservesLegacyTimeShift() throws {
        try withDirectory { directory in
            let source = directory.appendingPathComponent("original.pcapng")
            try PcapngWriter.write(defaultLinkType: 1, frames: [
                CapturedFrame(bytes: [0xA5], timestamp: Date(timeIntervalSince1970: 10), originalLength: 1),
                CapturedFrame(bytes: [0xA5], timestamp: nil, originalLength: 1),
            ], to: source)
            for (name, options) in [
                ("legacy", FrameExportOptions(shiftsTimeBy: 0.5)),
                ("corrected", FrameExportOptions(timeCorrection: .shiftBy(0.5))),
            ] {
                let output = directory.appendingPathComponent(name + ".pcapng")
                _ = try CaptureFrameExporter.export(from: source, scope: .wholeCapture, options: options, to: output)
                #expect(try PcapngReader.read(contentsOf: output).frames.map(\.timestamp)
                    == [Date(timeIntervalSince1970: 10.5), nil])
            }
        }
    }

    // MARK: Private

    private static func expectFrame(_ outcome: PcapngStreamOutcome) throws -> PcapngFrameEvent {
        guard case let .frame(event) = outcome else {
            Issue.record("expected a frame, got \(outcome)")
            throw CancellationError()
        }
        return event
    }

    private func withDirectory(_ body: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-export-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory)
    }
}
