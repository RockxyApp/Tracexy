import Foundation
import Testing
@testable import Tracexy

// MARK: - CaptureFilePropertiesTests

/// The container inventory folded by the streaming readers: pcapng sections,
/// interfaces and their options, statistics, block counts and comments; classic
/// pcap header facts; bounds; malformed input; and parity with Wireshark's
/// `capinfos` where an installation exists.
struct CaptureFilePropertiesTests {
    // MARK: Internal

    @Test
    func showcaseSectionAndInterfaceFactsAreFolded() throws {
        let properties = try Self.load(CaptureContainerFixtures.showcasePcapng())
        guard case .pcapng = properties.container else {
            Issue.record("expected pcapng container")
            return
        }
        #expect(properties.sections.count == 1)
        let section = try #require(properties.sections.first)
        #expect(section.littleEndian)
        #expect(section.majorVersion == 1)
        #expect(section.hardware?.text == "Mac16,10")
        #expect(section.operatingSystem?.text == "macOS 26.5")
        #expect(section.application?.text == "Tracexy fixture builder")
        #expect(section.comments.values.map(\.text) == ["Section comment one"])
        #expect(section.interfaces.count == 2)

        let en0 = section.interfaces[0]
        #expect(en0.name?.text == "en0")
        #expect(en0.interfaceDescription?.text == "Wi-Fi")
        #expect(en0.filter?.text == "tcp or udp")
        #expect(en0.filterKind == 0)
        #expect(en0.operatingSystem?.text == "macOS")
        #expect(en0.linkType == LinkType.ethernet)
        #expect(en0.ticksPerSecond == 1_000_000)
        #expect(en0.comments.values.map(\.text) == ["Interface comment"])
        #expect(en0.frameCount == ReplayCorpus.conversation().count)
        #expect(en0.displayName == "en0")

        let tunnel = section.interfaces[1]
        #expect(tunnel.name?.text == "utun4")
        #expect(tunnel.linkType == LinkType.raw)
        #expect(tunnel.ticksPerSecond == 1_000_000_000)
        #expect(tunnel.frameCount == 1)
        #expect(tunnel.interfaceDescription == nil)

        #expect(properties.totalFrames == ReplayCorpus.conversation().count + 1)
        #expect(properties.commentedFrameCount == 1)
        #expect(properties.untimedFrameCount == 0)
        #expect(properties.isStrictlyTimeOrdered == false) // interface 1 frame is earlier than the last en0 frame
        #expect(properties.carriesFileAuthoredText)
    }

    @Test
    func showcaseStatisticsAndBlockInventoryAreFolded() throws {
        let properties = try Self.load(CaptureContainerFixtures.showcasePcapng())
        let section = try #require(properties.sections.first)
        let en0Stats = try #require(section.interfaces[0].statistics)
        #expect(en0Stats.received == 1_234)
        #expect(en0Stats.dropped == 5)
        #expect(en0Stats.blockCount == 1)
        #expect(en0Stats.startTime == Date(timeIntervalSince1970: 1_700_000_000))
        #expect(en0Stats.endTime == Date(timeIntervalSince1970: 1_700_000_100))
        #expect(section.interfaces[1].statistics?.received == 1)

        let blocks = properties.blockInventory
        #expect(blocks.interfaceStatisticsBlockCount == 2)
        #expect(blocks.nameResolutionBlockCount == 1)
        #expect(blocks.customBlockCount == 1)
        #expect(blocks.decryptionSecrets.count == 1)
        #expect(blocks.decryptionSecrets.first?.secretsType == 0x544C4B4C)
        #expect(blocks.decryptionSecrets.first?.kindLabel == "TLS key log")
        #expect(blocks.decryptionSecrets.first?.secretsLength == UInt64("CLIENT_RANDOM 00 11\n".utf8.count))
        #expect(blocks.unknownBlockTypes == [0x000000F0: 1])
    }

    @Test
    func bigEndianShowcaseFoldsIdentically() throws {
        let little = try Self.load(CaptureContainerFixtures.showcasePcapng(little: true))
        let big = try Self.load(CaptureContainerFixtures.showcasePcapng(little: false))
        #expect(big.sections.first?.littleEndian == false)
        #expect(big.sections.first?.interfaces == little.sections.first?.interfaces)
        #expect(big.totalFrames == little.totalFrames)
        #expect(big.blockInventory == little.blockInventory)
        #expect(big.firstTimestamp == little.firstTimestamp)
    }

    @Test
    func classicPcapReportsHeaderFactsAsOneSection() throws {
        let bytes = ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation(), variant: .littleNano)
        let properties = try Self.load(bytes)
        guard case let .pcap(facts) = properties.container else {
            Issue.record("expected classic container")
            return
        }
        #expect(facts.littleEndian)
        #expect(facts.nanosecondResolution)
        #expect(facts.linkType == LinkType.ethernet)
        #expect(facts.fcsLengthWords == nil)
        #expect(properties.sections.count == 1)
        #expect(properties.sections[0].interfaces.count == 1)
        #expect(properties.sections[0].interfaces[0].ticksPerSecond == 1_000_000_000)
        #expect(properties.sections[0].interfaces[0].frameCount == ReplayCorpus.conversation().count)
        #expect(properties.totalFrames == ReplayCorpus.conversation().count)
        #expect(properties.isStrictlyTimeOrdered)
        let offsets = ReplayCorpus.conversation().map(\.offsetSeconds)
        #expect(properties.elapsed == TimeInterval((offsets.max() ?? 0) - (offsets.min() ?? 0)))
        #expect(properties.firstTimestamp == ReplayCorpus.epoch.addingTimeInterval(TimeInterval(offsets.min() ?? 0)))
        #expect(!properties.carriesFileAuthoredText)
    }

    @Test
    func classicLinkTypeWordExposesFCSHint() {
        let facts = ClassicPcapFacts(
            littleEndian: true, nanosecondResolution: false, snapLength: 65_535,
            linkType: 1, rawLinkTypeWord: 0x28000001
        )
        #expect(facts.fcsLengthWords == 2)
        let plain = ClassicPcapFacts(
            littleEndian: true, nanosecondResolution: false, snapLength: 65_535,
            linkType: 1, rawLinkTypeWord: 0x20000001
        )
        #expect(plain.fcsLengthWords == nil)
    }

    @Test
    func stringOptionsAreCappedAndLossyDecodesAreFlagged() throws {
        let long = String(repeating: "x", count: 1_000)
        let invalid: [UInt8] = [0x66, 0x6F, 0xFF, 0xFE, 0x6F]
        var file = CaptureContainerFixtures.sectionHeader(little: true, options: .init(
            hardware: long,
            rawOptions: CaptureContainerFixtures.bytesOption(code: 3, invalid, true)
        ))
        file += PcapngFixture.interfaceDescription(little: true)
        let properties = try Self.load(file)
        let section = try #require(properties.sections.first)
        let hardware = try #require(section.hardware)
        #expect(hardware.isTruncated)
        #expect(hardware.text.utf8.count == CaptureBoundedText.maxBytes)
        let os = try #require(section.operatingSystem)
        #expect(os.isLossy)
        #expect(!os.isTruncated)
        #expect(os.text.hasPrefix("fo"))
    }

    @Test
    func truncatedMultibyteScalarIsTrimmedNotLossy() throws {
        // 255 ASCII bytes then a 2-byte scalar straddling the 256-byte cap.
        let text = String(repeating: "a", count: 255) + "é" + "tail"
        var file = CaptureContainerFixtures.sectionHeader(little: true, options: .init(application: text))
        file += PcapngFixture.interfaceDescription(little: true)
        let properties = try Self.load(file)
        let application = try #require(properties.sections.first?.application)
        #expect(application.isTruncated)
        #expect(!application.isLossy)
        #expect(application.text == String(repeating: "a", count: 255))
    }

    @Test
    func commentListAndInterfaceListAreBounded() throws {
        let comments = (0 ..< 40).map { "c\($0)" }
        var file = CaptureContainerFixtures.sectionHeader(little: true, options: .init(comments: comments))
        for index in 0 ..< (CaptureSection.maxInterfaces + 5) {
            file += CaptureContainerFixtures.interfaceDescription(little: true, options: .init(name: "if\(index)"))
        }
        file += PcapngFixture.enhancedPacket(little: true, interfaceID: 68, ticks: 1, captured: [0, 1, 2, 3])
        let properties = try Self.load(file)
        let section = try #require(properties.sections.first)
        #expect(section.comments.values.count == CaptureBoundedTextList.maxCount)
        #expect(section.comments.omittedCount == 40 - CaptureBoundedTextList.maxCount)
        #expect(section.interfaces.count == CaptureSection.maxInterfaces)
        #expect(section.interfaceOverflowCount == 5)
        #expect(section.unattributedFrameCount == 1)
        #expect(properties.totalFrames == 1)
    }

    @Test
    func sectionListIsBoundedAndFramesStillCount() throws {
        var file: [UInt8] = []
        for _ in 0 ..< (CaptureFileProperties.maxSections + 2) {
            file += PcapngFixture.sectionHeader(little: true)
            file += PcapngFixture.interfaceDescription(little: true)
            file += PcapngFixture.enhancedPacket(little: true, ticks: 5, captured: [1, 2, 3, 4])
        }
        let properties = try Self.load(file)
        #expect(properties.sections.count == CaptureFileProperties.maxSections)
        #expect(properties.sectionOverflowCount == 2)
        #expect(properties.totalFrames == CaptureFileProperties.maxSections + 2)
    }

    @Test
    func unknownBlockTypeKeysAreBounded() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true)
        for type in UInt32(0x100) ..< UInt32(0x100 + CaptureBlockInventory.maxUnknownTypes + 3) {
            file += CaptureContainerFixtures.unknownBlock(little: true, type: type)
        }
        let properties = try Self.load(file)
        let blocks = try #require(properties.sections.first?.blocks)
        #expect(blocks.unknownBlockTypes.count == CaptureBlockInventory.maxUnknownTypes)
        #expect(blocks.unknownBlockOverflowCount == 3)
    }

    @Test
    func optionOverrunIsMalformed() throws {
        // A section option whose declared length runs past the block.
        var body = PcapngFixture.u32(0x1A2B3C4D, true) + PcapngFixture.u16(1, true) + PcapngFixture.u16(0, true)
        body += PcapngFixture.u64(.max, true)
        body += PcapngFixture.u16(2, true) + PcapngFixture.u16(200, true) + [0, 0, 0, 0]
        let file = PcapngFixture.block(type: 0x0A0D0D0A, little: true, body: body)
        #expect(throws: PacketError.self) {
            try Self.load(file)
        }
    }

    @Test
    func statisticsForUndeclaredInterfaceIsMalformed() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true)
        file += CaptureContainerFixtures.interfaceStatistics(little: true, interfaceID: 4, options: .init(received: 1))
        #expect(throws: PacketError.self) {
            try Self.load(file)
        }
    }

    @Test
    func secretsLengthOverrunIsMalformedAndSecretsAreNeverRetained() throws {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true)
        var body = PcapngFixture.u32(0x544C4B4C, true) + PcapngFixture.u32(4_000, true)
        body += [1, 2, 3, 4]
        file += PcapngFixture.block(type: 0x0000000A, little: true, body: body)
        #expect(throws: PacketError.self) {
            try Self.load(file)
        }
        let fine = try Self.load(CaptureContainerFixtures.showcasePcapng())
        #expect(fine.blockInventory.decryptionSecrets.count == 1)
        // The summary type has no field that could hold the secrets.
        #expect(Mirror(reflecting: fine.blockInventory.decryptionSecrets[0]).children.count == 2)
    }

    @Test
    func truncatedTailKeepsPropertiesOfCompleteBlocks() throws {
        var file = CaptureContainerFixtures.showcasePcapng()
        file.removeLast(7)
        let (properties, completion) = try Self.loadWithCompletion(file)
        #expect(completion.reason != .cleanEndOfFile)
        #expect(properties.sections.first?.interfaces.count == 2)
        #expect(properties.totalFrames == ReplayCorpus.conversation().count + 1)
    }

    @Test
    func untimedSimplePacketsCountPerInterface() throws {
        let properties = try Self.load(ReplayCorpus.pcapngSimplePacketBytes())
        #expect(properties.untimedFrameCount > 0)
        #expect(properties.sections[0].interfaces[0].untimedFrameCount == properties.untimedFrameCount)
    }

    @Test
    func savedLoadResultCarriesProperties() throws {
        try ReplayCorpus.withTemporaryFile(CaptureContainerFixtures.showcasePcapng(), ext: "pcapng") { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            #expect(result.properties.totalFrames == result.totalFrames)
            #expect(result.properties.interfaceCount == 2)
            #expect(result.metadata.totalFrames == result.properties.totalFrames)
            #expect(result.metadata.untimedFrameCount == result.properties.untimedFrameCount)
        }
    }

    // MARK: Wireshark parity

    @Test(.enabled(if: WiresharkOracle.isAvailable, "Wireshark is not installed on this machine"))
    func capinfosAgreesOnShowcase() throws {
        try ReplayCorpus.withTemporaryFile(CaptureContainerFixtures.showcasePcapng(), ext: "pcapng") { url in
            let report = try WiresharkOracle.capinfos(url)
            let properties = try SavedCaptureStreamLoader(contentsOf: url).load().properties
            #expect(report["File type"]?.contains("pcapng") == true)
            #expect(report.int("Number of packets") == properties.totalFrames)
            #expect(report["Capture hardware"] == "Mac16,10")
            #expect(report["Capture oper-sys"] == "macOS 26.5")
            #expect(report["Capture application"] == "Tracexy fixture builder")
            #expect(report["Capture comment"] == "Section comment one")
            #expect(report["if0.Name"] == "en0")
            #expect(report["if0.Description"] == "Wi-Fi")
            #expect(report["if0.Filter string"] == "tcp or udp")
            #expect(report.int("if0.Number of packets") == properties.sections[0].interfaces[0].frameCount)
            #expect(report["if1.Name"] == "utun4")
            #expect(report.int("if1.Number of packets") == properties.sections[0].interfaces[1].frameCount)
            #expect(report["if0.Encapsulation"]?.contains("Ethernet") == true)
            #expect(report.int("Number of interfaces in file") == properties.interfaceCount)
            #expect(report.int("Number of decryption secrets in file") == 1)
            #expect(report["Packet 2 Comment"] == "Frame two comment")
            #expect(report.int("if0.Number of stat entries") == 1)
            #expect(report.int("if1.Number of stat entries") == 1)
        }
    }

    @Test(.enabled(if: WiresharkOracle.isAvailable, "Wireshark is not installed on this machine"))
    func capinfosAgreesOnClassicVariants() throws {
        for variant in [ReplayCorpus.ClassicVariant.littleMicro, .bigMicro, .littleNano, .bigNano] {
            let bytes = ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation(), variant: variant)
            try ReplayCorpus.withTemporaryFile(bytes, ext: "pcap") { url in
                let report = try WiresharkOracle.capinfos(url)
                let properties = try SavedCaptureStreamLoader(contentsOf: url).load().properties
                #expect(report.int("Number of packets") == properties.totalFrames)
                #expect(report["File type"]?.contains("pcap") == true)
                #expect(report["Strict time order"] == (properties.isStrictlyTimeOrdered ? "True" : "False"))
                guard case let .pcap(facts) = properties.container else {
                    Issue.record("expected classic container")
                    return
                }
                #expect(report.int("Packet size limit") == Int(facts.snapLength))
                let offsets = ReplayCorpus.conversation().map(\.offsetSeconds)
                #expect(properties.firstTimestamp == ReplayCorpus.epoch.addingTimeInterval(TimeInterval(offsets.min() ?? 0)))
            }
        }
    }

    @Test(.enabled(if: WiresharkOracle.isAvailable, "Wireshark is not installed on this machine"))
    func tsharkFrameCommentsMatchCommentedFrameCount() throws {
        try ReplayCorpus.withTemporaryFile(CaptureContainerFixtures.showcasePcapng(), ext: "pcapng") { url in
            let rows = try WiresharkOracle.tsharkFields(url, fields: ["frame.number"], filter: "frame.comment")
            let properties = try SavedCaptureStreamLoader(contentsOf: url).load().properties
            #expect(rows.count == properties.commentedFrameCount)
            #expect(rows.first?.first == "2")
        }
    }

    // MARK: Private

    private static func load(_ bytes: [UInt8]) throws -> CaptureFileProperties {
        try loadWithCompletion(bytes).properties
    }

    private static func loadWithCompletion(_ bytes: [UInt8]) throws
        -> (properties: CaptureFileProperties, completion: CaptureStreamCompletion)
    {
        var captured: (CaptureFileProperties, CaptureStreamCompletion)?
        try ReplayCorpus.withTemporaryFile(bytes, ext: "pcapng") { url in
            let reader = try CaptureStreamReader(contentsOf: url)
            while true {
                if case let .end(completion) = try reader.next() {
                    captured = (reader.fileProperties, completion)
                    break
                }
            }
        }
        return try #require(captured)
    }
}
