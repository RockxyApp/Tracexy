import Foundation
import Testing
@testable import Tracexy

// MARK: - IPFragmentFixture

/// Fragmented DNS responses over IPv4 and IPv6, built byte by byte.
private enum IPFragmentFixture {
    // MARK: Internal

    static let client = "192.0.2.10"
    static let server = "198.51.100.53"
    static let client6: [UInt16] = [0x2001, 0xDB8, 0, 0, 0, 0, 0, 0x10]
    static let server6: [UInt16] = [0x2001, 0xDB8, 0, 0, 0, 0, 0, 0x53]

    /// A UDP datagram from the server's port 53 carrying a DNS response with
    /// `answers` A records: 200 make about 3,240 bytes, three 1,480-byte fragments.
    static func response(port: UInt16 = 40_001, answers: Int = 200) -> [UInt8] {
        let records = (0 ..< answers).map { "10.0.\($0 / 256).\($0 % 256)" }
        return PacketBuilder.udp(
            srcPort: 53, dstPort: port, payload: PacketBuilder.dnsResponse(name: "big.example", answers: records)
        )
    }

    static func query(port: UInt16 = 40_001) -> [UInt8] {
        PacketBuilder.ethernetIPv4(
            proto: 17, src: client, dst: server,
            payload: PacketBuilder.udp(srcPort: port, dstPort: 53, payload: PacketBuilder.dnsQuery(name: "big.example"))
        )
    }

    /// Ethernet frames of `datagram` split into IPv4 fragments of `size` bytes.
    static func ipv4Fragments(
        _ datagram: [UInt8],
        identification: UInt16 = 0x2001,
        size: Int = 1_480,
        source: String = server,
        destination: String = client
    )
        -> [[UInt8]]
    {
        stride(from: 0, to: datagram.count, by: size).map { offset in
            let chunk = Array(datagram[offset ..< min(offset + size, datagram.count)])
            let more = offset + size < datagram.count
            return ipv4Fragment(
                chunk, identification: identification, offset: offset, more: more,
                source: source, destination: destination
            )
        }
    }

    static func ipv4Fragment(
        _ chunk: [UInt8],
        identification: UInt16,
        offset: Int,
        more: Bool,
        source: String = server,
        destination: String = client
    )
        -> [UInt8]
    {
        let flags = UInt16(more ? 0x2000 : 0) | UInt16(offset / 8)
        var header: [UInt8] = [0x45, 0x00] + be16(UInt16(20 + chunk.count)) + be16(identification) + be16(flags)
        header += [64, 17, 0, 0] + ipv4(source) + ipv4(destination)
        return ethernet(type: [0x08, 0x00]) + header + chunk
    }

    /// Ethernet frames of `datagram` split into IPv6 fragments of `size` bytes.
    static func ipv6Fragments(
        _ datagram: [UInt8],
        identification: UInt32 = 0xABCD0001,
        size: Int = 1_232
    )
        -> [[UInt8]]
    {
        stride(from: 0, to: datagram.count, by: size).map { offset in
            let chunk = Array(datagram[offset ..< min(offset + size, datagram.count)])
            let more = offset + size < datagram.count
            let fragment: [UInt8] = [17, 0] + be16(UInt16(offset / 8) << 3 | (more ? 1 : 0)) + be32(identification)
            return PacketBuilder.ethernetIPv6(nextHeader: 44, src: server6, dst: client6, payload: fragment + chunk)
        }
    }

    static func frames(_ bytes: [[UInt8]], spacing: TimeInterval = 0.01) -> [CapturedFrame] {
        bytes.enumerated().map { index, frame in
            CapturedFrame(
                bytes: frame,
                timestamp: Date(timeIntervalSince1970: 1_800_000_000 + Double(index) * spacing),
                originalLength: frame.count
            )
        }
    }

    static func writePcap(_ bytes: [[UInt8]]) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("fragments-\(UUID().uuidString).pcap")
        let records = bytes.enumerated().map {
            ReplayCorpus.Frame(bytes: $0.element, offsetSeconds: $0.offset, linkType: LinkType.ethernet)
        }
        try Data(ReplayCorpus.classicPcapBytes(records)).write(to: url)
        return url
    }

    // MARK: Private

    private static func ethernet(type: [UInt8]) -> [UInt8] {
        [6, 6, 6, 6, 6, 6, 1, 2, 3, 4, 5, 6] + type
    }

    private static func ipv4(_ address: String) -> [UInt8] {
        address.split(separator: ".").compactMap { UInt8($0) }
    }

    private static func be16(_ value: UInt16) -> [UInt8] {
        [UInt8(value >> 8), UInt8(value & 0xFF)]
    }

    private static func be32(_ value: UInt32) -> [UInt8] {
        [UInt8(value >> 24), UInt8(value >> 16 & 0xFF), UInt8(value >> 8 & 0xFF), UInt8(value & 0xFF)]
    }
}

// MARK: - IPFragmentDecodeTests

@Suite("IP fragments: decoding")
struct IPFragmentDecodeTests {
    @Test("Every fragment stops at the IP layer, the first one too, and keeps its fragment facts")
    func fragmentsStopAtIP() throws {
        let datagram = IPFragmentFixture.response()
        let fragments = IPFragmentFixture.ipv4Fragments(datagram)
        #expect(fragments.count == 3)
        for (index, bytes) in fragments.enumerated() {
            let packet = SessionBuilder.decodePacket(
                IPFragmentFixture.frames([bytes])[0], linkType: LinkType.ethernet
            )
            let fragment = try #require(packet.ipFragment)
            #expect(packet.fiveTuple == nil)
            #expect(packet.transport == nil)
            #expect(!packet.layers.contains { $0.proto == .udp || $0.proto == .dns })
            #expect(fragment.version == .v4)
            #expect(fragment.identification == 0x2001)
            #expect(fragment.protocolNumber == 17)
            #expect(fragment.offset == index * 1_480)
            #expect(fragment.moreFragments == (index < 2))
            #expect(fragment.isPayloadComplete)
            #expect(Array(packet.rawBytes[fragment.payloadRange])
                == Array(datagram[(index * 1_480) ..< min((index + 1) * 1_480, datagram.count)]))
        }
    }

    @Test("An IPv6 Fragment header gives the same facts, with its 32-bit identification")
    func ipv6FragmentFacts() throws {
        let datagram = IPFragmentFixture.response(port: 40_002, answers: 100)
        let fragments = IPFragmentFixture.ipv6Fragments(datagram)
        #expect(fragments.count == 2)
        let packet = SessionBuilder.decodePacket(
            IPFragmentFixture.frames([fragments[0]])[0],
            linkType: LinkType.ethernet
        )
        let fragment = try #require(packet.ipFragment)
        #expect(fragment.version == .v6)
        #expect(fragment.identification == 0xABCD0001)
        #expect(fragment.protocolNumber == 17)
        #expect(fragment.offset == 0 && fragment.moreFragments)
        #expect(packet.fiveTuple == nil)
    }

    @Test("An unfragmented datagram decodes exactly as before")
    func unfragmentedUnchanged() {
        let packet = SessionBuilder.decodePacket(
            IPFragmentFixture.frames([IPFragmentFixture.query()])[0], linkType: LinkType.ethernet
        )
        #expect(packet.ipFragment == nil)
        #expect(packet.appProtocol == .dns)
        #expect(packet.fiveTuple != nil)
    }
}

// MARK: - IPFragmentReassemblerTests

@Suite("IP fragments: the reassembler")
struct IPFragmentReassemblerTests {
    // MARK: Internal

    @Test("Fragments in order complete on the last; the datagram is byte-exact")
    func inOrder() throws {
        let datagram = IPFragmentFixture.response()
        var decoder = SequentialFrameDecoder()
        let packets = Self.decode(IPFragmentFixture.ipv4Fragments(datagram), with: &decoder)
        #expect(packets[0].reassembly == nil && packets[1].reassembly == nil)
        let completed = packets[2]
        let reassembly = try #require(completed.reassembly)
        #expect(reassembly.frames == [1, 2, 3])
        #expect(reassembly.length == datagram.count)
        #expect(completed.appProtocol == .dns)
        #expect(completed.fiveTuple?.proto == .udp)
        #expect(completed.reassembledUDPPayload == Array(datagram.dropFirst(8)))
        #expect(completed.udpPayloadRange == nil)
        // Layers built from the datagram carry no byte ranges into this frame.
        let reassembledLayers = completed.layers.drop { $0.title != "Reassembled IPv4 Datagram" }
        #expect(reassembledLayers.count >= 3)
        #expect(reassembledLayers.allSatisfy { $0.byteRange == nil && $0.fields.allSatisfy { $0.byteRange == nil } })
    }

    @Test("Fragments arriving last-first complete on the frame that fills the last gap")
    func outOfOrder() throws {
        let datagram = IPFragmentFixture.response()
        var decoder = SequentialFrameDecoder()
        let packets = Self.decode(IPFragmentFixture.ipv4Fragments(datagram).reversed(), with: &decoder)
        #expect(packets[0].reassembly == nil && packets[1].reassembly == nil)
        let reassembly = try #require(packets[2].reassembly)
        // In datagram order: the frame carrying offset 0 arrived third.
        #expect(reassembly.frames == [3, 2, 1])
        #expect(packets[2].reassembledUDPPayload == Array(datagram.dropFirst(8)))
    }

    @Test("A repeated identical fragment changes nothing")
    func duplicate() throws {
        let fragments = IPFragmentFixture.ipv4Fragments(IPFragmentFixture.response())
        var decoder = SequentialFrameDecoder()
        let packets = Self.decode([fragments[0], fragments[0], fragments[1], fragments[2]], with: &decoder)
        #expect(try #require(packets[3].reassembly).frames == [1, 3, 4])
    }

    @Test("Overlapping fragments that disagree are never rebuilt, nor are the rest of that datagram")
    func conflicting() {
        let datagram = IPFragmentFixture.response()
        var fragments = IPFragmentFixture.ipv4Fragments(datagram)
        var altered = Array(datagram[1_000 ..< 1_480])
        altered[0] ^= 0xFF
        fragments.insert(
            IPFragmentFixture.ipv4Fragment(altered, identification: 0x2001, offset: 1_000, more: true),
            at: 1
        )
        var decoder = SequentialFrameDecoder()
        let packets = Self.decode(fragments, with: &decoder)
        #expect(packets.allSatisfy { $0.reassembly == nil && $0.fiveTuple == nil })
        #expect(decoder.discards.conflicting == 1)
    }

    @Test("A missing fragment means no datagram")
    func missing() {
        let fragments = IPFragmentFixture.ipv4Fragments(IPFragmentFixture.response())
        var decoder = SequentialFrameDecoder()
        let packets = Self.decode([fragments[0], fragments[2]], with: &decoder)
        #expect(packets.allSatisfy { $0.reassembly == nil })
    }

    @Test("A fragment cut short by the snapshot length rules its datagram out")
    func truncated() {
        var fragments = IPFragmentFixture.ipv4Fragments(IPFragmentFixture.response())
        fragments[1] = Array(fragments[1].prefix(200))
        var decoder = SequentialFrameDecoder()
        let packets = Self.decode(fragments, with: &decoder)
        #expect(packets.allSatisfy { $0.reassembly == nil })
        #expect(decoder.discards.truncated == 1)
    }

    @Test("A datagram waiting past the timeout on the capture's clock is dropped")
    func expires() {
        let fragments = IPFragmentFixture.ipv4Fragments(IPFragmentFixture.response())
        var decoder = SequentialFrameDecoder()
        let frames = IPFragmentFixture.frames(fragments, spacing: 20)
        let packets = frames.enumerated().map { index, frame in
            decoder.decode(frame, linkType: LinkType.ethernet, ordinal: UInt64(index + 1))
        }
        #expect(packets.allSatisfy { $0.reassembly == nil })
        #expect(decoder.discards.expired == 1)
    }

    @Test("Past the pending bound the datagram that started first is dropped")
    func evicts() {
        var configuration = IPReassemblyConfiguration()
        configuration.maximumPendingDatagrams = 2
        var decoder = SequentialFrameDecoder(reassembly: configuration)
        let datagram = IPFragmentFixture.response()
        let first = IPFragmentFixture.ipv4Fragments(datagram, identification: 1)
        let second = IPFragmentFixture.ipv4Fragments(datagram, identification: 2)
        let third = IPFragmentFixture.ipv4Fragments(datagram, identification: 3)
        let packets = Self.decode([first[0], second[0], third[0]] + first.dropFirst(), with: &decoder)
        #expect(packets.allSatisfy { $0.reassembly == nil })
        // The third datagram pushes out the first; the first's later fragments then
        // open a new, incomplete entry that pushes out the second.
        #expect(decoder.discards.evicted == 2)
    }

    @Test("Without capture times a datagram still expires, by frame span")
    func expiresBySpanWithoutTimes() {
        var configuration = IPReassemblyConfiguration()
        configuration.maximumFrameSpan = 2
        var decoder = SequentialFrameDecoder(reassembly: configuration)
        let fragments = IPFragmentFixture.ipv4Fragments(IPFragmentFixture.response())
        let untimed = fragments.map { CapturedFrame(bytes: $0, timestamp: nil, originalLength: $0.count) }
        let filler = CapturedFrame(bytes: IPFragmentFixture.query(), timestamp: nil, originalLength: 71)
        let frames = [untimed[0], filler, filler, filler, untimed[1], untimed[2]]
        let packets = frames.enumerated().map { index, frame in
            decoder.decode(frame, linkType: LinkType.ethernet, ordinal: UInt64(index + 1))
        }
        #expect(packets.allSatisfy { $0.reassembly == nil })
        #expect(decoder.discards.expired == 1)
    }

    @Test("A datagram past 64 fragments is not rebuilt")
    func tooManyFragments() {
        let datagram = IPFragmentFixture.response(answers: 40)
        let fragments = IPFragmentFixture.ipv4Fragments(datagram, size: 8)
        #expect(fragments.count > 64)
        var decoder = SequentialFrameDecoder()
        let packets = Self.decode(fragments, with: &decoder)
        #expect(packets.allSatisfy { $0.reassembly == nil })
        #expect(decoder.discards.oversized == 1)
    }

    @Test("Overlapping fragments that agree keep only new bytes, so a datagram never holds more than itself")
    func overlapKeepsOnlyNewBytes() {
        let datagram = IPFragmentFixture.response()
        var fragments: [[UInt8]] = []
        // Fragments of 1,480 bytes starting every 8 bytes across the first 1,480:
        // each overlaps the others almost entirely.
        for offset in stride(from: 0, to: 1_480, by: 8) {
            let chunk = Array(datagram[offset ..< min(offset + 1_480, datagram.count)])
            fragments.append(IPFragmentFixture.ipv4Fragment(chunk, identification: 0x2001, offset: offset, more: true))
        }
        var decoder = SequentialFrameDecoder()
        _ = Self.decode(fragments.prefix(60), with: &decoder)
        #expect(decoder.retainedByteCount <= datagram.count)
        #expect(decoder.pendingDatagramCount == 1)
    }

    @Test("A key that failed gives itself back after a quiet stretch, so a reused identification rebuilds")
    func failedKeyIsReleased() throws {
        let datagram = IPFragmentFixture.response()
        let fragments = IPFragmentFixture.ipv4Fragments(datagram)
        var altered = fragments[1]
        altered[altered.count - 1] ^= 0xFF
        var configuration = IPReassemblyConfiguration()
        configuration.failedEntryQuietFrames = 1
        var decoder = SequentialFrameDecoder(reassembly: configuration)
        let filler = IPFragmentFixture.query()
        // A conflicting copy of the second fragment fails the first datagram.
        let packets = Self.decode(
            [fragments[1], altered, filler, filler] + fragments,
            with: &decoder
        )
        #expect(decoder.discards.conflicting == 1)
        #expect(try #require(packets.last).reassembly != nil)
    }

    @Test("Fragments that never complete stay bounded")
    func orphansStayBounded() {
        var decoder = SequentialFrameDecoder()
        let datagram = IPFragmentFixture.response()
        let orphans = (0 ..< 2_000).map { index in
            IPFragmentFixture.ipv4Fragment(
                Array(datagram.prefix(1_480)), identification: UInt16(index), offset: 0, more: true
            )
        }
        _ = Self.decode(orphans, with: &decoder)
        #expect(decoder.pendingDatagramCount <= 256)
        #expect(decoder.retainedByteCount <= 256 * 1_480)
    }

    @Test("An IPv6 datagram whose fragmentable part opens with Destination Options still reaches UDP")
    func ipv6ExtensionAfterFragment() throws {
        let udp = IPFragmentFixture.response(port: 40_002, answers: 100)
        // Destination Options (next header UDP, 8 bytes, PadN) before the UDP header.
        let datagram: [UInt8] = [17, 0, 1, 4, 0, 0, 0, 0] + udp
        var fragments: [[UInt8]] = []
        for offset in stride(from: 0, to: datagram.count, by: 1_232) {
            let chunk = Array(datagram[offset ..< min(offset + 1_232, datagram.count)])
            let more = offset + 1_232 < datagram.count
            let header: [UInt8] = [
                60,
                0,
                UInt8((offset / 8) >> 5),
                UInt8(((offset / 8) << 3) & 0xF8) | (more ? 1 : 0),
                0xAB,
                0xCD,
                0x00,
                0x02
            ]
            fragments.append(PacketBuilder.ethernetIPv6(
                nextHeader: 44, src: IPFragmentFixture.server6, dst: IPFragmentFixture.client6, payload: header + chunk
            ))
        }
        var decoder = SequentialFrameDecoder()
        let packets = Self.decode(fragments, with: &decoder)
        let completed = try #require(packets.last)
        #expect(completed.reassembly != nil)
        #expect(completed.fiveTuple?.proto == .udp)
        #expect(completed.appProtocol == .dns)
        #expect(completed.layers.contains { $0.title == "IPv6 Destination Options" && $0.byteRange == nil })
    }

    @Test("Statistics ▸ IP counts the completing frame by its own IP header")
    func ipStatisticsCountsCompletingFrame() throws {
        var decoder = SequentialFrameDecoder()
        let packets = Self.decode(IPFragmentFixture.ipv4Fragments(IPFragmentFixture.response()), with: &decoder)
        let fact = try #require(IPFrameFact(packets[2]))
        #expect(fact.source == IPFragmentFixture.server)
        #expect(fact.headers.count == 1)
        let ipv6 = Self.decode(
            IPFragmentFixture.ipv6Fragments(IPFragmentFixture.response(answers: 100)),
            with: &decoder
        )
        #expect(IPFrameFact(ipv6[0])?.source.hasPrefix("2001:db8") == true)
    }

    @Test("IPv6 fragments rebuild the same way")
    func ipv6() throws {
        let datagram = IPFragmentFixture.response(port: 40_002, answers: 100)
        var decoder = SequentialFrameDecoder()
        let packets = Self.decode(IPFragmentFixture.ipv6Fragments(datagram), with: &decoder)
        let reassembly = try #require(packets[1].reassembly)
        #expect(reassembly.version == .v6)
        #expect(reassembly.frames == [1, 2])
        #expect(packets[1].appProtocol == .dns)
        #expect(packets[1].layers.contains { $0.title == "Reassembled IPv6 Datagram" })
    }

    @Test("The completing frame names every fragment frame, with its locator, for the citation")
    func sourcesForCitation() {
        let fragments = IPFragmentFixture.ipv4Fragments(IPFragmentFixture.response())
        var decoder = SequentialFrameDecoder()
        let token = UUID()
        for (index, frame) in IPFragmentFixture.frames(fragments).enumerated() {
            _ = decoder.decode(
                frame, linkType: LinkType.ethernet, ordinal: UInt64(index + 1),
                locator: SessionEvidenceLocator(sourceToken: token, offset: UInt64(index * 100))
            )
        }
        #expect(decoder.lastReassembledFrom.map(\.ordinal.rawValue) == [1, 2, 3])
        #expect(decoder.lastReassembledFrom.compactMap(\.locator?.offset) == [0, 100, 200])
    }

    // MARK: Private

    private static func decode(
        _ bytes: some Collection<[UInt8]>,
        with decoder: inout SequentialFrameDecoder
    )
        -> [DecodedPacket]
    {
        IPFragmentFixture.frames(Array(bytes)).enumerated().map { index, frame in
            decoder.decode(frame, linkType: LinkType.ethernet, ordinal: UInt64(index + 1))
        }
    }
}

// MARK: - IPFragmentPathTests

/// Every reader of a capture rebuilds the datagram on the same frame, so sessions,
/// frames, Follow, exports and the inspector agree.
@Suite("IP fragments: every path agrees")
struct IPFragmentPathTests {
    // MARK: Internal

    @Test("Batch, live (in uneven batches) and saved-file folds give identical sessions")
    func replayEquivalence() async throws {
        let bytes = Self.capture()
        let frames = IPFragmentFixture.frames(bytes)
        let batchFold = SessionBuilder.buildDetailed(from: frames, linkType: LinkType.ethernet)
        let batch = batchFold.sessions

        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        var index = 0
        for size in [1, 2, 1, 3, 2] where index < frames.count {
            let end = min(index + size, frames.count)
            await engine.ingest(Array(frames[index ..< end]), linkType: LinkType.ethernet, epoch: 1)
            index = end
        }
        if index < frames.count {
            await engine.ingest(Array(frames[index...]), linkType: LinkType.ethernet, epoch: 1)
        }
        let live = try #require(await engine.snapshot(epoch: 1))
        let liveFold = try #require(await engine.detailedSnapshot(epoch: 1))
        #expect(liveFold.sessions == batchFold.sessions)
        #expect(liveFold.connections == batchFold.connections)
        #expect(liveFold.datagramEvidence == batchFold.datagramEvidence)
        #expect(liveFold.tlsEvidence == batchFold.tlsEvidence)

        // With locators, the completing response's evidence names every fragment.
        let located = LiveSessionEngine()
        await located.reset(epoch: 2)
        let token = UUID()
        let locators = frames.indices.map { SessionEvidenceLocator(sourceToken: token, offset: UInt64($0 * 2_000)) }
        #expect(await located.ingest(frames, linkType: LinkType.ethernet, epoch: 2, locators: locators))
        let locatedFold = try #require(await located.detailedSnapshot(epoch: 2))
        let response = try #require(locatedFold.datagramEvidence.summaries.flatMap(\.observations)
            .first { $0.provenance.ordinal.rawValue == 4 })
        #expect(response.provenance.reassembledFrom.map(\.ordinal.rawValue) == [2, 3, 4])
        #expect(response.provenance.reassembledFrom.compactMap(\.locator?.offset) == [2_000, 4_000, 6_000])

        let url = try IPFragmentFixture.writePcap(bytes)
        defer { try? FileManager.default.removeItem(at: url) }
        let saved = try SavedCaptureStreamLoader(contentsOf: url).load().sessions

        #expect(Self.shape(batch) == Self.shape(live))
        #expect(Self.shape(batch).map(\.packets) == Self.shape(saved).map(\.packets))
        #expect(Self.shape(batch).map(\.bytes) == Self.shape(saved).map(\.bytes))
        // Two DNS sessions, each a query and its completing response frame, as
        // Wireshark's UDP conversations count them.
        let dns = batch.filter { $0.protocolStack.contains(.dns) }
        #expect(dns.count == 2)
        #expect(dns.allSatisfy { $0.packetsUp + $0.packetsDown == 2 })
    }

    @Test("The frame list names fragments as Wireshark does and cites every fragment on the completing row")
    func frameList() throws {
        let url = try IPFragmentFixture.writePcap(Self.capture())
        defer { try? FileManager.default.removeItem(at: url) }
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let rows = try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID())
            .scan().rows
        #expect(rows[1].info == "Fragmented IP protocol (proto=UDP 17, off=0, ID=2001)")
        #expect(rows[1].sessionID == nil)
        #expect(rows[3].protocolName == "DNS")
        #expect(rows[3].provenance.reassembledFrom.map(\.ordinal.rawValue) == [2, 3, 4])
        #expect(rows[3].sessionID == rows[0].sessionID)
        // An IPv6 fragment shows its IPv6 addresses, not the Ethernet ones.
        #expect(rows[5].source.contains("2001:db8"))
    }

    @Test("Exporting a session keeps every fragment of its rebuilt datagram")
    func sessionExport() throws {
        let bytes = Self.capture()
        let url = try IPFragmentFixture.writePcap(bytes)
        defer { try? FileManager.default.removeItem(at: url) }
        let sessions = SessionBuilder.build(from: IPFragmentFixture.frames(bytes), linkType: LinkType.ethernet)
        let session = try #require(sessions.first { $0.protocolStack.contains(.dns) })

        let streamed = try SessionExporter.frames(matching: session.id, streamingFrom: url).frames
        #expect(streamed.map(\.bytes) == Array(bytes[0 ..< 4]))
        let inMemory = SessionExporter.frames(
            matching: session.id, in: IPFragmentFixture.frames(bytes), defaultLinkType: LinkType.ethernet
        )
        #expect(inMemory.map(\.bytes) == Array(bytes[0 ..< 4]))

        let output = FileManager.default.temporaryDirectory.appendingPathComponent("session-\(UUID().uuidString).pcap")
        defer { try? FileManager.default.removeItem(at: output) }
        let summary = try CaptureFrameExporter.export(
            from: url, scope: .sessions([session.id]), options: FrameExportOptions(format: .pcap), to: output
        )
        #expect(summary.writtenFrameCount == 4)
    }

    @Test("A session note lands on the frame that completes a datagram when that is the session's first frame")
    func sessionNoteOnCompletingFrame() throws {
        // One-way: only the fragmented response, no query.
        let bytes = IPFragmentFixture.ipv4Fragments(IPFragmentFixture.response())
        let url = try IPFragmentFixture.writePcap(bytes)
        defer { try? FileManager.default.removeItem(at: url) }
        let session = try #require(SessionBuilder.build(
            from: IPFragmentFixture.frames(bytes),
            linkType: LinkType.ethernet
        ).first)
        var options = FrameExportOptions()
        options.sessionFrameComments = [session.id: "Large response"]
        let output = FileManager.default.temporaryDirectory.appendingPathComponent("note-\(UUID().uuidString).pcapng")
        defer { try? FileManager.default.removeItem(at: output) }
        _ = try CaptureFrameExporter.export(from: url, scope: .wholeCapture, options: options, to: output)
        let reader = try CaptureStreamReader(contentsOf: output)
        var comments: [Bool] = []
        while case let .frame(event) = try reader.next() {
            comments.append(event.reference.hasComment)
        }
        #expect(comments == [false, false, true])
    }

    @Test("Follow UDP reads the rebuilt datagram's whole payload")
    func followDatagram() throws {
        let bytes = Self.capture()
        let url = try IPFragmentFixture.writePcap(bytes)
        defer { try? FileManager.default.removeItem(at: url) }
        let response = IPFragmentFixture.response()
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let packet = SessionBuilder.decodePacket(IPFragmentFixture.frames([bytes[0]])[0], linkType: LinkType.ethernet)
        let tuple = try #require(packet.fiveTuple)
        let result = try FollowDatagramReader(contentsOf: url, expectedIdentity: identity, tuple: tuple).read()
        let lengths = result.messages.map(\.capturedPayloadLength).sorted()
        #expect(lengths.last == response.count - 8)
    }

    @Test("Inspecting the completing frame alone shows the fragment; with its fragments, the datagram")
    func citedFrame() {
        let fragments = IPFragmentFixture.ipv4Fragments(IPFragmentFixture.response())
        var decoder = SequentialFrameDecoder()
        let frames = IPFragmentFixture.frames(fragments)
        for (index, frame) in frames.enumerated() {
            _ = decoder.decode(frame, linkType: LinkType.ethernet, ordinal: UInt64(index + 1))
        }
        let sources = decoder.lastReassembledFrom
        let cited = SessionFrameProvenance(
            ordinal: FrameOrdinal(3), timestamp: frames[2].timestamp, capturedLength: fragments[2].count,
            originalLength: fragments[2].count, linkType: LinkType.ethernet, reassembledFrom: sources
        )
        let alone = MainContentCoordinator.decodeCitedFrame(
            sessionID: UUID(), provenance: cited, bytes: fragments[2]
        )
        #expect(!alone.layers.contains { $0.proto == .dns })
        let rebuilt = MainContentCoordinator.decodeCitedFrame(
            sessionID: UUID(), provenance: cited, bytes: fragments[2],
            fragments: zip(sources, fragments).map { ($0, $1) }
        )
        #expect(rebuilt.layers.contains { $0.title == "Reassembled IPv4 Datagram" })
        #expect(rebuilt.layers.contains { $0.proto == .dns })
    }

    @Test("tshark reassembles on the same frames", .enabled(if: WiresharkOracle.tsharkURL != nil))
    func wiresharkParity() throws {
        let bytes = Self.capture()
        let url = try IPFragmentFixture.writePcap(bytes)
        defer { try? FileManager.default.removeItem(at: url) }
        let tshark = try #require(WiresharkOracle.tsharkURL)
        let process = Process()
        process.executableURL = tshark
        process.arguments = ["-r", url.path, "-Y", "dns.flags.response == 1", "-T", "fields", "-e", "frame.number"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        let oracle = (String(bytes: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "")
            .split(separator: "\n").compactMap { UInt64($0) }

        var decoder = SequentialFrameDecoder()
        let ours = IPFragmentFixture.frames(bytes).enumerated().compactMap { index, frame -> UInt64? in
            let packet = decoder.decode(frame, linkType: LinkType.ethernet, ordinal: UInt64(index + 1))
            return packet.dnsFacts?.isResponse == true ? UInt64(index + 1) : nil
        }
        #expect(ours == oracle)
    }

    // MARK: Private

    private struct Shape: Equatable {
        let id: UUID
        let packets: Int
        let bytes: Int
    }

    /// Query, three IPv4 fragments (frames 2–4); IPv6 query, two IPv6 fragments.
    private static func capture() -> [[UInt8]] {
        let query6 = PacketBuilder.ethernetIPv6(
            nextHeader: 17, src: IPFragmentFixture.client6, dst: IPFragmentFixture.server6,
            payload: PacketBuilder.udp(
                srcPort: 40_002,
                dstPort: 53,
                payload: PacketBuilder.dnsQuery(name: "big.example")
            )
        )
        return [IPFragmentFixture.query()]
            + IPFragmentFixture.ipv4Fragments(IPFragmentFixture.response())
            + [query6]
            + IPFragmentFixture.ipv6Fragments(IPFragmentFixture.response(port: 40_002, answers: 100))
    }

    private static func shape(_ sessions: [SessionSummary]) -> [Shape] {
        sessions.map { Shape(id: $0.id, packets: $0.packetsUp + $0.packetsDown, bytes: $0.bytesUp + $0.bytesDown) }
    }
}
