import Foundation
import Testing
@testable import Tracexy

// MARK: - SavedCaptureStreamLoaderTests

/// The saved loader must fold a file once, off-main-ready, into one result whose
/// sessions equal a batch build, whose evidence points at the exact representative
/// frame, and whose raw memory stays bounded to the retained window and activity
/// cap.
struct SavedCaptureStreamLoaderTests {
    // MARK: Internal

    // MARK: - Batch equivalence and cleared raw bytes

    @Test
    func sessionsEqualBatchBuildWithRepresentativeBytesCleared() throws {
        let frames: [(bytes: [UInt8], time: TimeInterval)] = [
            (
                PacketBuilder
                    .tlsClientHelloFrame(sni: "one.example", src: "10.0.0.5", dst: "203.0.113.1", srcPort: 40_001),
                1.0
            ),
            (
                PacketBuilder
                    .tlsClientHelloFrame(sni: "two.example", src: "10.0.0.5", dst: "203.0.113.2", srcPort: 40_002),
                2.0
            ),
            (
                PacketBuilder
                    .tlsClientHelloFrame(sni: "one.example", src: "10.0.0.5", dst: "203.0.113.1", srcPort: 40_001),
                3.0
            ),
        ]
        try Self.withPcap(frames) { url in
            let loader = try SavedCaptureStreamLoader(contentsOf: url)
            let result = try loader.load()

            // Baseline: the exact same file, decoded and folded by the batch builder.
            let fileFrames = try PcapReader.read(contentsOf: url).frames
            var batch = SessionBuilder.build(from: fileFrames, linkType: LinkType.ethernet)
            for index in batch.indices {
                batch[index].representativeBytes = []
            }

            #expect(result.sessions == batch)
            #expect(!result.sessions.isEmpty)
            #expect(!result.sessions.contains { !$0.representativeBytes.isEmpty })
            // Decoded layers/metadata are preserved even with raw bytes cleared.
            #expect(result.sessions.allSatisfy { !$0.decodedLayers.isEmpty })
            #expect(result.completeness == .complete)
            #expect(result.totalFrames == 3)
            #expect(result.defaultLinkType == LinkType.ethernet)
        }
    }

    // MARK: - Representative selection maps to evidence

    @Test
    func representativeSelectionChangesAndEvidenceReloadsExactBytes() throws {
        let syn = PacketBuilder.tcpSynFrame(src: "10.0.0.9", dst: "203.0.113.50", srcPort: 44_000, dstPort: 443)
        let hello = PacketBuilder.tlsClientHelloFrame(
            sni: "rep.example",
            src: "10.0.0.9",
            dst: "203.0.113.50",
            srcPort: 44_000
        )
        // Same five-tuple: the SYN opens the session as its representative, then the
        // richer ClientHello displaces it, so the evidence must point at the hello.
        try Self.withPcap([(syn, 1.0), (hello, 2.0)]) { url in
            let loader = try SavedCaptureStreamLoader(contentsOf: url)
            let result = try loader.load()

            guard let session = result.sessions.first(where: { $0.host == "rep.example" }),
                  let reference = result.evidence[session.id] else
            {
                Issue.record("missing rep.example session or its evidence")
                return
            }
            #expect(result.evidence.count == 1)
            #expect(reference.originalLength == hello.count)
            #expect(reference.linkType == LinkType.ethernet)

            let bytes = try CaptureEvidenceReader.read(reference, from: url)
            #expect(bytes == hello) // the hello, not the SYN
        }
    }

    // MARK: - Evidence reopen rejects a changed file

    @Test
    func evidenceReopenRejectsReplacementTruncationAndOverLimit() throws {
        let hello = PacketBuilder.tlsClientHelloFrame(
            sni: "guard.example",
            src: "10.0.0.1",
            dst: "203.0.113.7",
            srcPort: 41_000
        )
        let url = try Self.makeURL()
        defer { try? FileManager.default.removeItem(at: url) }
        try Data(Self.pcapBytes([(hello, 1.0)])).write(to: url)

        let loader = try SavedCaptureStreamLoader(contentsOf: url)
        let result = try loader.load()
        guard let session = result.sessions.first, let reference = result.evidence[session.id] else {
            Issue.record("missing session/evidence")
            return
        }
        // A clean reopen works before the file changes.
        #expect(try CaptureEvidenceReader.read(reference, from: url) == hello)

        // Over-limit captured length is rejected on bounds alone, before any read.
        #expect(throws: PacketError.self) {
            _ = try CaptureEvidenceReader.read(reference, from: url, maxCapturedLength: 4)
        }

        let impossibleLengths = CaptureEvidenceReference(
            identity: reference.identity,
            payloadOffset: reference.payloadOffset,
            capturedLength: reference.capturedLength,
            originalLength: reference.capturedLength - 1,
            timestamp: reference.timestamp,
            linkType: reference.linkType
        )
        #expect(throws: PacketError.self) {
            _ = try CaptureEvidenceReader.read(impossibleLengths, from: url)
        }

        // Replacement with different content/size fails identity revalidation.
        let other = PacketBuilder.tlsClientHelloFrame(
            sni: "different.example",
            src: "10.0.0.1",
            dst: "203.0.113.8",
            srcPort: 41_050
        )
        try Data(Self.pcapBytes([(other, 5.0), (other, 6.0)])).write(to: url)
        #expect(throws: PacketError.self) {
            _ = try CaptureEvidenceReader.read(reference, from: url)
        }

        // Truncation to an empty file also fails (size no longer matches).
        try Data([UInt8]()).write(to: url)
        #expect(throws: (any Error).self) {
            _ = try CaptureEvidenceReader.read(reference, from: url)
        }
    }

    // MARK: - Bounded retained tail

    @Test
    func retainedTailHonoursCapacityAndReportsEviction() throws {
        let frames = (0 ..< 5).map { index in
            (PacketBuilder.tlsClientHelloFrame(
                sni: "s\(index).example", src: "10.0.0.5", dst: "203.0.113.\(index + 1)",
                srcPort: UInt16(40_100 + index)
            ), Double(index) + 1)
        }
        try Self.withPcap(frames) { url in
            let loader = try SavedCaptureStreamLoader(contentsOf: url, configuration: .init(retainedCapacity: 2))
            let result = try loader.load()
            #expect(result.totalFrames == 5)
            // The window keeps only the last two frames; the earlier three are
            // reported as local inspection-window eviction, not capture loss.
            #expect(result.retainedTail.count == 2)
            #expect(result.retainedTail.evictionCount == 3)
        }
    }

    // MARK: - Bounded activity with exact totals

    @Test
    func activityStaysBoundedWhileTotalsAndDurationAreExact() throws {
        let frames = (0 ..< 40).map { index in
            (PacketBuilder.tlsClientHelloFrame(
                sni: "a.example", src: "10.0.0.5", dst: "203.0.113.1", srcPort: 40_001
            ), Double(index))
        }
        let expectedBytes = frames.reduce(0) { $0 + $1.0.count }
        try Self.withPcap(frames) { url in
            let loader = try SavedCaptureStreamLoader(contentsOf: url, configuration: .init(activityBucketCap: 8))
            let result = try loader.load()
            #expect(result.activity.buckets.count <= 8)
            #expect(result.activity.totalFrames == 40)
            #expect(result.activity.totalBytes == expectedBytes)
            #expect(abs(result.activity.duration - 39) < 1e-6)
            // Per-bucket totals conserve the exact frame/byte totals.
            #expect(result.activity.buckets.reduce(0) { $0 + $1.frameCount } == 40)
            #expect(result.activity.buckets.reduce(0) { $0 + $1.byteCount } == expectedBytes)
        }
    }

    // MARK: - Cancellation publishes no result

    @Test
    func cancellationThrowsBeforeAnyResult() throws {
        let frames = [(
            PacketBuilder.tlsClientHelloFrame(sni: "c.example", src: "10.0.0.5", dst: "203.0.113.1", srcPort: 40_001),
            1.0
        )]
        try Self.withPcap(frames) { url in
            let loader = try SavedCaptureStreamLoader(contentsOf: url, configuration: .init(isCancelled: { true }))
            #expect(throws: CancellationError.self) {
                _ = try loader.load()
            }
        }
    }

    // MARK: - Truncated tail preserves prior sessions

    @Test
    func truncatedTailPublishesPriorSessionsWithIncompleteness() throws {
        let hello = PacketBuilder.tlsClientHelloFrame(
            sni: "prior.example",
            src: "10.0.0.5",
            dst: "203.0.113.1",
            srcPort: 40_001
        )
        var file = Self.pcapBytes([(hello, 1.0)])
        // Append a complete record header declaring a payload that is not present.
        file += Self.leRecordHeader(tsSec: 2, tsFrac: 0, inclLen: 64, origLen: 64)
        file += [0x01, 0x02, 0x03, 0x04]
        try Self.withRawPcap(file) { url in
            let loader = try SavedCaptureStreamLoader(contentsOf: url)
            let result = try loader.load()
            #expect(result.completeness == .incompleteTruncatedTail(.partialBody))
            #expect(result.sessions.contains { $0.host == "prior.example" })
            #expect(result.totalFrames == 1)
        }
    }

    // MARK: - Over-limit safety

    @Test
    func overLimitCapturedLengthThrowsFromLoad() throws {
        let hello = PacketBuilder.tlsClientHelloFrame(
            sni: "big.example",
            src: "10.0.0.5",
            dst: "203.0.113.1",
            srcPort: 40_001
        )
        try Self.withPcap([(hello, 1.0)]) { url in
            let loader = try SavedCaptureStreamLoader(contentsOf: url, configuration: .init(maxCapturedLength: 4))
            #expect(throws: PacketError.self) {
                _ = try loader.load()
            }
        }
    }

    // MARK: - Mixed-interface pcapng

    @Test
    func mixedInterfacePcapngDecodesEachFrameUnderItsOwnLinkType() throws {
        let ethFrame = PacketBuilder.tlsClientHelloFrame(
            sni: "eth.example",
            src: "10.0.0.5",
            dst: "203.0.113.1",
            srcPort: 40_001
        )
        // A Raw (link type 101) frame is an IPv4 packet with no Ethernet header.
        let rawFrame = Array(ethFrame.dropFirst(14))

        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1) // Ethernet
        file += PcapngFixture.interfaceDescription(little: true, linkType: 101) // Raw IPv4
        file += PcapngFixture.enhancedPacket(little: true, interfaceID: 0, ticks: 1_000_000, captured: ethFrame)
        file += PcapngFixture.enhancedPacket(little: true, interfaceID: 1, ticks: 2_000_000, captured: rawFrame)

        try Self.withRawPcap(file, ext: "pcapng") { url in
            let loader = try SavedCaptureStreamLoader(contentsOf: url)
            let result = try loader.load()
            #expect(result.format == .pcapng)
            #expect(result.totalFrames == 2)
            #expect(result.completeness == .complete)
            // Both frames decoded to TLS despite different link types (Ethernet vs
            // Raw IPv4), proving per-frame link type was honoured.
            #expect(result.sessions.contains { $0.host == "eth.example" })
            #expect(result.sessions.allSatisfy { $0.protocolStack.contains(.tls) })
            for session in result.sessions {
                let reference = try #require(result.evidence[session.id])
                #expect([1, 101].contains(reference.linkType))
            }
        }
    }

    @Test
    func pcapngWithoutAnInterfaceFailsClosed() throws {
        let file = PcapngFixture.sectionHeader(little: true)
        try Self.withRawPcap(file, ext: "pcapng") { url in
            let loader = try SavedCaptureStreamLoader(contentsOf: url)
            #expect(throws: PacketError.self) {
                _ = try loader.load()
            }
        }
    }

    // MARK: - Connection snapshot folded alongside sessions

    @Test
    func loadFoldsConnectionSnapshotAlongsideSessions() throws {
        try Self.withRawPcap(ReplayCorpus.classicPcapBytes(ReplayCorpus.tcpConnectionFrames())) { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            #expect(!result.connections.summaries.isEmpty)
            // The passive fold ran over the saved frames: a validated handshake and
            // an observed reset are both present in the same load.
            #expect(result.connections.summaries.contains { $0.handshake == .threeWayObserved })
            #expect(result.connections.summaries.contains { $0.closeReason != nil })
            // Sessions are still produced alongside the connection snapshot.
            #expect(!result.sessions.isEmpty)
        }
    }

    // MARK: - Connection analysis assessed over the exact returned connections

    @Test
    func loadAssessesConnectionAnalysisOverItsExactConnections() throws {
        try Self.withRawPcap(ReplayCorpus.classicPcapBytes(ReplayCorpus.tcpConnectionFrames())) { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            // The result's analysis is exactly a production assessment of the exact
            // connection snapshot the same result returned.
            #expect(result.connectionAnalysis == ConnectionAssessor().assess(result.connections))
            // The corpus actually produces findings, so the equality is not vacuous.
            #expect(!result.connectionAnalysis.findings.isEmpty)
        }
    }

    // MARK: - Datagram evidence folded from the one final fold

    @Test
    func loadFoldsDatagramEvidenceFromItsOneFinalFold() throws {
        try Self.withRawPcap(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())) { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            let datagram = result.datagramEvidence
            // The primary conversation has UDP DNS (v4 + v6) and one ICMP echo.
            #expect(datagram.summaries.count == 3)
            #expect(datagram.retainedObservationCount == 5)
            #expect(datagram.excludedTCPDNSFactCount == 0)
            #expect(!datagram.capacityReached)

            // The returned evidence is exactly a batch fold of the same file frames
            // (locator-independent shape): same session ids and retained totals — the
            // loader surfaced its one fold's datagram table, not a re-derivation.
            let fileFrames = try PcapReader.read(contentsOf: url).frames
            let batch = SessionBuilder.buildDetailed(from: fileFrames, linkType: LinkType.ethernet).datagramEvidence
            #expect(batch.retainedObservationCount == datagram.retainedObservationCount)
            #expect(Set(batch.summaries.map(\.sessionID)) == Set(datagram.summaries.map(\.sessionID)))
        }
    }

    @Test
    func loadOfDatagramFreeCaptureReturnsEmptyEvidence() throws {
        // A single TLS-over-TCP frame carries no UDP DNS / ICMP fact.
        let tls = PacketBuilder.tlsClientHelloFrame(
            sni: "none.example", src: "10.0.0.5", dst: "203.0.113.1", srcPort: 40_001
        )
        try Self.withPcap([(tls, 1.0)]) { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            #expect(result.datagramEvidence == .empty)
        }
    }

    // MARK: - TLS evidence folded from the one final fold

    @Test
    func loadFoldsTLSEvidenceFromItsOneFinalFold() throws {
        try Self.withRawPcap(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())) { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            let tls = result.tlsEvidence
            // The primary conversation's split TLS ClientHello: one flow, one retained
            // direct fragment record, one excluded recovered multi-frame record.
            #expect(tls.summaries.count == 1)
            #expect(tls.retainedObservationCount == 1)
            #expect(tls.excludedReassembledRecordCount == 1)
            #expect(tls.recoveredTruncationIndicatorCount == 0)
            #expect(!tls.capacityReached)
            // The single retained observation is the honest direct fragment, never the
            // recovered complete record.
            let observation = try #require(tls.summaries.first?.observations.first)
            #expect(observation.fact.bodyComplete == false)

            // The returned evidence is exactly a batch fold of the same file frames
            // (locator-independent shape): same session ids and retained/excluded totals.
            let fileFrames = try PcapReader.read(contentsOf: url).frames
            let batch = SessionBuilder.buildDetailed(from: fileFrames, linkType: LinkType.ethernet).tlsEvidence
            #expect(batch.retainedObservationCount == tls.retainedObservationCount)
            #expect(batch.excludedReassembledRecordCount == tls.excludedReassembledRecordCount)
            #expect(Set(batch.summaries.map(\.sessionID)) == Set(tls.summaries.map(\.sessionID)))
        }
    }

    @Test
    func loadOfTLSFreeCaptureReturnsEmptyTLSEvidence() throws {
        // A single UDP DNS frame carries no TLS record.
        let dns = PacketBuilder.dnsQueryFrame(name: "none.example", src: "10.0.0.5", dst: "203.0.113.53")
        try Self.withPcap([(dns, 1.0)]) { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            #expect(result.tlsEvidence == .empty)
        }
    }

    // MARK: - Datagram analysis assessed over the exact returned datagram evidence

    @Test
    func loadAssessesDatagramAnalysisOverItsExactDatagramEvidence() throws {
        try Self.withRawPcap(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())) { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            // The result's datagram analysis is exactly a production assessment of the
            // exact datagram evidence the same result returned.
            #expect(result.datagramAnalysis == DatagramAssessor().assess(result.datagramEvidence))
            // Not vacuous: the conversation retains DNS + ICMP observations, so the
            // propagated coverage counters are non-zero (no TC maps to a finding here).
            #expect(result.datagramAnalysis.retainedInputObservationCount == 5)
            #expect(result.datagramAnalysis.retainedICMPObservationCount > 0)
            #expect(result.datagramAnalysis.findings.isEmpty)
        }
    }

    @Test
    func loadDatagramAnalysisIsNonVacuousWithTruncatedDNSResponse() throws {
        // Set the DNS TC bit on the generated IPv4 UDP-DNS response frame so the saved
        // datagram analysis carries one real `dnsTruncationIndicated` note.
        let frames = Self.conversationWithTruncatedDNSResponse()
        try Self.withRawPcap(ReplayCorpus.classicPcapBytes(frames)) { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            #expect(result.datagramAnalysis == DatagramAssessor().assess(result.datagramEvidence))
            // Exactly one TC note, always a `note` severity, mapped from the mutation.
            let tcFindings = result.datagramAnalysis.findings.filter { $0.kind == .dnsTruncationIndicated }
            #expect(tcFindings.count == 1)
            #expect(result.datagramAnalysis.findings.allSatisfy { $0.severity == .note })
        }
    }

    // MARK: Private

    /// The primary conversation with the DNS TC (truncation) bit set on the first
    /// generated IPv4 UDP-DNS *response* frame. A local, test-only byte mutation: it
    /// locates the fixed DNS header signature (id `0x1234`, flags `0x8180` —
    /// response/RD/RA with TC clear) and ORs `0x02` into the flags high byte
    /// (`0x8180 -> 0x8380`). It adds no production decoder/builder API and changes no
    /// corpus or goldens.
    private static func conversationWithTruncatedDNSResponse() -> [ReplayCorpus.Frame] {
        let signature: [UInt8] = [0x12, 0x34, 0x81, 0x80]
        var frames = ReplayCorpus.conversation()
        for index in frames.indices {
            guard let start = indexOfSubsequence(signature, in: frames[index].bytes) else {
                continue
            }
            var bytes = frames[index].bytes
            bytes[start + 2] |= 0x02
            frames[index] = ReplayCorpus.Frame(
                bytes: bytes, offsetSeconds: frames[index].offsetSeconds, linkType: frames[index].linkType
            )
            break // only the first (IPv4) DNS response
        }
        return frames
    }

    private static func indexOfSubsequence(_ needle: [UInt8], in haystack: [UInt8]) -> Int? {
        guard !needle.isEmpty, haystack.count >= needle.count else {
            return nil
        }
        for start in 0 ... (haystack.count - needle.count)
            where Array(haystack[start ..< start + needle.count]) == needle
        {
            return start
        }
        return nil
    }

    private static func le32(_ value: UInt32) -> [UInt8] {
        [UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF), UInt8((value >> 16) & 0xFF), UInt8((value >> 24) & 0xFF)]
    }

    private static func le16(_ value: UInt16) -> [UInt8] {
        [UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF)]
    }

    private static func leRecordHeader(tsSec: UInt32, tsFrac: UInt32, inclLen: UInt32, origLen: UInt32) -> [UInt8] {
        le32(tsSec) + le32(tsFrac) + le32(inclLen) + le32(origLen)
    }

    /// A little-endian microsecond `.pcap` with Ethernet link type wrapping each
    /// frame at its given capture time.
    private static func pcapBytes(_ frames: [(bytes: [UInt8], time: TimeInterval)]) -> [UInt8] {
        var header: [UInt8] = [0xD4, 0xC3, 0xB2, 0xA1]
        header += le16(2) + le16(4)
        header += le32(0) + le32(0)
        header += le32(65_535)
        header += le32(LinkType.ethernet)
        var bytes = header
        for frame in frames {
            let seconds = UInt32(frame.time.rounded(.down))
            let micros = UInt32(((frame.time - Double(seconds)) * 1_000_000).rounded())
            let length = UInt32(frame.bytes.count)
            bytes += leRecordHeader(tsSec: seconds, tsFrac: micros, inclLen: length, origLen: length)
            bytes += frame.bytes
        }
        return bytes
    }

    private static func makeURL(ext: String = "pcap") throws -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("savedloader-\(UUID().uuidString).\(ext)")
    }

    private static func withPcap(
        _ frames: [(bytes: [UInt8], time: TimeInterval)],
        _ body: (URL) throws -> Void
    )
        throws
    {
        try withRawPcap(pcapBytes(frames), body)
    }

    private static func withRawPcap(_ bytes: [UInt8], ext: String = "pcap", _ body: (URL) throws -> Void) throws {
        let url = try makeURL(ext: ext)
        try Data(bytes).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        try body(url)
    }
}
