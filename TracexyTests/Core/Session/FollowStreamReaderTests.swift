import Foundation
import Testing
@testable import Tracexy

// MARK: - FollowStreamReaderTests

/// The on-demand follow-stream reader must reconstruct one TCP conversation from a
/// stable saved source without ever touching the live spool: it decodes each
/// scanned frame once, folds only exact-tuple matches, honors first-observed bytes
/// under retransmission/overlap/reordering, enforces hard byte/run bounds, and
/// reports every truncation as a separate neutral limitation.
struct FollowStreamReaderTests {
    // MARK: Internal

    // MARK: - Two directions over classic PCAP

    @Test
    func classicPcapReconstructsBothDirections() throws {
        let request = Array("GET / HTTP/1.1".utf8)
        let response = Array("HTTP/1.1 200 OK".utf8)
        let frames = [
            Self.tcpFrame(client: true, seq: 1_000, payload: request),
            Self.tcpFrame(client: false, seq: 5_000, payload: response),
        ]
        try Self.withCapture(.pcap(frames)) { url, identity in
            let reader = try FollowStreamReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple
            )
            let result = try reader.read()

            #expect(result.format == .pcap)
            #expect(result.tuple == Self.tuple)
            #expect(result.scannedFrameCount == 2)
            #expect(result.matchedFrameCount == 2)
            #expect(result.completeness == .complete)
            #expect(result.limitations.isEmpty)

            // The client is the canonical `a` endpoint (10.0.0.5 < 203.0.113.9).
            #expect(result.aToB.anchorSequence == 1_000)
            #expect(result.aToB.runs == [
                FollowStreamRun(sequenceAnchor: 1_000, firstCaptureOrdinal: 1, bytes: request),
            ])
            #expect(result.aToB.retainedByteCount == request.count)
            #expect(result.bToA.anchorSequence == 5_000)
            #expect(result.bToA.runs == [
                FollowStreamRun(sequenceAnchor: 5_000, firstCaptureOrdinal: 2, bytes: response),
            ])
        }
    }

    // MARK: - PCAPNG

    @Test
    func pcapngReconstructsStream() throws {
        let request = Array("PING".utf8)
        let response = Array("PONG".utf8)
        let frames = [
            Self.tcpFrame(client: true, seq: 100, payload: request),
            Self.tcpFrame(client: false, seq: 200, payload: response),
        ]
        try Self.withCapture(.pcapng(frames)) { url, identity in
            let result = try FollowStreamReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple
            ).read()

            #expect(result.format == .pcapng)
            #expect(result.matchedFrameCount == 2)
            #expect(result.aToB.runs.map(\.bytes) == [request])
            #expect(result.bToA.runs.map(\.bytes) == [response])
            #expect(result.limitations.isEmpty)
        }
    }

    // MARK: - Unrelated tuple filtering

    @Test
    func unrelatedTupleFramesAreNotFolded() throws {
        let mine = Array("mine".utf8)
        let frames = [
            Self.tcpFrame(client: true, seq: 1_000, payload: mine),
            // A different conversation (other server port) sharing the file.
            Self.rawTCPFrame(
                src: "10.0.0.5", dst: "203.0.113.9", srcPort: 50_000, dstPort: 8_443,
                seq: 1_000, payload: Array("other".utf8)
            ),
        ]
        try Self.withCapture(.pcap(frames)) { url, identity in
            let result = try FollowStreamReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple
            ).read()

            #expect(result.scannedFrameCount == 2)
            #expect(result.matchedFrameCount == 1)
            #expect(result.aToB.runs.map(\.bytes) == [mine])
            #expect(result.bToA.runs.isEmpty)
        }
    }

    // MARK: - Retransmission does not duplicate bytes

    @Test
    func retransmittedBytesAreNotDuplicated() throws {
        let payload = Array("ABCD".utf8)
        let frames = [
            Self.tcpFrame(client: true, seq: 1_000, payload: payload),
            Self.tcpFrame(client: true, seq: 1_000, payload: payload),
        ]
        try Self.withCapture(.pcap(frames)) { url, identity in
            let result = try FollowStreamReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple
            ).read()

            #expect(result.matchedFrameCount == 2)
            #expect(result.aToB.runs.map(\.bytes) == [payload])
            #expect(result.aToB.retainedByteCount == 4)
            #expect(result.aToB.observedOmittedByteCount == 0)
            #expect(!result.limitations.contains(.overlapConflict))
        }
    }

    // MARK: - Conflicting overlap preserves first-observed bytes

    @Test
    func conflictingOverlapPreservesFirstObservedAndFlags() throws {
        let frames = [
            Self.tcpFrame(client: true, seq: 1_000, payload: Array("ABCD".utf8)),
            // Overlaps offsets 2..3 with disagreeing bytes and extends 4..5.
            Self.tcpFrame(client: true, seq: 1_002, payload: Array("XYZW".utf8)),
        ]
        try Self.withCapture(.pcap(frames)) { url, identity in
            let result = try FollowStreamReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple
            ).read()

            // First-observed C,D are kept; only the new Z,W are appended.
            #expect(result.aToB.runs.map(\.bytes) == [Array("ABCDZW".utf8)])
            #expect(result.aToB.retainedByteCount == 6)
            #expect(result.limitations.contains(.overlapConflict))
        }
    }

    // MARK: - Out-of-order arrival bridges into one contiguous run

    @Test
    func outOfOrderSegmentsBridgeIntoOneRun() throws {
        let frames = [
            Self.tcpFrame(client: true, seq: 1_000, payload: Array("AAAA".utf8)),
            Self.tcpFrame(client: true, seq: 1_008, payload: Array("CCCC".utf8)),
            Self.tcpFrame(client: true, seq: 1_004, payload: Array("BBBB".utf8)),
        ]
        try Self.withCapture(.pcap(frames)) { url, identity in
            let result = try FollowStreamReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple
            ).read()

            #expect(result.aToB.runs.map(\.bytes) == [Array("AAAABBBBCCCC".utf8)])
            #expect(result.aToB.retainedByteCount == 12)
            // The gap was bridged, so out-of-order is set but no gap remains.
            #expect(result.limitations.contains(.outOfOrder))
            #expect(!result.limitations.contains(.sequenceGap))
            // The bridging frame preserves the leading byte's first-observed ordinal.
            #expect(result.aToB.runs.first?.firstCaptureOrdinal == 1)
        }
    }

    // MARK: - Unfilled gap is a neutral sequence gap

    @Test
    func unfilledGapReportsSequenceGap() throws {
        let frames = [
            Self.tcpFrame(client: true, seq: 1_000, payload: Array("AAAA".utf8)),
            Self.tcpFrame(client: true, seq: 1_008, payload: Array("CCCC".utf8)),
        ]
        try Self.withCapture(.pcap(frames)) { url, identity in
            let result = try FollowStreamReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple
            ).read()

            #expect(result.aToB.runs.count == 2)
            #expect(result.aToB.retainedByteCount == 8)
            #expect(result.limitations.contains(.sequenceGap))
        }
    }

    // MARK: - Byte bound

    @Test
    func byteBoundLimitsRetentionAndCountsOmitted() throws {
        let frames = [
            Self.tcpFrame(client: true, seq: 1_000, payload: Array("ABCD".utf8)),
            Self.tcpFrame(client: true, seq: 1_004, payload: Array("EFGH".utf8)),
        ]
        try Self.withCapture(.pcap(frames)) { url, identity in
            let result = try FollowStreamReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple,
                configuration: .init(maxRetainedBytesPerDirection: 4)
            ).read()

            #expect(result.aToB.runs.map(\.bytes) == [Array("ABCD".utf8)])
            #expect(result.aToB.retainedByteCount == 4)
            #expect(result.aToB.observedOmittedByteCount == 4)
            #expect(result.limitations.contains(.byteRetentionTruncated))
        }
    }

    // MARK: - Run bound

    @Test
    func runBoundLimitsRetentionAndCountsOmitted() throws {
        let frames = [
            Self.tcpFrame(client: true, seq: 1_000, payload: Array("ABCD".utf8)),
            // Isolated from the first run (gap), so it would create a second run.
            Self.tcpFrame(client: true, seq: 1_008, payload: Array("EFGH".utf8)),
        ]
        try Self.withCapture(.pcap(frames)) { url, identity in
            let result = try FollowStreamReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple,
                configuration: .init(maxRunsPerDirection: 1)
            ).read()

            #expect(result.aToB.runs.map(\.bytes) == [Array("ABCD".utf8)])
            #expect(result.aToB.observedOmittedByteCount == 4)
            #expect(result.limitations.contains(.runRetentionTruncated))
        }
    }

    // MARK: - Serial ambiguity

    @Test
    func exactHalfSpaceDistanceIsSerialAmbiguous() throws {
        let anchored = Array("ABCD".utf8)
        let frames = [
            Self.tcpFrame(client: true, seq: 1_000, payload: anchored),
            // Exactly one serial half-space ahead of the anchor: unresolvable.
            Self.tcpFrame(client: true, seq: 1_000 &+ 0x80000000, payload: Array("ZZZZ".utf8)),
        ]
        try Self.withCapture(.pcap(frames)) { url, identity in
            let result = try FollowStreamReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple
            ).read()

            #expect(result.limitations.contains(.serialAmbiguous))
            // The ambiguous segment's bytes were not placed.
            #expect(result.aToB.runs.map(\.bytes) == [anchored])
            #expect(result.aToB.retainedByteCount == 4)
        }
    }

    // MARK: - Snaplen truncation

    @Test
    func snaplenTruncationIsFlagged() throws {
        let payload = Array("PAYLOAD".utf8)
        let frame = Self.tcpFrame(client: true, seq: 1_000, payload: payload)
        // Model a snaplen: claim a larger original on-wire length than captured.
        try Self.withCapture(.pcapRaw([(frame, UInt32(frame.count + 40))])) { url, identity in
            let result = try FollowStreamReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple
            ).read()

            #expect(result.matchedFrameCount == 1)
            #expect(result.limitations.contains(.capturedFrameTruncated))
            #expect(result.aToB.runs.map(\.bytes) == [payload])
        }
    }

    // MARK: - Truncated source tail

    @Test
    func truncatedSourceTailPreservesPriorFramesAndFlags() throws {
        let payload = Array("PRIOR".utf8)
        let frame = Self.tcpFrame(client: true, seq: 1_000, payload: payload)
        var bytes = Self.classicPcap([(frame, UInt32(frame.count))])
        // Append a complete record header declaring a payload that is absent.
        bytes += Self.leRecordHeader(tsSec: 9, tsFrac: 0, inclLen: 64, origLen: 64)
        bytes += [0x01, 0x02, 0x03, 0x04]
        try Self.withRawCapture(bytes, ext: "pcap") { url, identity in
            let result = try FollowStreamReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple
            ).read()

            #expect(result.completeness == .incompleteTruncatedTail(.partialBody))
            #expect(result.limitations.contains(.sourceTailTruncated))
            #expect(result.matchedFrameCount == 1)
            #expect(result.aToB.runs.map(\.bytes) == [payload])
        }
    }

    // MARK: - Identity mismatch

    @Test
    func identityMismatchThrows() throws {
        let frame = Self.tcpFrame(client: true, seq: 1_000, payload: Array("HELLO".utf8))
        try Self.withCapture(.pcap([frame])) { url, identity in
            let wrong = PcapFileIdentity(
                size: identity.size &+ 1,
                modifiedAt: identity.modifiedAt,
                device: identity.device,
                inode: identity.inode
            )
            #expect(throws: FollowStreamError.identityMismatch) {
                _ = try FollowStreamReader(contentsOf: url, expectedIdentity: wrong, tuple: Self.tuple)
            }
        }
    }

    @Test
    func sourceMutationDuringReadThrowsInsteadOfPublishing() throws {
        let frames = [
            Self.tcpFrame(client: true, seq: 1_000, payload: Array("ONE".utf8)),
            Self.tcpFrame(client: true, seq: 1_003, payload: Array("TWO".utf8)),
        ]
        try Self.withCapture(.pcap(frames)) { url, identity in
            let reader = try FollowStreamReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple,
                configuration: .init(progressStride: 1)
            )
            let mutationHandle = try FileHandle(forWritingTo: url)
            defer { try? mutationHandle.close() }
            var changed = false
            #expect(throws: FollowStreamError.identityMismatch) {
                _ = try reader.read { _ in
                    guard !changed else {
                        return
                    }
                    changed = true
                    _ = try? mutationHandle.seekToEnd()
                    try? mutationHandle.write(contentsOf: Data([0xAA]))
                }
            }
            #expect(changed)
        }
    }

    // MARK: - Non-TCP rejection

    @Test
    func nonTCPTupleThrows() throws {
        let frame = Self.tcpFrame(client: true, seq: 1_000, payload: Array("HELLO".utf8))
        try Self.withCapture(.pcap([frame])) { url, identity in
            let udpTuple = FiveTuple(
                proto: .udp,
                source: IPEndpoint(ip: "10.0.0.5", port: 50_000),
                destination: IPEndpoint(ip: "203.0.113.9", port: 443)
            )
            #expect(throws: FollowStreamError.tupleNotTCP) {
                _ = try FollowStreamReader(contentsOf: url, expectedIdentity: identity, tuple: udpTuple)
            }
        }
    }

    // MARK: - Cancellation publishes no result

    @Test
    func cancellationThrowsBeforeAnyResult() throws {
        let frame = Self.tcpFrame(client: true, seq: 1_000, payload: Array("HELLO".utf8))
        try Self.withCapture(.pcap([frame])) { url, identity in
            let reader = try FollowStreamReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple,
                configuration: .init(isCancelled: { true })
            )
            #expect(throws: CancellationError.self) {
                _ = try reader.read()
            }
        }
    }

    // MARK: - Deterministic repeated results

    @Test
    func repeatedReadsAreDeterministic() throws {
        let frames = [
            Self.tcpFrame(client: true, seq: 1_000, payload: Array("AAAA".utf8)),
            Self.tcpFrame(client: true, seq: 1_008, payload: Array("CCCC".utf8)),
            Self.tcpFrame(client: true, seq: 1_004, payload: Array("BBBB".utf8)),
            Self.tcpFrame(client: false, seq: 7_000, payload: Array("REPLY".utf8)),
        ]
        try Self.withCapture(.pcap(frames)) { url, identity in
            let first = try FollowStreamReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple
            ).read()
            let second = try FollowStreamReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple
            ).read()
            #expect(first == second)
        }
    }

    @Test
    func sequenceWrapAroundRemainsContiguous() throws {
        let first = Array("ABCD".utf8)
        let second = Array("EF".utf8)
        let frames = [
            Self.tcpFrame(client: true, seq: UInt32.max &- 1, payload: first),
            Self.tcpFrame(client: true, seq: 2, payload: second),
        ]
        try Self.withCapture(.pcap(frames)) { url, identity in
            let result = try FollowStreamReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple
            ).read()

            #expect(result.aToB.runs == [
                FollowStreamRun(
                    sequenceAnchor: UInt32.max &- 1,
                    firstCaptureOrdinal: 1,
                    bytes: first + second
                ),
            ])
            #expect(!result.limitations.contains(.serialAmbiguous))
            #expect(!result.limitations.contains(.sequenceGap))
        }
    }

    @Test
    func configurationClampsInternalAllocationCeilings() {
        let configuration = FollowStreamReader.Configuration(
            maxCapturedLength: .max,
            maxRetainedBytesPerDirection: .max,
            maxRunsPerDirection: .max
        )
        #expect(configuration.maxCapturedLength == CapturedFrame.maxReasonableLength)
        #expect(
            configuration.maxRetainedBytesPerDirection
                == FollowStreamReader.Configuration.maximumRetainedBytesPerDirection
        )
        #expect(
            configuration.maxRunsPerDirection
                == FollowStreamReader.Configuration.maximumRunsPerDirection
        )
    }

    // MARK: Private

    // MARK: Fixture kinds

    private enum CaptureKind {
        case pcap([[UInt8]])
        case pcapng([[UInt8]])
        /// Classic PCAP with an explicit original length per frame (snaplen tests).
        case pcapRaw([(captured: [UInt8], originalLength: UInt32)])
    }

    /// The canonical followed conversation: 10.0.0.5:50000 ↔ 203.0.113.9:443.
    /// 10.0.0.5 sorts before 203.0.113.9, so the client is the canonical `a`
    /// endpoint and client→server traffic is the `aToB` direction.
    private static let tuple = FiveTuple(
        proto: .tcp,
        source: IPEndpoint(ip: "10.0.0.5", port: 50_000),
        destination: IPEndpoint(ip: "203.0.113.9", port: 443)
    )

    // MARK: Frame builders

    private static func tcpFrame(client: Bool, seq: UInt32, payload: [UInt8]) -> [UInt8] {
        client
            ? rawTCPFrame(
                src: "10.0.0.5", dst: "203.0.113.9", srcPort: 50_000, dstPort: 443,
                seq: seq, payload: payload
            )
            : rawTCPFrame(
                src: "203.0.113.9", dst: "10.0.0.5", srcPort: 443, dstPort: 50_000,
                seq: seq, payload: payload
            )
    }

    private static func rawTCPFrame(
        src: String, dst: String, srcPort: UInt16, dstPort: UInt16, seq: UInt32, payload: [UInt8]
    )
        -> [UInt8]
    {
        PacketBuilder.ethernetIPv4(
            proto: 6, src: src, dst: dst,
            payload: PacketBuilder.tcp(
                srcPort: srcPort, dstPort: dstPort, flags: 0x18, payload: payload, sequence: seq
            )
        )
    }

    // MARK: Capture-file assembly

    private static func le16(_ value: UInt16) -> [UInt8] {
        [UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF)]
    }

    private static func le32(_ value: UInt32) -> [UInt8] {
        [UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF), UInt8((value >> 16) & 0xFF), UInt8((value >> 24) & 0xFF)]
    }

    private static func leRecordHeader(tsSec: UInt32, tsFrac: UInt32, inclLen: UInt32, origLen: UInt32) -> [UInt8] {
        le32(tsSec) + le32(tsFrac) + le32(inclLen) + le32(origLen)
    }

    /// A little-endian microsecond `.pcap` (Ethernet link type) wrapping each frame
    /// with an explicit original length, so a snaplen case can declare a larger
    /// on-wire length than the captured bytes.
    private static func classicPcap(_ records: [(captured: [UInt8], originalLength: UInt32)]) -> [UInt8] {
        var header: [UInt8] = [0xD4, 0xC3, 0xB2, 0xA1]
        header += le16(2) + le16(4)
        header += le32(0) + le32(0)
        header += le32(65_535)
        header += le32(LinkType.ethernet)
        var bytes = header
        for (index, record) in records.enumerated() {
            bytes += leRecordHeader(
                tsSec: UInt32(index + 1), tsFrac: 0,
                inclLen: UInt32(record.captured.count), origLen: record.originalLength
            )
            bytes += record.captured
        }
        return bytes
    }

    private static func pcapngFile(_ frames: [[UInt8]]) -> [UInt8] {
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: 1)
        for (index, frame) in frames.enumerated() {
            file += PcapngFixture.enhancedPacket(
                little: true, ticks: UInt64(index + 1) * 1_000_000, captured: frame
            )
        }
        return file
    }

    private static func bytes(for kind: CaptureKind) -> (bytes: [UInt8], ext: String) {
        switch kind {
        case let .pcap(frames):
            (classicPcap(frames.map { (captured: $0, originalLength: UInt32($0.count)) }), "pcap")
        case let .pcapng(frames):
            (pcapngFile(frames), "pcapng")
        case let .pcapRaw(records):
            (classicPcap(records), "pcap")
        }
    }

    // MARK: Temp-file harness

    private static func makeURL(ext: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("followstream-\(UUID().uuidString).\(ext)")
    }

    private static func withCapture(_ kind: CaptureKind, _ body: (URL, PcapFileIdentity) throws -> Void) throws {
        let assembled = bytes(for: kind)
        try withRawCapture(assembled.bytes, ext: assembled.ext, body)
    }

    private static func withRawCapture(
        _ bytes: [UInt8], ext: String, _ body: (URL, PcapFileIdentity) throws -> Void
    )
        throws
    {
        let url = makeURL(ext: ext)
        try Data(bytes).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        // The expected identity is the opened file's own identity — the coordinator
        // records this before scheduling a read.
        let identity = try CaptureStreamReader(contentsOf: url).identity
        try body(url, identity)
    }
}
