import Foundation
import Testing
@testable import Tracexy

// MARK: - SessionFrameScannerTests

/// The Frames facet's backend: matching by the fold's session identity, capture
/// order, direction, bounded retention, identity checks, cancellation, and parity
/// with `tshark` where Wireshark is installed.
struct SessionFrameScannerTests {
    // MARK: Internal

    @Test
    func listsEveryFrameOfATCPSessionInCaptureOrder() throws {
        let frames = ReplayCorpus.tcpConnectionFrames()
        try ReplayCorpus.withTemporaryFile(ReplayCorpus.classicPcapBytes(frames)) { url in
            let sessions = SessionBuilder.build(
                from: ReplayCorpus.tcpConnectionCapturedFrames(),
                linkType: LinkType.ethernet
            )
            let session = try #require(sessions.first { $0.protocolStack.contains(.tcp) })
            let expected = Self.expectedOrdinals(frames, sessionID: session.id)
            let result = try Self.scan(url, session: session)
            #expect(result.frames.map(\.ordinal) == expected)
            #expect(result.matchedFrameCount == expected.count)
            #expect(result.scannedFrameCount == frames.count)
            #expect(result.omittedFrameCount == 0)
            #expect(result.completeness == .complete)
            // Capture order, first frame at relative time 0, every later frame later.
            #expect(result.frames.first?.relativeTime == 0)
            #expect(result.frames.map(\.ordinal) == result.frames.map(\.ordinal).sorted())
            // A client-sent SYN is the first frame and is attributed to the client.
            #expect(result.frames.first?.direction == .clientToServer)
            #expect(result.frames.first?.tcpFlags?.contains(.syn) == true)
            #expect(result.frames.contains { $0.direction == .serverToClient })
            #expect(result.frames.allSatisfy { $0.provenance.locator != nil })
            #expect(result.frames.allSatisfy { !$0.summary.isEmpty })
        }
    }

    @Test
    func listsUDPSessionFramesToo() throws {
        let frames = ReplayCorpus.conversation()
        try ReplayCorpus.withTemporaryFile(ReplayCorpus.classicPcapBytes(frames)) { url in
            let sessions = SessionBuilder.build(
                from: ReplayCorpus.conversationCapturedFrames(),
                linkType: LinkType.ethernet
            )
            let dns = try #require(sessions.first { $0.protocolStack.contains(.dns) })
            let result = try Self.scan(url, session: dns)
            #expect(result.frames.map(\.ordinal) == Self.expectedOrdinals(frames, sessionID: dns.id))
            #expect(result.matchedFrameCount == 2)
        }
    }

    @Test
    func retentionIsBoundedAndOverflowIsCounted() throws {
        let frames = ReplayCorpus.tcpConnectionFrames()
        try ReplayCorpus.withTemporaryFile(ReplayCorpus.classicPcapBytes(frames)) { url in
            let sessions = SessionBuilder.build(
                from: ReplayCorpus.tcpConnectionCapturedFrames(),
                linkType: LinkType.ethernet
            )
            let session = try #require(sessions.first { $0.protocolStack.contains(.tcp) })
            let expected = Self.expectedOrdinals(frames, sessionID: session.id)
            let result = try Self.scan(url, session: session, configuration: .init(maxRetainedFrames: 2))
            #expect(result.frames.count == 2)
            #expect(result.frames.map(\.ordinal) == Array(expected.prefix(2)))
            #expect(result.matchedFrameCount == expected.count)
            #expect(result.omittedFrameCount == expected.count - 2)
        }
    }

    @Test
    func identityMismatchIsRefusedBeforeScanning() throws {
        try ReplayCorpus.withTemporaryFile(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())) { url in
            let stale = PcapFileIdentity(size: 1, modifiedAt: nil, device: 0, inode: 0)
            #expect(throws: FollowStreamError.identityMismatch) {
                try SessionFrameScanner(
                    contentsOf: url, expectedIdentity: stale, sessionID: UUID(), sourceToken: UUID(),
                    clientEndpoint: nil
                )
            }
        }
    }

    @Test
    func cancellationThrows() throws {
        let frames = ReplayCorpus.tcpConnectionFrames()
        try ReplayCorpus.withTemporaryFile(ReplayCorpus.classicPcapBytes(frames)) { url in
            let sessions = SessionBuilder.build(
                from: ReplayCorpus.tcpConnectionCapturedFrames(),
                linkType: LinkType.ethernet
            )
            let session = try #require(sessions.first)
            #expect(throws: CancellationError.self) {
                try Self.scan(url, session: session, configuration: .init(isCancelled: { true }))
            }
        }
    }

    @Test
    func truncatedTailIsReportedNotThrown() throws {
        var bytes = ReplayCorpus.classicPcapBytes(ReplayCorpus.tcpConnectionFrames())
        bytes.removeLast(9)
        try ReplayCorpus.withTemporaryFile(bytes) { url in
            let sessions = SessionBuilder.build(
                from: ReplayCorpus.tcpConnectionCapturedFrames(),
                linkType: LinkType.ethernet
            )
            let session = try #require(sessions.first { $0.protocolStack.contains(.tcp) })
            let result = try Self.scan(url, session: session)
            guard case .incompleteTruncatedTail = result.completeness else {
                Issue.record("expected truncated completeness")
                return
            }
        }
    }

    @Test
    func pcapngFramesCarryInterfaceAndComment() throws {
        try ReplayCorpus.withTemporaryFile(CaptureContainerFixtures.showcasePcapng(), ext: "pcapng") { url in
            let loaded = try SavedCaptureStreamLoader(contentsOf: url).load()
            let dns = try #require(loaded.sessions
                .first { $0.protocolStack.contains(.dns) && $0.captureInterfaceIDs == [0] })
            let result = try Self.scan(url, session: dns)
            #expect(result.frames.allSatisfy { $0.interfaceID == 0 })
            // Frame 2 of the corpus carries the fixture's comment; it belongs to the
            // ICMP session, so the DNS list has none.
            let dnsHasComment = result.frames.contains { $0.hasComment }
            #expect(!dnsHasComment)
            let icmp = try #require(loaded.sessions.first { $0.protocolStack.contains(.icmp) })
            let icmpFrames = try Self.scan(url, session: icmp)
            let icmpHasComment = icmpFrames.frames.contains { $0.hasComment }
            #expect(icmpHasComment)
        }
    }

    @Test(.enabled(if: WiresharkOracle.isAvailable, "Wireshark is not installed on this machine"))
    func tsharkAgreesOnTheTCPSessionFrames() throws {
        let frames = ReplayCorpus.tcpConnectionFrames()
        try ReplayCorpus.withTemporaryFile(ReplayCorpus.classicPcapBytes(frames)) { url in
            let sessions = SessionBuilder.build(
                from: ReplayCorpus.tcpConnectionCapturedFrames(),
                linkType: LinkType.ethernet
            )
            let session = try #require(sessions.first { $0.protocolStack.contains(.tcp) })
            let source = try #require(session.sourceEndpointValue)
            let destination = try #require(session.destinationEndpointValue)
            let filter = "ip.addr == \(source.ip) && ip.addr == \(destination.ip) "
                + "&& tcp.port == \(source.port) && tcp.port == \(destination.port)"
            let rows = try WiresharkOracle.tsharkFields(url, fields: ["frame.number"], filter: filter)
            let result = try Self.scan(url, session: session)
            #expect(rows.compactMap { $0.first.flatMap { UInt64($0) } } == result.frames.map(\.ordinal))
        }
    }

    // MARK: Private

    private static func scan(
        _ url: URL,
        session: SessionSummary,
        configuration: SessionFrameScanner.Configuration = .init()
    )
        throws -> SessionFramesResult
    {
        let handle = try FileHandle(forReadingFrom: url)
        let identity = PcapFileIdentity.snapshot(of: handle)
        try handle.close()
        let scanner = try SessionFrameScanner(
            contentsOf: url,
            expectedIdentity: identity,
            sessionID: session.id,
            sourceToken: SavedCaptureStreamLoader.sourceToken(for: identity),
            clientEndpoint: session.sourceEndpointValue,
            configuration: configuration
        )
        return try scanner.scan()
    }

    /// One-based ordinals of the corpus frames whose decoded tuple folds into `sessionID`.
    private static func expectedOrdinals(_ frames: [ReplayCorpus.Frame], sessionID: UUID) -> [UInt64] {
        frames.enumerated().compactMap { index, frame in
            let captured = CapturedFrame(
                bytes: frame.bytes,
                timestamp: frame.timestamp,
                originalLength: frame.bytes.count
            )
            let packet = SessionBuilder.decodePacket(captured, linkType: frame.linkType)
            guard let tuple = packet.fiveTuple, SessionBuilder.sessionID(for: tuple) == sessionID else {
                return nil
            }
            return UInt64(index + 1)
        }
    }
}
