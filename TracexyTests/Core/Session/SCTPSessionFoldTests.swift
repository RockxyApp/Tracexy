import Foundation
import Testing
@testable import Tracexy

/// SCTP folds into sessions exactly as TCP and UDP do: one session per endpoint
/// pair, bytes and packets split by direction, and status driven only by observed
/// control chunks. Nothing here claims association tracking or stream reassembly.
@Suite("SCTP session fold")
struct SCTPSessionFoldTests {
    // MARK: Internal

    @Test("both directions of an SCTP flow fold into one session with directional bytes")
    func foldsBothDirectionsIntoOneSession() throws {
        let out = frame(from: client, to: server, chunks: [dataChunk(tsn: 1)])
        let back = frame(from: server, to: client, chunks: [sackChunk()])
        let sessions = SessionBuilder.build(from: frames([out, back]), linkType: LinkType.ethernet)

        #expect(sessions.count == 1)
        let session = try #require(sessions.first)
        #expect(session.sourceEndpointValue == client)
        #expect(session.destinationEndpointValue == server)
        #expect(session.protocolStack.contains(.sctp))
        #expect(session.packetsUp == 1)
        #expect(session.packetsDown == 1)
        #expect(session.bytesUp == out.count)
        #expect(session.bytesDown == back.count)
        #expect(session.status == .ok)
    }

    @Test("a reversed first frame folds to the same session id as the forward one")
    func sessionIdentityIsDirectionIndependent() {
        let out = frame(from: client, to: server, chunks: [dataChunk(tsn: 1)])
        let back = frame(from: server, to: client, chunks: [sackChunk()])
        let forwardFirst = SessionBuilder.build(from: frames([out, back]), linkType: LinkType.ethernet)
        let reverseFirst = SessionBuilder.build(from: frames([back, out]), linkType: LinkType.ethernet)
        #expect(forwardFirst.map(\.id) == reverseFirst.map(\.id))
    }

    @Test("a different port pair is a different session")
    func separatePortPairsStaySeparateSessions() {
        let sessions = SessionBuilder.build(
            from: frames([
                frame(from: client, to: server, chunks: [dataChunk(tsn: 1)]),
                frame(
                    from: client, to: IPEndpoint(ip: server.ip, port: 9_999),
                    chunks: [dataChunk(tsn: 1)]
                ),
            ]),
            linkType: LinkType.ethernet
        )
        #expect(sessions.count == 2)
    }

    @Test("an observed ABORT chunk is the only thing that makes an SCTP session an error")
    func abortChunkIsTheErrorEvidence() {
        let orderly = SessionBuilder.build(
            from: frames([
                frame(from: client, to: server, chunks: [dataChunk(tsn: 1)]),
                frame(from: server, to: client, chunks: [chunk(type: SCTPChunkType.shutdown)]),
            ]),
            linkType: LinkType.ethernet
        )
        #expect(orderly.count == 1)
        #expect(orderly.first?.status == .ok, "a SHUTDOWN is an orderly close, not an error")

        let aborted = SessionBuilder.build(
            from: frames([
                frame(from: client, to: server, chunks: [dataChunk(tsn: 1)]),
                frame(from: server, to: client, chunks: [chunk(type: SCTPChunkType.abort)]),
            ]),
            linkType: LinkType.ethernet
        )
        #expect(aborted.count == 1)
        #expect(aborted.first?.status == .error)
    }

    @Test("typed chunk facts carry the common header and wire-order chunk types")
    func typedFactsCarryTheCommonHeader() throws {
        let packet = decode(frame(
            from: client, to: server,
            chunks: [dataChunk(tsn: 7), chunk(type: SCTPChunkType.abort)],
            verificationTag: 0xDEADBEEF
        ))
        let facts = try #require(packet.sctpFacts)
        #expect(facts.sourcePort == client.port)
        #expect(facts.destinationPort == server.port)
        #expect(facts.verificationTag == 0xDEADBEEF)
        #expect(facts.chunkTypes == [SCTPChunkType.data, SCTPChunkType.abort])
        #expect(facts.chunksOmitted == false)
        #expect(facts.containsAbort)
    }

    @Test("chunk facts stop at the retention limit and say so instead of claiming absence")
    func chunkFactsAreBounded() throws {
        let many = (0 ..< 70).map { _ in chunk(type: 3) } + [chunk(type: SCTPChunkType.abort)]
        let packet = decode(frame(from: client, to: server, chunks: many))
        let facts = try #require(packet.sctpFacts)
        #expect(facts.chunkTypes.count == 64)
        #expect(facts.chunksOmitted)
        #expect(
            facts.containsAbort == false,
            "an ABORT past the retention limit was never retained, so the facts must not claim it"
        )
        let sessions = SessionBuilder.build(
            from: frames([frame(from: client, to: server, chunks: many)]), linkType: LinkType.ethernet
        )
        #expect(sessions.first?.status == .ok)
    }

    @Test("a frame cut inside the SCTP common header folds no session and carries no facts")
    func truncatedCommonHeaderFoldsNothing() {
        let full = frame(from: client, to: server, chunks: [dataChunk(tsn: 1)])
        let cut = Array(full.prefix(34 + 8))
        let packet = decode(cut)
        #expect(packet.sctpFacts == nil)
        #expect(packet.fiveTuple == nil)
        #expect(SessionBuilder.build(
            from: [CapturedFrame(bytes: cut, timestamp: Self.start, originalLength: full.count)],
            linkType: LinkType.ethernet
        ).isEmpty)
    }

    @Test("an INIT chunk names the association opener even when the capture starts mid-flow")
    func initChunkOrientsTheSession() throws {
        // The first captured frame travels service → ephemeral, so without an
        // opener the port heuristic would call 2_905 the client. A later INIT from
        // the ephemeral side is real evidence and must win.
        let service = IPEndpoint(ip: "192.0.2.9", port: 2_905)
        let ephemeral = IPEndpoint(ip: "192.0.2.10", port: 50_000)
        let sessions = SessionBuilder.build(
            from: frames([
                frame(from: service, to: ephemeral, chunks: [sackChunk()]),
                frame(from: ephemeral, to: service, chunks: [chunk(type: SCTPChunkType.initiation)]),
            ]),
            linkType: LinkType.ethernet
        )
        #expect(sessions.count == 1)
        let session = try #require(sessions.first)
        #expect(session.sourceEndpointValue == ephemeral)
        #expect(session.destinationEndpointValue == service)
    }

    @Test("without an opener, a service-port-first SCTP flow still reads the service as the host")
    func servicePortFirstFlowFlipsWithoutAnOpener() throws {
        let service = IPEndpoint(ip: "192.0.2.9", port: 132)
        let ephemeral = IPEndpoint(ip: "192.0.2.10", port: 50_000)
        let sessions = SessionBuilder.build(
            from: frames([frame(from: service, to: ephemeral, chunks: [sackChunk()])]),
            linkType: LinkType.ethernet
        )
        let session = try #require(sessions.first)
        #expect(session.sourceEndpointValue == ephemeral)
        #expect(session.destinationEndpointValue == service)
    }

    @Test("Statistics ▸ IPv4 reads an SCTP frame's port type as SCTP")
    func portTypeReadsAsSCTP() throws {
        let fact = try #require(IPFrameFact(decode(frame(from: client, to: server, chunks: [dataChunk(tsn: 1)]))))
        #expect(fact.portType == "SCTP")
        #expect(fact.destinationPort == server.port)
    }

    // MARK: Private

    private static let start = Date(timeIntervalSince1970: 1_800_000_000)

    private let client = IPEndpoint(ip: "192.0.2.1", port: 5_000)
    private let server = IPEndpoint(ip: "192.0.2.2", port: 5_001)

    private func frames(_ list: [[UInt8]]) -> [CapturedFrame] {
        list.enumerated().map { offset, bytes in
            CapturedFrame(
                bytes: bytes,
                timestamp: Self.start.addingTimeInterval(Double(offset) / 10),
                originalLength: bytes.count,
                direction: offset.isMultiple(of: 2) ? .outbound : .inbound
            )
        }
    }

    private func decode(_ bytes: [UInt8]) -> DecodedPacket {
        PacketDecoder.decode(
            PacketBuffer(bytes), linkType: LinkType.ethernet, timestamp: Self.start, originalLength: bytes.count
        )
    }

    /// One chunk with no body beyond its fixed four-byte header.
    private func chunk(type: UInt8) -> [UInt8] {
        [type, 0] + SyntheticIPPacketEnvelope.word(4)
    }

    /// A SACK chunk (type 3) with the RFC 4960 §3.3.4 fixed fields and no blocks.
    private func sackChunk() -> [UInt8] {
        [3, 0] + SyntheticIPPacketEnvelope.word(16)
            + SyntheticIPPacketEnvelope.doubleWord(1)
            + SyntheticIPPacketEnvelope.doubleWord(0x1000)
            + [0, 0, 0, 0]
    }

    /// A DATA chunk (type 0) carrying five payload bytes and its fixed header.
    private func dataChunk(tsn: UInt32) -> [UInt8] {
        [0, 3] + SyntheticIPPacketEnvelope.word(21)
            + SyntheticIPPacketEnvelope.doubleWord(tsn)
            + [0, 0, 0, 0]
            + SyntheticIPPacketEnvelope.doubleWord(42)
            + Array("hello".utf8) + [0, 0, 0]
    }

    private func frame(
        from source: IPEndpoint,
        to destination: IPEndpoint,
        chunks: [[UInt8]],
        verificationTag: UInt32 = 0x12345678
    )
        -> [UInt8]
    {
        var sctp = SyntheticIPPacketEnvelope.word(Int(source.port))
            + SyntheticIPPacketEnvelope.word(Int(destination.port))
            + SyntheticIPPacketEnvelope.doubleWord(verificationTag)
            + [0, 0, 0, 0] + chunks.flatMap { $0 }
        let checksum = SCTPChecksum.value(sctp)
        sctp.replaceSubrange(8 ..< 12, with: SyntheticIPPacketEnvelope.doubleWord(checksum))
        let ip = SyntheticIPPacketEnvelope.ipHeader(
            source: SyntheticIPPacketEnvelope.address(source.ip, ipv6: false) ?? [],
            destination: SyntheticIPPacketEnvelope.address(destination.ip, ipv6: false) ?? [],
            transportLength: sctp.count, protocolNumber: 132, ipv6: false
        )
        return SyntheticIPPacketEnvelope.ethernetHeader(inbound: false, ipv6: false) + ip + sctp
    }
}
