import Foundation
import Testing
@testable import Tracexy

/// Follow Stream's "Filter Out This Stream" keeps every session except the
/// followed one, and each run shows its offset from the stream's first frame.
struct FollowStreamFilterOutTests {
    // MARK: Internal

    @Test
    func filterOutKeepsEveryOtherSession() throws {
        let tuple = FiveTuple(
            proto: .tcp,
            source: IPEndpoint(ip: "192.0.2.10", port: 52_100),
            destination: IPEndpoint(ip: "198.51.100.7", port: 80)
        )
        let term = FollowStreamExport.filterOutTerm(tuple)
        #expect(term == "not (tcp and ((source.ip == 192.0.2.10 and source.port == 52100 and "
            + "destination.ip == 198.51.100.7 and destination.port == 80) or "
            + "(source.ip == 198.51.100.7 and source.port == 80 and "
            + "destination.ip == 192.0.2.10 and destination.port == 52100)))")

        let frames = [
            PacketBuilder.httpRequestFrame(host: "a.test", path: "/", src: "192.0.2.10", dst: "198.51.100.7"),
            PacketBuilder.httpRequestFrame(host: "b.test", path: "/", src: "192.0.2.10", dst: "198.51.100.8"),
        ]
        let sessions = SessionBuilder.build(
            from: frames.enumerated().map { index, bytes in
                CapturedFrame(
                    bytes: bytes, timestamp: Date(timeIntervalSince1970: 1_700_000_000 + Double(index)),
                    originalLength: bytes.count, capturedLength: bytes.count, linkType: LinkType.ethernet
                )
            },
            linkType: LinkType.ethernet
        )
        let engine = InvestigationQueryEngine()
        let snapshot = InvestigationSnapshot(
            fold: SessionFoldSnapshot(
                sessions: sessions, connections: .empty, datagramEvidence: .empty, tlsEvidence: .empty,
                segmentSeries: .empty
            ),
            connectionAssessor: ConnectionAssessor(),
            datagramAssessor: DatagramAssessor()
        )
        let result = try engine.evaluate(engine.compile(SessionQueryParser().parse(term)), over: snapshot)
        #expect(result.matched.map(\.host) == ["b.test"])
    }

    @Test
    func filterOutPreservesTransportAndEndpointPortPairing() throws {
        let tuple = FiveTuple(
            proto: .tcp,
            source: IPEndpoint(ip: "192.0.2.10", port: 52_100),
            destination: IPEndpoint(ip: "198.51.100.7", port: 80)
        )
        let packets = try [
            synthetic(.tcp, source: "192.0.2.10", sourcePort: 52_100, destination: "198.51.100.7", destinationPort: 80),
            synthetic(.tcp, source: "198.51.100.7", sourcePort: 80, destination: "192.0.2.10", destinationPort: 52_100),
            synthetic(.tcp, source: "192.0.2.10", sourcePort: 80, destination: "198.51.100.7", destinationPort: 52_100),
            synthetic(.udp, source: "192.0.2.10", sourcePort: 52_100, destination: "198.51.100.7", destinationPort: 80),
        ].flatMap { $0 }
        let sessions = SessionBuilder.build(from: packets, linkType: LinkType.ethernet)
        let snapshot = InvestigationSnapshot(
            fold: SessionFoldSnapshot(
                sessions: sessions, connections: .empty, datagramEvidence: .empty, tlsEvidence: .empty,
                segmentSeries: .empty
            ),
            connectionAssessor: ConnectionAssessor(),
            datagramAssessor: DatagramAssessor()
        )
        let engine = InvestigationQueryEngine()
        let result = try engine.evaluate(engine.compile(SessionQueryParser().parse(
            FollowStreamExport.filterOutTerm(tuple)
        )), over: snapshot)

        let otherPair = FiveTuple(
            proto: .tcp,
            source: IPEndpoint(ip: "192.0.2.10", port: 80),
            destination: IPEndpoint(ip: "198.51.100.7", port: 52_100)
        )
        let otherTransport = FiveTuple(proto: .udp, source: tuple.a, destination: tuple.b)
        #expect(sessions.count == 3)
        #expect(result.matched.count == 2)
        #expect(Set(result.matched.map(\.id)) == Set([
            SessionBuilder.sessionID(for: otherPair), SessionBuilder.sessionID(for: otherTransport),
        ]))
        // Without a SYN, the fold orients service-to-ephemeral traffic toward the
        // service endpoint; filtering must preserve its exact IP-port pairing.
        let preserved = try #require(result.matched.first { $0.id == SessionBuilder.sessionID(for: otherPair) })
        #expect(preserved.protocolStack.contains(.tcp))
        #expect(preserved.sourceEndpointValue == IPEndpoint(ip: "198.51.100.7", port: 52_100))
        #expect(preserved.destinationEndpointValue == IPEndpoint(ip: "192.0.2.10", port: 80))
    }

    @Test
    func udpFilterOutExcludesBothDirectionsAndKeepsOtherSessions() throws {
        let tuple = FiveTuple(
            proto: .udp,
            source: IPEndpoint(ip: "192.0.2.10", port: 52_100),
            destination: IPEndpoint(ip: "198.51.100.7", port: 53)
        )
        let packets = try [
            synthetic(.udp, source: "192.0.2.10", sourcePort: 52_100, destination: "198.51.100.7", destinationPort: 53),
            synthetic(.udp, source: "198.51.100.7", sourcePort: 53, destination: "192.0.2.10", destinationPort: 52_100),
            synthetic(.udp, source: "192.0.2.10", sourcePort: 53, destination: "198.51.100.7", destinationPort: 52_100),
            synthetic(.tcp, source: "192.0.2.10", sourcePort: 52_100, destination: "198.51.100.7", destinationPort: 53),
        ].flatMap { $0 }
        let sessions = SessionBuilder.build(from: packets, linkType: LinkType.ethernet)
        let snapshot = InvestigationSnapshot(
            fold: SessionFoldSnapshot(
                sessions: sessions, connections: .empty, datagramEvidence: .empty, tlsEvidence: .empty,
                segmentSeries: .empty
            ),
            connectionAssessor: ConnectionAssessor(),
            datagramAssessor: DatagramAssessor()
        )
        let engine = InvestigationQueryEngine()
        let result = try engine.evaluate(engine.compile(SessionQueryParser().parse(
            FollowStreamExport.filterOutTerm(tuple)
        )), over: snapshot)

        let otherPair = FiveTuple(
            proto: .udp,
            source: IPEndpoint(ip: "192.0.2.10", port: 53),
            destination: IPEndpoint(ip: "198.51.100.7", port: 52_100)
        )
        let otherTransport = FiveTuple(proto: .tcp, source: tuple.a, destination: tuple.b)
        #expect(sessions.count == 3)
        #expect(result.matched.count == 2)
        #expect(!result.matched.contains { $0.id == SessionBuilder.sessionID(for: tuple) })
        #expect(Set(result.matched.map(\.id)) == Set([
            SessionBuilder.sessionID(for: otherPair), SessionBuilder.sessionID(for: otherTransport),
        ]))
        // UDP uses the same service-port orientation as a midstream TCP capture.
        let preserved = try #require(result.matched.first { $0.id == SessionBuilder.sessionID(for: otherPair) })
        #expect(preserved.protocolStack.contains(.udp))
        #expect(preserved.sourceEndpointValue == IPEndpoint(ip: "198.51.100.7", port: 52_100))
        #expect(preserved.destinationEndpointValue == IPEndpoint(ip: "192.0.2.10", port: 53))
    }

    // MARK: Private

    private func synthetic(
        _ proto: ProtocolKind,
        source: String,
        sourcePort: Int,
        destination: String,
        destinationPort: Int
    )
        throws -> [CapturedFrame]
    {
        let payload = CapturedFrame(
            bytes: [0x01],
            timestamp: Date(),
            originalLength: 1,
            linkType: LinkType.ethernet
        )
        let options = SyntheticTCPPacketBuilder.Options(
            sourceAddress: source, destinationAddress: destination,
            sourcePort: sourcePort, destinationPort: destinationPort, ipv6: false
        )
        if proto == .tcp {
            return try SyntheticTCPPacketBuilder.wrap(
                [payload], options: options, linkType: LinkType.ethernet,
                maxFrameBytes: 65_535, maxTotalFrameBytes: 65_535
            )
        }
        return try SyntheticUDPPacketBuilder.wrap(
            [payload], options: SyntheticUDPPacketBuilder.Options(
                sourceAddress: source, destinationAddress: destination,
                sourcePort: sourcePort, destinationPort: destinationPort, ipv6: false
            ), linkType: LinkType.ethernet, maxFrameBytes: 65_535, maxTotalFrameBytes: 65_535
        )
    }
}
