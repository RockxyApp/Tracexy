import Foundation
import Testing
@testable import Tracexy

/// Follow Stream's "Filter Out This Stream" keeps every session except the
/// followed one, and each run shows its offset from the stream's first frame.
struct FollowStreamFilterOutTests {
    @Test
    func filterOutKeepsEveryOtherSession() throws {
        let tuple = FiveTuple(
            proto: .tcp,
            source: IPEndpoint(ip: "192.0.2.10", port: 52_100),
            destination: IPEndpoint(ip: "198.51.100.7", port: 80)
        )
        let term = FollowStreamExport.filterOutTerm(tuple)
        #expect(term == "not (ip == 192.0.2.10 and ip == 198.51.100.7 and port == 52100 and port == 80)")

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
}
