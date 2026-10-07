import Foundation
import Testing
@testable import Tracexy

/// The ladder is drawn from the session's retained evidence through the real fold.
struct SessionLadderTests {
    @Test
    func handshakeDataAndCloseInCaptureOrder() throws {
        let snapshot = InvestigationSnapshot(
            fold: SessionBuilder.buildDetailed(
                from: ReplayCorpus.tcpConnectionCapturedFrames(), linkType: LinkType.ethernet
            )
        )
        let tuple = try #require(snapshot.connections.summaries.first?.tuple)
        let ladder = SessionLadder.build(snapshot.selectingSession(SessionBuilder.sessionID(for: tuple)))
        #expect(!ladder.isEmpty)
        #expect(ladder.leftEndpoint == tuple.a.display)
        #expect(ladder.rightEndpoint == tuple.b.display)
        let labels = ladder.steps.map(\.label)
        let syn = try #require(labels.firstIndex(of: "SYN"))
        let synAck = try #require(labels.firstIndex(of: "SYN, ACK"))
        #expect(syn < synAck)
        // At most one "Data" arrow per direction.
        #expect(labels.count { $0 == "Data" } <= 2)
        // Offsets start at zero and never go backwards.
        let offsets = ladder.steps.compactMap(\.offset)
        #expect(offsets.first == 0)
        #expect(offsets == offsets.sorted())
        #expect(ladder.steps.allSatisfy { $0.provenance != nil })
    }

    @Test
    func dnsStepsNameTheResponseCode() throws {
        let frames = [
            PacketBuilder.dnsQueryFrame(name: "a.example.test", src: "192.0.2.10", dst: "192.0.2.53"),
            PacketBuilder.dnsResponseFrame(
                name: "a.example.test",
                answers: ["192.0.2.80"],
                src: "192.0.2.53",
                dst: "192.0.2.10"
            ),
        ].map { CapturedFrame(bytes: $0, timestamp: Date(timeIntervalSince1970: 5), originalLength: $0.count) }
        let snapshot = InvestigationSnapshot(fold: SessionBuilder.buildDetailed(
            from: frames,
            linkType: LinkType.ethernet
        ))
        let session = try #require(snapshot.sessions.first)
        let ladder = SessionLadder.build(snapshot.selectingSession(session.id))
        #expect(ladder.steps.map(\.label) == ["DNS query", "DNS response NOERROR"])
        #expect(ladder.steps.map(\.direction) == [.aToB, .bToA])
        #expect(ladder.steps.allSatisfy { !$0.isAttention })
    }
}
