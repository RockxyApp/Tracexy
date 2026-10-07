import Foundation
import Testing
@testable import Tracexy

// MARK: - TCPCompletenessTests

/// Wireshark's `tcp.completeness` per session: the stages the capture showed,
/// with the same bit values, a column, and a Session Expression term.
struct TCPCompletenessTests {
    @Test
    func stagesMatchWiresharkBits() {
        let everything: TCPCompleteness = [.syn, .synAck, .ack, .data, .fin, .rst]
        #expect(everything.rawValue == 63)
        #expect(everything.stageString == "RFDASS")
        #expect(TCPCompleteness([.syn]).stageString == "·····S")
        #expect(TCPCompleteness([.syn, .synAck, .ack, .data, .fin]).isComplete)
        #expect(TCPCompleteness([.syn, .synAck, .ack, .rst]).isComplete)
        #expect(!TCPCompleteness([.syn, .synAck, .ack, .data]).isComplete)
        #expect(!TCPCompleteness([.synAck, .ack, .data, .fin]).isComplete)
    }

    @Test
    func parserAcceptsNumbersAndVerdicts() throws {
        let parser = SessionQueryParser()
        #expect(try parser.parse("tcp.completeness == 31") == .leaf(.tcpCompleteness(.value(31))))
        #expect(try parser.parse("tcp.completeness == complete") == .leaf(.tcpCompleteness(.complete)))
        #expect(try parser.parse("tcp.completeness == incomplete") == .leaf(.tcpCompleteness(.incomplete)))
        #expect(throws: SessionQueryParseError.self) { _ = try parser.parse("tcp.completeness == 64") }
        #expect(throws: SessionQueryParseError.self) { _ = try parser.parse("tcp.completeness == finished") }
        #expect(DisplayFilterTranslator.translate("tcp.completeness == 31")
            == .translated("tcp.completeness == 31", approximate: false))
    }

    @Test
    func theFoldAndTsharkAgreeOnAFixture() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("completeness-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("conv.pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: ReplayCorpus.conversationCapturedFrames(), to: url)
        let loaded = try SavedCaptureStreamLoader(contentsOf: url).load()
        let tcp = loaded.sessions.filter { $0.protocolStack.contains(.tcp) }
        #expect(!tcp.isEmpty)
        let nonTCPEmpty = loaded.sessions.filter { !$0.protocolStack.contains(.tcp) }
            .allSatisfy(\.tcpCompleteness.isEmpty)
        #expect(nonTCPEmpty)

        if WiresharkOracle.isAvailable {
            for session in tcp {
                let client = try #require(session.sourceEndpointValue)
                let rows = try WiresharkOracle.tsharkFields(
                    url, fields: ["tcp.completeness"],
                    filter: "tcp.port == \(client.port) && ip.addr == \(client.ip)",
                    // Two passes, so every frame carries the stream's final value.
                    extraArguments: ["-2"]
                )
                let values = Set(rows.compactMap(\.first))
                #expect(values == [String(session.tcpCompleteness.rawValue)], "\(session.host)")
            }
        }
    }

    @Test
    func evaluationNeverMatchesNonTCP() throws {
        var tcp = SessionSummary(
            id: SessionBuilder.stableID("complete-tcp"), startTime: nil, duration: nil, processName: nil,
            host: "a", sourceEndpoint: "192.0.2.1:1", destinationEndpoint: "192.0.2.2:2",
            protocolStack: [.tcp], status: .ok, latencyMilliseconds: nil, bytesUp: 0, bytesDown: 0
        )
        tcp.tcpCompleteness = [.syn, .synAck, .ack, .fin]
        var udp = tcp
        udp.protocolStack = [.udp]
        let engine = InvestigationQueryEngine()
        let query = try engine.compile(SessionQueryParser().parse("tcp.completeness == incomplete"))
        let snapshot = InvestigationSnapshot(fold: SessionFoldSnapshot(
            sessions: [tcp, udp], connections: .empty, datagramEvidence: .empty, tlsEvidence: .empty,
            segmentSeries: .empty
        ))
        let result = try engine.evaluate(query, over: snapshot)
        #expect(result.matched.isEmpty)
        let complete = try engine.compile(SessionQueryParser().parse("tcp.completeness == 23"))
        let matched = try engine.evaluate(complete, over: snapshot).matched
        #expect(matched.map(\.host) == ["a"])
    }
}

// MARK: - PresenceTermTests

/// A field named on its own tests presence, as a bare field does in Wireshark.
struct PresenceTermTests {
    @Test
    func bareFieldsParseAsPresence() throws {
        let parser = SessionQueryParser()
        #expect(try parser.parse("finding") == .leaf(.hasEvidence(.anyFinding)))
        #expect(try parser.parse("sni and not finding") == .all([
            .leaf(.hasEvidence(.serverNameIndication)), .not(.leaf(.hasEvidence(.anyFinding))),
        ]))
        #expect(try parser.parse("(process) or latency") == .any([
            .leaf(.hasEvidence(.processAttribution)), .leaf(.hasEvidence(.latency)),
        ]))
        #expect(try parser.parse("finding == reset") == .leaf(.findingKind(.reset)), "comparisons are unchanged")
        #expect(DisplayFilterTranslator.translate("_ws.expert") == .translated("finding", approximate: true))
    }
}
