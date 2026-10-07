import Foundation
import Testing
@testable import Tracexy

/// An acknowledgement beyond the farthest sequence the peer was seen to send
/// (Wireshark's "ACKed segment that wasn't captured"). It describes the capture, so
/// it is a note and it is only reported once the peer's own edge is known. Every
/// case drives the real `ConnectionTable` fold.
@Suite("ConnectionAssessor ACKed unseen segment")
struct ConnectionAckedUnseenTests {
    // MARK: Internal

    @Test("An ACK past the server's last captured byte is reported, citing that ACK")
    func ackBeyondTheCapturedEdge() throws {
        var table = ConnectionTable()
        handshake(&table)
        ingest(
            &table,
            from: server,
            to: client,
            flags: [.psh, .ack],
            seq: 5_001,
            ack: 1_001,
            payload: 100,
            ordinal: 4,
            at: 4
        )
        // 5_101..<5_201 was sent but never captured; the client acknowledges it.
        ingest(&table, from: client, to: server, flags: [.ack], seq: 1_001, ack: 5_201, ordinal: 5, at: 5)

        let result = ConnectionAssessor().assess(table.snapshot())
        let finding = try #require(result.findings.first { $0.kind == .ackedUnseenSegmentObserved })
        #expect(finding.severity == .note)
        #expect(finding.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(5)])
        #expect(finding.citations.first?.direction == .aToB)
        #expect(result.findings.map(\.kind) == [.ackedUnseenSegmentObserved])
    }

    @Test("Ordinary acknowledgements, including the handshake's, report nothing")
    func ordinaryAcknowledgementsAreQuiet() {
        var table = ConnectionTable()
        handshake(&table)
        ingest(
            &table,
            from: server,
            to: client,
            flags: [.psh, .ack],
            seq: 5_001,
            ack: 1_001,
            payload: 100,
            ordinal: 4,
            at: 4
        )
        ingest(&table, from: client, to: server, flags: [.ack], seq: 1_001, ack: 5_101, ordinal: 5, at: 5)
        ingest(&table, from: client, to: server, flags: [.fin, .ack], seq: 1_001, ack: 5_101, ordinal: 6, at: 6)
        ingest(&table, from: server, to: client, flags: [.fin, .ack], seq: 5_101, ack: 1_002, ordinal: 7, at: 7)
        ingest(&table, from: client, to: server, flags: [.ack], seq: 1_002, ack: 5_102, ordinal: 8, at: 8)

        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(!result.findings.contains { $0.kind == .ackedUnseenSegmentObserved })
    }

    @Test("With the peer's edge unknown (capture began mid-connection) nothing is claimed")
    func unknownPeerEdgeFailsClosed() {
        var table = ConnectionTable()
        // No SYNs and no server data captured: the server's edge is unknown.
        ingest(&table, from: client, to: server, flags: [.ack], seq: 1_001, ack: 9_999, ordinal: 1, at: 1)
        ingest(
            &table,
            from: client,
            to: server,
            flags: [.psh, .ack],
            seq: 1_001,
            ack: 9_999,
            payload: 10,
            ordinal: 2,
            at: 2
        )

        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(!result.findings.contains { $0.kind == .ackedUnseenSegmentObserved })
    }

    @Test("Query name, Wireshark field and rank")
    func namesAndRank() throws {
        #expect(try SessionQueryParser().parse("finding == ackedUnseen") == .leaf(.findingKind(.ackedUnseen)))
        #expect(InvestigationQueryEngine.projected(.ackedUnseenSegmentObserved) == .ackedUnseen)
        #expect(ConnectionAnalysisFindingKind.ackedUnseenSegmentObserved.rank
            > ConnectionAnalysisFindingKind.spuriousRetransmissionObserved.rank)
        let translated = DisplayFilterTranslator.translate("tcp.analysis.ack_lost_segment")
        guard case let .translated(expression, _) = translated else {
            Issue.record("tcp.analysis.ack_lost_segment should translate")
            return
        }
        #expect(expression == "finding == ackedUnseen")
    }

    // MARK: Private

    private let client = IPEndpoint(ip: "192.0.2.10", port: 50_000)
    private let server = IPEndpoint(ip: "203.0.113.5", port: 443)
    private let token = UUID(uuid: (7, 7, 7, 7, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16))

    private var tuple: FiveTuple {
        FiveTuple(proto: .tcp, source: client, destination: server)
    }

    /// A validated three-way handshake at ordinals 1...3 with no window scaling:
    /// client ISN 1_000, server ISN 5_000.
    private func handshake(_ table: inout ConnectionTable, clientWindow: UInt16 = 65_535) {
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, window: clientWindow, ordinal: 1, at: 1)
        ingest(&table, from: server, to: client, flags: [.syn, .ack], seq: 5_000, ack: 1_001, ordinal: 2, at: 2)
        ingest(
            &table,
            from: client,
            to: server,
            flags: [.ack],
            seq: 1_001,
            ack: 5_001,
            window: clientWindow,
            ordinal: 3,
            at: 3
        )
    }

    private func packet(
        from source: IPEndpoint,
        to destination: IPEndpoint,
        flags: TCPFlags,
        seq: UInt32,
        ack: UInt32,
        payload: Int,
        window: UInt16,
        at timestamp: Double
    )
        -> DecodedPacket
    {
        var pkt = DecodedPacket(timestamp: Date(timeIntervalSince1970: timestamp), originalLength: 0)
        pkt.transport = .tcp
        pkt.sourceEndpoint = source
        pkt.destinationEndpoint = destination
        pkt.fiveTuple = FiveTuple(proto: .tcp, source: source, destination: destination)
        pkt.tcpFacts = TCPSegmentFacts(
            sequenceNumber: seq,
            acknowledgementNumber: ack,
            flags: flags,
            windowSize: window,
            headerLength: 20,
            payloadSequence: flags.contains(.syn) ? seq &+ 1 : seq,
            payloadLength: payload,
            options: TCPOptionFacts()
        )
        return pkt
    }

    private func provenance(ordinal: UInt64, at timestamp: Double) -> SessionFrameProvenance {
        SessionFrameProvenance(
            ordinal: FrameOrdinal(ordinal),
            timestamp: Date(timeIntervalSince1970: timestamp),
            capturedLength: 60,
            originalLength: 60,
            linkType: 1,
            locator: SessionEvidenceLocator(sourceToken: token, offset: ordinal)
        )
    }

    private func ingest(
        _ table: inout ConnectionTable,
        from source: IPEndpoint,
        to destination: IPEndpoint,
        flags: TCPFlags,
        seq: UInt32 = 0,
        ack: UInt32 = 0,
        payload: Int = 0,
        window: UInt16 = 65_535,
        ordinal: UInt64,
        at timestamp: Double
    ) {
        table.ingest(
            packet(
                from: source, to: destination, flags: flags, seq: seq, ack: ack,
                payload: payload, window: window, at: timestamp
            ),
            provenance: provenance(ordinal: ordinal, at: timestamp)
        )
    }
}
