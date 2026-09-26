import Foundation
import Testing
@testable import Tracexy

/// The four flow-control findings (zero window, window full, duplicate
/// acknowledgement, keep-alive). Every case drives the real `ConnectionTable` fold
/// so a finding is proven from segments — the fold's new events, their order
/// relative to the sequence verdicts, and the assessor's coalescing — rather than
/// from a hand-built summary.
@Suite("ConnectionAssessor flow-control findings")
struct ConnectionHealthFindingTests {
    // MARK: Internal

    @Test("Repeated zero-window ACKs fold into one zeroWindowObserved warning citing each advertisement")
    func zeroWindowFromFold() throws {
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
        ingest(&table, from: client, to: server, flags: [.ack], seq: 1_001, ack: 5_101, window: 0, ordinal: 5, at: 5)
        ingest(&table, from: client, to: server, flags: [.ack], seq: 1_001, ack: 5_101, window: 0, ordinal: 6, at: 6)

        let result = ConnectionAssessor().assess(table.snapshot())
        let zero = try #require(result.findings.first { $0.kind == .zeroWindowObserved })
        #expect(zero.severity == .warning)
        #expect(zero.tuple == tuple)
        #expect(zero.citations.map(\.sourceEventKind) == [.zeroWindow, .zeroWindow])
        #expect(zero.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(5), FrameOrdinal(6)])
        #expect(zero.citations.allSatisfy { $0.direction == .aToB })
        // The repeated advertisement is a window statement, not a duplicate
        // acknowledgement: the zero window explains it and it is reported once.
        #expect(result.findings.map(\.kind) == [.zeroWindowObserved])
    }

    @Test("A zero-window probe joins the zero-window finding and replaces the probe byte's sequence verdict")
    func zeroWindowProbeFromFold() throws {
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
        ingest(&table, from: client, to: server, flags: [.ack], seq: 1_001, ack: 5_101, window: 0, ordinal: 5, at: 5)
        ingest(&table, from: server, to: client, flags: [.ack], seq: 5_101, ack: 1_001, payload: 1, ordinal: 6, at: 6)
        ingest(&table, from: server, to: client, flags: [.ack], seq: 5_101, ack: 1_001, payload: 1, ordinal: 7, at: 8)

        let snapshot = table.snapshot()
        let summary = try #require(snapshot.summaries.first)
        let probeEvents = summary.events.filter { $0.kind == .zeroWindowProbe }
        #expect(probeEvents.map(\.occurrenceOrdinal) == [FrameOrdinal(6), FrameOrdinal(7)])
        // Neither probe byte is reported as an advance, a retransmission or (the
        // resent probe sits one behind the edge) a keep-alive.
        #expect(!summary.events.contains { $0.kind == .retransmission || $0.kind == .keepAlive })
        #expect(!summary.events.contains { $0.kind == .sequenceAdvanced && $0.occurrenceOrdinal >= FrameOrdinal(6) })

        let result = ConnectionAssessor().assess(snapshot)
        let zero = try #require(result.findings.first { $0.kind == .zeroWindowObserved })
        #expect(zero.citations.map(\.sourceEventKind) == [.zeroWindow, .zeroWindowProbe, .zeroWindowProbe])
        #expect(zero.citations.map(\.direction) == [.aToB, .bToA, .bToA])
        #expect(!result.findings.contains { $0.kind == .retransmissionObserved })
    }

    @Test("A segment ending exactly at the peer's window edge folds into windowFullObserved")
    func windowFullFromFold() throws {
        var table = ConnectionTable()
        handshake(&table, clientWindow: 1_000)
        ingest(
            &table,
            from: server,
            to: client,
            flags: [.psh, .ack],
            seq: 5_001,
            ack: 1_001,
            payload: 600,
            ordinal: 4,
            at: 4
        )
        ingest(
            &table,
            from: server,
            to: client,
            flags: [.psh, .ack],
            seq: 5_601,
            ack: 1_001,
            payload: 400,
            ordinal: 5,
            at: 5
        )

        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(result.findings.map(\.kind) == [.windowFullObserved])
        let full = try #require(result.findings.first)
        #expect(full.severity == .note)
        #expect(full.citations.map(\.sourceEventKind) == [.windowFull])
        #expect(full.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(5)])
        #expect(full.citations.first?.direction == .bToA)
    }

    @Test("Window full is not claimed for a midstream connection whose scale is unknown")
    func windowFullFailsClosedMidstream() {
        var table = ConnectionTable()
        ingest(
            &table,
            from: client,
            to: server,
            flags: [.ack],
            seq: 1_001,
            ack: 5_001,
            window: 1_000,
            ordinal: 1,
            at: 1
        )
        ingest(
            &table,
            from: server,
            to: client,
            flags: [.psh, .ack],
            seq: 5_001,
            ack: 1_001,
            payload: 1_000,
            ordinal: 2,
            at: 2
        )
        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(result.findings.isEmpty)
    }

    @Test("Three duplicate acknowledgements fold into one duplicateAcknowledgementObserved note citing each")
    func duplicateAcknowledgementFromFold() throws {
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
        // The next server segment is missing from the capture; later ones arrive
        // and the client re-acknowledges the same edge for each.
        ingest(
            &table,
            from: server,
            to: client,
            flags: [.psh, .ack],
            seq: 5_201,
            ack: 1_001,
            payload: 100,
            ordinal: 6,
            at: 6
        )
        ingest(&table, from: client, to: server, flags: [.ack], seq: 1_001, ack: 5_101, ordinal: 7, at: 7)
        ingest(
            &table,
            from: server,
            to: client,
            flags: [.psh, .ack],
            seq: 5_301,
            ack: 1_001,
            payload: 100,
            ordinal: 8,
            at: 8
        )
        ingest(&table, from: client, to: server, flags: [.ack], seq: 1_001, ack: 5_101, ordinal: 9, at: 9)
        ingest(&table, from: client, to: server, flags: [.ack], seq: 1_001, ack: 5_101, ordinal: 10, at: 10)

        let result = ConnectionAssessor().assess(table.snapshot())
        let duplicate = try #require(result.findings.first { $0.kind == .duplicateAcknowledgementObserved })
        #expect(duplicate.severity == .note)
        #expect(duplicate.citations.map(\.sourceEventKind) == [
            .duplicateAcknowledgement, .duplicateAcknowledgement, .duplicateAcknowledgement,
        ])
        #expect(duplicate.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(7), FrameOrdinal(9), FrameOrdinal(10)])
        #expect(duplicate.citations.allSatisfy { $0.direction == .aToB })
        // The server's segments ahead of the gap are the usual out-of-order note.
        #expect(result.findings.contains { $0.kind == .outOfOrderObserved })
        #expect(!result.findings.contains { $0.kind == .zeroWindowObserved || $0.kind == .windowFullObserved })
    }

    @Test("A healthy exchange with in-order ACKs and window updates yields no flow-control finding")
    func healthyExchangeHasNoFlowControlFinding() {
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
        ingest(
            &table,
            from: server,
            to: client,
            flags: [.psh, .ack],
            seq: 5_101,
            ack: 1_001,
            payload: 100,
            ordinal: 6,
            at: 6
        )
        ingest(
            &table,
            from: client,
            to: server,
            flags: [.ack],
            seq: 1_001,
            ack: 5_201,
            window: 32_768,
            ordinal: 7,
            at: 7
        )
        // Same ack, larger window: a window update.
        ingest(
            &table,
            from: client,
            to: server,
            flags: [.ack],
            seq: 1_001,
            ack: 5_201,
            window: 65_535,
            ordinal: 8,
            at: 8
        )
        ingest(&table, from: client, to: server, flags: [.fin, .ack], seq: 1_001, ack: 5_201, ordinal: 9, at: 9)
        ingest(&table, from: server, to: client, flags: [.fin, .ack], seq: 5_201, ack: 1_002, ordinal: 10, at: 10)
        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(result.findings.isEmpty)
    }

    @Test("Keep-alive probes fold into keepAliveObserved and their answers are not duplicate ACKs")
    func keepAliveFromFold() throws {
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
        for round in 0 ..< 2 {
            let base = UInt64(6 + round * 2)
            ingest(
                &table,
                from: server,
                to: client,
                flags: [.ack],
                seq: 5_100,
                ack: 1_001,
                payload: 1,
                ordinal: base,
                at: Double(base)
            )
            ingest(
                &table,
                from: client,
                to: server,
                flags: [.ack],
                seq: 1_001,
                ack: 5_101,
                ordinal: base + 1,
                at: Double(base + 1)
            )
        }

        let snapshot = table.snapshot()
        let summary = try #require(snapshot.summaries.first)
        #expect(summary.events.filter { $0.kind == .keepAlive }.map(\.occurrenceOrdinal) == [
            FrameOrdinal(6),
            FrameOrdinal(8)
        ])
        #expect(!summary.events.contains { $0.kind == .retransmission })

        let result = ConnectionAssessor().assess(snapshot)
        #expect(result.findings.map(\.kind) == [.keepAliveObserved])
        let keepAlive = try #require(result.findings.first)
        #expect(keepAlive.severity == .note)
        #expect(keepAlive.citations.map(\.sourceEventKind) == [.keepAlive, .keepAlive])
        #expect(keepAlive.citations.allSatisfy { $0.direction == .bToA })
    }

    @Test("Flow-control finding ids are stable and seeded only by connection id and kind")
    func stableIdentity() throws {
        func zeroWindow() throws -> ConnectionAnalysisFinding {
            var table = ConnectionTable()
            handshake(&table)
            ingest(
                &table,
                from: client,
                to: server,
                flags: [.ack],
                seq: 1_001,
                ack: 5_001,
                window: 0,
                ordinal: 4,
                at: 4
            )
            return try #require(ConnectionAssessor().assess(table.snapshot()).findings.first)
        }
        let first = try zeroWindow()
        let second = try zeroWindow()
        #expect(first.kind == .zeroWindowObserved)
        #expect(first.id == second.id)
        let expected = SessionBuilder.stableID(
            "connectionAnalysis|\(first.connectionID.rawValue.uuidString)|zeroWindowObserved"
        )
        #expect(first.id == expected)
    }

    @Test("Zero window ranks with the warnings; the flow-control notes rank after retransmission")
    func kindRankOrder() {
        #expect(ConnectionAnalysisFindingKind.resetObserved.rank < ConnectionAnalysisFindingKind.zeroWindowObserved
            .rank)
        #expect(ConnectionAnalysisFindingKind.zeroWindowObserved.rank
            < ConnectionAnalysisFindingKind.retransmissionObserved.rank)
        #expect(ConnectionAnalysisFindingKind.retransmissionObserved.rank
            < ConnectionAnalysisFindingKind.windowFullObserved.rank)
        #expect(ConnectionAnalysisFindingKind.windowFullObserved.rank
            < ConnectionAnalysisFindingKind.duplicateAcknowledgementObserved.rank)
        #expect(ConnectionAnalysisFindingKind.outOfOrderObserved.rank
            < ConnectionAnalysisFindingKind.keepAliveObserved.rank)
        let kinds: [ConnectionAnalysisFindingKind] = [
            .connectionRefusedObserved, .handshakeUnansweredObserved, .resetObserved, .zeroWindowObserved,
            .retransmissionObserved, .windowFullObserved, .duplicateAcknowledgementObserved, .overlapObserved,
            .outOfOrderObserved, .keepAliveObserved,
        ]
        #expect(Set(kinds.map(\.rank)).count == kinds.count)
        #expect(Set(kinds.map(\.stableDiscriminator)).count == kinds.count)
    }

    @Test("Flow-control findings project to their own query finding kinds and parser names")
    func queryProjection() throws {
        var table = ConnectionTable()
        handshake(&table)
        ingest(&table, from: client, to: server, flags: [.ack], seq: 1_001, ack: 5_001, window: 0, ordinal: 4, at: 4)
        let analysis = ConnectionAssessor().assess(table.snapshot())
        #expect(analysis.findings.map(\.kind) == [.zeroWindowObserved])

        let parser = SessionQueryParser()
        #expect(try parser.parse("finding == zeroWindow") == .leaf(.findingKind(.zeroWindow)))
        #expect(try parser.parse("finding == windowFull") == .leaf(.findingKind(.windowFull)))
        #expect(try parser.parse("finding == duplicateAck") == .leaf(.findingKind(.duplicateAck)))
        #expect(try parser.parse("finding == keepAlive") == .leaf(.findingKind(.keepAlive)))
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
