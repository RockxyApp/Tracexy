import Foundation
import Testing
@testable import Tracexy

/// Fast and spurious retransmission. Both are refinements named
/// after the sender behaviour the segments show (RFC 5681 fast retransmit;
/// re-sending bytes the peer had already acknowledged), never a cause. Every
/// case drives the real `ConnectionTable` fold.
@Suite("ConnectionAssessor retransmission kinds")
struct ConnectionRetransmissionKindTests {
    // MARK: Internal

    @Test("The segment the peer asked for with repeated duplicate ACKs is a fast retransmission")
    func fastRetransmissionFromFold() throws {
        var table = ConnectionTable()
        gapWithDuplicateAcknowledgements(&table, duplicates: 3)
        ingest(
            &table,
            from: server,
            to: client,
            flags: [.psh, .ack],
            seq: 5_101,
            ack: 1_001,
            payload: 100,
            ordinal: 11,
            at: 11
        )

        let snapshot = table.snapshot()
        let summary = try #require(snapshot.summaries.first)
        #expect(summary.events.filter { $0.kind == .fastRetransmission }.map(\.occurrenceOrdinal) == [FrameOrdinal(11)])

        let result = ConnectionAssessor().assess(snapshot)
        let fast = try #require(result.findings.first { $0.kind == .fastRetransmissionObserved })
        #expect(fast.severity == .note)
        #expect(fast.citations.map(\.sourceEventKind) == [.fastRetransmission])
        #expect(fast.citations.first?.direction == .bToA)
        #expect(result.findings.contains { $0.kind == .duplicateAcknowledgementObserved })
        #expect(!result.findings.contains { $0.kind == .spuriousRetransmissionObserved })
    }

    @Test("A fast retransmission is reported once per repeated edge; a later resend is a plain retransmission")
    func fastRetransmissionOncePerEdge() throws {
        var table = ConnectionTable()
        gapWithDuplicateAcknowledgements(&table, duplicates: 3)
        ingest(
            &table,
            from: server,
            to: client,
            flags: [.psh, .ack],
            seq: 5_101,
            ack: 1_001,
            payload: 100,
            ordinal: 11,
            at: 11
        )
        ingest(
            &table,
            from: server,
            to: client,
            flags: [.psh, .ack],
            seq: 5_101,
            ack: 1_001,
            payload: 100,
            ordinal: 12,
            at: 12
        )

        let result = ConnectionAssessor().assess(table.snapshot())
        let fast = try #require(result.findings.first { $0.kind == .fastRetransmissionObserved })
        #expect(fast.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(11)])
        let plain = try #require(result.findings.first { $0.kind == .retransmissionObserved })
        #expect(plain.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(12)])
        // The client never acknowledged past 5_101, so the resend is not spurious.
        #expect(!result.findings.contains { $0.kind == .spuriousRetransmissionObserved })
    }

    @Test("One duplicate acknowledgement is not enough for a fast retransmission")
    func singleDuplicateIsNotFast() {
        var table = ConnectionTable()
        gapWithDuplicateAcknowledgements(&table, duplicates: 1)
        ingest(
            &table,
            from: server,
            to: client,
            flags: [.psh, .ack],
            seq: 5_101,
            ack: 1_001,
            payload: 100,
            ordinal: 11,
            at: 11
        )

        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(!result.findings.contains { $0.kind == .fastRetransmissionObserved })
    }

    @Test("Re-sending bytes the peer already acknowledged is a spurious retransmission")
    func spuriousRetransmissionFromFold() throws {
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
            seq: 5_001,
            ack: 1_001,
            payload: 100,
            ordinal: 6,
            at: 6
        )

        let result = ConnectionAssessor().assess(table.snapshot())
        let spurious = try #require(result.findings.first { $0.kind == .spuriousRetransmissionObserved })
        #expect(spurious.severity == .note)
        #expect(spurious.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(6)])
        #expect(spurious.citations.first?.direction == .bToA)
        // It refines the generic finding, which still cites the same frame.
        let plain = try #require(result.findings.first { $0.kind == .retransmissionObserved })
        #expect(plain.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(6)])
    }

    @Test("A retransmission of bytes not yet acknowledged is not spurious")
    func unacknowledgedResendIsNotSpurious() {
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
        ingest(
            &table,
            from: server,
            to: client,
            flags: [.psh, .ack],
            seq: 5_001,
            ack: 1_001,
            payload: 100,
            ordinal: 5,
            at: 5
        )

        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(result.findings.map(\.kind) == [.retransmissionObserved])
    }

    @Test("A keep-alive probe is never a spurious retransmission")
    func keepAliveIsNotSpurious() {
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
            flags: [.ack],
            seq: 5_100,
            ack: 1_001,
            payload: 1,
            ordinal: 6,
            at: 60
        )

        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(result.findings.map(\.kind) == [.keepAliveObserved])
    }

    @Test("The two kinds rank after the other notes and project to their own query names")
    func rankAndQueryNames() throws {
        let kinds: [ConnectionAnalysisFindingKind] = [
            .keepAliveObserved, .fastRetransmissionObserved, .spuriousRetransmissionObserved,
        ]
        #expect(kinds.map(\.rank) == kinds.map(\.rank).sorted())
        #expect(Set(kinds.map(\.stableDiscriminator)).count == kinds.count)
        let parser = SessionQueryParser()
        #expect(try parser.parse("finding == fastRetransmission") == .leaf(.findingKind(.fastRetransmission)))
        #expect(try parser.parse("finding == spuriousRetransmission")
            == .leaf(.findingKind(.spuriousRetransmission)))
    }

    // MARK: Private

    private let client = IPEndpoint(ip: "192.0.2.10", port: 50_000)
    private let server = IPEndpoint(ip: "203.0.113.5", port: 443)
    private let token = UUID(uuid: (7, 7, 7, 7, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16))

    private var tuple: FiveTuple {
        FiveTuple(proto: .tcp, source: client, destination: server)
    }

    /// Handshake, one server segment the client acknowledges (ordinal 4–5), a
    /// missing server segment at 5_101, then later server segments each answered
    /// by a duplicate acknowledgement of 5_101 — `duplicates` of them.
    private func gapWithDuplicateAcknowledgements(_ table: inout ConnectionTable, duplicates: Int) {
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
        for index in 0 ..< duplicates {
            let ordinal = UInt64(6 + index * 2)
            ingest(
                &table,
                from: server,
                to: client,
                flags: [.psh, .ack],
                seq: 5_201 + UInt32(index) * 100,
                ack: 1_001,
                payload: 100,
                ordinal: ordinal,
                at: Double(ordinal)
            )
            ingest(
                &table,
                from: client,
                to: server,
                flags: [.ack],
                seq: 1_001,
                ack: 5_101,
                ordinal: ordinal + 1,
                at: Double(ordinal + 1)
            )
        }
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
