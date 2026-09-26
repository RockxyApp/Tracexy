import Foundation
import Testing
@testable import Tracexy

/// The remaining summary-level termination findings (abort after data,
/// half-close), the tuple-reuse mapping, and the narrowed retransmission report
/// under an unanswered handshake. Every case drives the real `ConnectionTable`
/// fold, so each finding is proven from segments rather than a hand-built summary.
@Suite("ConnectionAssessor termination findings")
struct ConnectionTerminationFindingTests {
    // MARK: Internal

    // MARK: Abort after data

    @Test("Data followed by a reset folds into abortAfterDataObserved citing first data, last data and the reset")
    func abortFromFold() throws {
        var table = ConnectionTable()
        handshake(&table)
        ingest(
            &table,
            from: client,
            to: server,
            flags: [.psh, .ack],
            seq: 1_001,
            ack: 5_001,
            payload: 50,
            ordinal: 4,
            at: 4
        )
        ingest(
            &table,
            from: server,
            to: client,
            flags: [.psh, .ack],
            seq: 5_001,
            ack: 1_051,
            payload: 100,
            ordinal: 5,
            at: 5
        )
        ingest(&table, from: server, to: client, flags: [.rst, .ack], seq: 5_101, ack: 1_051, ordinal: 6, at: 6)

        let result = ConnectionAssessor().assess(table.snapshot())
        let abort = try #require(result.findings.first { $0.kind == .abortAfterDataObserved })
        #expect(abort.severity == .warning)
        #expect(abort.tuple == tuple)
        #expect(abort.citations.map(\.sourceEventKind) == [.payloadObserved, .payloadObserved, .rst])
        #expect(abort.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(4), FrameOrdinal(5), FrameOrdinal(6)])
        #expect(abort.citations.map(\.direction) == [.aToB, .bToA, .bToA])
        #expect(abort.omittedCitationCount == 0)
        // The abort cites the very same reset, so the generic reset is superseded.
        #expect(!result.findings.contains { $0.kind == .resetObserved })
    }

    @Test("A single observed payload before the reset cites exactly that payload and the reset")
    func abortCitesOnePayloadWhenOnlyOneObserved() throws {
        var table = ConnectionTable()
        handshake(&table)
        ingest(
            &table,
            from: client,
            to: server,
            flags: [.psh, .ack],
            seq: 1_001,
            ack: 5_001,
            payload: 50,
            ordinal: 4,
            at: 4
        )
        ingest(&table, from: server, to: client, flags: [.rst, .ack], seq: 5_001, ack: 1_051, ordinal: 5, at: 5)

        let result = ConnectionAssessor().assess(table.snapshot())
        let abort = try #require(result.findings.first { $0.kind == .abortAfterDataObserved })
        #expect(abort.citations.map(\.sourceEventKind) == [.payloadObserved, .rst])
        #expect(abort.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(4), FrameOrdinal(5)])
    }

    @Test("A reset with no observed data before it stays a plain reset")
    func resetWithoutDataIsNotAnAbort() {
        var table = ConnectionTable()
        handshake(&table)
        ingest(&table, from: server, to: client, flags: [.rst, .ack], seq: 5_001, ack: 1_001, ordinal: 4, at: 4)

        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(result.findings.map(\.kind) == [.resetObserved])
    }

    @Test("A refused open takes precedence over the abort rule when the SYN itself carried data")
    func refusedTakesPrecedenceOverAbort() {
        var table = ConnectionTable()
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, payload: 20, ordinal: 1, at: 1)
        ingest(&table, from: server, to: client, flags: [.rst, .ack], seq: 0, ack: 1_001, ordinal: 2, at: 2)

        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(result.findings.contains { $0.kind == .connectionRefusedObserved })
        #expect(!result.findings.contains { $0.kind == .abortAfterDataObserved })
        #expect(!result.findings.contains { $0.kind == .resetObserved })
    }

    @Test("An orderly close is never an abort")
    func orderlyCloseIsNotAnAbort() {
        var table = ConnectionTable()
        handshake(&table)
        ingest(
            &table,
            from: client,
            to: server,
            flags: [.psh, .ack],
            seq: 1_001,
            ack: 5_001,
            payload: 50,
            ordinal: 4,
            at: 4
        )
        ingest(&table, from: client, to: server, flags: [.fin, .ack], seq: 1_051, ack: 5_001, ordinal: 5, at: 5)
        ingest(&table, from: server, to: client, flags: [.fin, .ack], seq: 5_001, ack: 1_052, ordinal: 6, at: 6)

        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(!result.findings.contains { $0.kind == .abortAfterDataObserved })
        #expect(!result.findings.contains { $0.kind == .resetObserved })
    }

    // MARK: Half-close

    @Test("A FIN in one direction followed by peer data folds into halfCloseObserved citing both frames")
    func halfCloseFromFold() throws {
        var table = ConnectionTable()
        handshake(&table)
        ingest(&table, from: client, to: server, flags: [.fin, .ack], seq: 1_001, ack: 5_001, ordinal: 4, at: 4)
        ingest(
            &table,
            from: server,
            to: client,
            flags: [.psh, .ack],
            seq: 5_001,
            ack: 1_002,
            payload: 100,
            ordinal: 5,
            at: 5
        )

        let result = ConnectionAssessor().assess(table.snapshot())
        let halfClose = try #require(result.findings.first { $0.kind == .halfCloseObserved })
        #expect(halfClose.severity == .note)
        #expect(halfClose.citations.map(\.sourceEventKind) == [.fin, .payloadObserved])
        #expect(halfClose.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(4), FrameOrdinal(5)])
        #expect(halfClose.citations.map(\.direction) == [.aToB, .bToA])
    }

    @Test("A later mutual close does not erase the half-close that was observed")
    func halfCloseSurvivesALaterMutualClose() throws {
        var table = ConnectionTable()
        handshake(&table)
        ingest(&table, from: client, to: server, flags: [.fin, .ack], seq: 1_001, ack: 5_001, ordinal: 4, at: 4)
        ingest(
            &table, from: server, to: client, flags: [.psh, .ack],
            seq: 5_001, ack: 1_002, payload: 100, ordinal: 5, at: 5
        )
        ingest(&table, from: server, to: client, flags: [.fin, .ack], seq: 5_101, ack: 1_002, ordinal: 6, at: 6)

        let result = ConnectionAssessor().assess(table.snapshot())
        let halfClose = try #require(result.findings.first { $0.kind == .halfCloseObserved })
        #expect(halfClose.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(4), FrameOrdinal(5)])
    }

    @Test("Bytes the peer merely re-sent after a FIN are not a half-close")
    func retransmittedPeerDataIsNotHalfClose() {
        var table = ConnectionTable()
        handshake(&table)
        ingest(
            &table, from: server, to: client, flags: [.psh, .ack],
            seq: 5_001, ack: 1_001, payload: 100, ordinal: 4, at: 4
        )
        ingest(&table, from: client, to: server, flags: [.fin, .ack], seq: 1_001, ack: 5_101, ordinal: 5, at: 5)
        // The same bytes again: a retransmission, not the peer still sending.
        ingest(
            &table, from: server, to: client, flags: [.psh, .ack],
            seq: 5_001, ack: 1_002, payload: 100, ordinal: 6, at: 6
        )

        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(result.findings.contains { $0.kind == .retransmissionObserved })
        #expect(!result.findings.contains { $0.kind == .halfCloseObserved })
    }

    @Test("A mutual FIN close with no data after either FIN is not a half-close")
    func mutualCloseIsNotHalfClose() {
        var table = ConnectionTable()
        handshake(&table)
        ingest(&table, from: client, to: server, flags: [.fin, .ack], seq: 1_001, ack: 5_001, ordinal: 4, at: 4)
        ingest(&table, from: server, to: client, flags: [.fin, .ack], seq: 5_001, ack: 1_002, ordinal: 5, at: 5)

        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(!result.findings.contains { $0.kind == .halfCloseObserved })
    }

    @Test("A FIN with only acknowledgements after it is not a half-close")
    func finWithoutPeerDataIsNotHalfClose() {
        var table = ConnectionTable()
        handshake(&table)
        ingest(&table, from: client, to: server, flags: [.fin, .ack], seq: 1_001, ack: 5_001, ordinal: 4, at: 4)
        ingest(&table, from: server, to: client, flags: [.ack], seq: 5_001, ack: 1_002, ordinal: 5, at: 5)

        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(!result.findings.contains { $0.kind == .halfCloseObserved })
    }

    @Test("Peer data that preceded the FIN is not a half-close")
    func peerDataBeforeFinIsNotHalfClose() {
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
        ingest(&table, from: client, to: server, flags: [.fin, .ack], seq: 1_001, ack: 5_101, ordinal: 5, at: 5)

        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(!result.findings.contains { $0.kind == .halfCloseObserved })
    }

    // MARK: Tuple reuse

    @Test("A conflicting SYN before any terminal folds into tupleReuseObserved")
    func tupleReuseFromFold() throws {
        var table = ConnectionTable()
        handshake(&table)
        ingest(&table, from: client, to: server, flags: [.syn], seq: 7_000, ordinal: 4, at: 4)

        let result = ConnectionAssessor().assess(table.snapshot())
        let reuse = try #require(result.findings.first { $0.kind == .tupleReuseObserved })
        #expect(reuse.severity == .warning)
        #expect(reuse.citations.map(\.sourceEventKind) == [.ambiguousTupleReuse])
        #expect(reuse.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(4)])
    }

    @Test("A SYN after an observed terminal opens a new connection rather than reporting reuse")
    func synAfterTerminalIsNotReuse() {
        var table = ConnectionTable()
        handshake(&table)
        ingest(&table, from: client, to: server, flags: [.fin, .ack], seq: 1_001, ack: 5_001, ordinal: 4, at: 4)
        ingest(&table, from: server, to: client, flags: [.fin, .ack], seq: 5_001, ack: 1_002, ordinal: 5, at: 5)
        ingest(&table, from: client, to: server, flags: [.syn], seq: 7_000, ordinal: 6, at: 6)

        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(!result.findings.contains { $0.kind == .tupleReuseObserved })
    }

    // MARK: Retransmission under an unanswered handshake

    @Test("A retried SYN reports the unanswered handshake once, not also as a retransmission")
    func retransmissionSupersededByUnansweredHandshake() throws {
        var table = ConnectionTable()
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 2, at: 2)
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 3, at: 4)

        let result = ConnectionAssessor().assess(table.snapshot())
        let unanswered = try #require(result.findings.first { $0.kind == .handshakeUnansweredObserved })
        #expect(unanswered.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(1), FrameOrdinal(2), FrameOrdinal(3)])
        #expect(!result.findings.contains { $0.kind == .retransmissionObserved })
    }

    @Test("An ordinary data retransmission is still reported — the supersession is narrow")
    func dataRetransmissionSurvives() throws {
        var table = ConnectionTable()
        handshake(&table)
        ingest(
            &table,
            from: client,
            to: server,
            flags: [.psh, .ack],
            seq: 1_001,
            ack: 5_001,
            payload: 50,
            ordinal: 4,
            at: 4
        )
        ingest(
            &table,
            from: client,
            to: server,
            flags: [.psh, .ack],
            seq: 1_001,
            ack: 5_001,
            payload: 50,
            ordinal: 5,
            at: 5
        )

        let result = ConnectionAssessor().assess(table.snapshot())
        let retransmission = try #require(result.findings.first { $0.kind == .retransmissionObserved })
        #expect(retransmission.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(5)])
        #expect(!result.findings.contains { $0.kind == .handshakeUnansweredObserved })
    }

    // MARK: Identity, order and projection

    @Test("The abort finding's id is seeded only by connection id and kind")
    func stableIdentity() throws {
        func abort() throws -> ConnectionAnalysisFinding {
            var table = ConnectionTable()
            handshake(&table)
            ingest(
                &table,
                from: client,
                to: server,
                flags: [.psh, .ack],
                seq: 1_001,
                ack: 5_001,
                payload: 50,
                ordinal: 4,
                at: 4
            )
            ingest(&table, from: server, to: client, flags: [.rst, .ack], seq: 5_001, ack: 1_051, ordinal: 5, at: 5)
            let result = ConnectionAssessor().assess(table.snapshot())
            return try #require(result.findings.first { $0.kind == .abortAfterDataObserved })
        }
        let first = try abort()
        let second = try abort()
        #expect(first.id == second.id)
        #expect(first.id == SessionBuilder.stableID(
            "connectionAnalysis|\(first.connectionID.rawValue.uuidString)|abortAfterDataObserved"
        ))
    }

    @Test("Abort ranks before reset before tuple reuse, and half-close after out-of-order")
    func kindRankOrder() {
        #expect(ConnectionAnalysisFindingKind.abortAfterDataObserved.rank
            < ConnectionAnalysisFindingKind.resetObserved.rank)
        #expect(ConnectionAnalysisFindingKind.resetObserved.rank
            < ConnectionAnalysisFindingKind.tupleReuseObserved.rank)
        #expect(ConnectionAnalysisFindingKind.outOfOrderObserved.rank
            < ConnectionAnalysisFindingKind.halfCloseObserved.rank)
    }

    @Test("The three new kinds parse as query finding values")
    func queryProjection() throws {
        let parser = SessionQueryParser()
        #expect(try parser.parse("finding == abortAfterData") == .leaf(.findingKind(.abortAfterData)))
        #expect(try parser.parse("finding == halfClose") == .leaf(.findingKind(.halfClose)))
        #expect(try parser.parse("finding == tupleReuse") == .leaf(.findingKind(.tupleReuse)))
    }

    // MARK: Private

    private let client = IPEndpoint(ip: "192.0.2.10", port: 50_000)
    private let server = IPEndpoint(ip: "203.0.113.5", port: 443)
    private let token = UUID(uuid: (4, 4, 4, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16))

    private var tuple: FiveTuple {
        FiveTuple(proto: .tcp, source: client, destination: server)
    }

    /// A validated three-way handshake at ordinals 1...3: client ISN 1_000, server
    /// ISN 5_000, no window scaling.
    private func handshake(_ table: inout ConnectionTable) {
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: server, to: client, flags: [.syn, .ack], seq: 5_000, ack: 1_001, ordinal: 2, at: 2)
        ingest(&table, from: client, to: server, flags: [.ack], seq: 1_001, ack: 5_001, ordinal: 3, at: 3)
    }

    private func packet(
        from source: IPEndpoint,
        to destination: IPEndpoint,
        flags: TCPFlags,
        seq: UInt32,
        ack: UInt32,
        payload: Int,
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
            windowSize: 65_535,
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
        ordinal: UInt64,
        at timestamp: Double
    ) {
        table.ingest(
            packet(from: source, to: destination, flags: flags, seq: seq, ack: ack, payload: payload, at: timestamp),
            provenance: provenance(ordinal: ordinal, at: timestamp)
        )
    }
}
