import Foundation
import Testing
@testable import Tracexy

/// The two summary-level lifecycle findings. Half of these tests drive the
/// real `ConnectionTable` fold so the finding is proven from segments, not from a
/// hand-built summary; the rest pin the assessor's rule boundaries directly.
@Suite("ConnectionAssessor lifecycle findings")
struct ConnectionLifecycleFindingTests {
    // MARK: Internal

    // MARK: Folded from real segments

    @Test("SYN answered only by a responder RST folds into connectionRefusedObserved citing SYN and RST")
    func refusedFromFold() throws {
        var table = ConnectionTable()
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: server, to: client, flags: [.rst, .ack], seq: 0, ack: 1_001, ordinal: 2, at: 2)

        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(result.findings.map(\.kind) == [.connectionRefusedObserved])
        let finding = try #require(result.findings.first)
        #expect(finding.severity == .warning)
        #expect(finding.tuple == tuple)
        #expect(finding.citations.map(\.sourceEventKind) == [.syn, .rst])
        #expect(finding.citations.map(\.direction) == [.aToB, .bToA])
        #expect(finding.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(1), FrameOrdinal(2)])
        #expect(finding.omittedCitationCount == 0)
        // The refused open is reported once: the generic reset finding is superseded.
        #expect(!result.findings.contains { $0.kind == .resetObserved })
    }

    @Test("A SYN retried without any SYN+ACK folds into handshakeUnansweredObserved citing every SYN")
    func unansweredFromFold() throws {
        var table = ConnectionTable()
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 2, at: 2)
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 3, at: 4)

        let result = ConnectionAssessor().assess(table.snapshot())
        let unanswered = try #require(result.findings.first { $0.kind == .handshakeUnansweredObserved })
        #expect(unanswered.severity == .warning)
        #expect(unanswered.citations.map(\.sourceEventKind) == [.syn, .syn, .syn])
        #expect(unanswered.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(1), FrameOrdinal(2), FrameOrdinal(3)])
        #expect(unanswered.citations.allSatisfy { $0.direction == .aToB })
        // No refused or reset finding can exist without a reset.
        #expect(!result.findings.contains { $0.kind == .connectionRefusedObserved || $0.kind == .resetObserved })
    }

    @Test("A single unanswered SYN is not a finding — the capture may simply have ended")
    func singleSYNIsNotAFinding() {
        var table = ConnectionTable()
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(result.findings.isEmpty)
    }

    @Test("A retried SYN that is eventually answered yields no lifecycle finding")
    func answeredRetryIsNotAFinding() {
        var table = ConnectionTable()
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 2, at: 2)
        ingest(&table, from: server, to: client, flags: [.syn, .ack], seq: 5_000, ack: 1_001, ordinal: 3, at: 3)
        ingest(&table, from: client, to: server, flags: [.ack], seq: 1_001, ack: 5_001, ordinal: 4, at: 4)
        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(!result.findings.contains {
            $0.kind == .handshakeUnansweredObserved || $0.kind == .connectionRefusedObserved
        })
    }

    @Test("A reset from the initiator after its own SYN is a plain reset, not a refusal")
    func initiatorResetIsNotRefused() {
        var table = ConnectionTable()
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: client, to: server, flags: [.rst], seq: 1_001, ordinal: 2, at: 2)
        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(result.findings.map(\.kind) == [.resetObserved])
    }

    @Test("A reset after an observed SYN+ACK is a plain reset, not a refusal")
    func resetAfterSYNACKIsNotRefused() {
        var table = ConnectionTable()
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: server, to: client, flags: [.syn, .ack], seq: 5_000, ack: 1_001, ordinal: 2, at: 2)
        ingest(&table, from: server, to: client, flags: [.rst], seq: 5_001, ordinal: 3, at: 3)
        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(result.findings.map(\.kind) == [.resetObserved])
    }

    @Test("A lone RST with no observed open is a plain reset")
    func loneResetIsNotRefused() {
        var table = ConnectionTable()
        ingest(&table, from: server, to: client, flags: [.rst], seq: 0, ordinal: 1, at: 1)
        let result = ConnectionAssessor().assess(table.snapshot())
        #expect(result.findings.map(\.kind) == [.resetObserved])
    }

    // MARK: Identity, order and bounds

    @Test("Lifecycle finding ids are stable and seeded only by connection id and kind")
    func stableIdentity() throws {
        func refused() throws -> ConnectionAnalysisFinding {
            var table = ConnectionTable()
            ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
            ingest(&table, from: server, to: client, flags: [.rst, .ack], seq: 0, ack: 1_001, ordinal: 2, at: 2)
            return try #require(ConnectionAssessor().assess(table.snapshot()).findings.first)
        }
        let first = try refused()
        let second = try refused()
        #expect(first.id == second.id)
        let expected = SessionBuilder.stableID(
            "connectionAnalysis|\(first.connectionID.rawValue.uuidString)|connectionRefusedObserved"
        )
        #expect(first.id == expected)
    }

    @Test("Refused ranks before unanswered before reset at an equal first cited ordinal")
    func kindRankOrder() {
        #expect(ConnectionAnalysisFindingKind.connectionRefusedObserved.rank
            < ConnectionAnalysisFindingKind.handshakeUnansweredObserved.rank)
        #expect(ConnectionAnalysisFindingKind.handshakeUnansweredObserved.rank
            < ConnectionAnalysisFindingKind.resetObserved.rank)
    }

    @Test("Unanswered citations honor the per-finding bound with an exact omission count")
    func unansweredCitationBound() throws {
        var table = ConnectionTable()
        for ordinal in 1 ... 5 {
            ingest(
                &table, from: client, to: server, flags: [.syn], seq: 1_000,
                ordinal: UInt64(ordinal), at: Double(ordinal)
            )
        }
        let config = ConnectionAssessor.Configuration(maxCitationsPerFinding: 2)
        let result = ConnectionAssessor(configuration: config).assess(table.snapshot())
        let unanswered = try #require(result.findings.first { $0.kind == .handshakeUnansweredObserved })
        #expect(unanswered.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(1), FrameOrdinal(2)])
        #expect(unanswered.omittedCitationCount == 3)
    }

    @Test("Coverage follows the connection's loss knowledge")
    func coverageFollowsLoss() throws {
        var table = ConnectionTable()
        table.ingest(
            packet(from: client, to: server, flags: [.syn], seq: 1_000, at: 1),
            provenance: provenance(ordinal: 1, at: 1),
            loss: .lossReported
        )
        table.ingest(
            packet(from: server, to: client, flags: [.rst, .ack], seq: 0, ack: 1_001, at: 2),
            provenance: provenance(ordinal: 2, at: 2),
            loss: .noLossReported
        )
        let finding = try #require(ConnectionAssessor().assess(table.snapshot()).findings.first)
        #expect(finding.kind == .connectionRefusedObserved)
        #expect(finding.coverage == .captureLossReported)
    }

    // MARK: Query projection

    @Test("Lifecycle findings project to their own query finding kinds")
    func queryProjection() throws {
        var table = ConnectionTable()
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: server, to: client, flags: [.rst, .ack], seq: 0, ack: 1_001, ordinal: 2, at: 2)
        let analysis = ConnectionAssessor().assess(table.snapshot())
        let finding = try #require(analysis.findings.first)
        #expect(finding.kind == .connectionRefusedObserved)
        let parser = SessionQueryParser()
        #expect(try parser.parse("finding == connectionRefused") == .leaf(.findingKind(.connectionRefused)))
        #expect(try parser.parse("finding == handshakeUnanswered") == .leaf(.findingKind(.handshakeUnanswered)))
    }

    // MARK: Private

    private let client = IPEndpoint(ip: "192.0.2.10", port: 50_000)
    private let server = IPEndpoint(ip: "203.0.113.5", port: 443)
    private let token = UUID(uuid: (9, 9, 9, 9, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16))

    private var tuple: FiveTuple {
        FiveTuple(proto: .tcp, source: client, destination: server)
    }

    private func packet(
        from source: IPEndpoint,
        to destination: IPEndpoint,
        flags: TCPFlags,
        seq: UInt32 = 0,
        ack: UInt32 = 0,
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
            payloadSequence: seq,
            payloadLength: 0,
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
        ordinal: UInt64,
        at timestamp: Double
    ) {
        table.ingest(
            packet(from: source, to: destination, flags: flags, seq: seq, ack: ack, at: timestamp),
            provenance: provenance(ordinal: ordinal, at: timestamp)
        )
    }
}
