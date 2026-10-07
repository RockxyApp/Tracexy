import Foundation
import Testing
@testable import Tracexy

/// The per-segment TCP series fold. Every case offers decoded frames in capture
/// order and pins exactly what the table retained, what it counted, and that the
/// retained run is always a *prefix* with no hole in it. Nothing here derives a
/// series; that is `TCPStreamHealthTests`.
@Suite("TCPSegmentSeriesTable")
struct TCPSegmentSeriesTableTests {
    // MARK: Internal

    // MARK: Retention

    @Test("Every TCP segment of a flow is retained in capture order with its header fields")
    func retainsSegmentsInOrder() throws {
        var table = TCPSegmentSeriesTable()
        offer(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 0)
        offer(&table, from: server, to: client, flags: [.syn, .ack], seq: 5_000, ack: 1_001, ordinal: 2, at: 0.02)
        offer(&table, from: client, to: server, flags: [.ack], seq: 1_001, ack: 5_001, ordinal: 3, at: 0.03)

        let snapshot = table.snapshot()
        let summary = try #require(snapshot.summaries.first)
        #expect(snapshot.summaries.count == 1)
        #expect(summary.observations.map(\.provenance.ordinal.rawValue) == [1, 2, 3])
        #expect(summary.observations.map(\.direction) == [.aToB, .bToA, .aToB])
        #expect(summary.observations[0].sequenceNumber == 1_000)
        #expect(summary.observations[1].acknowledgementNumber == 1_001)
        #expect(summary.observations[1].flags == [.syn, .ack])
        #expect(summary.observations[2].windowSize == 65_535)
        #expect(summary.omittedObservationCount == 0)
        #expect(snapshot.retainedObservationCount == 3)
        #expect(!snapshot.capacityReached)
    }

    @Test("The session id is the shared tuple-derived id, not a connection id")
    func usesTupleDerivedSessionID() throws {
        var table = TCPSegmentSeriesTable()
        offer(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 0)
        let summary = try #require(table.snapshot().summaries.first)
        let tuple = FiveTuple(proto: .tcp, source: client, destination: server)
        #expect(summary.sessionID == SessionBuilder.sessionID(for: tuple))
        #expect(table.snapshot().summary(for: summary.sessionID) == summary)
        #expect(table.snapshot().summary(for: UUID()) == nil)
    }

    @Test("A direction is derived from the canonical tuple and both are kept apart")
    func separatesDirections() throws {
        var table = TCPSegmentSeriesTable()
        offer(&table, from: client, to: server, flags: [.ack], seq: 1, ordinal: 1, at: 0)
        offer(&table, from: server, to: client, flags: [.ack], seq: 2, ordinal: 2, at: 1)
        let summary = try #require(table.snapshot().summaries.first)
        #expect(Set(summary.observations.map(\.direction)) == [.aToB, .bToA])
        // The canonical ordering is the tuple's, not the arrival order.
        let tuple = summary.tuple
        #expect(summary.observations[0].direction == (tuple.a == client ? .aToB : .bToA))
    }

    @Test("Window scale is retained per segment exactly as the option stated it")
    func retainsWindowScale() throws {
        var table = TCPSegmentSeriesTable()
        offer(&table, from: client, to: server, flags: [.syn], seq: 1_000, shift: 7, ordinal: 1, at: 0)
        offer(&table, from: client, to: server, flags: [.ack], seq: 1_001, ordinal: 2, at: 0.1)
        let summary = try #require(table.snapshot().summaries.first)
        #expect(summary.observations[0].windowScale == 7)
        #expect(summary.observations[1].windowScale == nil)
    }

    @Test("Non-TCP, tupleless and unplaceable frames fold nothing")
    func ignoresIrrelevantFrames() {
        var table = TCPSegmentSeriesTable()
        var udp = DecodedPacket(timestamp: Date(timeIntervalSince1970: 0), originalLength: 80)
        udp.transport = .udp
        udp.sourceEndpoint = client
        udp.destinationEndpoint = server
        udp.fiveTuple = FiveTuple(proto: .udp, source: client, destination: server)
        table.offer(udp, provenance: provenance(ordinal: 1, at: 0))

        var tupleless = packet(from: client, to: server, flags: [.ack], seq: 1, at: 0)
        tupleless.fiveTuple = nil
        table.offer(tupleless, provenance: provenance(ordinal: 2, at: 0))

        // A source matching neither canonical endpoint is left unplaced, never guessed.
        var mismatched = packet(from: client, to: server, flags: [.ack], seq: 1, at: 0)
        mismatched.sourceEndpoint = IPEndpoint(ip: "198.51.100.99", port: 1)
        table.offer(mismatched, provenance: provenance(ordinal: 3, at: 0))

        #expect(table.snapshot() == TCPSegmentSeriesTable.Snapshot.empty)
    }

    // MARK: Bounds

    @Test("The per-summary bound closes the prefix and counts every later segment exactly")
    func perSummaryBoundKeepsAPrefix() throws {
        var table = TCPSegmentSeriesTable(
            configuration: TCPSegmentSeriesTable.Configuration(maxObservationsPerSummary: 3)
        )
        for ordinal in 1 ... 10 {
            offer(
                &table, from: client, to: server, flags: [.ack],
                seq: UInt32(ordinal), ordinal: UInt64(ordinal), at: Double(ordinal)
            )
        }
        let snapshot = table.snapshot()
        let summary = try #require(snapshot.summaries.first)
        // A prefix, not a sample: the first three ordinals and nothing later.
        #expect(summary.observations.map(\.provenance.ordinal.rawValue) == [1, 2, 3])
        #expect(summary.omittedObservationCount == 7)
        #expect(snapshot.omittedObservationCount == 7)
        #expect(snapshot.retainedObservationCount == 3)
        #expect(snapshot.capacityReached)
    }

    @Test("The global bound stops retention across flows while each flow counts its own omissions")
    func globalBoundIsShared() {
        var table = TCPSegmentSeriesTable(
            configuration: TCPSegmentSeriesTable.Configuration(maxTotalObservations: 3)
        )
        offer(&table, from: client, to: server, flags: [.ack], seq: 1, ordinal: 1, at: 0)
        offer(&table, from: client, to: server, flags: [.ack], seq: 2, ordinal: 2, at: 1)
        offer(&table, from: clientB, to: serverB, flags: [.ack], seq: 3, ordinal: 3, at: 2)
        offer(&table, from: clientB, to: serverB, flags: [.ack], seq: 4, ordinal: 4, at: 3)
        offer(&table, from: client, to: server, flags: [.ack], seq: 5, ordinal: 5, at: 4)

        let snapshot = table.snapshot()
        #expect(snapshot.retainedObservationCount == 3)
        #expect(snapshot.omittedObservationCount == 2)
        #expect(snapshot.summaries.count == 2)
        #expect(snapshot.summaries[0].observations.count == 2)
        #expect(snapshot.summaries[0].omittedObservationCount == 1)
        #expect(snapshot.summaries[1].observations.count == 1)
        #expect(snapshot.summaries[1].omittedObservationCount == 1)
        #expect(snapshot.capacityReached)
    }

    @Test("A new flow beyond the summary cap retains nothing and is counted globally")
    func summaryCapDropsNewFlows() {
        var table = TCPSegmentSeriesTable(configuration: TCPSegmentSeriesTable.Configuration(maxSummaries: 1))
        offer(&table, from: client, to: server, flags: [.ack], seq: 1, ordinal: 1, at: 0)
        offer(&table, from: clientB, to: serverB, flags: [.ack], seq: 2, ordinal: 2, at: 1)
        offer(&table, from: clientB, to: serverB, flags: [.ack], seq: 3, ordinal: 3, at: 2)

        let snapshot = table.snapshot()
        #expect(snapshot.summaries.count == 1)
        #expect(snapshot.retainedObservationCount == 1)
        #expect(snapshot.omittedObservationCount == 2)
        #expect(snapshot.capacityReached)
    }

    @Test("Bounds are clamped so no configuration can disable the table")
    func boundsAreClamped() {
        let configuration = TCPSegmentSeriesTable.Configuration(
            maxSummaries: 0,
            maxObservationsPerSummary: -5,
            maxTotalObservations: 0
        )
        #expect(configuration.maxSummaries == 1)
        #expect(configuration.maxObservationsPerSummary == 1)
        #expect(configuration.maxTotalObservations == 1)
    }

    @Test("Saturating addition caps at the maximum and reports the overflow")
    func saturatingAddition() {
        #expect(TCPSegmentSeriesTable.saturatingAdd(3, 4) == (7, false))
        let saturated = TCPSegmentSeriesTable.saturatingAdd(.max, 1)
        #expect(saturated.value == .max)
        #expect(saturated.overflowed)
    }

    // MARK: Coverage facts

    @Test("Loss knowledge merges stickily and only from retained frames")
    func mergesLossKnowledge() throws {
        var table = TCPSegmentSeriesTable(
            configuration: TCPSegmentSeriesTable.Configuration(maxObservationsPerSummary: 2)
        )
        offer(&table, from: client, to: server, flags: [.ack], seq: 1, ordinal: 1, at: 0, loss: .noLossReported)
        offer(&table, from: client, to: server, flags: [.ack], seq: 2, ordinal: 2, at: 1, loss: .lossReported)
        // A frame past the prefix cannot change a coverage fact about the run drawn.
        offer(&table, from: client, to: server, flags: [.ack], seq: 3, ordinal: 3, at: 2, loss: .unknown)

        let summary = try #require(table.snapshot().summaries.first)
        #expect(summary.lossKnowledge == .lossReported)
        #expect(summary.omittedObservationCount == 1)
    }

    @Test("A short capture is recorded from the retained frames only")
    func recordsSnapLengthTruncation() throws {
        var table = TCPSegmentSeriesTable()
        offer(&table, from: client, to: server, flags: [.ack], seq: 1, ordinal: 1, at: 0)
        #expect(try #require(table.snapshot().summaries.first).snapLengthTruncationObserved == false)
        offer(
            &table, from: client, to: server, flags: [.ack],
            seq: 2, ordinal: 2, at: 1, captured: 60, original: 1_500
        )
        #expect(try #require(table.snapshot().summaries.first).snapLengthTruncationObserved)
    }

    @Test("An untimed frame is retained like any other; only the analysis skips it")
    func retainsUntimedFrames() throws {
        var table = TCPSegmentSeriesTable()
        var untimed = packet(from: client, to: server, flags: [.ack], seq: 1, at: 0)
        untimed.timestamp = nil
        table.offer(
            untimed,
            provenance: SessionFrameProvenance(
                ordinal: FrameOrdinal(1),
                timestamp: nil,
                capturedLength: 60,
                originalLength: 60,
                linkType: 1
            )
        )
        let summary = try #require(table.snapshot().summaries.first)
        #expect(summary.observations.count == 1)
        #expect(summary.observations[0].provenance.timestamp == nil)
    }

    // MARK: Determinism

    @Test("Replaying the same ordered frames yields an identical snapshot")
    func replayIsDeterministic() {
        func fold() -> TCPSegmentSeriesTable.Snapshot {
            var table = TCPSegmentSeriesTable()
            for ordinal in 1 ... 6 {
                let outbound = ordinal.isMultiple(of: 2)
                offer(
                    &table,
                    from: outbound ? server : client,
                    to: outbound ? client : server,
                    flags: [.ack],
                    seq: UInt32(ordinal * 10),
                    ordinal: UInt64(ordinal),
                    at: Double(ordinal) / 10
                )
            }
            return table.snapshot()
        }
        let first = fold()
        let second = fold()
        #expect(first == second)
    }

    // MARK: Private

    private let client = IPEndpoint(ip: "198.51.100.10", port: 50_000)
    private let server = IPEndpoint(ip: "203.0.113.5", port: 443)
    private let clientB = IPEndpoint(ip: "198.51.100.20", port: 50_001)
    private let serverB = IPEndpoint(ip: "203.0.113.6", port: 80)
    private let token = UUID(uuid: (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16))

    private func packet(
        from source: IPEndpoint,
        to destination: IPEndpoint,
        flags: TCPFlags,
        seq: UInt32,
        ack: UInt32 = 0,
        payload: Int = 0,
        window: UInt16 = 65_535,
        shift: UInt8? = nil,
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
            options: TCPOptionFacts(windowScaleRaw: shift, windowScale: shift)
        )
        return pkt
    }

    private func provenance(
        ordinal: UInt64,
        at timestamp: Double,
        captured: Int = 120,
        original: Int = 120
    )
        -> SessionFrameProvenance
    {
        SessionFrameProvenance(
            ordinal: FrameOrdinal(ordinal),
            timestamp: Date(timeIntervalSince1970: timestamp),
            capturedLength: captured,
            originalLength: original,
            linkType: 1,
            locator: SessionEvidenceLocator(sourceToken: token, offset: ordinal)
        )
    }

    private func offer(
        _ table: inout TCPSegmentSeriesTable,
        from source: IPEndpoint,
        to destination: IPEndpoint,
        flags: TCPFlags,
        seq: UInt32,
        ack: UInt32 = 0,
        payload: Int = 0,
        window: UInt16 = 65_535,
        shift: UInt8? = nil,
        ordinal: UInt64,
        at timestamp: Double,
        captured: Int = 120,
        original: Int = 120,
        loss: CaptureLossKnowledge = .unknown
    ) {
        table.offer(
            packet(
                from: source, to: destination, flags: flags, seq: seq, ack: ack,
                payload: payload, window: window, shift: shift, at: timestamp
            ),
            provenance: provenance(ordinal: ordinal, at: timestamp, captured: captured, original: original),
            loss: loss
        )
    }
}
