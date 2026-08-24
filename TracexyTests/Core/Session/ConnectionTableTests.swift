import Foundation
import Testing
@testable import Tracexy

@Suite("ConnectionTable passive fold")
struct ConnectionTableTests {
    // MARK: Internal

    // MARK: Identity & direction

    @Test("Connection identity is deterministic and disjoint from tuple-only session ids")
    func deterministicIdentity() throws {
        let tuple = FiveTuple(proto: .tcp, source: clientA, destination: serverA)
        let expected = ConnectionID(tuple: tuple, firstOrdinal: FrameOrdinal(1))

        func fold() -> ConnectionID? {
            var table = ConnectionTable()
            ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
            return table.snapshot().summaries.first?.id
        }

        let first = try #require(fold())
        let second = try #require(fold())
        #expect(first == expected)
        #expect(first == second)
        // The connection id must not equal the tuple-only session id: the seed
        // is deliberately disjoint so existing session ids are unchanged.
        #expect(first.rawValue != SessionBuilder.sessionID(for: tuple))
    }

    @Test("Direction is derived only from the canonical tuple endpoints")
    func canonicalDirection() throws {
        var table = ConnectionTable()
        // The client is the canonically-smaller endpoint, so its SYN is aToB.
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        let clientInitiated = try #require(table.snapshot().summaries.first)
        #expect(clientInitiated.initiator == .aToB)

        var reverse = ConnectionTable()
        // A SYN from the larger endpoint is bToA — still by tuple, not by role.
        ingest(&reverse, from: serverA, to: clientA, flags: [.syn], seq: 7_000, ordinal: 1, at: 1)
        let serverInitiated = try #require(reverse.snapshot().summaries.first)
        #expect(serverInitiated.initiator == .bToA)
    }

    // MARK: Handshake

    @Test("A sequence-validated three-way handshake reaches threeWayObserved with three citations")
    func validatedThreeWayHandshake() throws {
        var table = ConnectionTable()
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: serverA, to: clientA, flags: [.syn, .ack], seq: 5_000, ack: 1_001, ordinal: 2, at: 2)
        ingest(&table, from: clientA, to: serverA, flags: [.ack], seq: 1_001, ack: 5_001, ordinal: 3, at: 3)

        let summary = try #require(table.snapshot().summaries.first)
        #expect(summary.handshake == .threeWayObserved)
        #expect(summary.phase == .active)
        #expect(summary.initiator == .aToB)
        #expect(!summary.limitations.contains(.startUnobserved))
        #expect(!summary.limitations.contains(.handshakeIncomplete))

        let completed = try #require(summary.events.first { $0.kind == .handshakeCompleted })
        #expect(completed.provenance.count == 3)
        #expect(completed.provenance.map(\.ordinal) == [FrameOrdinal(1), FrameOrdinal(2), FrameOrdinal(3)])
        #expect(completed.direction == .aToB)
        #expect(completed.sequenceNumber == 1_001)
        #expect(completed.acknowledgementNumber == 5_001)
    }

    @Test("A final ACK with the wrong acknowledgement number does not complete the handshake")
    func falseFinalACKRejected() throws {
        var table = ConnectionTable()
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: serverA, to: clientA, flags: [.syn, .ack], seq: 5_000, ack: 1_001, ordinal: 2, at: 2)
        // ack != responderISN + 1
        ingest(&table, from: clientA, to: serverA, flags: [.ack], seq: 1_001, ack: 9_999, ordinal: 3, at: 3)

        let summary = try #require(table.snapshot().summaries.first)
        #expect(summary.handshake == .synAckObserved)
        #expect(summary.limitations.contains(.handshakeIncomplete))
        #expect(!summary.events.contains { $0.kind == .handshakeCompleted })
    }

    @Test("A SYN+ACK acking the wrong ISN is treated as ambiguous, not a handshake step")
    func falseSYNACKRejected() throws {
        var table = ConnectionTable()
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: serverA, to: clientA, flags: [.syn, .ack], seq: 5_000, ack: 4_242, ordinal: 2, at: 2)

        let summary = try #require(table.snapshot().summaries.first)
        #expect(summary.handshake == .synObserved)
        #expect(summary.limitations.contains(.ambiguousTupleReuse))
    }

    // MARK: Initiator discipline

    @Test("Initiator is known for a clean SYN, unknown for SYN+ACK-first and midstream starts")
    func initiatorDiscipline() throws {
        var synFirst = ConnectionTable()
        ingest(&synFirst, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        #expect(try #require(synFirst.snapshot().summaries.first).initiator == .aToB)

        var synAckFirst = ConnectionTable()
        ingest(&synAckFirst, from: serverA, to: clientA, flags: [.syn, .ack], seq: 5_000, ack: 1_001, ordinal: 1, at: 1)
        let synAck = try #require(synAckFirst.snapshot().summaries.first)
        #expect(synAck.initiator == nil)
        #expect(synAck.handshake == .synAckObserved)
        #expect(synAck.limitations.contains(.startUnobserved))
        #expect(synAck.limitations.contains(.handshakeIncomplete))

        var midstream = ConnectionTable()
        ingest(&midstream, from: clientA, to: serverA, flags: [.ack], payload: 200, ordinal: 1, at: 1)
        let mid = try #require(midstream.snapshot().summaries.first)
        #expect(mid.initiator == nil)
        #expect(mid.phase == .active)
        #expect(mid.handshake == .none)
        #expect(mid.limitations.contains(.startUnobserved))
        #expect(mid.limitations.contains(.handshakeIncomplete))
    }

    @Test("A SYN with captured payload records both setup and payload facts")
    func synWithPayloadIsNotSilentlyDropped() throws {
        var table = ConnectionTable()
        ingest(
            &table, from: clientA, to: serverA, flags: [.syn], seq: 1_000,
            payload: 24, ordinal: 1, at: 1
        )
        let summary = try #require(table.snapshot().summaries.first)
        #expect(summary.events.contains { event in
            event.kind == .payloadObserved && event.direction == .aToB
                && event.sequenceNumber == 1_000 && event.payloadLength == 24
        })
        #expect(summary.phase == .active)
        #expect(summary.limitations.contains(.handshakeIncomplete))
    }

    // MARK: Close observation

    @Test("An RST closes immediately with a directional reset reason")
    func resetClosesImmediately() throws {
        var table = ConnectionTable()
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: serverA, to: clientA, flags: [.rst], seq: 5_000, ordinal: 2, at: 2)

        let summary = try #require(table.snapshot().summaries.first)
        #expect(summary.phase == .closed)
        #expect(summary.isTerminal)
        #expect(summary.closeReason == .reset(.bToA))
        #expect(summary.events.contains { $0.kind == .rst })
    }

    @Test("A single FIN reaches closing; FINs in both directions close orderly")
    func finClose() throws {
        var oneWay = ConnectionTable()
        establishThreeWay(&oneWay)
        ingest(&oneWay, from: clientA, to: serverA, flags: [.fin, .ack], seq: 1_001, ack: 5_001, ordinal: 4, at: 4)
        let closing = try #require(oneWay.snapshot().summaries.first)
        #expect(closing.phase == .closing)
        #expect(closing.finDirections == .aToB)
        #expect(closing.closeReason == nil)

        var bothWays = ConnectionTable()
        establishThreeWay(&bothWays)
        ingest(&bothWays, from: clientA, to: serverA, flags: [.fin, .ack], seq: 1_001, ack: 5_001, ordinal: 4, at: 4)
        ingest(&bothWays, from: serverA, to: clientA, flags: [.fin, .ack], seq: 5_001, ack: 1_002, ordinal: 5, at: 5)
        let orderly = try #require(bothWays.snapshot().summaries.first)
        #expect(orderly.phase == .closed)
        #expect(orderly.closeReason == .orderly)
        #expect(orderly.finDirections.contains(.aToB))
        #expect(orderly.finDirections.contains(.bToA))
    }

    // MARK: Tuple reuse

    @Test("A same-ISN SYN is a retransmission; a different ISN before terminal is ambiguous reuse")
    func synRetransmissionVersusAmbiguousReuse() throws {
        var retransmission = ConnectionTable()
        ingest(&retransmission, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&retransmission, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 2, at: 2)
        let retrans = try #require(retransmission.snapshot().summaries.first)
        #expect(!retrans.limitations.contains(.ambiguousTupleReuse))
        #expect(retrans.events.filter { $0.kind == .syn }.count == 2)

        var ambiguous = ConnectionTable()
        ingest(&ambiguous, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&ambiguous, from: clientA, to: serverA, flags: [.syn], seq: 2_000, ordinal: 2, at: 2)
        let reuse = try #require(ambiguous.snapshot().summaries.first)
        #expect(reuse.limitations.contains(.ambiguousTupleReuse))
        #expect(reuse.events.contains { $0.kind == .ambiguousTupleReuse })
        // Ambiguity stays within the same id — no split.
        #expect(ambiguous.snapshot().summaries.count == 1)
    }

    @Test("A matching SYN+ACK retransmission after completion stays non-ambiguous")
    func lateSYNACKRetransmissionStaysInConnection() throws {
        var table = ConnectionTable()
        establishThreeWay(&table)
        ingest(
            &table, from: serverA, to: clientA, flags: [.syn, .ack],
            seq: 5_000, ack: 1_001, ordinal: 4, at: 4
        )
        let summary = try #require(table.snapshot().summaries.first)
        #expect(summary.handshake == .threeWayObserved)
        #expect(!summary.limitations.contains(.ambiguousTupleReuse))
        #expect(summary.events.filter { $0.kind == .synAck }.count == 2)
    }

    @Test("A fresh SYN after a terminal starts a new id; a late non-SYN stays attached")
    func terminalReuseAndLateSegment() throws {
        var reopened = ConnectionTable()
        establishThreeWay(&reopened)
        ingest(&reopened, from: clientA, to: serverA, flags: [.fin, .ack], seq: 1_001, ack: 5_001, ordinal: 4, at: 4)
        ingest(&reopened, from: serverA, to: clientA, flags: [.fin, .ack], seq: 5_001, ack: 1_002, ordinal: 5, at: 5)
        ingest(&reopened, from: clientA, to: serverA, flags: [.syn], seq: 9_000, ordinal: 6, at: 6)

        let summaries = reopened.snapshot().summaries
        #expect(summaries.count == 2)
        let fresh = try #require(summaries.first { !$0.isTerminal })
        #expect(fresh.id == ConnectionID(tuple: fresh.tuple, firstOrdinal: FrameOrdinal(6)))
        #expect(fresh.handshake == .synObserved)
        #expect(fresh.phase == .opening)

        var lingering = ConnectionTable()
        establishThreeWay(&lingering)
        ingest(&lingering, from: clientA, to: serverA, flags: [.fin, .ack], seq: 1_001, ack: 5_001, ordinal: 4, at: 4)
        ingest(&lingering, from: serverA, to: clientA, flags: [.fin, .ack], seq: 5_001, ack: 1_002, ordinal: 5, at: 5)
        ingest(&lingering, from: clientA, to: serverA, flags: [.ack], payload: 300, ordinal: 6, at: 6)

        let after = lingering.snapshot().summaries
        #expect(after.count == 1)
        let closed = try #require(after.first)
        #expect(closed.phase == .closed)
        #expect(closed.closeReason == .orderly)
        #expect(closed.events.contains { $0.kind == .lateSegmentAfterClose })
        // Three data-ish frames plus two FINs stay counted on the same id.
        #expect(closed.packetCount == 6)
    }

    // MARK: Byte totals & truncation

    @Test("Captured and original byte totals accumulate and mark truncation")
    func byteTotalsAndTruncation() throws {
        var table = ConnectionTable()
        table.ingest(
            packet(from: clientA, to: serverA, flags: [.ack], payload: 100, at: 1),
            provenance: provenance(ordinal: 1, at: 1, captured: 100, original: 100)
        )
        table.ingest(
            packet(from: clientA, to: serverA, flags: [.ack], payload: 60, at: 2),
            provenance: provenance(ordinal: 2, at: 2, captured: 64, original: 200)
        )

        let summary = try #require(table.snapshot().summaries.first)
        #expect(summary.capturedByteTotal == 164)
        #expect(summary.originalByteTotal == 300)
        #expect(summary.limitations.contains(.payloadTruncated))
    }

    @Test("Provenance normalizes negative lengths to zero and raises original to at least captured")
    func provenanceNormalization() {
        let negative = SessionFrameProvenance(
            ordinal: FrameOrdinal(1), timestamp: Date(timeIntervalSince1970: 1),
            capturedLength: -5, originalLength: -10, linkType: 1
        )
        #expect(negative.capturedLength == 0)
        #expect(negative.originalLength == 0)

        let shortOriginal = SessionFrameProvenance(
            ordinal: FrameOrdinal(2), timestamp: Date(timeIntervalSince1970: 2),
            capturedLength: 100, originalLength: 40, linkType: 1
        )
        #expect(shortOriginal.capturedLength == 100)
        #expect(shortOriginal.originalLength == 100)
    }

    // MARK: Loss knowledge

    @Test("Loss knowledge merges stickily with lossReported strongest")
    func lossKnowledgeMerge() throws {
        #expect(CaptureLossKnowledge.unknown.merged(with: .noLossReported) == .noLossReported)
        #expect(CaptureLossKnowledge.noLossReported.merged(with: .lossReported) == .lossReported)
        // Sticky: a later unknown never downgrades a reported loss.
        #expect(CaptureLossKnowledge.lossReported.merged(with: .unknown) == .lossReported)

        var table = ConnectionTable()
        table.ingest(
            packet(from: clientA, to: serverA, flags: [.syn], seq: 1_000, at: 1),
            provenance: provenance(ordinal: 1, at: 1), loss: .noLossReported
        )
        table.ingest(
            packet(from: clientA, to: serverA, flags: [.ack], payload: 10, at: 2),
            provenance: provenance(ordinal: 2, at: 2), loss: .lossReported
        )
        table.ingest(
            packet(from: clientA, to: serverA, flags: [.ack], payload: 10, at: 3),
            provenance: provenance(ordinal: 3, at: 3), loss: .unknown
        )
        #expect(try #require(table.snapshot().summaries.first).lossKnowledge == .lossReported)
    }

    // MARK: Eviction

    @Test("Active-cap eviction removes the least-recently-used connection and finalizes it")
    func lruEviction() throws {
        let config = ConnectionTable.Configuration(maxActiveConnections: 1)
        var table = ConnectionTable(configuration: config)
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: clientB, to: serverB, flags: [.syn], seq: 2_000, ordinal: 2, at: 2)

        let snapshot = table.snapshot()
        assertWithinBounds(snapshot, config)
        let evicted = try #require(snapshot.summaries.first { $0.tuple.a == clientA })
        #expect(evicted.closeReason == .stateEviction)
        #expect(evicted.phase == .closed)
        #expect(evicted.events.contains { $0.kind == .stateEvicted })
        let survivor = try #require(snapshot.summaries.first { $0.tuple.a == clientB })
        #expect(!survivor.isTerminal)
    }

    @Test("Eviction ties break on the earliest first ordinal")
    func lruEvictionTieBreak() throws {
        let config = ConnectionTable.Configuration(maxActiveConnections: 1)
        var table = ConnectionTable(configuration: config)
        // Equal last timestamps; connA has the earlier first ordinal, so it loses.
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 5)
        ingest(&table, from: clientB, to: serverB, flags: [.syn], seq: 2_000, ordinal: 2, at: 5)

        let snapshot = table.snapshot()
        let evicted = try #require(snapshot.summaries.first { $0.tuple.a == clientA })
        #expect(evicted.closeReason == .stateEviction)
        let survivor = try #require(snapshot.summaries.first { $0.tuple.a == clientB })
        #expect(!survivor.isTerminal)
    }

    @Test("A frame after eviction opens a new id flagged priorStateEvicted")
    func postEvictionContinuation() throws {
        let config = ConnectionTable.Configuration(maxActiveConnections: 1)
        var table = ConnectionTable(configuration: config)
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: clientB, to: serverB, flags: [.syn], seq: 2_000, ordinal: 2, at: 2)
        // connA was evicted above; a later frame for it must start fresh.
        ingest(&table, from: clientA, to: serverA, flags: [.ack], payload: 40, ordinal: 3, at: 3)

        let snapshot = table.snapshot()
        let revived = try #require(snapshot.summaries.first { $0.tuple.a == clientA && !$0.isTerminal })
        #expect(revived.id == ConnectionID(tuple: revived.tuple, firstOrdinal: FrameOrdinal(3)))
        #expect(revived.limitations.contains(.priorStateEvicted))
        #expect(revived.limitations.contains(.startUnobserved))
    }

    @Test("Capacity finalization preserves an observed close and still accepts late frames")
    func terminalFinalizationPreservesCloseAndLateAttachment() throws {
        let config = ConnectionTable.Configuration(maxActiveConnections: 1)
        var table = ConnectionTable(configuration: config)
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: serverA, to: clientA, flags: [.rst], seq: 5_000, ordinal: 2, at: 2)
        let closedID = try #require(table.snapshot().summaries.first).id

        // A second tuple forces the already-terminal A state into the published
        // budget. That must not rewrite reset into stateEviction.
        ingest(&table, from: clientB, to: serverB, flags: [.syn], seq: 2_000, ordinal: 3, at: 3)
        var closed = try #require(table.snapshot().summaries.first { $0.id == closedID })
        #expect(closed.closeReason == .reset(.bToA))

        // A non-SYN late frame still attaches to the same finalized identity.
        ingest(&table, from: clientA, to: serverA, flags: [.ack], seq: 1_001, ordinal: 4, at: 4)
        closed = try #require(table.snapshot().summaries.first { $0.id == closedID })
        #expect(closed.closeReason == .reset(.bToA))
        #expect(closed.packetCount == 3)
        #expect(closed.events.contains { $0.kind == .lateSegmentAfterClose })
    }

    // MARK: Event bounds

    @Test("The per-connection event cap drops oldest events and records the omission")
    func perConnectionEventCap() throws {
        let config = ConnectionTable.Configuration(maxEventsPerConnection: 2)
        var table = ConnectionTable(configuration: config)
        // Frame 1 emits firstObserved + syn + a trailing sequenceAdvanced; frame 2
        // emits payloadObserved + a trailing overlap sequence event (seq 1000 is a
        // one-byte retransmit that straddles the expected sequence). The cap keeps
        // only the two newest events across both frames.
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: clientA, to: serverA, flags: [.ack], seq: 1_000, payload: 50, ordinal: 2, at: 2)

        let snapshot = table.snapshot()
        assertWithinBounds(snapshot, config)
        let summary = try #require(snapshot.summaries.first)
        #expect(summary.events.count == 2)
        #expect(summary.omittedEventCount >= 1)
        #expect(summary.limitations.contains(.eventHistoryTruncated))
        // The retained window is exactly the newest two events, in order; no
        // synthetic truncation event replaces the dropped ones.
        #expect(summary.events.map(\.kind) == [.payloadObserved, .overlap])
    }

    @Test("The global event cap bounds total retained events across connections")
    func globalEventCap() {
        let config = ConnectionTable.Configuration(maxEventsPerConnection: 10, maxTotalEvents: 3)
        var table = ConnectionTable(configuration: config)
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: clientB, to: serverB, flags: [.syn], seq: 2_000, ordinal: 2, at: 2)

        let snapshot = table.snapshot()
        assertWithinBounds(snapshot, config)
        #expect(snapshot.retainedEventCount <= config.maxTotalEvents)
        #expect(snapshot.summaries.contains { $0.omittedEventCount >= 1 })
        #expect(snapshot.summaries.contains { $0.limitations.contains(.eventHistoryTruncated) })
    }

    @Test("The global event cap also includes finalized published summaries")
    func globalEventCapIncludesPublishedSummaries() {
        let config = ConnectionTable.Configuration(
            maxActiveConnections: 1,
            maxEventsPerConnection: 10,
            maxTotalEvents: 3,
            maxPublishedSummaries: 4
        )
        var table = ConnectionTable(configuration: config)
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: clientB, to: serverB, flags: [.syn], seq: 2_000, ordinal: 2, at: 2)
        ingest(&table, from: clientC, to: serverC, flags: [.syn], seq: 3_000, ordinal: 3, at: 3)

        let snapshot = table.snapshot()
        assertWithinBounds(snapshot, config)
        #expect(snapshot.publishedSummaryCount == 2)
        #expect(snapshot.retainedEventCount <= config.maxTotalEvents)
        #expect(snapshot.summaries.filter(\.isTerminal).contains {
            $0.limitations.contains(.eventHistoryTruncated)
        })
    }

    // MARK: Summary bounds

    @Test("The published-summary cap drops the oldest terminal summary and counts the omission")
    func publishedSummaryCap() {
        let config = ConnectionTable.Configuration(maxActiveConnections: 1, maxPublishedSummaries: 1)
        var table = ConnectionTable(configuration: config)
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: clientB, to: serverB, flags: [.syn], seq: 2_000, ordinal: 2, at: 2)
        ingest(&table, from: clientC, to: serverC, flags: [.syn], seq: 3_000, ordinal: 3, at: 3)

        let snapshot = table.snapshot()
        assertWithinBounds(snapshot, config)
        #expect(snapshot.omittedSummaryCount == 1)
        #expect(snapshot.publishedSummaryCount == 1)
    }

    // MARK: Saturating counters

    @Test("saturatingAdd reports overflow and clamps to the maximum")
    func saturatingAddSeam() {
        let ordinary = ConnectionTable.saturatingAdd(1, 2)
        #expect(ordinary.value == 3)
        #expect(!ordinary.overflowed)

        let overflowed = ConnectionTable.saturatingAdd(.max, 1)
        #expect(overflowed.value == .max)
        #expect(overflowed.overflowed)
    }

    @Test("Byte totals saturate and mark counterOverflow when reached through ingest")
    func byteCounterOverflow() throws {
        var table = ConnectionTable()
        for ordinal in 1 ... 3 {
            table.ingest(
                packet(from: clientA, to: serverA, flags: [.ack], payload: 100, at: Double(ordinal)),
                provenance: provenance(
                    ordinal: UInt64(ordinal), at: Double(ordinal), captured: Int.max, original: Int.max
                )
            )
        }
        let summary = try #require(table.snapshot().summaries.first)
        #expect(summary.originalByteTotal == .max)
        #expect(summary.capturedByteTotal == .max)
        #expect(summary.limitations.contains(.counterOverflow))
    }

    // MARK: Determinism

    @Test("Identical ordered folds under a small config produce equal snapshots")
    func deterministicSnapshots() {
        let config = ConnectionTable.Configuration(
            maxActiveConnections: 2, maxEventsPerConnection: 4, maxTotalEvents: 6, maxPublishedSummaries: 3
        )

        func fold() -> ConnectionTable.Snapshot {
            var table = ConnectionTable(configuration: config)
            establishThreeWay(&table)
            ingest(
                &table,
                from: clientA,
                to: serverA,
                flags: [.ack],
                seq: 1_001,
                ack: 5_001,
                payload: 500,
                ordinal: 4,
                at: 4
            )
            ingest(&table, from: clientA, to: serverA, flags: [.fin, .ack], seq: 1_501, ack: 5_001, ordinal: 5, at: 5)
            ingest(&table, from: serverA, to: clientA, flags: [.fin, .ack], seq: 5_001, ack: 1_502, ordinal: 6, at: 6)
            ingest(&table, from: clientB, to: serverB, flags: [.syn], seq: 8_000, ordinal: 7, at: 7)
            return table.snapshot()
        }

        let firstRun = fold()
        let secondRun = fold()
        #expect(firstRun == secondRun)
    }

    // MARK: Sequence observation

    @Test("maxPendingSegmentsPerDirection clamps to at least one")
    func pendingBoundClampsToOne() {
        let config = ConnectionTable.Configuration(maxPendingSegmentsPerDirection: 0)
        #expect(config.maxPendingSegmentsPerDirection == 1)
    }

    @Test("The first sequence-bearing segment initializes its direction and emits sequenceAdvanced")
    func firstSegmentInitializes() throws {
        var table = ConnectionTable()
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)

        let summary = try #require(table.snapshot().summaries.first)
        let seqEvent = try #require(summary.events.first { isSequenceEvent($0.kind) })
        #expect(seqEvent.kind == .sequenceAdvanced)
        #expect(seqEvent.direction == .aToB)
        #expect(seqEvent.sequenceNumber == 1_000)
        #expect(seqEvent.provenance.contains { $0.ordinal == FrameOrdinal(1) })
    }

    @Test("Each direction folds through its own tracker, independently")
    func perDirectionTrackersAreIndependent() throws {
        var table = ConnectionTable()
        // aToB anchors at 1000; bToA anchors separately at 5000.
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: serverA, to: clientA, flags: [.syn, .ack], seq: 5_000, ack: 1_001, ordinal: 2, at: 2)
        // A pure ACK completes the handshake but carries no sequence space.
        ingest(&table, from: clientA, to: serverA, flags: [.ack], seq: 1_001, ack: 5_001, ordinal: 3, at: 3)
        // Each direction advances at its own expected sequence.
        ingest(&table, from: clientA, to: serverA, flags: [.ack], seq: 1_001, payload: 10, ordinal: 4, at: 4)
        ingest(&table, from: serverA, to: clientA, flags: [.ack], seq: 5_001, payload: 20, ordinal: 5, at: 5)

        let summary = try #require(table.snapshot().summaries.first)
        // If the trackers were shared, the bToA advance at 5001 would read as far
        // ahead of aToB's expected 1011; that it is a clean advance proves them
        // separate.
        #expect(summary.events.contains {
            $0.kind == .sequenceAdvanced && $0.direction == .aToB
                && $0.sequenceNumber == 1_001 && $0.payloadLength == 10
        })
        #expect(summary.events.contains {
            $0.kind == .sequenceAdvanced && $0.direction == .bToA
                && $0.sequenceNumber == 5_001 && $0.payloadLength == 20
        })
        // The pure ACK at ordinal 3 emitted no sequence event.
        #expect(!summary.events.contains { event in
            isSequenceEvent(event.kind) && event.provenance.contains { $0.ordinal == FrameOrdinal(3) }
        })
    }

    @Test("A contiguous segment emits sequenceAdvanced without a gap")
    func contiguousAdvanceEmitsSequenceAdvanced() throws {
        var table = ConnectionTable()
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1) // expected 1001
        ingest(&table, from: clientA, to: serverA, flags: [.ack], seq: 1_001, payload: 10, ordinal: 2, at: 2)

        let summary = try #require(table.snapshot().summaries.first)
        #expect(summary.events.contains {
            $0.kind == .sequenceAdvanced && $0.sequenceNumber == 1_001 && $0.payloadLength == 10
        })
        #expect(!summary.limitations.contains(.sequenceGapObserved))
    }

    @Test("An exact retransmission emits a retransmission sequence event")
    func duplicateEmitsRetransmission() throws {
        var table = ConnectionTable()
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1) // expected 1001
        ingest(&table, from: clientA, to: serverA, flags: [.ack], seq: 1_001, payload: 10, ordinal: 2, at: 2) // 1011
        ingest(
            &table,
            from: clientA,
            to: serverA,
            flags: [.ack],
            seq: 1_001,
            payload: 10,
            ordinal: 3,
            at: 3
        ) // duplicate

        let summary = try #require(table.snapshot().summaries.first)
        #expect(summary.events.contains { event in
            event.kind == .retransmission && event.provenance.contains { $0.ordinal == FrameOrdinal(3) }
        })
    }

    @Test("A straddling segment emits an overlap sequence event")
    func overlapEmitsOverlap() throws {
        var table = ConnectionTable()
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1) // expected 1001
        ingest(&table, from: clientA, to: serverA, flags: [.ack], seq: 1_001, payload: 10, ordinal: 2, at: 2) // 1011
        ingest(
            &table,
            from: clientA,
            to: serverA,
            flags: [.ack],
            seq: 1_006,
            payload: 10,
            ordinal: 3,
            at: 3
        ) // 1006..<1016

        let summary = try #require(table.snapshot().summaries.first)
        #expect(summary.events.contains { event in
            event.kind == .overlap && event.provenance.contains { $0.ordinal == FrameOrdinal(3) }
        })
    }

    @Test("An out-of-order gap buffers with a sticky gap limitation, then a filler drains it")
    func gapBuffersThenDrainsButKeepsGapLimitation() throws {
        var table = ConnectionTable()
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1) // expected 1001
        ingest(
            &table,
            from: clientA,
            to: serverA,
            flags: [.ack],
            seq: 1_006,
            payload: 5,
            ordinal: 2,
            at: 2
        ) // ahead by 5

        var summary = try #require(table.snapshot().summaries.first)
        #expect(summary.events.contains { $0.kind == .outOfOrderBuffered })
        #expect(summary.limitations.contains(.sequenceGapObserved))

        ingest(
            &table,
            from: clientA,
            to: serverA,
            flags: [.ack],
            seq: 1_001,
            payload: 5,
            ordinal: 3,
            at: 3
        ) // fills + connects
        summary = try #require(table.snapshot().summaries.first)
        #expect(summary.events.contains { $0.kind == .pendingDrained })
        // Draining does not erase the historical discontinuity.
        #expect(summary.limitations.contains(.sequenceGapObserved))
    }

    @Test("Sequence tracking wraps across the UInt32 boundary")
    func sequenceWrapsAcrossBoundary() throws {
        var table = ConnectionTable()
        let base = UInt32.max - 1 // SYN consumes one -> expected UInt32.max
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: base, ordinal: 1, at: 1)
        ingest(
            &table,
            from: clientA,
            to: serverA,
            flags: [.ack],
            seq: UInt32.max,
            payload: 4,
            ordinal: 2,
            at: 2
        ) // -> 3
        ingest(
            &table,
            from: clientA,
            to: serverA,
            flags: [.ack],
            seq: 3,
            payload: 2,
            ordinal: 3,
            at: 3
        ) // contiguous past wrap

        let summary = try #require(table.snapshot().summaries.first)
        #expect(summary.events.contains { $0.kind == .sequenceAdvanced && $0.sequenceNumber == 3 })
        #expect(!summary.limitations.contains(.serialDistanceAmbiguous))
        #expect(!summary.limitations.contains(.sequenceGapObserved))
    }

    @Test("A half-space serial distance is ambiguous and sets a sticky limitation")
    func halfSpaceDistanceIsAmbiguous() throws {
        var table = ConnectionTable()
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 0, ordinal: 1, at: 1) // expected 1
        ingest(&table, from: clientA, to: serverA, flags: [.ack], seq: 1, payload: 3, ordinal: 2, at: 2) // expected 4
        ingest(&table, from: clientA, to: serverA, flags: [.ack], seq: 4 &+ 0x80000000, payload: 1, ordinal: 3, at: 3)

        let summary = try #require(table.snapshot().summaries.first)
        #expect(summary.events.contains { event in
            event.kind == .serialAmbiguous && event.provenance.contains { $0.ordinal == FrameOrdinal(3) }
        })
        #expect(summary.limitations.contains(.serialDistanceAmbiguous))
    }

    @Test("Exceeding the tiny per-direction pending bound overflows and truncates ordering state")
    func pendingOverflowTruncatesState() throws {
        let config = ConnectionTable.Configuration(maxPendingSegmentsPerDirection: 1)
        var table = ConnectionTable(configuration: config)
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 0, ordinal: 1, at: 1) // expected 1
        ingest(
            &table,
            from: clientA,
            to: serverA,
            flags: [.ack],
            seq: 10,
            payload: 1,
            ordinal: 2,
            at: 2
        ) // buffered (pending 1)
        ingest(&table, from: clientA, to: serverA, flags: [.ack], seq: 20, payload: 1, ordinal: 3, at: 3) // overflow

        var summary = try #require(table.snapshot().summaries.first)
        #expect(summary.events.contains { $0.kind == .pendingOverflow })
        #expect(summary.limitations.contains(.sequenceGapObserved))
        #expect(summary.limitations.contains(.sequenceStateTruncated))

        // Truncation is sticky: a later clean advance does not clear it.
        ingest(&table, from: clientA, to: serverA, flags: [.ack], seq: 1, payload: 9, ordinal: 4, at: 4)
        summary = try #require(table.snapshot().summaries.first)
        #expect(summary.limitations.contains(.sequenceStateTruncated))
    }

    @Test("A sequence event carries the triggering frame's direction, facts, and provenance")
    func sequenceEventCarriesFactsAndEvidence() throws {
        var table = ConnectionTable()
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1) // expected 1001
        ingest(
            &table, from: clientA, to: serverA, flags: [.ack],
            seq: 1_001, ack: 5_001, payload: 12, ordinal: 2, at: 2
        )

        let summary = try #require(table.snapshot().summaries.first)
        let advance = try #require(summary.events.first {
            $0.kind == .sequenceAdvanced && $0.sequenceNumber == 1_001
        })
        #expect(advance.direction == .aToB)
        #expect(advance.acknowledgementNumber == 5_001)
        #expect(advance.payloadLength == 12)
        #expect(advance.provenance.count == 1)
        #expect(advance.provenance.first?.ordinal == FrameOrdinal(2))
    }

    @Test("A late frame after finalized publication marks truncated and fabricates no sequence event")
    func finalizedLateFrameTruncatesWithoutSequenceEvent() throws {
        let config = ConnectionTable.Configuration(maxActiveConnections: 1)
        var table = ConnectionTable(configuration: config)
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: serverA, to: clientA, flags: [.rst], seq: 5_000, ordinal: 2, at: 2) // connA closed
        let closedID = try #require(table.snapshot().summaries.first).id

        // A second tuple forces terminal connA out of the active budget into
        // published state, releasing its trackers.
        ingest(&table, from: clientB, to: serverB, flags: [.syn], seq: 2_000, ordinal: 3, at: 3)
        // A late non-SYN frame for the now-published connA.
        ingest(&table, from: clientA, to: serverA, flags: [.ack], seq: 1_001, payload: 40, ordinal: 4, at: 4)

        let closed = try #require(table.snapshot().summaries.first { $0.id == closedID })
        #expect(closed.limitations.contains(.sequenceStateTruncated))
        #expect(closed.events.contains { event in
            event.kind == .lateSegmentAfterClose && event.provenance.contains { $0.ordinal == FrameOrdinal(4) }
        })
        // No fabricated sequence classification for the late (ordinal-4) frame.
        #expect(!closed.events.contains { event in
            isSequenceEvent(event.kind) && event.provenance.contains { $0.ordinal == FrameOrdinal(4) }
        })
    }

    // MARK: Application recovery

    @Test("A split ClientHello over a connection emits one applicationRecord and hands off metadata")
    func applicationRecordEmittedOnceForSplitTLS() throws {
        var table = ConnectionTable()
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)

        let hello = PacketBuilder.tlsClientHello(sni: "conn.example")
        let cut = hello.count / 2
        // Client data starts at seq 1001 (the SYN consumed sequence 1000).
        table.ingest(
            dataPacket(from: clientA, to: serverA, seq: 1_001, payloadBytes: Array(hello[..<cut]), at: 2),
            provenance: provenance(ordinal: 2, at: 2)
        )
        let outcome = table.ingest(
            dataPacket(
                from: clientA, to: serverA, seq: 1_001 + UInt32(cut),
                payloadBytes: Array(hello[cut...]), at: 3
            ),
            provenance: provenance(ordinal: 3, at: 3)
        )

        // The transient handoff carries the classified application for the session.
        #expect(outcome.application?.appProtocol == .tls)
        #expect(outcome.application?.sni == "conn.example")

        let summary = try #require(table.snapshot().summaries.first)
        let records = summary.events.filter { $0.kind == .applicationRecord }
        #expect(records.count == 1)
        let record = try #require(records.first)
        #expect(record.direction == .aToB)
        #expect(record.applicationKind == .tls)
        // TLS becomes identifiable from the first fragment before the full record is
        // complete. The one-shot availability event records that truthful first state;
        // the second fragment enriches the transient session handoff without emitting
        // a duplicate event.
        #expect(record.applicationComplete == false)
        // The record carries no raw application detail beyond kind/completion.
        #expect(!summary.limitations.contains(.applicationProbeTruncated))
        // Sequence observation still folded normally alongside the probe.
        #expect(summary.events.contains { $0.kind == .sequenceAdvanced })
    }

    @Test("An application-prefix overflow truncates only recovery and keeps sequence observation")
    func applicationProbeOverflowTruncatesButKeepsSequence() throws {
        let config = ConnectionTable.Configuration(maxApplicationPrefixBytes: 8)
        var table = ConnectionTable(configuration: config)
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)

        // A single oversized data segment overflows the 8-byte application bound.
        let outcome = table.ingest(
            dataPacket(
                from: clientA, to: serverA, seq: 1_001,
                payloadBytes: [UInt8](repeating: 0xAB, count: 20), at: 2
            ),
            provenance: provenance(ordinal: 2, at: 2)
        )
        #expect(outcome.application == nil)

        let summary = try #require(table.snapshot().summaries.first)
        #expect(summary.limitations.contains(.applicationProbeTruncated))
        #expect(summary.events.contains { $0.kind == .applicationProbeTruncated })
        #expect(!summary.events.contains { $0.kind == .applicationRecord })
        // Sequence observation is unaffected: the 20-byte payload still advanced.
        #expect(summary.events.contains {
            $0.kind == .sequenceAdvanced && $0.sequenceNumber == 1_001 && $0.payloadLength == 20
        })
        #expect(!summary.limitations.contains(.sequenceStateTruncated))
    }

    @Test("Terminal tuple reuse gives the reopened connection a fresh application probe")
    func tupleReuseGetsFreshApplicationProbe() throws {
        var table = ConnectionTable()
        // Connection 1: open, carry a complete ClientHello, close orderly.
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        let hello = PacketBuilder.tlsClientHello(sni: "first.example")
        table.ingest(
            dataPacket(from: clientA, to: serverA, seq: 1_001, payloadBytes: hello, at: 2),
            provenance: provenance(ordinal: 2, at: 2)
        )
        ingest(
            &table,
            from: clientA,
            to: serverA,
            flags: [.fin, .ack],
            seq: 1_001 + UInt32(hello.count),
            ack: 5_001,
            ordinal: 3,
            at: 3
        )
        ingest(&table, from: serverA, to: clientA, flags: [.fin, .ack], seq: 5_001, ack: 1_002, ordinal: 4, at: 4)

        // Connection 2: a fresh SYN reopens the tuple; its own ClientHello must be
        // recovered independently by a brand-new probe.
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 9_000, ordinal: 5, at: 5)
        let second = PacketBuilder.tlsClientHello(sni: "second.example")
        let outcome = table.ingest(
            dataPacket(from: clientA, to: serverA, seq: 9_001, payloadBytes: second, at: 6),
            provenance: provenance(ordinal: 6, at: 6)
        )
        #expect(outcome.application?.sni == "second.example")

        let summaries = table.snapshot().summaries
        #expect(summaries.count == 2)
        // Each distinct connection id emitted exactly one applicationRecord.
        for summary in summaries {
            #expect(summary.events.filter { $0.kind == .applicationRecord }.count == 1)
        }
        let reopened = try #require(summaries.first { !$0.isTerminal })
        #expect(reopened.id == ConnectionID(tuple: reopened.tuple, firstOrdinal: FrameOrdinal(5)))
    }

    // MARK: Private

    // Documentation-only endpoints (RFC 5737). The lower-valued IP in each pair
    // is the canonical `a`, so a client→server SYN is aToB.
    private let clientA = IPEndpoint(ip: "192.0.2.10", port: 50_000)
    private let serverA = IPEndpoint(ip: "203.0.113.5", port: 443)
    private let clientB = IPEndpoint(ip: "198.51.100.20", port: 50_001)
    private let serverB = IPEndpoint(ip: "203.0.113.6", port: 443)
    private let clientC = IPEndpoint(ip: "198.51.100.30", port: 50_002)
    private let serverC = IPEndpoint(ip: "203.0.113.7", port: 443)
    // A fixed capture-local source token keeps locators — and therefore
    // snapshots — equal across identical folds.
    private let token = UUID(uuid: (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16))

    private func packet(
        from source: IPEndpoint,
        to destination: IPEndpoint,
        flags: TCPFlags,
        seq: UInt32 = 0,
        ack: UInt32 = 0,
        payload: Int = 0,
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
            windowSize: 0,
            headerLength: 20,
            payloadSequence: seq,
            payloadLength: payload,
            options: TCPOptionFacts()
        )
        return pkt
    }

    /// A PSH+ACK data segment carrying real application bytes, so the connection's
    /// per-direction application probe folds it. `seq` is the payload's own sequence
    /// (the caller accounts for any prior SYN), and no per-frame app protocol is set
    /// so the probe relies on the reassembled prefix, not a single-frame classify.
    private func dataPacket(
        from source: IPEndpoint,
        to destination: IPEndpoint,
        seq: UInt32,
        payloadBytes: [UInt8],
        at timestamp: Double
    )
        -> DecodedPacket
    {
        var pkt = packet(
            from: source, to: destination, flags: [.psh, .ack],
            seq: seq, payload: payloadBytes.count, at: timestamp
        )
        pkt.tcpPayloadSequence = seq
        pkt.tcpPayloadBytes = payloadBytes
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

    /// Whether an event kind is one of the sequence-observation kinds (as opposed
    /// to a lifecycle kind).
    private func isSequenceEvent(_ kind: ConnectionEventKind) -> Bool {
        switch kind {
        case .sequenceAdvanced,
             .retransmission,
             .overlap,
             .outOfOrderBuffered,
             .pendingDrained,
             .pendingOverflow,
             .serialAmbiguous:
            true
        default:
            false
        }
    }

    private func establishThreeWay(_ table: inout ConnectionTable) {
        ingest(&table, from: clientA, to: serverA, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: serverA, to: clientA, flags: [.syn, .ack], seq: 5_000, ack: 1_001, ordinal: 2, at: 2)
        ingest(&table, from: clientA, to: serverA, flags: [.ack], seq: 1_001, ack: 5_001, ordinal: 3, at: 3)
    }

    private func assertWithinBounds(_ snapshot: ConnectionTable.Snapshot, _ config: ConnectionTable.Configuration) {
        #expect(snapshot.activeConnectionCount <= config.maxActiveConnections)
        #expect(snapshot.publishedSummaryCount <= config.maxPublishedSummaries)
        #expect(snapshot.summaries.count == snapshot.activeConnectionCount + snapshot.publishedSummaryCount)
        for summary in snapshot.summaries {
            #expect(summary.events.count <= config.maxEventsPerConnection)
            for event in summary.events {
                #expect(!event.provenance.isEmpty)
                #expect(event.provenance.count <= 3)
            }
        }
        #expect(snapshot.retainedEventCount <= config.maxTotalEvents)
        #expect(snapshot.retainedEventCount == snapshot.summaries.reduce(0) { $0 + $1.events.count })
        #expect(!snapshot.countersOverflowed)
    }
}
