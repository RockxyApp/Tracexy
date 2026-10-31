import Foundation
import Testing
@testable import Tracexy

/// The derived TCP health charts and the words that render them. Every case
/// folds frames through the real ``TCPSegmentSeriesTable`` and pins the derived
/// values, so a chart claim is checkable without a window.
@Suite("TCPStreamHealth")
struct TCPStreamHealthTests {
    // MARK: Internal

    // MARK: Sequence

    @Test("Sequence is relative to each direction's first observed segment, not to an ISN")
    func sequenceIsRelativeToWhatWasObserved() throws {
        let health = try project { table in
            // A midstream capture: no SYN, so the base is simply the first segment seen.
            offer(&table, from: client, to: server, flags: [.ack], seq: 9_000, payload: 100, ordinal: 1, at: 0)
            offer(&table, from: client, to: server, flags: [.ack], seq: 9_100, payload: 100, ordinal: 2, at: 0.1)
        }
        let line = try #require(health.series(for: .sequence).first { $0.role == .sequenceReached })
        #expect(line.points.map(\.value) == [100, 200])
        #expect(line.points.map(\.provenance?.ordinal.rawValue) == [1, 2])
    }

    @Test("A SYN occupies one sequence number, so a handshake reaches 1 before any data")
    func synOccupiesOneSequenceNumber() throws {
        let health = try project { table in
            handshake(&table)
        }
        let sent = try #require(health.series(for: .sequence).first {
            $0.role == .sequenceReached && $0.direction == direction(of: client)
        })
        #expect(sent.points.map(\.value) == [1])
    }

    @Test("Sequence plots observed payload byte intervals separately from the reached edge")
    func payloadSequenceIntervalsExcludeControlSequenceBytes() throws {
        let health = try project { table in
            handshake(&table)
            offer(
                &table, from: client, to: server, flags: [.syn, .ack], seq: 1_001,
                payload: 50, ordinal: 4, at: 0.1
            )
            offer(
                &table, from: client, to: server, flags: [.fin, .ack], seq: 1_052,
                payload: 10, ordinal: 5, at: 0.2
            )
            offer(&table, from: client, to: server, flags: [.ack], seq: 1_063, ordinal: 6, at: 0.3)
        }
        let direction = direction(of: client)
        let intervals = try #require(health.series(for: .sequence).first {
            $0.role == .sequencePayload && $0.direction == direction
        })
        #expect(intervals.points.map(\.value) == [2, 52])
        #expect(intervals.points.map(\.rangeEnd) == [52, 62])
        #expect(intervals.points.map(\.provenance?.ordinal.rawValue) == [4, 5])
        let reached = try #require(health.series(for: .sequence).first {
            $0.role == .sequenceReached && $0.direction == direction
        })
        #expect(reached.points.last?.value == 63)
    }

    @Test("SACK ranges crossing the relative sequence half-space are omitted")
    func sackRangeCrossingHalfSpaceIsUnplottable() throws {
        let health = try project { table in
            offer(&table, from: client, to: server, flags: [.ack], seq: 0, ordinal: 1, at: 0)
            offer(
                &table, from: server, to: client, flags: [.ack], seq: 5_000,
                sackBlocks: [TCPSACKBlock(leftEdge: 0x7FFFFFFF, rightEdge: 0x80000001)], ordinal: 2, at: 1
            )
        }
        #expect(!health.series.contains { $0.role == .sackRange })
        #expect(health.coverage.unplottableSACKRangeCount == 1)
        #expect(!health.series.contains { $0.role == .goodput })
    }

    @Test("Payload intervals crossing the relative sequence half-space are omitted with coverage")
    func payloadRangeCrossingHalfSpaceIsUnplottable() throws {
        let health = try project { table in
            offer(&table, from: client, to: server, flags: [.ack], seq: 0, ordinal: 1, at: 0)
            offer(
                &table, from: client, to: server, flags: [.psh, .ack], seq: 0x7FFFFFFF,
                payload: 2, ordinal: 2, at: 1
            )
        }
        #expect(!health.series.contains { $0.role == .sequencePayload })
        #expect(health.coverage.unplottablePayloadRangeCount == 1)
        #expect(SessionStreamHealth.caveat(for: .sequence, coverage: health.coverage)?
            .contains("1 captured payload range") == true)
    }

    @Test("Receiver-reported SACK ranges plot in peer sequence space at the citing ACK")
    func sackRangesAreMappedAndCited() throws {
        let health = try project { table in
            handshake(&table)
            offer(&table, from: client, to: server, flags: [.psh, .ack], seq: 1_001, payload: 500, ordinal: 4, at: 0.1)
            offer(
                &table, from: server, to: client, flags: [.ack], seq: 5_001, ack: 1_101,
                sackBlocks: [
                    TCPSACKBlock(leftEdge: 1_101, rightEdge: 1_201),
                    TCPSACKBlock(leftEdge: 1_301, rightEdge: 1_351)
                ],
                ordinal: 5, at: 0.2
            )
        }
        let lines = health.series.filter { $0.role == .sackRange && $0.direction == direction(of: client) }
        #expect(lines.map(\.variant) == [0, 1])
        #expect(lines.map { $0.points.map(\.value) } == [[101], [301]])
        #expect(lines.map { $0.points.map(\.rangeEnd) } == [[201], [351]])
        #expect(lines.map { $0.points.first?.provenance?.ordinal.rawValue } == [5, 5])
        #expect(health.coverage.unplottableSACKRangeCount == 0)
        let line = try #require(lines.last)
        #expect(SessionStreamChartLine(series: line, tuple: health.tuple).label.contains("SACK range 2 reported"))
        #expect(Set(health.series.map(\.id)).count == health.series.count)
    }

    @Test("D-SACK ranges are highlighted only by the RFC 2883 same-ACK rules")
    func duplicateSACKRangesAreHighlightedWithReceiverCaveat() throws {
        let belowAcknowledgement = try project { table in
            offer(&table, from: client, to: server, flags: [.ack], seq: 1_000, ordinal: 1, at: 0)
            offer(
                &table, from: server, to: client, flags: [.ack], seq: 5_000, ack: 1_100,
                sackBlocks: [TCPSACKBlock(leftEdge: 1_000, rightEdge: 1_100)], ordinal: 2, at: 0.1
            )
        }
        let below = try #require(belowAcknowledgement.series.first { $0.role == .duplicateSACKRange })
        #expect(below.points.map(\.value) == [0])
        #expect(below.points.map(\.rangeEnd) == [100])
        #expect(below.points.first?.provenance?.ordinal.rawValue == 2)

        let containedAboveAcknowledgement = try project { table in
            offer(&table, from: client, to: server, flags: [.ack], seq: 1_000, ordinal: 1, at: 0)
            offer(
                &table, from: server, to: client, flags: [.ack], seq: 5_000, ack: 1_050,
                sackBlocks: [
                    TCPSACKBlock(leftEdge: 1_100, rightEdge: 1_150),
                    TCPSACKBlock(leftEdge: 1_090, rightEdge: 1_200),
                ], ordinal: 2, at: 0.1
            )
        }
        let contained = try #require(containedAboveAcknowledgement.series.first {
            $0.role == .duplicateSACKRange
        })
        #expect(contained.points.map(\.value) == [100])
        #expect(contained.points.map(\.rangeEnd) == [150])
        #expect(!containedAboveAcknowledgement.series.contains { $0.role == .sackRange && $0.variant == 0 })

        let presentation = SessionStreamHealth(health: containedAboveAcknowledgement)
        let sequence = try #require(presentation.chart(for: .sequence))
        #expect(sequence.lines.contains { $0.role == .duplicateSACKRange && $0.label.contains("D-SACK range") })
        #expect(sequence.caveat?.contains("receiver's report of duplicate sequence data") == true)

        let spanningAcknowledgement = try project { table in
            offer(&table, from: client, to: server, flags: [.ack], seq: 1_000, ordinal: 1, at: 0)
            offer(
                &table, from: server, to: client, flags: [.ack], seq: 5_000, ack: 1_050,
                sackBlocks: [
                    TCPSACKBlock(leftEdge: 1_040, rightEdge: 1_080),
                    TCPSACKBlock(leftEdge: 1_030, rightEdge: 1_090),
                ], ordinal: 2, at: 0.1
            )
        }
        #expect(!spanningAcknowledgement.series.contains { $0.role == .duplicateSACKRange })
        #expect(spanningAcknowledgement.series.contains { $0.role == .sackRange && $0.variant == 0 })
    }

    @Test("SACK mapping handles sequence wrap and accounts for unusable ranges")
    func sackRangeSequenceWrapAndInvalidRanges() throws {
        let health = try project { table in
            offer(&table, from: client, to: server, flags: [.ack], seq: 0xFFFFFF00, ordinal: 1, at: 0)
            offer(
                &table, from: server, to: client, flags: [.ack], seq: 1,
                sackBlocks: [
                    TCPSACKBlock(leftEdge: 0xFFFFFFF0, rightEdge: 0x10),
                    TCPSACKBlock(leftEdge: 0x20, rightEdge: 0x20),
                    TCPSACKBlock(leftEdge: 0x20, rightEdge: 0x80000020),
                ], ordinal: 2, at: 1
            )
        }
        let line = try #require(health.series.first { $0.role == .sackRange })
        #expect(line.points.map(\.value) == [240])
        #expect(line.points.map(\.rangeEnd) == [272])
        #expect(health.coverage.unplottableSACKRangeCount == 2)
        #expect(SessionStreamHealth.caveat(for: .sequence, coverage: health.coverage)?
            .contains("2 receiver-reported SACK ranges") == true)
    }

    @Test("A retransmission redraws lower sequence and never starts a round-trip sample")
    func retransmissionDipsAndIsNotTimed() throws {
        let health = try project { table in
            handshake(&table)
            offer(
                &table,
                from: client,
                to: server,
                flags: [.psh, .ack],
                seq: 1_001,
                ack: 5_001,
                payload: 100,
                ordinal: 4,
                at: 0.1
            )
            // The same bytes again: lower end than the flow already reached.
            offer(
                &table,
                from: client,
                to: server,
                flags: [.psh, .ack],
                seq: 1_001,
                ack: 5_001,
                payload: 100,
                ordinal: 5,
                at: 0.4
            )
            offer(
                &table,
                from: server,
                to: client,
                flags: [.ack],
                seq: 5_001,
                ack: 1_101,
                ordinal: 6,
                at: 0.5
            )
        }
        let clientDirection = direction(of: client)
        let sent = try #require(health.series(for: .sequence).first {
            $0.role == .sequenceReached && $0.direction == clientDirection
        })
        #expect(sent.points.map(\.value) == [1, 101, 101])
        // Karn: the acknowledgement at 0.5 cannot say which data transmission it
        // covered, so only the handshake's own sample is reported.
        let roundTrip = try #require(health.series(for: .roundTrip).first { $0.direction == clientDirection })
        #expect(roundTrip.points.count == 1)
        #expect(roundTrip.points.map(\.date) == [instant(0)])
        #expect(roundTrip.points.map { ($0.value * 100).rounded() / 100 } == [0.02])
        #expect(health.coverage.ambiguousRoundTripSampleCount == 1)
    }

    @Test("An overlapping retransmission invalidates only the pending ranges it touches")
    func partialOverlapDiscardsOnlyOverlappingRoundTrips() throws {
        let health = try project { table in
            handshake(&table)
            offer(&table, from: client, to: server, flags: [.psh, .ack], seq: 1_001, payload: 100, ordinal: 4, at: 0.1)
            offer(&table, from: client, to: server, flags: [.psh, .ack], seq: 1_101, payload: 100, ordinal: 5, at: 0.2)
            offer(&table, from: client, to: server, flags: [.psh, .ack], seq: 1_201, payload: 100, ordinal: 6, at: 0.3)
            // This range overlaps the first two candidates but not the third.
            offer(&table, from: client, to: server, flags: [.psh, .ack], seq: 1_051, payload: 100, ordinal: 7, at: 0.4)
            offer(&table, from: server, to: client, flags: [.ack], seq: 5_001, ack: 1_301, ordinal: 8, at: 0.5)
        }
        let clientDirection = direction(of: client)
        let roundTrip = try #require(health.series(for: .roundTrip).first { $0.direction == clientDirection })
        #expect(roundTrip.points.map(\.provenance?.ordinal.rawValue) == [1, 6])
        #expect(roundTrip.points.map { ($0.value * 100).rounded() / 100 } == [0.02, 0.2])
        #expect(health.coverage.ambiguousRoundTripSampleCount == 2)
        #expect(
            SessionStreamHealth.caveat(for: .roundTrip, coverage: health.coverage)?
                .contains("2 cumulative-ACK RTT candidates") == true
        )
    }

    @Test("Repeated broad retransmissions invalidate each pending RTT candidate once")
    func repeatedBroadOverlapCountsEachCandidateOnce() throws {
        let health = try project { table in
            handshake(&table)
            for index in 0 ..< 4 {
                offer(
                    &table, from: client, to: server, flags: [.psh, .ack],
                    seq: 1_001 + UInt32(index * 100), payload: 100,
                    ordinal: UInt64(4 + index), at: 0.1 + Double(index) * 0.1
                )
            }
            for index in 0 ..< 40 {
                offer(
                    &table, from: client, to: server, flags: [.psh, .ack],
                    seq: 1_001, payload: 400, ordinal: UInt64(8 + index),
                    at: 1 + Double(index) * 0.01
                )
            }
            offer(
                &table, from: server, to: client, flags: [.ack],
                seq: 5_001, ack: 1_401, ordinal: 48, at: 2
            )
        }
        let clientDirection = direction(of: client)
        let roundTrip = try #require(health.series(for: .roundTrip).first { $0.direction == clientDirection })
        #expect(roundTrip.points.map(\.provenance?.ordinal.rawValue) == [1])
        #expect(health.coverage.ambiguousRoundTripSampleCount == 4)
    }

    @Test("Successor links remain valid after appends and partial ACK advancement")
    func overlapSuccessorsSurviveAppendAndAckHeadAdvance() throws {
        let health = try project { table in
            handshake(&table)
            for index in 0 ..< 4 {
                offer(
                    &table, from: client, to: server, flags: [.psh, .ack],
                    seq: 1_001 + UInt32(index * 100), payload: 100,
                    ordinal: UInt64(4 + index), at: 0.1 + Double(index) * 0.1
                )
            }
            offer(
                &table, from: client, to: server, flags: [.psh, .ack],
                seq: 1_001, payload: 400, ordinal: 8, at: 0.6
            )
            offer(&table, from: client, to: server, flags: [.psh, .ack], seq: 1_401, payload: 100, ordinal: 9, at: 0.7)
            offer(&table, from: client, to: server, flags: [.psh, .ack], seq: 1_501, payload: 100, ordinal: 10, at: 0.8)
            // This advances past the old candidates and the first appended segment,
            // while leaving the second appended segment pending.
            offer(&table, from: server, to: client, flags: [.ack], seq: 5_001, ack: 1_501, ordinal: 11, at: 0.9)
            offer(&table, from: client, to: server, flags: [.psh, .ack], seq: 1_501, payload: 100, ordinal: 12, at: 1)
            offer(&table, from: server, to: client, flags: [.ack], seq: 5_001, ack: 1_601, ordinal: 13, at: 1.1)
        }
        let clientDirection = direction(of: client)
        let roundTrip = try #require(health.series(for: .roundTrip).first { $0.direction == clientDirection })
        #expect(roundTrip.points.map(\.provenance?.ordinal.rawValue) == [1, 9])
        #expect(health.coverage.ambiguousRoundTripSampleCount == 5)
    }

    @Test("Full-source derivation stops at a cooperative cancellation checkpoint")
    func fullSourceDerivationChecksCancellationDuringBaseResolution() throws {
        var table = TCPSegmentSeriesTable(
            configuration: TCPSegmentSeriesTable.Configuration(maxObservationsPerSummary: 600)
        )
        for index in 0 ..< 600 {
            offer(
                &table, from: client, to: server, flags: [.ack],
                seq: 9_000 + UInt32(index), payload: 1,
                ordinal: UInt64(index + 1), at: Double(index) / 1_000
            )
        }
        let summary = try #require(table.snapshot().summaries.first)
        var cancellationChecks = 0
        #expect(throws: CancellationError.self) {
            _ = try TCPStreamHealth(summary: summary, checkingCancellation: {
                cancellationChecks += 1
                return cancellationChecks < 4
            })
        }
        #expect(cancellationChecks == 4)
    }

    @Test("Cancellation interrupts one acknowledgement draining many pending RTT candidates")
    func acknowledgementDrainChecksCancellation() throws {
        var table = TCPSegmentSeriesTable(
            configuration: TCPSegmentSeriesTable.Configuration(maxObservationsPerSummary: 700)
        )
        for index in 0 ..< 600 {
            offer(
                &table, from: client, to: server, flags: [.ack],
                seq: 9_000 + UInt32(index), payload: 1,
                ordinal: UInt64(index + 1), at: Double(index) / 1_000
            )
        }
        offer(
            &table, from: server, to: client, flags: [.ack],
            seq: 5_000, ack: 9_600, ordinal: 601, at: 0.601
        )
        let summary = try #require(table.snapshot().summaries.first)
        var cancellationChecks = 0
        #expect(throws: CancellationError.self) {
            _ = try TCPStreamHealth(summary: summary, checkingCancellation: {
                cancellationChecks += 1
                return cancellationChecks < 10
            })
        }
        #expect(cancellationChecks == 10)
    }

    @Test("An untimed retransmission still invalidates its ambiguous round-trip candidate")
    func untimedRetransmissionInvalidatesPendingSample() throws {
        let health = try project { table in
            handshake(&table)
            offer(&table, from: client, to: server, flags: [.psh, .ack], seq: 1_001, payload: 100, ordinal: 4, at: 0.1)
            offer(&table, from: client, to: server, flags: [.psh, .ack], seq: 1_101, payload: 100, ordinal: 5, at: 0.2)
            var retransmission = packet(
                from: client, to: server, flags: [.psh, .ack], seq: 1_001, payload: 100, at: 0.3
            )
            retransmission.timestamp = nil
            table.offer(retransmission, provenance: SessionFrameProvenance(
                ordinal: FrameOrdinal(6), timestamp: nil, capturedLength: 140, originalLength: 140, linkType: 1
            ))
            offer(&table, from: server, to: client, flags: [.ack], seq: 5_001, ack: 1_201, ordinal: 7, at: 0.5)
        }
        let clientDirection = direction(of: client)
        let roundTrip = try #require(health.series(for: .roundTrip).first { $0.direction == clientDirection })
        #expect(roundTrip.points.map(\.provenance?.ordinal.rawValue) == [1, 5])
        #expect(health.coverage.ambiguousRoundTripSampleCount == 1)
    }

    @Test("The acknowledged line is plotted in the acknowledged direction's own space")
    func acknowledgedLineUsesThePeerSpace() throws {
        let health = try project { table in
            handshake(&table)
            offer(
                &table,
                from: client,
                to: server,
                flags: [.psh, .ack],
                seq: 1_001,
                ack: 5_001,
                payload: 400,
                ordinal: 4,
                at: 0.1
            )
            offer(&table, from: server, to: client, flags: [.ack], seq: 5_001, ack: 1_401, ordinal: 5, at: 0.2)
        }
        let acknowledged = try #require(health.series(for: .sequence).first {
            $0.role == .sequenceAcknowledged && $0.direction == direction(of: client)
        })
        // Only the server's two acknowledgements land in the client's space: the
        // SYN+ACK's 1_001 (the SYN alone) and 1_401 (400 bytes past it). The client's
        // own ACKs belong to the other direction's line.
        #expect(acknowledged.points.map(\.value) == [1, 401])
        #expect(acknowledged.points.map(\.provenance?.ordinal.rawValue) == [2, 5])
    }

    // MARK: Round trip

    @Test("A round trip is the interval from a data segment to the acknowledgement covering it")
    func roundTripCitesBothFrames() throws {
        let health = try project { table in
            handshake(&table)
            offer(
                &table,
                from: client,
                to: server,
                flags: [.psh, .ack],
                seq: 1_001,
                ack: 5_001,
                payload: 50,
                ordinal: 4,
                at: 1
            )
            offer(&table, from: server, to: client, flags: [.ack], seq: 5_001, ack: 1_051, ordinal: 5, at: 1.25)
        }
        let roundTrip = try #require(health.series(for: .roundTrip).first { $0.direction == direction(of: client) })
        let last = try #require(roundTrip.points.last)
        #expect((last.value * 1_000).rounded() == 250)
        #expect(last.provenance?.ordinal.rawValue == 4)
        #expect(last.relatedProvenance?.ordinal.rawValue == 5)
        // The point sits at the data segment's instant, which is what it measures from.
        #expect(last.date == instant(1))
    }

    @Test("The first exact SACK report has a separate RTT sample citing both frames")
    func sackRoundTripCitesDataAndSACKReportOnce() throws {
        let health = try project { table in
            handshake(&table)
            offer(
                &table, from: client, to: server, flags: [.psh, .ack], seq: 1_001,
                ack: 5_001, payload: 50, ordinal: 4, at: 1
            )
            offer(
                &table, from: server, to: client, flags: [.ack], seq: 5_001,
                ack: 1_001, sackBlocks: [TCPSACKBlock(leftEdge: 1_001, rightEdge: 1_051)], ordinal: 5, at: 1.25
            )
            offer(
                &table, from: server, to: client, flags: [.ack], seq: 5_001,
                ack: 1_001, sackBlocks: [TCPSACKBlock(leftEdge: 1_001, rightEdge: 1_051)], ordinal: 6, at: 1.5
            )
        }
        let clientDirection = direction(of: client)
        let sack = try #require(health.series(for: .roundTrip).first {
            $0.role == .sackRoundTrip && $0.direction == clientDirection
        })
        #expect(sack.points.count == 1)
        #expect(sack.points.first?.value == 0.25)
        #expect(sack.points.first?.provenance?.ordinal.rawValue == 4)
        #expect(sack.points.first?.relatedProvenance?.ordinal.rawValue == 5)
        let cumulative = health.series(for: .roundTrip).first {
            $0.role == .roundTrip && $0.direction == clientDirection
        }
        #expect(cumulative?.points.contains { $0.provenance?.ordinal.rawValue == 4 } == false)
    }

    @Test("SACK RTT uses wrap-safe relative sequence ranges and excludes overlap ambiguity")
    func sackRoundTripWrapAndOverlapRules() throws {
        let wrapped = try project { table in
            offer(
                &table,
                from: client,
                to: server,
                flags: [.ack, .psh],
                seq: 0xFFFFFFF0,
                payload: 32,
                ordinal: 1,
                at: 1
            )
            offer(
                &table,
                from: server,
                to: client,
                flags: [.ack],
                seq: 5_000,
                ack: 0xFFFFFFF0,
                sackBlocks: [TCPSACKBlock(leftEdge: 0xFFFFFFF0, rightEdge: 0x10)],
                ordinal: 2,
                at: 1.25
            )
        }
        let wrappedLine = try #require(wrapped.series(for: .roundTrip).first { $0.role == .sackRoundTrip })
        #expect(wrappedLine.points.map(\.value) == [0.25])

        let ambiguous = try project { table in
            handshake(&table)
            offer(
                &table,
                from: client,
                to: server,
                flags: [.psh, .ack],
                seq: 1_001,
                ack: 5_001,
                payload: 50,
                ordinal: 4,
                at: 1
            )
            offer(
                &table,
                from: client,
                to: server,
                flags: [.psh, .ack],
                seq: 1_001,
                ack: 5_001,
                payload: 50,
                ordinal: 5,
                at: 1.1
            )
            offer(
                &table,
                from: server,
                to: client,
                flags: [.ack],
                seq: 5_001,
                ack: 1_001,
                sackBlocks: [TCPSACKBlock(leftEdge: 1_001, rightEdge: 1_051)],
                ordinal: 6,
                at: 1.25
            )
        }
        #expect(!ambiguous.series.contains { $0.role == .sackRoundTrip })
    }

    @Test("Data the prefix never sees acknowledged produces no round-trip point")
    func unacknowledgedDataIsNotTimed() throws {
        let health = try project { table in
            offer(
                &table,
                from: client,
                to: server,
                flags: [.psh, .ack],
                seq: 1_001,
                payload: 50,
                ordinal: 1,
                at: 0
            )
            offer(
                &table,
                from: client,
                to: server,
                flags: [.psh, .ack],
                seq: 1_051,
                payload: 50,
                ordinal: 2,
                at: 0.1
            )
        }
        #expect(health.series(for: .roundTrip).isEmpty)
    }

    @Test("A reset never acknowledges anything and closes no round trip")
    func resetIsNotAnAcknowledgement() throws {
        let health = try project { table in
            offer(
                &table,
                from: client,
                to: server,
                flags: [.psh, .ack],
                seq: 1_001,
                payload: 50,
                ordinal: 1,
                at: 0
            )
            offer(&table, from: server, to: client, flags: [.rst, .ack], seq: 5_001, ack: 1_051, ordinal: 2, at: 0.2)
        }
        #expect(health.series(for: .roundTrip).isEmpty)
    }

    // MARK: Bytes in flight

    @Test("Bytes in flight appear only once the peer has acknowledged something")
    func bytesInFlightNeedsABaseline() throws {
        let health = try project { table in
            handshake(&table)
            offer(
                &table,
                from: client,
                to: server,
                flags: [.psh, .ack],
                seq: 1_001,
                ack: 5_001,
                payload: 100,
                ordinal: 4,
                at: 0.1
            )
            offer(
                &table,
                from: client,
                to: server,
                flags: [.psh, .ack],
                seq: 1_101,
                ack: 5_001,
                payload: 100,
                ordinal: 5,
                at: 0.2
            )
            offer(&table, from: server, to: client, flags: [.ack], seq: 5_001, ack: 1_101, ordinal: 6, at: 0.3)
            offer(
                &table,
                from: client,
                to: server,
                flags: [.psh, .ack],
                seq: 1_201,
                ack: 5_001,
                payload: 100,
                ordinal: 7,
                at: 0.4
            )
        }
        let inFlight = try #require(health.series(for: .receiveWindow).first {
            $0.role == .bytesInFlight && $0.direction == direction(of: client)
        })
        // The SYN is acknowledged by the SYN+ACK, so the first two data segments are
        // measured against edge 1; the last is measured against edge 101.
        #expect(inFlight.points.map(\.value) == [100, 200, 200])
        #expect(inFlight.points.map(\.provenance?.ordinal.rawValue) == [4, 5, 7])
    }

    // MARK: Receive window

    @Test("A window is scaled only when both SYNs carried the option, and never on a SYN itself")
    func windowScalingNeedsBothSYNs() throws {
        let health = try project { table in
            offer(
                &table,
                from: client,
                to: server,
                flags: [.syn],
                seq: 1_000,
                window: 1_000,
                shift: 3,
                ordinal: 1,
                at: 0
            )
            offer(
                &table,
                from: server,
                to: client,
                flags: [.syn, .ack],
                seq: 5_000,
                ack: 1_001,
                window: 2_000,
                shift: 4,
                ordinal: 2,
                at: 0.02
            )
            offer(
                &table,
                from: client,
                to: server,
                flags: [.ack],
                seq: 1_001,
                ack: 5_001,
                window: 1_000,
                ordinal: 3,
                at: 0.03
            )
        }
        #expect(health.coverage.windowScaling == .applied)
        // The window the *server's* direction was offered is advertised by the client.
        let offeredToServer = try #require(health.series(for: .receiveWindow).first {
            $0.role == .receiveWindowOffered && $0.direction == direction(of: server)
        })
        // The SYN's own window is never scaled; the later ACK's is shifted by 3.
        #expect(offeredToServer.points.map(\.value) == [1_000, 8_000])
    }

    @Test("Both SYNs without the option is a known absence of scaling, not an unknown one")
    func noScalingIsAKnownAnswer() throws {
        let health = try project { table in
            handshake(&table)
        }
        #expect(health.coverage.windowScaling == .notInEffect)
        #expect(SessionStreamHealth.caveat(for: .receiveWindow, coverage: health.coverage) == nil)
    }

    @Test("A midstream capture leaves the scale unobserved and says so")
    func midstreamScalingIsUnknown() throws {
        let health = try project { table in
            offer(&table, from: client, to: server, flags: [.ack], seq: 9_000, payload: 10, ordinal: 1, at: 0)
            offer(&table, from: server, to: client, flags: [.ack], seq: 4_000, ack: 9_010, ordinal: 2, at: 0.1)
        }
        #expect(health.coverage.windowScaling == .notObserved)
        let caveat = try #require(SessionStreamHealth.caveat(for: .receiveWindow, coverage: health.coverage))
        #expect(caveat.contains("raw"))
        #expect(SessionStreamHealth.caveat(for: .sequence, coverage: health.coverage) == nil)
    }

    // MARK: Throughput

    @Test("Throughput buckets sum to exactly the wire bytes the prefix carried")
    func throughputIsAnExactSum() throws {
        let health = try project { table in
            for ordinal in 1 ... 10 {
                offer(
                    &table, from: client, to: server, flags: [.psh, .ack],
                    seq: UInt32(1_000 + ordinal * 100), payload: 100,
                    ordinal: UInt64(ordinal), at: Double(ordinal - 1) / 9,
                    original: 154
                )
            }
        }
        let throughput = try #require(health.series(for: .throughput).first)
        let span = 1.0
        let bucketDuration = span / 48
        let total = throughput.points.reduce(0.0) { $0 + $1.value * bucketDuration }
        #expect(total.rounded() == 1_540)
        #expect(throughput.points.count == 48)
        #expect(throughput.points.allSatisfy { $0.provenance == nil })
        #expect(!health.series.contains { $0.role == .goodput })
    }

    @Test("Goodput credits SACK and cumulative ACK ranges once")
    func goodputCountsNewSACKAndCumulativeACKBytesOnce() throws {
        let health = try project { table in
            handshake(&table)
            offer(&table, from: client, to: server, flags: [.psh, .ack], seq: 1_001, payload: 100, ordinal: 4, at: 1)
            offer(
                &table, from: server, to: client, flags: [.ack], seq: 5_001, ack: 1_001,
                sackBlocks: [TCPSACKBlock(leftEdge: 1_051, rightEdge: 1_101)], ordinal: 5, at: 2
            )
            // Cumulative ACK covers all 100 bytes; the 50 SACKed bytes are not
            // credited twice. Repeated ACK/SACK evidence adds no bytes.
            offer(&table, from: server, to: client, flags: [.ack], seq: 5_001, ack: 1_101, ordinal: 6, at: 3)
            offer(
                &table, from: server, to: client, flags: [.ack], seq: 5_001, ack: 1_101,
                sackBlocks: [TCPSACKBlock(leftEdge: 1_051, rightEdge: 1_101)], ordinal: 7, at: 4
            )
            offer(&table, from: client, to: server, flags: [.ack], seq: 1_101, ack: 5_001, ordinal: 8, at: 48)
        }
        let sentByClient = direction(of: client)
        let goodput = try #require(health.series.first { $0.role == .goodput && $0.direction == sentByClient })
        let bucketDuration = 48.0 / 48
        #expect((goodput.points.reduce(0.0) { $0 + $1.value * bucketDuration }).rounded() == 100)
        #expect(goodput.points.allSatisfy { $0.provenance == nil })
        let line = SessionStreamChartLine(series: goodput, tuple: health.tuple)
        #expect(line.label.contains("ACKed from"))
        #expect(SessionStreamChart.caption(for: .throughput).contains("receiver-ACKed sequence bytes"))
    }

    @Test("Overlapping SACK blocks contribute only their newly covered bytes")
    func goodputCountsOverlappingSACKBlocksOnce() throws {
        let health = try project { table in
            handshake(&table)
            offer(&table, from: client, to: server, flags: [.psh, .ack], seq: 1_001, payload: 100, ordinal: 4, at: 1)
            offer(
                &table, from: server, to: client, flags: [.ack], seq: 5_001, ack: 1_001,
                sackBlocks: [
                    TCPSACKBlock(leftEdge: 1_051, rightEdge: 1_081),
                    TCPSACKBlock(leftEdge: 1_071, rightEdge: 1_101),
                ], ordinal: 5, at: 2
            )
            offer(
                &table, from: server, to: client, flags: [.ack], seq: 5_001, ack: 1_001,
                sackBlocks: [TCPSACKBlock(leftEdge: 1_051, rightEdge: 1_101)], ordinal: 6, at: 3
            )
            offer(&table, from: client, to: server, flags: [.ack], seq: 1_101, ack: 5_001, ordinal: 7, at: 48)
        }
        let goodput = try #require(health.series.first {
            $0.role == .goodput && $0.direction == direction(of: client)
        })
        let bucketDuration = 48.0 / 48
        #expect((goodput.points.reduce(0.0) { $0 + $1.value * bucketDuration }).rounded() == 50)
    }

    @Test("D-SACK-shaped ranges do not add duplicate Goodput")
    func goodputExcludesDSACKRanges() throws {
        let health = try project { table in
            offer(
                &table,
                from: client,
                to: server,
                flags: [.psh, .ack],
                seq: 1_000,
                ack: 5_000,
                payload: 100,
                ordinal: 1,
                at: 0
            )
            // This first SACK block is below this ACK's cumulative edge, the RFC 2883
            // D-SACK form. It remains visible in the distinct D-SACK overlay but
            // does not earn novel Goodput.
            offer(
                &table, from: server, to: client, flags: [.ack], seq: 5_000, ack: 1_100,
                sackBlocks: [TCPSACKBlock(leftEdge: 1_000, rightEdge: 1_050)], ordinal: 2, at: 1
            )
            offer(&table, from: client, to: server, flags: [.ack], seq: 1_100, ack: 5_000, ordinal: 3, at: 48)
        }
        #expect(!health.series.contains { $0.role == .goodput })
        #expect(health.series.contains { $0.role == .duplicateSACKRange })
    }

    @Test("Goodput clips SACK ranges at the accepted cumulative ACK edge")
    func goodputClipsSACKRangesAtACKEdge() throws {
        let health = try project { table in
            // Midstream: the sender's first captured sequence is the relative base,
            // so the receiver's first ACK at 1100 is also the Goodput baseline.
            offer(&table, from: client, to: server, flags: [.psh, .ack], seq: 1_000, payload: 300, ordinal: 1, at: 0)
            offer(
                &table, from: server, to: client, flags: [.ack], seq: 5_000, ack: 1_100,
                sackBlocks: [
                    TCPSACKBlock(leftEdge: 1_050, rightEdge: 1_150),
                    TCPSACKBlock(leftEdge: 900, rightEdge: 950),
                ], ordinal: 2, at: 1
            )
            offer(&table, from: client, to: server, flags: [.ack], seq: 1_300, ack: 5_000, ordinal: 3, at: 48)
        }
        let goodput = try #require(health.series.first {
            $0.role == .goodput && $0.direction == direction(of: client)
        })
        #expect((goodput.points.reduce(0.0) { $0 + $1.value }).rounded() == 50)
        // The raw SACK ranges remain visible even where Goodput clips them.
        #expect(health.series.filter { $0.role == .sackRange }.count == 2)
    }

    @Test("Goodput ignores SACK ranges carried by stale or unresolvable ACKs")
    func goodputIgnoresStaleAndUnresolvableACKS() throws {
        let staleHealth = try project { table in
            offer(&table, from: client, to: server, flags: [.psh, .ack], seq: 1_000, payload: 400, ordinal: 1, at: 0)
            offer(
                &table, from: server, to: client, flags: [.ack], seq: 5_000, ack: 1_100,
                sackBlocks: [TCPSACKBlock(leftEdge: 1_200, rightEdge: 1_250)], ordinal: 2, at: 1
            )
            offer(
                &table, from: server, to: client, flags: [.ack], seq: 5_000, ack: 1_050,
                sackBlocks: [TCPSACKBlock(leftEdge: 1_300, rightEdge: 1_350)], ordinal: 3, at: 2
            )
            offer(&table, from: client, to: server, flags: [.ack], seq: 1_400, ack: 5_000, ordinal: 4, at: 48)
        }
        let staleGoodput = try #require(staleHealth.series.first {
            $0.role == .goodput && $0.direction == direction(of: client)
        })
        #expect((staleGoodput.points.reduce(0.0) { $0 + $1.value }).rounded() == 50)

        let unresolvableHealth = try project { table in
            offer(&table, from: client, to: server, flags: [.psh, .ack], seq: 1_000, payload: 200, ordinal: 1, at: 0)
            offer(
                &table, from: server, to: client, flags: [.ack], seq: 5_000,
                ack: 1_000 &+ 0x80000000,
                sackBlocks: [TCPSACKBlock(leftEdge: 1_100, rightEdge: 1_150)], ordinal: 2, at: 1
            )
            offer(&table, from: client, to: server, flags: [.ack], seq: 1_200, ack: 5_000, ordinal: 3, at: 48)
        }
        #expect(!unresolvableHealth.series.contains {
            $0.role == .goodput && $0.direction == direction(of: client)
        })
    }

    @Test("A prefix with no elapsed span yields no throughput rather than an infinite rate")
    func zeroSpanYieldsNoThroughput() throws {
        let health = try project { table in
            offer(&table, from: client, to: server, flags: [.psh, .ack], seq: 1_001, payload: 10, ordinal: 1, at: 5)
            offer(&table, from: client, to: server, flags: [.psh, .ack], seq: 1_011, payload: 10, ordinal: 2, at: 5)
        }
        #expect(health.series(for: .throughput).isEmpty)
        #expect(!health.availableKinds.contains(.throughput))
    }

    // MARK: Coverage

    @Test("An untimed frame is plotted by nothing and counted once")
    func untimedFramesAreCounted() throws {
        var table = TCPSegmentSeriesTable()
        offer(&table, from: client, to: server, flags: [.psh, .ack], seq: 1_001, payload: 10, ordinal: 1, at: 0)
        var untimed = packet(from: client, to: server, flags: [.psh, .ack], seq: 1_011, payload: 10, at: 1)
        untimed.timestamp = nil
        table.offer(untimed, provenance: SessionFrameProvenance(
            ordinal: FrameOrdinal(2),
            timestamp: nil,
            capturedLength: 120,
            originalLength: 120,
            linkType: 1
        ))
        let health = try TCPStreamHealth(summary: #require(table.snapshot().summaries.first))
        #expect(health.coverage.untimedSegmentCount == 1)
        #expect(health.coverage.retainedSegmentCount == 2)
        let sent = try #require(health.series(for: .sequence).first)
        #expect(sent.points.count == 1)
    }

    @Test("A closed prefix names the run it covers and how much it left out")
    func coverageNamesTheRun() throws {
        var table = TCPSegmentSeriesTable(
            configuration: TCPSegmentSeriesTable.Configuration(maxObservationsPerSummary: 3)
        )
        for ordinal in 1 ... 8 {
            offer(
                &table, from: client, to: server, flags: [.psh, .ack],
                seq: UInt32(1_000 + ordinal * 10), payload: 10,
                ordinal: UInt64(ordinal), at: Double(ordinal) / 10
            )
        }
        let health = try TCPStreamHealth(summary: #require(table.snapshot().summaries.first))
        #expect(health.coverage.isTruncated)
        #expect(health.coverage.firstOrdinal == 1)
        #expect(health.coverage.lastOrdinal == 3)
        #expect(health.coverage.omittedSegmentCount == 5)

        let caveats = SessionStreamHealth.caveats(for: health.coverage)
        #expect(caveats.count == 2)
        #expect(caveats[0].contains("frames 1 to 3"))
        #expect(caveats[0].contains("5 later segments"))
        #expect(caveats[1].contains("nothing about dropped frames"))
    }

    @Test("A session with no retained TCP segments draws nothing")
    func emptyProjection() {
        let health = TCPStreamHealth.empty(
            sessionID: UUID(),
            tuple: FiveTuple(proto: .tcp, source: client, destination: server)
        )
        #expect(health.isEmpty)
        #expect(health.availableKinds.isEmpty)
        #expect(SessionStreamHealth(health: health).isEmpty)
        #expect(SessionStreamHealth.empty.isEmpty)
        #expect(SessionStreamHealth.caveats(for: .empty).count == 1)
    }

    @Test("Series order is fixed by kind, then role, then direction")
    func seriesOrderIsDeterministic() throws {
        let health = try project { table in
            handshake(&table)
            offer(
                &table,
                from: client,
                to: server,
                flags: [.psh, .ack],
                seq: 1_001,
                ack: 5_001,
                payload: 100,
                ordinal: 4,
                at: 0.1
            )
            offer(
                &table,
                from: server,
                to: client,
                flags: [.psh, .ack],
                seq: 5_001,
                ack: 1_101,
                payload: 100,
                ordinal: 5,
                at: 0.2
            )
            offer(&table, from: client, to: server, flags: [.ack], seq: 1_101, ack: 5_101, ordinal: 6, at: 0.3)
        }
        #expect(health.availableKinds == [.sequence, .throughput, .roundTrip, .receiveWindow])
        let kinds = health.series.map(\.kind.rawValue)
        #expect(kinds == kinds.sorted())
        // Ids are unique, so `ForEach` never re-keys.
        #expect(Set(health.series.map(\.id)).count == health.series.count)
    }

    // MARK: Presentation

    @Test("Every line names its direction by endpoint, never client or server")
    func linesAreNamedByEndpoint() throws {
        let health = try project { table in
            handshake(&table)
            offer(
                &table,
                from: client,
                to: server,
                flags: [.psh, .ack],
                seq: 1_001,
                ack: 5_001,
                payload: 100,
                ordinal: 4,
                at: 0.1
            )
            offer(&table, from: server, to: client, flags: [.ack], seq: 5_001, ack: 1_101, ordinal: 5, at: 0.2)
        }
        let presented = SessionStreamHealth(health: health)
        let sequence = try #require(presented.charts.first { $0.kind == .sequence })
        #expect(sequence.title == "Sequence")
        #expect(sequence.axisCaption.contains("first observed sequence number"))
        let labels = sequence.lines.map(\.label)
        #expect(labels.contains("Sent by \(client.display)"))
        #expect(labels.contains("Acknowledged to \(client.display)"))
        #expect(labels.allSatisfy { !$0.lowercased().contains("client") && !$0.lowercased().contains("server") })
    }

    @Test("Each role reads in exactly one unit")
    func valuesReadInOneUnit() {
        #expect(SessionStreamHealth.valueLabel(0.25, role: .roundTrip) == "250 ms")
        #expect(SessionStreamHealth.valueLabel(1.5, role: .roundTrip) == "1.50 s")
        #expect(SessionStreamHealth.valueLabel(4_096, role: .receiveWindowOffered).hasSuffix("B"))
        #expect(SessionStreamHealth.valueLabel(4_096, role: .throughput).hasSuffix("/s"))
        #expect(SessionStreamHealth.valueLabel(-100, role: .sequenceReached).contains("100"))
        #expect(SessionStreamHealth.valueLabel(-5, role: .bytesInFlight) == SessionStreamHealth.valueLabel(
            0,
            role: .bytesInFlight
        ))
    }

    @Test("The panel falls back to an available chart when the remembered one has nothing to draw")
    func chartSelectionFallsBack() throws {
        let health = try project { table in
            offer(
                &table,
                from: client,
                to: server,
                flags: [.psh, .ack],
                seq: 1_001,
                payload: 10,
                ordinal: 1,
                at: 0
            )
            offer(
                &table,
                from: client,
                to: server,
                flags: [.psh, .ack],
                seq: 1_011,
                payload: 10,
                ordinal: 2,
                at: 1
            )
        }
        let presented = SessionStreamHealth(health: health)
        #expect(presented.chart(for: .roundTrip)?.kind == presented.charts.first?.kind)
        #expect(presented.chart(for: nil)?.kind == presented.charts.first?.kind)
        #expect(presented.chart(for: .sequence)?.kind == .sequence)
    }

    @Test("A reported loss outranks unknown loss in the single fidelity line")
    func fidelityLinePrecedence() {
        let reported = TCPStreamCoverage(
            retainedSegmentCount: 4,
            omittedSegmentCount: 0,
            untimedSegmentCount: 0,
            ambiguousRoundTripSampleCount: 0,
            unclassifiableSegmentCount: 0,
            unplottableSACKRangeCount: 0,
            unplottablePayloadRangeCount: 0,
            firstOrdinal: 1,
            lastOrdinal: 4,
            lossKnowledge: .lossReported,
            snapLengthTruncationObserved: true,
            windowScaling: .applied
        )
        let lines = SessionStreamHealth.caveats(for: reported)
        #expect(lines.count == 1)
        #expect(lines[0].contains("Capture loss was reported"))

        let clean = TCPStreamCoverage(
            retainedSegmentCount: 4,
            omittedSegmentCount: 0,
            untimedSegmentCount: 0,
            ambiguousRoundTripSampleCount: 0,
            unclassifiableSegmentCount: 0,
            unplottableSACKRangeCount: 0,
            unplottablePayloadRangeCount: 0,
            firstOrdinal: 1,
            lastOrdinal: 4,
            lossKnowledge: .noLossReported,
            snapLengthTruncationObserved: false,
            windowScaling: .applied
        )
        #expect(SessionStreamHealth.caveats(for: clean).isEmpty)
        #expect(SessionStreamHealth.caveat(for: .roundTrip, coverage: clean)?.contains("application delivery") == true)
    }

    // MARK: tshark parity

    /// Seventeen frames built below, with the values tshark 4.6.8 reports for the same
    /// frames written to a capture pinned here. If any of these change, write the frames
    /// to a pcap and compare with tshark again:
    /// Sequence, window, bytes-in-flight and unambiguous RTT values are checked against
    /// tshark 4.6.8. Tracexy deliberately excludes RTT candidates after retransmission
    /// overlap even though tshark exposes its flagged ambiguous `tcp.analysis.ack_rtt`.
    @Test("Every derived series matches what tshark reports for the same frames")
    func matchesTsharkOnTheFixture() throws {
        let health = try project { table in fixture(&table) }
        let up = direction(of: client)
        let down = direction(of: server)

        func points(_ role: TCPStreamSeriesRole, _ direction: ConnectionDirection) throws -> [Double] {
            try #require(health.series.first { $0.role == role && $0.direction == direction }).points.map(\.value)
        }

        // tcp.nxtseq of every sequence-bearing frame.
        #expect(try points(.sequenceReached, up) == [1, 501, 1_001, 1_001, 1_002])
        #expect(try points(.sequenceReached, down) == [1, 1_001, 1_002])

        // Exclude client frame 8: frame 9 retransmits its range before frame 10 ACKs it.
        // The other points are unambiguous handshake/data/FIN intervals.
        let upRoundTrips = try points(.roundTrip, up).map { ($0 * 1_000).rounded() }
        #expect(upRoundTrips == [30, 50, 20])
        let downRoundTrips = try points(.roundTrip, down).map { ($0 * 1_000).rounded() }
        #expect(downRoundTrips == [10, 10, 10])

        // tcp.window_size, scaled by RFC 7323 — and never on a SYN.
        #expect(health.coverage.windowScaling == .applied)
        #expect(try points(.receiveWindowOffered, up) == [2_000, 256_000, 256_000, 256_000, 0, 64_000, 64_000])
        #expect(try points(.receiveWindowOffered, down) == [1_004] + [Double](repeating: 256_000, count: 7))

        // tcp.analysis.bytes_in_flight. The trailing 1 on each direction is the FIN's own
        // sequence byte, which Wireshark leaves blank and this layer reports because the
        // peer had genuinely not acknowledged it yet — a definitional difference, not a
        // disagreement about the frames.
        #expect(try points(.bytesInFlight, up) == [500, 500, 500, 1])
        #expect(try points(.bytesInFlight, down) == [1_000, 1])

        // Throughput is an exact sum of frame.len per direction over the 1.030 s span.
        let bucketDuration = 1.030 / 48
        let upBytes = try points(.throughput, up).reduce(0) { $0 + $1 * bucketDuration }
        let downBytes = try points(.throughput, down).reduce(0) { $0 + $1 * bucketDuration }
        #expect(upBytes.rounded() == 1_936)
        #expect(downBytes.rounded() == 1_382)

        // Nothing was left out, so the panel states no coverage line at all.
        #expect(health.coverage.omittedSegmentCount == 0)
        #expect(health.coverage.untimedSegmentCount == 0)
        #expect(health.coverage.unclassifiableSegmentCount == 0)
        #expect(SessionStreamHealth(health: health).caveats == [
            "This capture reports nothing about dropped frames, so completeness between "
                + "these points is unknown.",
        ])
    }

    // MARK: Private

    private let client = IPEndpoint(ip: "198.51.100.10", port: 50_000)
    private let server = IPEndpoint(ip: "203.0.113.5", port: 443)
    private let token = UUID(uuid: (9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9))

    /// The canonical direction frames sent by `endpoint` travel in.
    private func direction(of endpoint: IPEndpoint) -> ConnectionDirection {
        let tuple = FiveTuple(proto: .tcp, source: client, destination: server)
        return tuple.a == endpoint ? .aToB : .bToA
    }

    private func instant(_ offset: Double) -> Date {
        Date(timeIntervalSince1970: offset)
    }

    /// Fold frames through the real table, then derive the single flow's charts.
    private func project(_ body: (inout TCPSegmentSeriesTable) -> Void) throws -> TCPStreamHealth {
        var table = TCPSegmentSeriesTable()
        body(&table)
        return try TCPStreamHealth(summary: #require(table.snapshot().summaries.first))
    }

    /// A validated three-way handshake with no window scaling, ordinals 1–3.
    private func handshake(_ table: inout TCPSegmentSeriesTable) {
        offer(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 0)
        offer(&table, from: server, to: client, flags: [.syn, .ack], seq: 5_000, ack: 1_001, ordinal: 2, at: 0.02)
        offer(&table, from: client, to: server, flags: [.ack], seq: 1_001, ack: 5_001, ordinal: 3, at: 0.03)
    }

    /// The seventeen-frame conversation from the TCP health fixture generator, frame for frame.
    private func fixture(_ table: inout TCPSegmentSeriesTable) {
        let cs: UInt32 = 1_000
        let ss: UInt32 = 5_000
        func up(
            _ ordinal: UInt64, _ at: Double, _ flags: TCPFlags, _ seq: UInt32, _ ack: UInt32,
            payload: Int = 0, window: UInt16 = 1_000, shift: UInt8? = nil, bytes: Int
        ) {
            offer(
                &table, from: client, to: server, flags: flags, seq: seq, ack: ack,
                payload: payload, window: window, shift: shift, ordinal: ordinal, at: at, original: bytes
            )
        }
        func down(
            _ ordinal: UInt64, _ at: Double, _ flags: TCPFlags, _ seq: UInt32, _ ack: UInt32,
            payload: Int = 0, window: UInt16 = 2_000, shift: UInt8? = nil, bytes: Int
        ) {
            offer(
                &table, from: server, to: client, flags: flags, seq: seq, ack: ack,
                payload: payload, window: window, shift: shift, ordinal: ordinal, at: at, original: bytes
            )
        }
        up(1, 0.000, [.syn], cs, 0, window: 1_004, shift: 8, bytes: 58)
        down(2, 0.030, [.syn, .ack], ss, cs + 1, shift: 7, bytes: 58)
        up(3, 0.040, [.ack], cs + 1, ss + 1, bytes: 54)
        up(4, 0.050, [.psh, .ack], cs + 1, ss + 1, payload: 500, bytes: 554)
        down(5, 0.100, [.ack], ss + 1, cs + 501, bytes: 54)
        down(6, 0.150, [.psh, .ack], ss + 1, cs + 501, payload: 1_000, bytes: 1_054)
        up(7, 0.160, [.ack], cs + 501, ss + 1_001, bytes: 54)
        up(8, 0.200, [.psh, .ack], cs + 501, ss + 1_001, payload: 500, bytes: 554)
        up(9, 0.400, [.psh, .ack], cs + 501, ss + 1_001, payload: 500, bytes: 554)
        down(10, 0.450, [.ack], ss + 1_001, cs + 1_001, bytes: 54)
        down(11, 0.600, [.ack], ss + 1_001, cs + 1_001, window: 0, bytes: 54)
        down(12, 0.900, [.ack], ss + 1_001, cs + 1_001, window: 500, bytes: 54)
        up(13, 1.000, [.fin, .ack], cs + 1_001, ss + 1_001, bytes: 54)
        down(14, 1.020, [.fin, .ack], ss + 1_001, cs + 1_002, window: 500, bytes: 54)
        up(15, 1.030, [.ack], cs + 1_002, ss + 1_002, bytes: 54)
    }

    private func packet(
        from source: IPEndpoint,
        to destination: IPEndpoint,
        flags: TCPFlags,
        seq: UInt32,
        ack: UInt32 = 0,
        payload: Int = 0,
        window: UInt16 = 65_535,
        shift: UInt8? = nil,
        sackBlocks: [TCPSACKBlock] = [],
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
            options: TCPOptionFacts(windowScaleRaw: shift, windowScale: shift, sackBlocks: sackBlocks)
        )
        return pkt
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
        sackBlocks: [TCPSACKBlock] = [],
        ordinal: UInt64,
        at timestamp: Double,
        original: Int = 120,
        loss: CaptureLossKnowledge = .unknown
    ) {
        table.offer(
            packet(
                from: source, to: destination, flags: flags, seq: seq, ack: ack,
                payload: payload, window: window, shift: shift, sackBlocks: sackBlocks, at: timestamp
            ),
            provenance: SessionFrameProvenance(
                ordinal: FrameOrdinal(ordinal),
                timestamp: Date(timeIntervalSince1970: timestamp),
                capturedLength: original,
                originalLength: original,
                linkType: 1,
                locator: SessionEvidenceLocator(sourceToken: token, offset: ordinal)
            ),
            loss: loss
        )
    }
}
