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
        // Karn: the acknowledgement at 0.5 cannot say which copy it answered, so only
        // the handshake's own sample and the first transmission's are reported.
        let roundTrip = try #require(health.series(for: .roundTrip).first { $0.direction == clientDirection })
        #expect(roundTrip.points.count == 2)
        // The SYN (0 → 0.02) and the first data segment (0.1 → 0.5).
        #expect(roundTrip.points.map(\.date) == [instant(0), instant(0.1)])
        #expect(roundTrip.points.map { ($0.value * 100).rounded() / 100 } == [0.02, 0.4])
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
            unclassifiableSegmentCount: 0,
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
            unclassifiableSegmentCount: 0,
            firstOrdinal: 1,
            lastOrdinal: 4,
            lossKnowledge: .noLossReported,
            snapLengthTruncationObserved: false,
            windowScaling: .applied
        )
        #expect(SessionStreamHealth.caveats(for: clean).isEmpty)
    }

    // MARK: tshark parity

    /// Seventeen frames built below, with the values tshark 4.6.8 reports for the same
    /// frames written to a capture pinned here. If any of these change, write the frames
    /// to a pcap and compare with tshark again:
    /// `tcp.nxtseq` is the sequence line, `tcp.analysis.ack_rtt` the round trips,
    /// `tcp.window_size` the offered windows and `tcp.analysis.bytes_in_flight` the
    /// unacknowledged bytes.
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

        // tcp.analysis.ack_rtt at frames 2, 5, 10, 14 (client data) and 3, 7, 15 (server data).
        let upRoundTrips = try points(.roundTrip, up).map { ($0 * 1_000).rounded() }
        #expect(upRoundTrips == [30, 50, 250, 20])
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
        original: Int = 120,
        loss: CaptureLossKnowledge = .unknown
    ) {
        table.offer(
            packet(
                from: source, to: destination, flags: flags, seq: seq, ack: ack,
                payload: payload, window: window, shift: shift, at: timestamp
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
