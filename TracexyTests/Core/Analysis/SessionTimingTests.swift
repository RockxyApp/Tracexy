import Foundation
import Testing
@testable import Tracexy

/// The passive response-time measurements. Every case drives the real
/// `ConnectionTable`, `TLSEvidenceTable` or `DatagramEvidenceTable` fold, so an interval
/// is proven from the frames that bound it rather than from a hand-built summary. The
/// policy under test is the file comment in `SessionTimingAnalysis.swift`: both
/// boundaries must be retained and timed, a "first X then Y" pairing needs complete
/// retention, and nothing names a cause.
@Suite("SessionTimingAssessor response times")
struct SessionTimingTests {
    // MARK: Internal

    // MARK: TCP handshake

    @Test("A clean handshake yields the answered round trip and the whole observed set-up")
    func handshakeIntervals() throws {
        var table = ConnectionTable()
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 10.0)
        ingest(&table, from: server, to: client, flags: [.syn, .ack], seq: 5_000, ack: 1_001, ordinal: 2, at: 10.02)
        ingest(&table, from: client, to: server, flags: [.ack], seq: 1_001, ack: 5_001, ordinal: 3, at: 10.03)

        let result = assess(connections: table.snapshot())
        let reply = try #require(result.measurements.first { $0.kind == .tcpHandshakeReply })
        #expect(reply.start.occurrenceOrdinal == FrameOrdinal(1))
        #expect(reply.end.occurrenceOrdinal == FrameOrdinal(2))
        #expect(abs(reply.elapsedMilliseconds - 20) < 0.001)
        #expect(reply.start.direction == .aToB)
        #expect(reply.end.direction == .bToA)

        let completion = try #require(result.measurements.first { $0.kind == .tcpHandshakeCompletion })
        #expect(completion.start.occurrenceOrdinal == FrameOrdinal(1))
        #expect(completion.end.occurrenceOrdinal == FrameOrdinal(3))
        #expect(abs(completion.elapsedMilliseconds - 30) < 0.001)
        #expect(result.untimedBoundaryCount == 0)
        #expect(result.incompleteRetentionCount == 0)
    }

    @Test("A retried SYN measures the reply from the attempt that was answered, and the set-up from the first")
    func retriedHandshake() throws {
        var table = ConnectionTable()
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 10.0)
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 2, at: 11.0)
        ingest(&table, from: server, to: client, flags: [.syn, .ack], seq: 5_000, ack: 1_001, ordinal: 3, at: 11.05)
        ingest(&table, from: client, to: server, flags: [.ack], seq: 1_001, ack: 5_001, ordinal: 4, at: 11.06)

        let result = assess(connections: table.snapshot())
        let reply = try #require(result.measurements.first { $0.kind == .tcpHandshakeReply })
        // The second attempt is the one the peer answered; the first is excluded on
        // purpose and the cited frames say which attempt this was.
        #expect(reply.start.occurrenceOrdinal == FrameOrdinal(2))
        #expect(abs(reply.elapsedMilliseconds - 50) < 0.001)

        let completion = try #require(result.measurements.first { $0.kind == .tcpHandshakeCompletion })
        #expect(completion.start.occurrenceOrdinal == FrameOrdinal(1))
        #expect(abs(completion.elapsed - 1.06) < 0.000001)
    }

    @Test("An unanswered SYN is measured as nothing at all")
    func unansweredSYNMeasuresNothing() {
        var table = ConnectionTable()
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 10.0)
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 2, at: 11.0)

        let result = assess(connections: table.snapshot())
        #expect(result.measurements.isEmpty)
        #expect(result.untimedBoundaryCount == 0)
        #expect(result.incompleteRetentionCount == 0)
    }

    @Test("A SYN+ACK seen with no prior SYN yields neither handshake interval")
    func midstreamSynAckMeasuresNothing() {
        var table = ConnectionTable()
        ingest(&table, from: server, to: client, flags: [.syn, .ack], seq: 5_000, ack: 1_001, ordinal: 1, at: 10.0)
        ingest(&table, from: client, to: server, flags: [.ack], seq: 1_001, ack: 5_001, ordinal: 2, at: 10.01)

        let result = assess(connections: table.snapshot())
        #expect(!result.measurements.contains { $0.kind == .tcpHandshakeReply })
        #expect(!result.measurements.contains { $0.kind == .tcpHandshakeCompletion })
    }

    // MARK: Request to reply

    @Test("The initiator's first payload and the responder's first later payload give the response time")
    func applicationResponse() throws {
        var table = ConnectionTable()
        handshake(&table)
        ingest(
            &table,
            from: client,
            to: server,
            flags: [.psh, .ack],
            seq: 1_001,
            ack: 5_001,
            payload: 80,
            ordinal: 4,
            at: 20.0
        )
        ingest(
            &table,
            from: client,
            to: server,
            flags: [.psh, .ack],
            seq: 1_081,
            ack: 5_001,
            payload: 20,
            ordinal: 5,
            at: 20.01
        )
        ingest(
            &table,
            from: server,
            to: client,
            flags: [.psh, .ack],
            seq: 5_001,
            ack: 1_101,
            payload: 300,
            ordinal: 6,
            at: 20.25
        )
        ingest(
            &table,
            from: server,
            to: client,
            flags: [.psh, .ack],
            seq: 5_301,
            ack: 1_101,
            payload: 300,
            ordinal: 7,
            at: 20.30
        )

        let result = assess(connections: table.snapshot())
        let response = try #require(result.measurements.first { $0.kind == .applicationResponse })
        #expect(response.start.occurrenceOrdinal == FrameOrdinal(4))
        #expect(response.end.occurrenceOrdinal == FrameOrdinal(6))
        #expect(abs(response.elapsedMilliseconds - 250) < 0.001)
        // One interval per connection: the second reply is more of the same answer.
        #expect(result.measurements.filter { $0.kind == .applicationResponse }.count == 1)
    }

    @Test("A request with no reply, and a reply before any request, are both measured as nothing")
    func oneSidedPayloadMeasuresNothing() {
        var requestOnly = ConnectionTable()
        handshake(&requestOnly)
        ingest(
            &requestOnly,
            from: client,
            to: server,
            flags: [.psh, .ack],
            seq: 1_001,
            ack: 5_001,
            payload: 80,
            ordinal: 4,
            at: 20.0
        )
        #expect(!assess(connections: requestOnly.snapshot()).measurements.contains { $0.kind == .applicationResponse })

        var replyFirst = ConnectionTable()
        handshake(&replyFirst)
        ingest(
            &replyFirst,
            from: server,
            to: client,
            flags: [.psh, .ack],
            seq: 5_001,
            ack: 1_001,
            payload: 30,
            ordinal: 4,
            at: 20.0
        )
        ingest(
            &replyFirst,
            from: client,
            to: server,
            flags: [.psh, .ack],
            seq: 1_001,
            ack: 5_031,
            payload: 80,
            ordinal: 5,
            at: 20.1
        )
        // The responder spoke first, so nothing here is a reply *to* a request.
        #expect(!assess(connections: replyFirst.snapshot()).measurements.contains { $0.kind == .applicationResponse })
    }

    @Test("A midstream connection with no observed initiator reports no response time")
    func midstreamPayloadMeasuresNothing() {
        var table = ConnectionTable()
        ingest(
            &table,
            from: client,
            to: server,
            flags: [.psh, .ack],
            seq: 1_001,
            ack: 5_001,
            payload: 80,
            ordinal: 1,
            at: 20.0
        )
        ingest(
            &table,
            from: server,
            to: client,
            flags: [.psh, .ack],
            seq: 5_001,
            ack: 1_081,
            payload: 90,
            ordinal: 2,
            at: 20.2
        )

        let result = assess(connections: table.snapshot())
        #expect(!result.measurements.contains { $0.kind == .applicationResponse })
    }

    // MARK: Refusals

    @Test("An untimed boundary frame is refused and counted, never measured against a substituted instant")
    func untimedBoundaryRefused() {
        var table = ConnectionTable()
        table.ingest(
            packet(from: client, to: server, flags: [.syn], seq: 1_000, ack: 0, payload: 0, window: 65_535, at: 10.0),
            provenance: SessionFrameProvenance(
                ordinal: FrameOrdinal(1), timestamp: nil, capturedLength: 60,
                originalLength: 60, linkType: 1,
                locator: SessionEvidenceLocator(sourceToken: token, offset: 1)
            )
        )
        ingest(&table, from: server, to: client, flags: [.syn, .ack], seq: 5_000, ack: 1_001, ordinal: 2, at: 10.02)

        let result = assess(connections: table.snapshot())
        #expect(result.measurements.isEmpty)
        #expect(result.untimedBoundaryCount == 1)
    }

    @Test("Truncated event history refuses the paired intervals and counts each refusal")
    func truncatedHistoryRefused() throws {
        // Four events fit; the fifth pushes the oldest out, so "first" is no longer
        // knowable for this connection.
        var table = ConnectionTable(configuration: .init(maxEventsPerConnection: 4))
        handshake(&table)
        ingest(
            &table,
            from: client,
            to: server,
            flags: [.psh, .ack],
            seq: 1_001,
            ack: 5_001,
            payload: 80,
            ordinal: 4,
            at: 20.0
        )
        ingest(
            &table,
            from: server,
            to: client,
            flags: [.psh, .ack],
            seq: 5_001,
            ack: 1_081,
            payload: 90,
            ordinal: 5,
            at: 20.2
        )

        let snapshot = table.snapshot()
        let summary = try #require(snapshot.summaries.first)
        #expect(summary.omittedEventCount > 0)

        let result = assess(connections: snapshot)
        #expect(!result.measurements.contains { $0.kind == .tcpHandshakeReply })
        #expect(!result.measurements.contains { $0.kind == .applicationResponse })
        #expect(result.incompleteRetentionCount >= 1)
    }

    @Test("A retained handshakeCompleted event still measures its own three frames under truncation")
    func completionSurvivesTruncation() throws {
        var table = ConnectionTable(configuration: .init(maxEventsPerConnection: 4))
        handshake(&table)
        ingest(
            &table,
            from: client,
            to: server,
            flags: [.psh, .ack],
            seq: 1_001,
            ack: 5_001,
            payload: 80,
            ordinal: 4,
            at: 20.0
        )

        let snapshot = table.snapshot()
        let summary = try #require(snapshot.summaries.first)
        #expect(summary.omittedEventCount > 0)
        #expect(summary.events.contains { $0.kind == .handshakeCompleted })

        let result = assess(connections: snapshot)
        let completion = try #require(result.measurements.first { $0.kind == .tcpHandshakeCompletion })
        #expect(completion.start.occurrenceOrdinal == FrameOrdinal(1))
        #expect(completion.end.occurrenceOrdinal == FrameOrdinal(3))
    }

    // MARK: TLS

    @Test("A ClientHello and the first later ServerHello give the TLS hello round trip")
    func tlsHelloReply() throws {
        var table = TLSEvidenceTable()
        offerTLS(&table, from: client, to: server, ordinal: 4, at: 30.0, handshake: .clientHello(clientHello))
        offerTLS(&table, from: server, to: client, ordinal: 5, at: 30.12, handshake: .serverHello(serverHello()))

        let result = assess(tls: table.snapshot())
        let reply = try #require(result.measurements.first { $0.kind == .tlsHandshakeReply })
        #expect(reply.start.occurrenceOrdinal == FrameOrdinal(4))
        #expect(reply.end.occurrenceOrdinal == FrameOrdinal(5))
        #expect(abs(reply.elapsedMilliseconds - 120) < 0.001)
        #expect(reply.sessionID == SessionBuilder.sessionID(for: tuple))
    }

    @Test("A HelloRetryRequest is a reply, so an HRR negotiation reports its first round trip")
    func helloRetryRequestIsAReply() {
        var table = TLSEvidenceTable()
        offerTLS(&table, from: client, to: server, ordinal: 4, at: 30.0, handshake: .clientHello(clientHello))
        offerTLS(
            &table, from: server, to: client, ordinal: 5, at: 30.05,
            handshake: .serverHello(serverHello(isHelloRetryRequest: true))
        )
        offerTLS(&table, from: client, to: server, ordinal: 6, at: 30.06, handshake: .clientHello(clientHello))
        offerTLS(&table, from: server, to: client, ordinal: 7, at: 30.20, handshake: .serverHello(serverHello()))

        let result = assess(tls: table.snapshot())
        let replies = result.measurements.filter { $0.kind == .tlsHandshakeReply }
        #expect(replies.count == 1)
        #expect(replies.first?.end.occurrenceOrdinal == FrameOrdinal(5))
    }

    @Test("An unanswered ClientHello, and a ServerHello with no hello before it, measure nothing")
    func tlsWithoutAPairMeasuresNothing() {
        var helloOnly = TLSEvidenceTable()
        offerTLS(&helloOnly, from: client, to: server, ordinal: 4, at: 30.0, handshake: .clientHello(clientHello))
        #expect(assess(tls: helloOnly.snapshot()).measurements.isEmpty)

        var serverOnly = TLSEvidenceTable()
        offerTLS(&serverOnly, from: server, to: client, ordinal: 4, at: 30.0, handshake: .serverHello(serverHello()))
        #expect(assess(tls: serverOnly.snapshot()).measurements.isEmpty)
    }

    @Test("A TLS flow that omitted an observation refuses the interval rather than guessing which hello was first")
    func tlsOmissionRefused() {
        // Three records fit, so the hellos that *would* bound the interval are retained
        // and the fourth record is the one this flow omitted.
        var table = TLSEvidenceTable(configuration: .init(maxObservationsPerSummary: 3))
        offerTLS(&table, from: client, to: server, ordinal: 4, at: 30.0, handshake: .clientHello(clientHello))
        offerTLS(&table, from: client, to: server, ordinal: 5, at: 30.5, handshake: .clientHello(clientHello))
        offerTLS(&table, from: server, to: client, ordinal: 6, at: 30.6, handshake: .serverHello(serverHello()))
        offerTLS(&table, from: server, to: client, ordinal: 7, at: 30.7, handshake: .serverHello(serverHello()))

        let snapshot = table.snapshot()
        #expect(snapshot.omittedObservationCount > 0)
        let result = assess(tls: snapshot)
        #expect(result.measurements.isEmpty)
        #expect(result.incompleteRetentionCount == 1)
    }

    // MARK: DNS

    @Test("Each DNS transaction id pairs its query with the response that carried it")
    func dnsResponseTimes() throws {
        var table = DatagramEvidenceTable()
        try offerDNS(&table, ordinal: 1, at: 40.0, id: 0xABCD, response: false)
        try offerDNS(&table, ordinal: 2, at: 40.0, id: 0xBEEF, response: false)
        try offerDNS(&table, ordinal: 3, at: 40.031, id: 0xBEEF, response: true)
        try offerDNS(&table, ordinal: 4, at: 40.150, id: 0xABCD, response: true)

        let result = assess(datagrams: table.snapshot())
        let dns = result.measurements.filter { $0.kind == .dnsResponse }
        #expect(dns.count == 2)
        // Capture order: the 0xBEEF answer landed first.
        #expect(dns.map(\.start.occurrenceOrdinal) == [FrameOrdinal(1), FrameOrdinal(2)])
        #expect(dns.map(\.end.occurrenceOrdinal) == [FrameOrdinal(4), FrameOrdinal(3)])
        #expect(abs((dns.first?.elapsedMilliseconds ?? 0) - 150) < 0.001)
    }

    @Test("A retried query keeps the first attempt as the start, so the interval covers the whole exchange")
    func dnsRetryKeepsFirstQuery() throws {
        var table = DatagramEvidenceTable()
        try offerDNS(&table, ordinal: 1, at: 40.0, id: 0xABCD, response: false)
        try offerDNS(&table, ordinal: 2, at: 41.0, id: 0xABCD, response: false)
        try offerDNS(&table, ordinal: 3, at: 41.05, id: 0xABCD, response: true)

        let result = assess(datagrams: table.snapshot())
        let dns = try #require(result.measurements.first { $0.kind == .dnsResponse })
        #expect(dns.start.occurrenceOrdinal == FrameOrdinal(1))
        #expect(abs(dns.elapsed - 1.05) < 0.000001)
    }

    @Test("A response with no retained query of its id, and a non-query opcode, measure nothing")
    func dnsWithoutAPairMeasuresNothing() throws {
        var table = DatagramEvidenceTable()
        try offerDNS(&table, ordinal: 1, at: 40.0, id: 0x1111, response: true)
        try offerDNS(&table, ordinal: 2, at: 40.0, id: 0x2222, response: false, opcode: 2)
        try offerDNS(&table, ordinal: 3, at: 40.1, id: 0x2222, response: true, opcode: 2)
        #expect(assess(datagrams: table.snapshot()).measurements.isEmpty)
    }

    @Test("A multicast name-resolution flow is never measured, because one question has many answerers")
    func multicastFlowSkipped() throws {
        var table = DatagramEvidenceTable()
        let host = IPEndpoint(ip: "192.0.2.10", port: 5_353)
        let group = IPEndpoint(ip: "224.0.0.251", port: 5_353)
        try offerDNS(&table, ordinal: 1, at: 40.0, id: 0, response: false, host: host, peer: group)
        try offerDNS(&table, ordinal: 2, at: 40.02, id: 0, response: true, host: host, peer: group)
        #expect(assess(datagrams: table.snapshot()).measurements.isEmpty)
    }

    @Test("A DNS flow that omitted an observation refuses the interval and counts the refusal")
    func dnsOmissionRefused() throws {
        // Three observations fit, so the query and its answer are both retained and the
        // fourth observation is the one this flow omitted.
        var table = DatagramEvidenceTable(configuration: .init(maxObservationsPerSummary: 3))
        try offerDNS(&table, ordinal: 1, at: 40.0, id: 0xABCD, response: false)
        try offerDNS(&table, ordinal: 2, at: 40.5, id: 0xBEEF, response: false)
        try offerDNS(&table, ordinal: 3, at: 40.6, id: 0xABCD, response: true)
        try offerDNS(&table, ordinal: 4, at: 40.7, id: 0xBEEF, response: true)

        let snapshot = table.snapshot()
        #expect(snapshot.omittedObservationCount > 0)
        let result = assess(datagrams: snapshot)
        #expect(result.measurements.isEmpty)
        #expect(result.incompleteRetentionCount == 1)
    }

    @Test("A TLS session's hello reply supersedes the generic request-to-reply row on the same two frames")
    func tlsReplySupersedesApplicationResponse() {
        var connections = ConnectionTable()
        handshake(&connections)
        // The ClientHello *is* the first payload, and the ServerHello the first reply,
        // so both rules land on frames 4 and 5.
        ingest(
            &connections, from: client, to: server, flags: [.psh, .ack],
            seq: 1_001, ack: 5_001, payload: 120, ordinal: 4, at: 30.0
        )
        ingest(
            &connections, from: server, to: client, flags: [.psh, .ack],
            seq: 5_001, ack: 1_121, payload: 90, ordinal: 5, at: 30.12
        )
        var tls = TLSEvidenceTable()
        offerTLS(&tls, from: client, to: server, ordinal: 4, at: 30.0, handshake: .clientHello(clientHello))
        offerTLS(&tls, from: server, to: client, ordinal: 5, at: 30.12, handshake: .serverHello(serverHello()))

        let result = assess(connections: connections.snapshot(), tls: tls.snapshot())
        #expect(result.measurements.contains { $0.kind == .tlsHandshakeReply })
        #expect(!result.measurements.contains { $0.kind == .applicationResponse })
        // Superseding is not a bound, so nothing is reported as omitted.
        #expect(result.omittedMeasurementCount == 0)
    }

    @Test("A request-to-reply pair on different frames than the hello survives alongside it")
    func applicationResponseSurvivesADifferentPair() throws {
        // Plain bytes are exchanged first (a proxy CONNECT shape), and TLS starts only
        // afterwards, so the two rules describe two genuinely different exchanges.
        var connections = ConnectionTable()
        handshake(&connections)
        ingest(
            &connections, from: client, to: server, flags: [.psh, .ack],
            seq: 1_001, ack: 5_001, payload: 50, ordinal: 4, at: 30.0
        )
        ingest(
            &connections, from: server, to: client, flags: [.psh, .ack],
            seq: 5_001, ack: 1_051, payload: 60, ordinal: 5, at: 30.08
        )
        ingest(
            &connections, from: client, to: server, flags: [.psh, .ack],
            seq: 1_051, ack: 5_061, payload: 120, ordinal: 6, at: 30.2
        )
        ingest(
            &connections, from: server, to: client, flags: [.psh, .ack],
            seq: 5_061, ack: 1_171, payload: 90, ordinal: 7, at: 30.5
        )
        var tls = TLSEvidenceTable()
        offerTLS(&tls, from: client, to: server, ordinal: 6, at: 30.2, handshake: .clientHello(clientHello))
        offerTLS(&tls, from: server, to: client, ordinal: 7, at: 30.5, handshake: .serverHello(serverHello()))

        let result = assess(connections: connections.snapshot(), tls: tls.snapshot())
        let response = try #require(result.measurements.first { $0.kind == .applicationResponse })
        #expect(response.start.occurrenceOrdinal == FrameOrdinal(4))
        #expect(response.end.occurrenceOrdinal == FrameOrdinal(5))
        let hello = try #require(result.measurements.first { $0.kind == .tlsHandshakeReply })
        #expect(hello.start.occurrenceOrdinal == FrameOrdinal(6))
    }

    // MARK: Identity, order and bounds

    @Test("Measurement identity is stable across assessments and distinct per interval")
    func stableIdentity() throws {
        var table = DatagramEvidenceTable()
        try offerDNS(&table, ordinal: 1, at: 40.0, id: 0xABCD, response: false)
        try offerDNS(&table, ordinal: 2, at: 40.1, id: 0xABCD, response: true)
        try offerDNS(&table, ordinal: 3, at: 40.2, id: 0xBEEF, response: false)
        try offerDNS(&table, ordinal: 4, at: 40.5, id: 0xBEEF, response: true)
        let snapshot = table.snapshot()

        let first = assess(datagrams: snapshot).measurements
        let second = assess(datagrams: snapshot).measurements
        #expect(first.map(\.id) == second.map(\.id))
        #expect(Set(first.map(\.id)).count == first.count)
    }

    @Test("Measurements are ordered by the frames that bound them, then by the kind's fixed rank")
    func deterministicOrder() {
        var connections = ConnectionTable()
        ingest(&connections, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 10.0)
        ingest(
            &connections,
            from: server,
            to: client,
            flags: [.syn, .ack],
            seq: 5_000,
            ack: 1_001,
            ordinal: 2,
            at: 10.02
        )
        ingest(&connections, from: client, to: server, flags: [.ack], seq: 1_001, ack: 5_001, ordinal: 3, at: 10.03)

        let result = assess(connections: connections.snapshot())
        // Both intervals start at frame 1, so the shorter one (ending at frame 2) leads,
        // and the kinds' ranks break nothing here because the end ordinals differ.
        #expect(result.measurements.map(\.kind) == [.tcpHandshakeReply, .tcpHandshakeCompletion])
        let ordinals = result.measurements.map(\.start.occurrenceOrdinal.rawValue)
        #expect(ordinals == ordinals.sorted())
    }

    @Test("The per-session bound drops the newest intervals and counts every one of them")
    func perSessionBound() throws {
        var table = DatagramEvidenceTable()
        for index in 0 ..< 4 {
            let id = UInt16(0x100 + index)
            try offerDNS(&table, ordinal: UInt64(index * 2 + 1), at: 40.0 + Double(index), id: id, response: false)
            try offerDNS(&table, ordinal: UInt64(index * 2 + 2), at: 40.5 + Double(index), id: id, response: true)
        }
        let assessor = SessionTimingAssessor(configuration: .init(maxMeasurementsPerSession: 2))
        let result = assessor.assess(connections: .empty, tls: .empty, datagrams: table.snapshot())
        #expect(result.measurements.count == 2)
        #expect(result.omittedMeasurementCount == 2)
        #expect(result.measurements.map(\.start.occurrenceOrdinal) == [FrameOrdinal(1), FrameOrdinal(3)])
    }

    @Test("Three empty inputs produce exactly the empty snapshot")
    func emptyInputs() {
        #expect(SessionTimingAssessor().assess(connections: .empty, tls: .empty, datagrams: .empty)
            == SessionTimingSnapshot.empty)
    }

    // MARK: Rollup

    @Test("The rollup reports the count, fastest, median and slowest per kind, and the slowest session")
    func distributions() throws {
        var table = DatagramEvidenceTable()
        let others = [
            IPEndpoint(ip: "203.0.113.54", port: 53),
            IPEndpoint(ip: "203.0.113.55", port: 53),
        ]
        try offerDNS(&table, ordinal: 1, at: 40.0, id: 0x11, response: false)
        try offerDNS(&table, ordinal: 2, at: 40.1, id: 0x11, response: true)
        try offerDNS(&table, ordinal: 3, at: 41.0, id: 0x22, response: false, peer: others[0])
        try offerDNS(&table, ordinal: 4, at: 41.3, id: 0x22, response: true, peer: others[0])
        try offerDNS(&table, ordinal: 5, at: 42.0, id: 0x33, response: false, peer: others[1])
        try offerDNS(&table, ordinal: 6, at: 42.2, id: 0x33, response: true, peer: others[1])

        let result = assess(datagrams: table.snapshot())
        let rollup = try #require(result.distributions().first)
        #expect(rollup.kind == .dnsResponse)
        #expect(rollup.count == 3)
        #expect(abs(rollup.fastest - 0.1) < 0.000001)
        // Three values 0.1 / 0.3 / 0.2 — the median is the middle one, not an average.
        #expect(abs(rollup.median - 0.2) < 0.000001)
        #expect(abs(rollup.slowest - 0.3) < 0.000001)
        #expect(rollup.slowestSessionID == SessionBuilder.sessionID(
            for: FiveTuple(proto: .udp, source: IPEndpoint(ip: "192.0.2.10", port: 51_000), destination: others[0])
        ))

        // Restricting to a scope drops the sessions outside it.
        let scoped = result.distributions(limitedTo: [SessionBuilder.sessionID(for: dnsTuple)])
        #expect(scoped.first?.count == 1)
        #expect(result.distributions(limitedTo: []).isEmpty)
    }

    @Test("Per-session projection returns only that session's intervals")
    func perSessionProjection() throws {
        var table = DatagramEvidenceTable()
        let other = IPEndpoint(ip: "203.0.113.54", port: 53)
        try offerDNS(&table, ordinal: 1, at: 40.0, id: 0x11, response: false)
        try offerDNS(&table, ordinal: 2, at: 40.1, id: 0x11, response: true)
        try offerDNS(&table, ordinal: 3, at: 41.0, id: 0x22, response: false, peer: other)
        try offerDNS(&table, ordinal: 4, at: 41.3, id: 0x22, response: true, peer: other)

        let result = assess(datagrams: table.snapshot())
        let mine = result.measurements(for: SessionBuilder.sessionID(for: dnsTuple))
        #expect(mine.count == 1)
        #expect(mine.first?.start.occurrenceOrdinal == FrameOrdinal(1))
    }

    // MARK: Presentation

    @Test("The panel names each interval, formats it at its scale, and states loss once")
    func presentation() {
        var table = ConnectionTable()
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 10.0)
        ingest(&table, from: server, to: client, flags: [.syn, .ack], seq: 5_000, ack: 1_001, ordinal: 2, at: 10.02)
        ingest(&table, from: client, to: server, flags: [.ack], seq: 1_001, ack: 5_001, ordinal: 3, at: 10.03)

        let result = assess(connections: table.snapshot())
        let panel = SessionResponseTimes(measurements: result.measurements)
        #expect(panel.rows.map(\.label) == ["Connection attempt answered", "Handshake completed"])
        #expect(panel.rows.map(\.value) == ["20 ms", "30 ms"])
        #expect(panel.rows.allSatisfy { $0.provenance.count == 2 })
        // `ingest` reports no loss, so the panel says nothing rather than promising
        // completeness.
        #expect(panel.caveat == nil)
        #expect(!panel.isEmpty)
        #expect(SessionResponseTimes(measurements: []).isEmpty)
    }

    @Test("Interval formatting keeps a sub-millisecond exchange legible and reads seconds above one")
    func durationFormatting() {
        #expect(SessionResponseTimes.durationLabel(0.00012) == "0.12 ms")
        #expect(SessionResponseTimes.durationLabel(0.0042) == "4.2 ms")
        #expect(SessionResponseTimes.durationLabel(0.020) == "20 ms")
        #expect(SessionResponseTimes.durationLabel(1.5) == "1.50 s")
        #expect(SessionResponseTimes.durationLabel(0) == "0.00 ms")
    }

    @Test("Unknown loss is stated once, and a reported loss outranks it")
    func caveatPrecedence() {
        var unknown = ConnectionTable()
        ingest(&unknown, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 10.0, loss: .unknown)
        ingest(
            &unknown, from: server, to: client, flags: [.syn, .ack],
            seq: 5_000, ack: 1_001, ordinal: 2, at: 10.02, loss: .unknown
        )
        let unknownPanel = SessionResponseTimes(measurements: assess(connections: unknown.snapshot()).measurements)
        #expect(unknownPanel.caveat?.contains("unknown") == true)

        var reported = ConnectionTable()
        ingest(&reported, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 10.0, loss: .unknown)
        ingest(
            &reported, from: server, to: client, flags: [.syn, .ack],
            seq: 5_000, ack: 1_001, ordinal: 2, at: 10.02, loss: .lossReported
        )
        let reportedPanel = SessionResponseTimes(measurements: assess(connections: reported.snapshot()).measurements)
        #expect(reportedPanel.caveat?.contains("Capture loss was reported") == true)
    }

    @Test("The rollup row spells its count out and carries the slowest session for the drill-in")
    func distributionRow() throws {
        var table = DatagramEvidenceTable()
        try offerDNS(&table, ordinal: 1, at: 40.0, id: 0x11, response: false)
        try offerDNS(&table, ordinal: 2, at: 40.1, id: 0x11, response: true)

        let rollup = try #require(assess(datagrams: table.snapshot()).distributions().first)
        let row = SessionResponseTimeDistributionRow(distribution: rollup)
        #expect(row.label == "DNS query answered")
        #expect(row.countLabel == "1 measured")
        #expect(row.median == "100 ms")
        #expect(row.slowestSessionID == SessionBuilder.sessionID(for: dnsTuple))
        #expect(row.id == SessionTimingMeasurementKind.dnsResponse.rank)
    }

    // MARK: Snapshot wiring

    @Test("An investigation snapshot measures its own fold, and a session replacement cannot make it stale")
    func snapshotDerivesTiming() {
        var table = ConnectionTable()
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 10.0)
        ingest(&table, from: server, to: client, flags: [.syn, .ack], seq: 5_000, ack: 1_001, ordinal: 2, at: 10.02)

        let snapshot = InvestigationSnapshot(fold: SessionFoldSnapshot(
            sessions: [], connections: table.snapshot(),
            datagramEvidence: .empty, tlsEvidence: .empty, segmentSeries: .empty
        ))
        #expect(snapshot.timing.measurements.map(\.kind) == [.tcpHandshakeReply])
        // A publication that replaces only the session projection re-derives the same
        // measurements from the same evidence — it cannot carry a stale set.
        #expect(snapshot.replacingSessions(with: []).timing == snapshot.timing)
        #expect(InvestigationSnapshot.empty.timing == SessionTimingSnapshot.empty)
    }

    // MARK: Private

    private let client = IPEndpoint(ip: "192.0.2.10", port: 50_000)
    private let server = IPEndpoint(ip: "203.0.113.5", port: 443)
    private let resolverEndpoint = IPEndpoint(ip: "203.0.113.53", port: 53)
    private let token = UUID(uuid: (7, 7, 7, 7, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16))

    private var tuple: FiveTuple {
        FiveTuple(proto: .tcp, source: client, destination: server)
    }

    private var dnsTuple: FiveTuple {
        FiveTuple(proto: .udp, source: IPEndpoint(ip: "192.0.2.10", port: 51_000), destination: resolverEndpoint)
    }

    private var clientHello: TLSClientHelloFact {
        TLSClientHelloFact(
            legacyVersion: 0x0303, offeredVersions: [0x0304],
            offeredVersionsOmittedCount: 0, extensionsComplete: true
        )
    }

    private func serverHello(isHelloRetryRequest: Bool = false) -> TLSServerHelloFact {
        TLSServerHelloFact(
            legacyVersion: 0x0303,
            selectedCipher: 0x1301,
            isHelloRetryRequest: isHelloRetryRequest,
            extensionsComplete: true,
            selectedVersion: isHelloRetryRequest ? nil : 0x0304
        )
    }

    private func assess(
        connections: ConnectionTable.Snapshot = .empty,
        tls: TLSEvidenceTable.Snapshot = .empty,
        datagrams: DatagramEvidenceTable.Snapshot = .empty
    )
        -> SessionTimingSnapshot
    {
        SessionTimingAssessor().assess(connections: connections, tls: tls, datagrams: datagrams)
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
        at timestamp: Double,
        loss: CaptureLossKnowledge = .noLossReported
    ) {
        table.ingest(
            packet(
                from: source, to: destination, flags: flags, seq: seq, ack: ack,
                payload: payload, window: window, at: timestamp
            ),
            provenance: provenance(ordinal: ordinal, at: timestamp),
            loss: loss
        )
    }

    /// A validated three-way handshake at ordinals 1...3: client ISN 1_000, server 5_000.
    private func handshake(_ table: inout ConnectionTable) {
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1, at: 1)
        ingest(&table, from: server, to: client, flags: [.syn, .ack], seq: 5_000, ack: 1_001, ordinal: 2, at: 2)
        ingest(&table, from: client, to: server, flags: [.ack], seq: 1_001, ack: 5_001, ordinal: 3, at: 3)
    }

    private func offerTLS(
        _ table: inout TLSEvidenceTable,
        from source: IPEndpoint,
        to destination: IPEndpoint,
        ordinal: UInt64,
        at timestamp: Double,
        handshake: TLSHandshakeFact
    ) {
        var pkt = DecodedPacket(timestamp: Date(timeIntervalSince1970: timestamp), originalLength: 0)
        pkt.transport = .tcp
        pkt.sourceEndpoint = source
        pkt.destinationEndpoint = destination
        pkt.fiveTuple = FiveTuple(proto: .tcp, source: source, destination: destination)
        pkt.tlsRecords = [TLSRecordFact(
            contentType: 22, legacyRecordVersion: 0x0301,
            declaredBodyLength: 40, capturedBodyLength: 40, handshake: handshake
        )]
        table.offer(
            pkt, application: nil,
            provenance: provenance(ordinal: ordinal, at: timestamp),
            loss: .noLossReported
        )
    }

    private func dnsFacts(id: UInt16, response: Bool, opcode: UInt8) throws -> DNSMessageFacts {
        var flags: UInt16 = 0
        if response {
            flags |= 0x8000
        }
        flags |= (UInt16(opcode) & 0x0F) << 11
        flags |= 0x0100
        func be(_ value: UInt16) -> [UInt8] {
            [UInt8(value >> 8), UInt8(value & 0xFF)]
        }
        return try DNSMessageFacts(
            dnsHeader: PacketBuffer(be(id) + be(flags) + be(1) + be(response ? 1 : 0) + be(0) + be(0))
        )
    }

    /// Offer one UDP-DNS frame. `host` is the side that asks and `peer` the side that
    /// answers, so a query and its response always build the same canonical tuple.
    private func offerDNS(
        _ table: inout DatagramEvidenceTable,
        ordinal: UInt64,
        at timestamp: Double,
        id: UInt16,
        response: Bool,
        opcode: UInt8 = 0,
        host: IPEndpoint? = nil,
        peer: IPEndpoint? = nil
    )
        throws
    {
        let asking = host ?? IPEndpoint(ip: "192.0.2.10", port: 51_000)
        let answering = peer ?? resolverEndpoint
        let resolvedSource = response ? answering : asking
        let resolvedDestination = response ? asking : answering
        var pkt = DecodedPacket(timestamp: Date(timeIntervalSince1970: timestamp), originalLength: 0)
        pkt.transport = .udp
        pkt.sourceEndpoint = resolvedSource
        pkt.destinationEndpoint = resolvedDestination
        pkt.fiveTuple = FiveTuple(proto: .udp, source: resolvedSource, destination: resolvedDestination)
        pkt.dnsFacts = try dnsFacts(id: id, response: response, opcode: opcode)
        table.offer(
            pkt,
            provenance: provenance(ordinal: ordinal, at: timestamp),
            loss: .noLossReported
        )
    }
}
