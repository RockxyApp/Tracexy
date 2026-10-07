import Foundation
import Testing
@testable import Tracexy

/// The DNS outcome findings (name error, server failure, unanswered retried
/// query). Most cases drive the real `DatagramEvidenceTable` fold from decoded
/// packets so the pairing is proven from frames; the rest pin rule boundaries.
@Suite("DatagramAssessor DNS outcome findings")
struct DatagramOutcomeFindingTests {
    // MARK: Internal

    // MARK: Response outcomes

    @Test("An NXDOMAIN standard-query response maps to dnsNameErrorObserved (note)")
    func nameError() throws {
        var table = DatagramEvidenceTable()
        try offer(&table, from: client, to: resolver, ordinal: 1, id: 0x1001, response: false, rd: true)
        try offer(&table, from: resolver, to: client, ordinal: 2, id: 0x1001, response: true, rcode: 3)
        let result = DatagramAssessor().assess(table.snapshot())
        #expect(result.findings.map(\.kind) == [.dnsNameErrorObserved])
        let finding = try #require(result.findings.first)
        #expect(finding.severity == .note)
        #expect(finding.citations.map(\.provenance.ordinal) == [FrameOrdinal(2)])
        #expect(finding.citations.map(\.direction) == [.bToA])
    }

    @Test("SERVFAIL and REFUSED responses coalesce into one dnsServerFailureObserved (warning)")
    func serverFailure() throws {
        var table = DatagramEvidenceTable()
        try offer(&table, from: client, to: resolver, ordinal: 1, id: 0x2001, response: false, rd: true)
        try offer(&table, from: resolver, to: client, ordinal: 2, id: 0x2001, response: true, rcode: 2)
        try offer(&table, from: client, to: resolver, ordinal: 3, id: 0x2002, response: false, rd: true)
        try offer(&table, from: resolver, to: client, ordinal: 4, id: 0x2002, response: true, rcode: 5)
        let result = DatagramAssessor().assess(table.snapshot())
        #expect(result.findings.map(\.kind) == [.dnsServerFailureObserved])
        let finding = try #require(result.findings.first)
        #expect(finding.severity == .warning)
        #expect(finding.citations.map(\.provenance.ordinal) == [FrameOrdinal(2), FrameOrdinal(4)])
    }

    @Test("Only standard-query responses map: queries, other opcodes and other RCODEs never do")
    func onlyStandardResponsesMap() throws {
        var table = DatagramEvidenceTable()
        // A query carrying an RCODE bit pattern is not a response.
        try offer(&table, from: client, to: resolver, ordinal: 1, id: 1, response: false, rd: true, rcode: 3)
        // A STATUS-opcode response with RCODE 2.
        try offer(&table, from: resolver, to: client, ordinal: 2, id: 1, response: true, opcode: 2, rcode: 2)
        // NOERROR, FORMERR, NOTIMP and an unassigned code.
        for (ordinal, rcode) in [(3, UInt8(0)), (4, 1), (5, 4), (6, 9)] {
            try offer(&table, from: resolver, to: client, ordinal: UInt64(ordinal), id: 1, response: true, rcode: rcode)
        }
        #expect(DatagramAssessor().assess(table.snapshot()).findings.isEmpty)
    }

    @Test("A truncated SERVFAIL response contributes to both the TC and the failure findings")
    func truncatedFailureContributesToBoth() throws {
        var table = DatagramEvidenceTable()
        try offer(&table, from: resolver, to: client, ordinal: 1, id: 7, response: true, rcode: 2, tc: true)
        let kinds = Set(DatagramAssessor().assess(table.snapshot()).findings.map(\.kind))
        #expect(kinds == [.dnsTruncationIndicated, .dnsServerFailureObserved])
    }

    // MARK: Unanswered retried queries

    @Test("A recursion-desired query id sent twice with no response maps to dnsQueryUnansweredObserved")
    func unansweredRetry() throws {
        var table = DatagramEvidenceTable()
        try offer(&table, from: client, to: resolver, ordinal: 1, id: 0x3001, response: false, rd: true)
        try offer(&table, from: client, to: resolver, ordinal: 2, id: 0x3001, response: false, rd: true)
        try offer(&table, from: client, to: resolver, ordinal: 3, id: 0x3001, response: false, rd: true)
        let result = DatagramAssessor().assess(table.snapshot())
        #expect(result.findings.map(\.kind) == [.dnsQueryUnansweredObserved])
        let finding = try #require(result.findings.first)
        #expect(finding.severity == .warning)
        #expect(finding.citations.map(\.provenance.ordinal) == [FrameOrdinal(1), FrameOrdinal(2), FrameOrdinal(3)])
        #expect(finding.citations.allSatisfy { $0.direction == .aToB })
    }

    @Test("A single query, or a retried query that is answered, is never unanswered")
    func singleOrAnsweredIsNotUnanswered() throws {
        var single = DatagramEvidenceTable()
        try offer(&single, from: client, to: resolver, ordinal: 1, id: 5, response: false, rd: true)
        #expect(DatagramAssessor().assess(single.snapshot()).findings.isEmpty)

        var answered = DatagramEvidenceTable()
        try offer(&answered, from: client, to: resolver, ordinal: 1, id: 5, response: false, rd: true)
        try offer(&answered, from: client, to: resolver, ordinal: 2, id: 5, response: false, rd: true)
        try offer(&answered, from: resolver, to: client, ordinal: 3, id: 5, response: true, rcode: 0)
        #expect(DatagramAssessor().assess(answered.snapshot()).findings.isEmpty)
    }

    @Test("Unanswered pairing is per transaction id: a different answered id does not answer the retried one")
    func pairingIsPerTransactionID() throws {
        var table = DatagramEvidenceTable()
        try offer(&table, from: client, to: resolver, ordinal: 1, id: 0x10, response: false, rd: true)
        try offer(&table, from: client, to: resolver, ordinal: 2, id: 0x10, response: false, rd: true)
        try offer(&table, from: client, to: resolver, ordinal: 3, id: 0x11, response: false, rd: true)
        try offer(&table, from: resolver, to: client, ordinal: 4, id: 0x11, response: true, rcode: 0)
        let result = DatagramAssessor().assess(table.snapshot())
        let finding = try #require(result.findings.first { $0.kind == .dnsQueryUnansweredObserved })
        #expect(finding.citations.map(\.provenance.ordinal) == [FrameOrdinal(1), FrameOrdinal(2)])
    }

    @Test("Retried queries without RD (mDNS-style) and multicast name ports never map as unanswered")
    func noRDOrMulticastPortsNeverUnanswered() throws {
        var noRD = DatagramEvidenceTable()
        try offer(&noRD, from: client, to: resolver, ordinal: 1, id: 0, response: false, rd: false)
        try offer(&noRD, from: client, to: resolver, ordinal: 2, id: 0, response: false, rd: false)
        #expect(DatagramAssessor().assess(noRD.snapshot()).findings.isEmpty)

        let mdns = IPEndpoint(ip: "224.0.0.251", port: 5_353)
        let local = IPEndpoint(ip: "192.0.2.10", port: 5_353)
        var multicast = DatagramEvidenceTable()
        try offer(&multicast, from: local, to: mdns, ordinal: 1, id: 0, response: false, rd: true)
        try offer(&multicast, from: local, to: mdns, ordinal: 2, id: 0, response: false, rd: true)
        #expect(DatagramAssessor().assess(multicast.snapshot()).findings.isEmpty)
    }

    @Test("Unanswered fails closed when the flow omitted observations to a bound")
    func unansweredFailsClosedUnderOmission() throws {
        let config = DatagramEvidenceTable.Configuration(maxObservationsPerSummary: 2)
        var table = DatagramEvidenceTable(configuration: config)
        try offer(&table, from: client, to: resolver, ordinal: 1, id: 9, response: false, rd: true)
        try offer(&table, from: client, to: resolver, ordinal: 2, id: 9, response: false, rd: true)
        // The answer arrives but is bounded away; the retried id must not be reported.
        try offer(&table, from: resolver, to: client, ordinal: 3, id: 9, response: true, rcode: 0)
        let snapshot = table.snapshot()
        #expect(snapshot.summaries.first?.omittedObservationCount == 1)
        #expect(DatagramAssessor().assess(snapshot).findings.isEmpty)
    }

    // MARK: ICMP outcomes

    @Test("ICMP error families map by family and type; codes only split fragmentation-needed")
    func icmpFamiliesMap() {
        struct Case {
            let facts: ICMPMessageFacts
            let kind: DatagramAnalysisFindingKind
        }
        let cases: [Case] = [
            Case(facts: .init(family: .ipv4, type: 3, code: 0), kind: .icmpDestinationUnreachableObserved),
            Case(facts: .init(family: .ipv4, type: 3, code: 3), kind: .icmpDestinationUnreachableObserved),
            Case(facts: .init(family: .ipv4, type: 3, code: 13), kind: .icmpDestinationUnreachableObserved),
            Case(facts: .init(family: .ipv6, type: 1, code: 4), kind: .icmpDestinationUnreachableObserved),
            Case(facts: .init(family: .ipv4, type: 3, code: 4), kind: .icmpPacketTooBigObserved),
            Case(facts: .init(family: .ipv6, type: 2, code: 0), kind: .icmpPacketTooBigObserved),
            Case(facts: .init(family: .ipv4, type: 11, code: 0), kind: .icmpTimeExceededObserved),
            Case(facts: .init(family: .ipv6, type: 3, code: 1), kind: .icmpTimeExceededObserved),
        ]
        for testCase in cases {
            let facts = testCase.facts
            var table = DatagramEvidenceTable()
            offerICMP(&table, ordinal: 1, family: facts.family, type: facts.type, code: facts.code)
            let result = DatagramAssessor().assess(table.snapshot())
            #expect(
                result.findings.map(\.kind) == [testCase.kind],
                "\(facts.family) type \(facts.type) code \(facts.code)"
            )
            let expectedSeverity: AnalysisSeverity = testCase
                .kind == .icmpDestinationUnreachableObserved ? .warning : .note
            #expect(result.findings.first?.severity == expectedSeverity)
            #expect(result.findings.first?.citations.map(\.provenance.ordinal) == [FrameOrdinal(1)])
            #expect(result.retainedICMPObservationCount == 1)
        }
    }

    @Test("Non-error ICMP types never map but are still counted as retained coverage")
    func icmpNonErrorTypesNeverMap() {
        var table = DatagramEvidenceTable()
        offerICMP(&table, ordinal: 1, family: .ipv4, type: 8, code: 0)
        offerICMP(&table, ordinal: 2, family: .ipv4, type: 0, code: 0)
        offerICMP(&table, ordinal: 3, family: .ipv4, type: 5, code: 1)
        offerICMP(&table, ordinal: 4, family: .ipv6, type: 128, code: 0)
        offerICMP(&table, ordinal: 5, family: .ipv6, type: 135, code: 0)
        let result = DatagramAssessor().assess(table.snapshot())
        #expect(result.findings.isEmpty)
        #expect(result.retainedICMPObservationCount == 5)
    }

    @Test("Repeated unreachable messages on one ICMP flow coalesce, oldest first")
    func icmpCoalesces() throws {
        var table = DatagramEvidenceTable()
        offerICMP(&table, ordinal: 1, family: .ipv4, type: 3, code: 1)
        offerICMP(&table, ordinal: 2, family: .ipv4, type: 3, code: 3)
        offerICMP(&table, ordinal: 3, family: .ipv4, type: 11, code: 0)
        let result = DatagramAssessor().assess(table.snapshot())
        #expect(Set(result.findings.map(\.kind)) == [.icmpDestinationUnreachableObserved, .icmpTimeExceededObserved])
        let unreachable = try #require(result.findings.first { $0.kind == .icmpDestinationUnreachableObserved })
        #expect(unreachable.citations.map(\.provenance.ordinal) == [FrameOrdinal(1), FrameOrdinal(2)])
        #expect(try SessionQueryParser().parse("finding == icmpUnreachable") == .leaf(.findingKind(.icmpUnreachable)))
    }

    // MARK: Identity, order, projection

    @Test("Outcome finding ids are stable and seeded only by session id and kind")
    func stableIdentity() throws {
        var table = DatagramEvidenceTable()
        try offer(&table, from: resolver, to: client, ordinal: 1, id: 1, response: true, rcode: 3)
        let finding = try #require(DatagramAssessor().assess(table.snapshot()).findings.first)
        let expected = SessionBuilder.stableID(
            "datagramAnalysis|\(finding.sessionID.uuidString)|dnsNameErrorObserved"
        )
        #expect(finding.id == expected)
    }

    @Test("Outcome findings project to their own query finding kinds")
    func queryProjection() throws {
        let parser = SessionQueryParser()
        #expect(try parser.parse("finding == dnsNameError") == .leaf(.findingKind(.dnsNameError)))
        #expect(try parser.parse("finding == dnsServerFailure") == .leaf(.findingKind(.dnsServerFailure)))
        #expect(try parser.parse("finding == dnsUnanswered") == .leaf(.findingKind(.dnsUnanswered)))
    }

    // MARK: Private

    private let client = IPEndpoint(ip: "192.0.2.10", port: 51_000)
    private let resolver = IPEndpoint(ip: "203.0.113.53", port: 53)
    private let token = UUID(uuid: (7, 7, 7, 7, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16))

    private func facts(
        id: UInt16,
        response: Bool,
        rd: Bool,
        opcode: UInt8,
        rcode: UInt8,
        tc: Bool
    )
        throws -> DNSMessageFacts
    {
        var flags: UInt16 = 0
        if response {
            flags |= 0x8000
        }
        flags |= (UInt16(opcode) & 0x0F) << 11
        if tc {
            flags |= 0x0200
        }
        if rd {
            flags |= 0x0100
        }
        flags |= UInt16(rcode) & 0x000F
        func be(_ value: UInt16) -> [UInt8] {
            [UInt8(value >> 8), UInt8(value & 0xFF)]
        }
        let bytes = be(id) + be(flags) + be(1) + be(response ? 1 : 0) + be(0) + be(0)
        return try DNSMessageFacts(dnsHeader: PacketBuffer(bytes))
    }

    private func offerICMP(
        _ table: inout DatagramEvidenceTable,
        ordinal: UInt64,
        family: ICMPFamily,
        type: UInt8,
        code: UInt8
    ) {
        let router = IPEndpoint(ip: family == .ipv4 ? "198.51.100.1" : "2001:db8::1", port: 0)
        let host = IPEndpoint(ip: family == .ipv4 ? "192.0.2.10" : "2001:db8::10", port: 0)
        var pkt = DecodedPacket(timestamp: Date(timeIntervalSince1970: Double(ordinal)), originalLength: 0)
        pkt.transport = family == .ipv4 ? .icmp : .icmpv6
        pkt.sourceEndpoint = router
        pkt.destinationEndpoint = host
        pkt.fiveTuple = FiveTuple(proto: family == .ipv4 ? .icmp : .icmpv6, source: router, destination: host)
        pkt.icmpFacts = ICMPMessageFacts(family: family, type: type, code: code)
        table.offer(
            pkt,
            provenance: SessionFrameProvenance(
                ordinal: FrameOrdinal(ordinal),
                timestamp: Date(timeIntervalSince1970: Double(ordinal)),
                capturedLength: 70,
                originalLength: 70,
                linkType: 1,
                locator: SessionEvidenceLocator(sourceToken: token, offset: ordinal)
            ),
            loss: .noLossReported
        )
    }

    private func offer(
        _ table: inout DatagramEvidenceTable,
        from source: IPEndpoint,
        to destination: IPEndpoint,
        ordinal: UInt64,
        id: UInt16,
        response: Bool,
        rd: Bool = false,
        opcode: UInt8 = 0,
        rcode: UInt8 = 0,
        tc: Bool = false
    )
        throws
    {
        var pkt = DecodedPacket(timestamp: Date(timeIntervalSince1970: Double(ordinal)), originalLength: 0)
        pkt.transport = .udp
        pkt.sourceEndpoint = source
        pkt.destinationEndpoint = destination
        pkt.fiveTuple = FiveTuple(proto: .udp, source: source, destination: destination)
        pkt.dnsFacts = try facts(id: id, response: response, rd: rd, opcode: opcode, rcode: rcode, tc: tc)
        table.offer(
            pkt,
            provenance: SessionFrameProvenance(
                ordinal: FrameOrdinal(ordinal),
                timestamp: Date(timeIntervalSince1970: Double(ordinal)),
                capturedLength: 80,
                originalLength: 80,
                linkType: 1,
                locator: SessionEvidenceLocator(sourceToken: token, offset: ordinal)
            ),
            loss: .noLossReported
        )
    }
}
