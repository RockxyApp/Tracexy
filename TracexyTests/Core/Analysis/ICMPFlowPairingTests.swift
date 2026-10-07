import Foundation
import Testing
@testable import Tracexy

/// The quoted inner header an ICMP error carries, and the paired
/// findings it lets the assessor report against the flow the error was about.
///
/// The decoder cases run over real frame bytes so the offsets, the bounds refusals
/// and the fail-closed rules are proven from the wire rather than from hand-built
/// facts. The assessor cases then drive the real `DatagramEvidenceTable` fold, and
/// the end-to-end case drives the whole `SessionBuilder` fold so the paired finding
/// is proven to land on the id of the session the capture actually published.
@Suite("ICMP quoted-flow pairing")
struct ICMPFlowPairingTests {
    // MARK: Internal

    // MARK: Decoding the quotation

    @Test("An IPv4 port-unreachable quoting a UDP datagram yields that flow's typed identity")
    func quotesIPv4UDPFlow() throws {
        let quoted = try #require(decodeICMPFacts(icmpv4Unreachable(code: 3, quoting: quotedIPv4UDP())).quotedFlow)
        #expect(quoted.proto == .udp)
        #expect(quoted.source == IPEndpoint(ip: "192.0.2.10", port: 51_000))
        #expect(quoted.destination == IPEndpoint(ip: "203.0.113.53", port: 53))
        #expect(quoted.tuple == FiveTuple(
            proto: .udp,
            source: IPEndpoint(ip: "192.0.2.10", port: 51_000),
            destination: IPEndpoint(ip: "203.0.113.53", port: 53)
        ))
    }

    @Test("An IPv4 fragmentation-needed quoting a TCP segment yields that flow")
    func quotesIPv4TCPFlow() throws {
        let bytes = icmpv4Unreachable(code: 4, quoting: quotedIPv4(proto: 6, sourcePort: 50_000, destinationPort: 443))
        let quoted = try #require(decodeICMPFacts(bytes).quotedFlow)
        #expect(quoted.proto == .tcp)
        #expect(quoted.source.port == 50_000)
        #expect(quoted.destination.port == 443)
    }

    @Test("An ICMPv6 packet-too-big quoting a TCP segment yields that IPv6 flow")
    func quotesIPv6TCPFlow() throws {
        let quoted = try #require(decodeICMPFacts(icmpv6PacketTooBig(quoting: quotedIPv6(nextHeader: 6))).quotedFlow)
        #expect(quoted.proto == .tcp)
        #expect(quoted.source == IPEndpoint(ip: "2001:db8:0:0:0:0:0:10", port: 50_000))
        #expect(quoted.destination == IPEndpoint(ip: "2001:db8:0:0:0:0:0:53", port: 443))
    }

    @Test("Quoted IPv4 options move the ports, and the header length is honoured")
    func honoursQuotedIPv4Options() throws {
        // IHL 6 (24 bytes): four option bytes before the transport header.
        var quoted = quotedIPv4(proto: 17, sourcePort: 51_000, destinationPort: 53)
        quoted[0] = 0x46
        quoted.insert(contentsOf: [UInt8](repeating: 0x01, count: 4), at: 20)
        let facts = try #require(decodeICMPFacts(icmpv4Unreachable(code: 3, quoting: quoted)).quotedFlow)
        #expect(facts.source.port == 51_000)
        #expect(facts.destination.port == 53)
    }

    @Test("A quotation cut short before the ports yields no flow at all")
    func truncatedQuotationYieldsNothing() {
        // Keep the 20-byte IPv4 header and only two of the four port bytes.
        let quoted = Array(quotedIPv4UDP().prefix(22))
        #expect(decodeICMPFacts(icmpv4Unreachable(code: 3, quoting: quoted)).quotedFlow == nil)
    }

    @Test("A quoted non-first fragment yields no flow: its transport header travelled elsewhere")
    func fragmentedQuotationYieldsNothing() {
        var quoted = quotedIPv4UDP()
        // Fragment offset 185 (1480 bytes in), no more-fragments.
        quoted[6] = 0x00
        quoted[7] = 0xB9
        #expect(decodeICMPFacts(icmpv4Unreachable(code: 3, quoting: quoted)).quotedFlow == nil)
    }

    @Test("A quoted transport other than TCP or UDP yields no flow")
    func nonTCPUDPQuotationYieldsNothing() {
        let quoted = quotedIPv4(proto: 1, sourcePort: 0, destinationPort: 0)
        #expect(decodeICMPFacts(icmpv4Unreachable(code: 3, quoting: quoted)).quotedFlow == nil)
    }

    @Test("A quoted IP version disagreeing with the ICMP family yields no flow")
    func versionMismatchYieldsNothing() {
        var quoted = quotedIPv4UDP()
        quoted[0] = 0x65 // version 6 nibble inside an ICMPv4 error
        #expect(decodeICMPFacts(icmpv4Unreachable(code: 3, quoting: quoted)).quotedFlow == nil)

        var v6 = quotedIPv6(nextHeader: 6)
        v6[0] = 0x45 // version 4 nibble inside an ICMPv6 error
        #expect(decodeICMPFacts(icmpv6PacketTooBig(quoting: v6)).quotedFlow == nil)
    }

    @Test("An IPv6 quotation carrying an extension header is refused rather than walked")
    func ipv6ExtensionHeaderQuotationYieldsNothing() {
        #expect(decodeICMPFacts(icmpv6PacketTooBig(quoting: quotedIPv6(nextHeader: 0))).quotedFlow == nil)
    }

    @Test("A non-quoting type never produces a quoted flow even when bytes follow it")
    func nonQuotingTypeYieldsNothing() {
        var bytes = icmpv4Unreachable(code: 3, quoting: quotedIPv4UDP())
        bytes[14 + 20] = 8 // Echo Request
        let facts = decodeICMPFacts(bytes)
        #expect(facts.type == 8)
        #expect(facts.quotedFlow == nil)
    }

    // MARK: Paired findings

    @Test("An unreachable quoting a flow reports on the ICMP conversation and on the quoted flow")
    func pairsUnreachableOntoQuotedFlow() throws {
        var table = DatagramEvidenceTable()
        offerICMP(&table, ordinal: 1, family: .ipv4, type: 3, code: 3, quoting: quotedTCPFlow)
        let result = DatagramAssessor().assess(table.snapshot())

        #expect(Set(result.findings.map(\.kind)) == [
            .icmpDestinationUnreachableObserved,
            .icmpUnreachableReportedForFlow,
        ])
        let paired = try #require(result.findings.first { $0.kind == .icmpUnreachableReportedForFlow })
        #expect(paired.severity == .warning)
        #expect(paired.sessionID == SessionBuilder.sessionID(for: quotedTCPFlow.tuple))
        #expect(paired.tuple == quotedTCPFlow.tuple)
        #expect(paired.citations.map(\.provenance.ordinal) == [FrameOrdinal(1)])

        // The cited frame belongs to the ICMP conversation, and says so.
        let onFlow = try #require(result.findings.first { $0.kind == .icmpDestinationUnreachableObserved })
        #expect(paired.citations.map(\.provenance) == onFlow.citations.map(\.provenance))
        #expect(paired.citations.map(\.sessionID) == onFlow.citations.map(\.sessionID))
        #expect(paired.sessionID != onFlow.sessionID)
    }

    @Test("Each paired kind mirrors its flow-level outcome exactly, severities included")
    func pairedKindsMirrorOutcomes() throws {
        struct Case {
            let family: ICMPFamily
            let type: UInt8
            let code: UInt8
            let onFlow: DatagramAnalysisFindingKind
            let paired: DatagramAnalysisFindingKind
            let severity: AnalysisSeverity
        }
        let cases: [Case] = [
            Case(
                family: .ipv4, type: 3, code: 0,
                onFlow: .icmpDestinationUnreachableObserved, paired: .icmpUnreachableReportedForFlow,
                severity: .warning
            ),
            Case(
                family: .ipv6, type: 1, code: 4,
                onFlow: .icmpDestinationUnreachableObserved, paired: .icmpUnreachableReportedForFlow,
                severity: .warning
            ),
            Case(
                family: .ipv4, type: 3, code: 4,
                onFlow: .icmpPacketTooBigObserved, paired: .icmpPacketTooBigReportedForFlow,
                severity: .note
            ),
            Case(
                family: .ipv6, type: 2, code: 0,
                onFlow: .icmpPacketTooBigObserved, paired: .icmpPacketTooBigReportedForFlow,
                severity: .note
            ),
            Case(
                family: .ipv4, type: 11, code: 0,
                onFlow: .icmpTimeExceededObserved, paired: .icmpTimeExceededReportedForFlow,
                severity: .note
            ),
            Case(
                family: .ipv6, type: 3, code: 1,
                onFlow: .icmpTimeExceededObserved, paired: .icmpTimeExceededReportedForFlow,
                severity: .note
            ),
        ]
        for testCase in cases {
            var table = DatagramEvidenceTable()
            offerICMP(
                &table, ordinal: 1, family: testCase.family,
                type: testCase.type, code: testCase.code, quoting: quotedTCPFlow
            )
            let result = DatagramAssessor().assess(table.snapshot())
            #expect(
                Set(result.findings.map(\.kind)) == [testCase.onFlow, testCase.paired],
                "\(testCase.family) type \(testCase.type) code \(testCase.code)"
            )
            let paired = try #require(result.findings.first { $0.kind == testCase.paired })
            #expect(paired.severity == testCase.severity)
            // One message is one observation, counted once.
            #expect(result.retainedICMPObservationCount == 1)
        }
    }

    @Test("An error with no readable quotation reports only on its own flow")
    func unquotedErrorIsNotPaired() {
        var table = DatagramEvidenceTable()
        offerICMP(&table, ordinal: 1, family: .ipv4, type: 3, code: 1, quoting: nil)
        let result = DatagramAssessor().assess(table.snapshot())
        #expect(result.findings.map(\.kind) == [.icmpDestinationUnreachableObserved])
    }

    @Test("A non-error type is never paired even when it carries a quotation")
    func nonErrorTypeIsNeverPaired() {
        var table = DatagramEvidenceTable()
        offerICMP(&table, ordinal: 1, family: .ipv4, type: 5, code: 1, quoting: quotedTCPFlow)
        let result = DatagramAssessor().assess(table.snapshot())
        #expect(result.findings.isEmpty)
        #expect(result.retainedICMPObservationCount == 1)
    }

    @Test("Repeated errors quoting one flow coalesce into a single paired finding, oldest first")
    func pairedFindingsCoalesce() {
        var table = DatagramEvidenceTable()
        offerICMP(&table, ordinal: 1, family: .ipv4, type: 3, code: 1, quoting: quotedTCPFlow)
        offerICMP(&table, ordinal: 2, family: .ipv4, type: 3, code: 3, quoting: quotedTCPFlow)
        let result = DatagramAssessor().assess(table.snapshot())
        let paired = result.findings.filter { $0.kind == .icmpUnreachableReportedForFlow }
        #expect(paired.count == 1)
        #expect(paired.first?.citations.map(\.provenance.ordinal) == [FrameOrdinal(1), FrameOrdinal(2)])
    }

    @Test("Errors quoting two different flows produce one paired finding each")
    func distinctQuotedFlowsStaySeparate() throws {
        let other = ICMPQuotedFlowFacts(
            proto: .udp,
            source: IPEndpoint(ip: "192.0.2.10", port: 51_000),
            destination: IPEndpoint(ip: "203.0.113.53", port: 53)
        )
        var table = DatagramEvidenceTable()
        offerICMP(&table, ordinal: 1, family: .ipv4, type: 3, code: 1, quoting: quotedTCPFlow)
        offerICMP(&table, ordinal: 2, family: .ipv4, type: 3, code: 3, quoting: other)
        let result = DatagramAssessor().assess(table.snapshot())
        let paired = result.findings.filter { $0.kind == .icmpUnreachableReportedForFlow }
        #expect(paired.count == 2)
        #expect(Set(paired.map(\.sessionID)) == [
            SessionBuilder.sessionID(for: quotedTCPFlow.tuple),
            SessionBuilder.sessionID(for: other.tuple),
        ])
        // The single flow-level finding still coalesces both messages.
        let onFlow = try #require(result.findings.first { $0.kind == .icmpDestinationUnreachableObserved })
        #expect(onFlow.citations.count == 2)
    }

    @Test("A paired finding id is seeded only by the quoted session id and the kind")
    func pairedIdentityIsStable() throws {
        var table = DatagramEvidenceTable()
        offerICMP(&table, ordinal: 1, family: .ipv4, type: 11, code: 0, quoting: quotedTCPFlow)
        let paired = try #require(
            DatagramAssessor().assess(table.snapshot())
                .findings.first { $0.kind == .icmpTimeExceededReportedForFlow }
        )
        #expect(paired.id == SessionBuilder.stableID(
            "datagramAnalysis|\(paired.sessionID.uuidString)|icmpTimeExceededReportedForFlow"
        ))
    }

    @Test("Each paired kind ranks immediately ahead of the flow-level kind it mirrors")
    func pairedKindsRankAheadOfTheirOutcome() {
        #expect(DatagramAnalysisFindingKind.icmpUnreachableReportedForFlow.rank
            < DatagramAnalysisFindingKind.icmpDestinationUnreachableObserved.rank)
        #expect(DatagramAnalysisFindingKind.icmpPacketTooBigReportedForFlow.rank
            < DatagramAnalysisFindingKind.icmpPacketTooBigObserved.rank)
        #expect(DatagramAnalysisFindingKind.icmpTimeExceededReportedForFlow.rank
            < DatagramAnalysisFindingKind.icmpTimeExceededObserved.rank)
        // Every kind still has a distinct rank, so the tie-break can never be a draw.
        let ranks = [
            DatagramAnalysisFindingKind.dnsTruncationIndicated,
            .dnsNameErrorObserved, .dnsServerFailureObserved, .dnsQueryUnansweredObserved,
            .icmpDestinationUnreachableObserved, .icmpPacketTooBigObserved, .icmpTimeExceededObserved,
            .icmpUnreachableReportedForFlow, .icmpPacketTooBigReportedForFlow,
            .icmpTimeExceededReportedForFlow,
        ].map(\.rank)
        #expect(Set(ranks).count == ranks.count)
    }

    @Test("Assessing the same evidence twice yields the same findings in the same order")
    func assessmentOrderIsRepeatable() {
        var table = DatagramEvidenceTable()
        offerICMP(&table, ordinal: 1, family: .ipv4, type: 3, code: 1, quoting: quotedTCPFlow)
        offerICMP(&table, ordinal: 2, family: .ipv4, type: 11, code: 0, quoting: quotedTCPFlow)
        let snapshot = table.snapshot()
        let first = DatagramAssessor().assess(snapshot).findings
        let second = DatagramAssessor().assess(snapshot).findings
        #expect(first == second)
        #expect(Set(first.map(\.kind)) == [
            .icmpDestinationUnreachableObserved,
            .icmpUnreachableReportedForFlow,
            .icmpTimeExceededObserved,
            .icmpTimeExceededReportedForFlow,
        ])
    }

    // MARK: Projection

    @Test("Paired kinds project to their own query names")
    func queryProjection() throws {
        let parser = SessionQueryParser()
        #expect(try parser.parse("finding == icmpReportedUnreachable")
            == .leaf(.findingKind(.icmpReportedUnreachable)))
        #expect(try parser.parse("finding == icmpReportedPacketTooBig")
            == .leaf(.findingKind(.icmpReportedPacketTooBig)))
        #expect(try parser.parse("finding == icmpReportedTimeExceeded")
            == .leaf(.findingKind(.icmpReportedTimeExceeded)))
    }

    // MARK: End to end

    @Test("A captured TCP session and an ICMP error quoting it publish the paired finding on that session")
    func pairsOntoTheCapturedSessionEndToEnd() throws {
        let frames = [
            CapturedFrame(bytes: tcpSYNFrame(), timestamp: Date(timeIntervalSince1970: 1), originalLength: 54),
            CapturedFrame(
                bytes: icmpv4Unreachable(
                    code: 3,
                    quoting: quotedIPv4(proto: 6, sourcePort: 50_000, destinationPort: 443)
                ),
                timestamp: Date(timeIntervalSince1970: 2),
                originalLength: 70
            ),
        ]
        let snapshot = InvestigationSnapshot(
            fold: SessionBuilder.buildDetailed(from: frames, linkType: LinkType.ethernet)
        )
        let tcpSession = try #require(snapshot.sessions.first { $0.protocolStack.contains(.tcp) })
        let paired = try #require(
            snapshot.datagramAnalysis.findings.first { $0.kind == .icmpUnreachableReportedForFlow }
        )
        #expect(paired.sessionID == tcpSession.id)
        // The cited frame is the ICMP one, on the ICMP conversation.
        #expect(paired.citations.map(\.provenance.ordinal) == [FrameOrdinal(2)])
        #expect(paired.citations.first?.sessionID != tcpSession.id)
        // And the ICMP conversation keeps its own finding.
        #expect(snapshot.datagramAnalysis.findings.contains { $0.kind == .icmpDestinationUnreachableObserved })
    }

    // MARK: Private

    /// The quoted flow every assessor case uses: a TCP connection that is not the
    /// ICMP conversation carrying the error.
    private let quotedTCPFlow = ICMPQuotedFlowFacts(
        proto: .tcp,
        source: IPEndpoint(ip: "192.0.2.10", port: 50_000),
        destination: IPEndpoint(ip: "203.0.113.5", port: 443)
    )
    private let token = UUID(uuid: (9, 9, 9, 9, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16))

    // MARK: Frame construction

    private func be16(_ value: UInt16) -> [UInt8] {
        [UInt8(value >> 8), UInt8(value & 0xFF)]
    }

    /// A 14-byte Ethernet header for the given EtherType.
    private func ethernet(_ etherType: UInt16) -> [UInt8] {
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02] + be16(etherType)
    }

    /// A 20-byte IPv4 header followed by four port bytes — the shape an ICMP error
    /// quotes back ("internet header + 64 bits of data").
    private func quotedIPv4(proto: UInt8, sourcePort: UInt16, destinationPort: UInt16) -> [UInt8] {
        var header: [UInt8] = [0x45, 0x00]
        header += be16(60) // total length
        header += be16(0x1234) // identification
        header += be16(0) // flags + fragment offset
        header += [64, proto]
        header += be16(0) // checksum
        header += [192, 0, 2, 10]
        header += [203, 0, 113, 5]
        return header + be16(sourcePort) + be16(destinationPort) + [0, 0, 0, 0]
    }

    /// The quoted UDP datagram used by the DNS-shaped cases.
    private func quotedIPv4UDP() -> [UInt8] {
        var bytes = quotedIPv4(proto: 17, sourcePort: 51_000, destinationPort: 53)
        bytes[16] = 203
        bytes[17] = 0
        bytes[18] = 113
        bytes[19] = 53
        return bytes
    }

    /// A 40-byte IPv6 header followed by four port bytes.
    private func quotedIPv6(nextHeader: UInt8) -> [UInt8] {
        var header: [UInt8] = [0x60, 0x00, 0x00, 0x00]
        header += be16(24) // payload length
        header += [nextHeader, 64]
        header += [0x20, 0x01, 0x0D, 0xB8] + [UInt8](repeating: 0, count: 11) + [0x10]
        header += [0x20, 0x01, 0x0D, 0xB8] + [UInt8](repeating: 0, count: 11) + [0x53]
        return header + be16(50_000) + be16(443) + [0, 0, 0, 0]
    }

    /// An Ethernet/IPv4 frame carrying an ICMP destination-unreachable message that
    /// quotes `quoting` after the eight fixed ICMP bytes.
    private func icmpv4Unreachable(code: UInt8, quoting: [UInt8]) -> [UInt8] {
        let icmp: [UInt8] = [3, code, 0, 0, 0, 0, 0, 0] + quoting
        var ip: [UInt8] = [0x45, 0x00]
        ip += be16(UInt16(20 + icmp.count))
        ip += be16(0x4321)
        ip += be16(0)
        ip += [64, 1]
        ip += be16(0)
        ip += [198, 51, 100, 1]
        ip += [192, 0, 2, 10]
        return ethernet(0x0800) + ip + icmp
    }

    /// An Ethernet/IPv6 frame carrying an ICMPv6 packet-too-big message.
    private func icmpv6PacketTooBig(quoting: [UInt8]) -> [UInt8] {
        let icmp: [UInt8] = [2, 0, 0, 0, 0, 0, 0x05, 0xA0] + quoting
        var ip: [UInt8] = [0x60, 0x00, 0x00, 0x00]
        ip += be16(UInt16(icmp.count))
        ip += [58, 64]
        ip += [0x20, 0x01, 0x0D, 0xB8] + [UInt8](repeating: 0, count: 11) + [0x01]
        ip += [0x20, 0x01, 0x0D, 0xB8] + [UInt8](repeating: 0, count: 11) + [0x10]
        return ethernet(0x86DD) + ip + icmp
    }

    /// A bare Ethernet/IPv4/TCP SYN for 192.0.2.10:50000 → 203.0.113.5:443, so the
    /// end-to-end case has a real session for the error to be paired onto.
    private func tcpSYNFrame() -> [UInt8] {
        var tcp = be16(50_000) + be16(443)
        tcp += [0, 0, 0, 1] // sequence
        tcp += [0, 0, 0, 0] // acknowledgement
        tcp += [0x50, 0x02] // data offset 5, SYN
        tcp += be16(65_535) + be16(0) + be16(0)
        var ip: [UInt8] = [0x45, 0x00]
        ip += be16(UInt16(20 + tcp.count))
        ip += be16(0x1111)
        ip += be16(0)
        ip += [64, 6]
        ip += be16(0)
        ip += [192, 0, 2, 10]
        ip += [203, 0, 113, 5]
        return ethernet(0x0800) + ip + tcp
    }

    // MARK: Decoding and folding

    /// Decode one synthetic Ethernet frame and return its ICMP facts.
    private func decodeICMPFacts(_ bytes: [UInt8]) -> ICMPMessageFacts {
        let packet = PacketDecoder.decode(
            PacketBuffer(bytes), linkType: LinkType.ethernet,
            timestamp: Date(timeIntervalSince1970: 1), originalLength: bytes.count
        )
        return packet.icmpFacts ?? ICMPMessageFacts(family: .ipv4, type: 0, code: 0)
    }

    /// Offer one ICMP observation on the router→host conversation, optionally
    /// carrying a quoted flow.
    private func offerICMP(
        _ table: inout DatagramEvidenceTable,
        ordinal: UInt64,
        family: ICMPFamily,
        type: UInt8,
        code: UInt8,
        quoting: ICMPQuotedFlowFacts?
    ) {
        let router = IPEndpoint(ip: family == .ipv4 ? "198.51.100.1" : "2001:db8::1", port: 0)
        let host = IPEndpoint(ip: family == .ipv4 ? "192.0.2.10" : "2001:db8::10", port: 0)
        let kind: ProtocolKind = family == .ipv4 ? .icmp : .icmpv6
        var packet = DecodedPacket(timestamp: Date(timeIntervalSince1970: Double(ordinal)), originalLength: 0)
        packet.transport = kind
        packet.sourceEndpoint = router
        packet.destinationEndpoint = host
        packet.fiveTuple = FiveTuple(proto: kind, source: router, destination: host)
        packet.icmpFacts = ICMPMessageFacts(family: family, type: type, code: code, quotedFlow: quoting)
        table.offer(
            packet,
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
}
