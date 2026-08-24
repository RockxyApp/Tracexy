import Foundation
import Testing
@testable import Tracexy

@Suite("DatagramAssessor passive analysis")
struct DatagramAnalysisTests {
    // MARK: Internal

    // MARK: The single mapping — TC bit set

    @Test("A truncated DNS query maps to the neutral note with exact session/tuple/direction/provenance")
    func truncatedQueryMapsToNote() throws {
        let prov = provenance(3)
        let obs = try dnsObservation(
            tuple: tupleA,
            direction: .aToB,
            provenance: prov,
            isResponse: false,
            isTruncated: true
        )
        let result = DatagramAssessor().assess(snapshot([summary(tuple: tupleA, observations: [obs])]))

        #expect(result.findings.count == 1)
        let finding = try #require(result.findings.first)
        #expect(finding.kind == .dnsTruncationIndicated)
        #expect(finding.severity == .note)
        #expect(finding.sessionID == sessionID(tupleA))
        #expect(finding.tuple == tupleA)
        // Direction and provenance are preserved verbatim from the source observation.
        let citation = try #require(finding.citations.first)
        #expect(citation.sessionID == sessionID(tupleA))
        #expect(citation.direction == .aToB)
        #expect(citation.provenance == prov)
        #expect(finding.citations.count == 1)
        #expect(finding.omittedCitationCount == 0)
    }

    @Test("A truncated DNS response also maps to the same neutral note, preserving its direction")
    func truncatedResponseMapsToNote() throws {
        let obs = try dnsObservation(
            tuple: tupleA,
            direction: .bToA,
            provenance: provenance(7),
            isResponse: true,
            isTruncated: true,
            responseCode: 0
        )
        let result = DatagramAssessor().assess(snapshot([summary(tuple: tupleA, observations: [obs])]))
        let finding = try #require(result.findings.first)
        #expect(finding.kind == .dnsTruncationIndicated)
        #expect(finding.severity == .note)
        #expect(finding.citations.first?.direction == .bToA)
    }

    // MARK: Non-TC DNS never maps — regardless of RCODE / opcode / counts / QR

    @Test("Non-truncated DNS produces zero findings for arbitrary RCODE, opcode, counts and QR")
    func nonTruncatedDNSNeverMaps() throws {
        // A deliberately hostile spread: NXDOMAIN, SERVFAIL, an unassigned opcode,
        // huge counts, both query and response — none of these is the TC bit.
        var observations: [DatagramEvidenceObservation] = []
        let rcodes: [UInt8] = [0, 2, 3, 5, 9, 15]
        let opcodes: [UInt8] = [0, 1, 2, 4, 5, 15]
        for (index, (rcode, opcode)) in zip(rcodes, opcodes).enumerated() {
            try observations.append(dnsObservation(
                tuple: tupleA,
                direction: index.isMultiple(of: 2) ? .aToB : .bToA,
                provenance: provenance(UInt64(index + 1)),
                isResponse: index.isMultiple(of: 2),
                isTruncated: false,
                opcode: opcode,
                responseCode: rcode,
                questionCount: UInt16(index),
                answerCount: 0xFFFF,
                authorityCount: 0xFFFF,
                additionalCount: 0xFFFF
            ))
        }
        let result = DatagramAssessor().assess(snapshot([summary(tuple: tupleA, observations: observations)]))
        #expect(result.findings.isEmpty)
        #expect(result.omittedFindingCount == 0)
        #expect(result.retainedICMPObservationCount == 0)
    }

    @Test("Every non-TC DNS flag combination other than the TC bit still maps to nothing")
    func onlyTCBitMaps() throws {
        // Set every flag except TC, plus a non-zero RCODE — still not a finding.
        let obs = try dnsObservation(
            tuple: tupleA,
            direction: .aToB,
            provenance: provenance(1),
            isResponse: true,
            isTruncated: false,
            isAuthoritativeAnswer: true,
            recursionDesired: true,
            recursionAvailable: true,
            authenticData: true,
            checkingDisabled: true,
            opcode: 2,
            responseCode: 3
        )
        let result = DatagramAssessor().assess(snapshot([summary(tuple: tupleA, observations: [obs])]))
        #expect(result.findings.isEmpty)
    }

    // MARK: ICMP never maps — v4/v6, any type/code

    @Test("ICMP v4/v6 with arbitrary type/code produce zero findings and exact retained ICMP coverage")
    func icmpNeverMapsAndCountsExactly() {
        // A spread across both families and a range of arbitrary type/code values,
        // including unreachable, too-big, time-exceeded, parameter-problem, redirect
        // and echo. None is a finding here.
        let icmpv4: [(UInt8, UInt8)] = [(3, 0), (3, 1), (3, 3), (11, 0), (5, 1), (8, 0)]
        let icmpv6: [(UInt8, UInt8)] = [(1, 0), (1, 4), (2, 0), (3, 0), (4, 1), (128, 0)]
        var observations: [DatagramEvidenceObservation] = []
        for (index, (type, code)) in icmpv4.enumerated() {
            observations.append(icmpObservation(
                tuple: tupleA, direction: .aToB, provenance: provenance(UInt64(index + 1)),
                family: .ipv4, type: type, code: code
            ))
        }
        for (index, (type, code)) in icmpv6.enumerated() {
            observations.append(icmpObservation(
                tuple: tupleB, direction: .bToA, provenance: provenance(UInt64(index + 100)),
                family: .ipv6, type: type, code: code
            ))
        }
        let result = DatagramAssessor().assess(snapshot([
            summary(tuple: tupleA, observations: Array(observations.prefix(6))),
            summary(tuple: tupleB, observations: Array(observations.suffix(6))),
        ]))
        #expect(result.findings.isEmpty)
        #expect(result.omittedFindingCount == 0)
        // Exactly the twelve ICMP observations are counted as retained ICMP coverage.
        #expect(result.retainedICMPObservationCount == 12)
    }

    @Test("A mixed summary retains only the TC finding, counts ICMP, and ignores non-TC DNS")
    func mixedSummaryIsolatesTheOneSignal() throws {
        let observations = try [
            dnsObservation(tuple: tupleA, direction: .aToB, provenance: provenance(1), isTruncated: false),
            icmpObservation(
                tuple: tupleA,
                direction: .aToB,
                provenance: provenance(2),
                family: .ipv4,
                type: 3,
                code: 1
            ),
            dnsObservation(tuple: tupleA, direction: .bToA, provenance: provenance(3), isTruncated: true),
            icmpObservation(
                tuple: tupleA,
                direction: .bToA,
                provenance: provenance(4),
                family: .ipv6,
                type: 1,
                code: 0
            ),
        ]
        let result = DatagramAssessor().assess(snapshot([summary(tuple: tupleA, observations: observations)]))
        #expect(result.findings.count == 1)
        #expect(result.findings.first?.kind == .dnsTruncationIndicated)
        #expect(result.findings.first?.citations.map(\.provenance.ordinal) == [FrameOrdinal(3)])
        #expect(result.retainedICMPObservationCount == 2)
    }

    // MARK: Coalescing & citation cap

    @Test("Multiple TC observations on one session coalesce into one finding; citations cap with exact omission")
    func coalescingAndCitationCapWithExactOmission() throws {
        // Five TC observations on one flow coalesce into a single finding.
        let observations = try (2 ... 6).map {
            try dnsObservation(tuple: tupleA, direction: .aToB, provenance: provenance(UInt64($0)), isTruncated: true)
        }
        let config = DatagramAssessor.Configuration(maxCitationsPerFinding: 2)
        let result = DatagramAssessor(configuration: config).assess(snapshot([
            summary(tuple: tupleA, observations: observations),
        ]))

        #expect(result.findings.count == 1)
        let finding = try #require(result.findings.first)
        #expect(finding.kind == .dnsTruncationIndicated)
        #expect(finding.citations.count == 2)
        // Exactly three citations were dropped to honor the per-finding bound.
        #expect(finding.omittedCitationCount == 3)
        // The retained citations are the two oldest, in capture-ordinal order.
        #expect(finding.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(2), FrameOrdinal(3)])
    }

    @Test("Citations order oldest-first by capture ordinal regardless of observation input order")
    func citationsOrderOldestFirst() throws {
        // Deliberately supply the observations newest-first; the citation order must
        // still be oldest-first.
        let observations = try [9, 4, 7, 2].map {
            try dnsObservation(tuple: tupleA, direction: .aToB, provenance: provenance(UInt64($0)), isTruncated: true)
        }
        let finding = try #require(DatagramAssessor().assess(snapshot([
            summary(tuple: tupleA, observations: observations),
        ])).findings.first)
        #expect(finding.citations.map(\.occurrenceOrdinal) == [
            FrameOrdinal(2),
            FrameOrdinal(4),
            FrameOrdinal(7),
            FrameOrdinal(9)
        ])
    }

    @Test("Equal ordinals use all remaining citation fields as deterministic tie-breaks")
    func equalOrdinalCitationOrderIsDeterministic() throws {
        let later = SessionFrameProvenance(
            ordinal: FrameOrdinal(UInt64.max),
            timestamp: Date(timeIntervalSince1970: 20),
            capturedLength: 100,
            originalLength: 100,
            linkType: 1,
            locator: SessionEvidenceLocator(sourceToken: token, offset: 20)
        )
        let earlier = SessionFrameProvenance(
            ordinal: FrameOrdinal(UInt64.max),
            timestamp: Date(timeIntervalSince1970: 10),
            capturedLength: 100,
            originalLength: 100,
            linkType: 1,
            locator: SessionEvidenceLocator(sourceToken: token, offset: 10)
        )
        let observations = try [later, earlier].map {
            try dnsObservation(tuple: tupleA, direction: .aToB, provenance: $0, isTruncated: true)
        }
        let forward = DatagramAssessor().assess(snapshot([
            summary(tuple: tupleA, observations: observations),
        ]))
        let reversed = DatagramAssessor().assess(snapshot([
            summary(tuple: tupleA, observations: Array(observations.reversed())),
        ]))
        #expect(forward == reversed)
        #expect(forward.findings.first?.citations.map(\.provenance.timestamp) == [
            earlier.timestamp,
            later.timestamp,
        ])
    }

    // MARK: Stable identity

    @Test("A finding id depends only on session id + kind, not on citations, counts or history")
    func findingIDStableAcrossCitationAndHistoryDifferences() throws {
        let sparse = try summary(tuple: tupleA, observations: [
            dnsObservation(tuple: tupleA, direction: .aToB, provenance: provenance(2), isTruncated: true),
        ])
        let dense = try summary(
            tuple: tupleA,
            observations: [2, 9, 20].map {
                try dnsObservation(
                    tuple: tupleA,
                    direction: .bToA,
                    provenance: provenance(UInt64($0)),
                    isTruncated: true
                )
            },
            omittedObservationCount: 7
        )
        let a = try #require(DatagramAssessor().assess(snapshot([sparse])).findings.first)
        let b = try #require(DatagramAssessor().assess(snapshot([dense])).findings.first)
        #expect(a.id == b.id)
    }

    @Test("The finding id is the deterministic stableID seed from session id + kind, not a random UUID")
    func findingIDMatchesDeterministicSeed() throws {
        let finding = try #require(try DatagramAssessor().assess(snapshot([
            summary(tuple: tupleA, observations: [
                dnsObservation(tuple: tupleA, direction: .aToB, provenance: provenance(2), isTruncated: true),
            ]),
        ])).findings.first)
        let expected = SessionBuilder.stableID(
            "datagramAnalysis|\(sessionID(tupleA).uuidString)|dnsTruncationIndicated"
        )
        #expect(finding.id == expected)
    }

    // MARK: Ordering & determinism

    @Test("Findings order by earliest cited ordinal and are invariant to input summary order")
    func shuffleInvariantOrdering() throws {
        let summaries = try threeSessionFindings()
        let ordered = DatagramAssessor().assess(snapshot(summaries))
        let reversed = DatagramAssessor().assess(snapshot(summaries.reversed()))
        #expect(ordered == reversed)
        // The order follows the earliest cited ordinal: tupleB(2), tupleA(5), tupleC(8).
        #expect(ordered.findings.map(\.sessionID) == [sessionID(tupleB), sessionID(tupleA), sessionID(tupleC)])
    }

    @Test("Assessing the same snapshot twice yields equal, hashable snapshots")
    func deterministicAndHashable() throws {
        let snap = try snapshot(threeSessionFindings())
        let first = DatagramAssessor().assess(snap)
        let second = DatagramAssessor().assess(snap)
        #expect(first == second)
        #expect(Set([first, second]).count == 1)
    }

    // MARK: Global finding cap

    @Test("The global finding cap keeps the earliest findings and counts omission exactly")
    func globalFindingCapDeterministicWithOmission() throws {
        let summaries = try threeSessionFindings()
        let config = DatagramAssessor.Configuration(maxFindings: 2)
        let result = DatagramAssessor(configuration: config).assess(snapshot(summaries))
        #expect(result.findings.count == 2)
        #expect(result.omittedFindingCount == 1)
        // The two kept are the earliest by first cited occurrence: tupleB(2), tupleA(5).
        #expect(result.findings.map(\.sessionID) == [sessionID(tupleB), sessionID(tupleA)])
    }

    // MARK: Coverage precedence

    @Test("Coverage follows strict precedence across all cases")
    func coveragePrecedence() throws {
        // 1. Reported loss wins even with omitted/truncated evidence present.
        #expect(try coverageOf(loss: .lossReported, omitted: 2, snapTruncated: true) == .captureLossReported)
        // 2. Omitted evidence: an omitted-observation count, or snap-length truncation.
        #expect(try coverageOf(loss: .noLossReported, omitted: 1, snapTruncated: false) == .omittedEvidence)
        #expect(try coverageOf(loss: .noLossReported, omitted: 0, snapTruncated: true) == .omittedEvidence)
        // Omitted evidence outranks unknown loss.
        #expect(try coverageOf(loss: .unknown, omitted: 1, snapTruncated: false) == .omittedEvidence)
        // 3. Unknown loss with no known omission.
        #expect(try coverageOf(loss: .unknown, omitted: 0, snapTruncated: false) == .unknownLoss)
        // 4. Bounded-local: loss explicitly not reported and nothing omitted.
        #expect(try coverageOf(loss: .noLossReported, omitted: 0, snapTruncated: false) == .boundedNoKnownOmission)
    }

    // MARK: Empty & input-counter propagation

    @Test("The empty evidence snapshot assesses to the canonical empty analysis")
    func emptyAssessesToEmpty() {
        #expect(DatagramAssessor().assess(.empty) == DatagramAnalysisSnapshot.empty)
    }

    @Test("A summary with only non-TC/ICMP evidence yields no finding but still propagates coverage")
    func noMappedEvidenceStillPropagates() throws {
        let observations = try [
            dnsObservation(tuple: tupleA, direction: .aToB, provenance: provenance(1), isTruncated: false),
            icmpObservation(
                tuple: tupleA,
                direction: .bToA,
                provenance: provenance(2),
                family: .ipv4,
                type: 8,
                code: 0
            ),
        ]
        let snap = snapshot(
            [summary(tuple: tupleA, observations: observations)],
            omittedObservationCount: 5,
            retainedObservationCount: 2,
            excludedTCPDNSFactCount: 9,
            capacityReached: true
        )
        let result = DatagramAssessor().assess(snap)
        #expect(result.findings.isEmpty)
        #expect(result.retainedICMPObservationCount == 1)
        #expect(result.inputOmittedObservationCount == 5)
        #expect(result.retainedInputObservationCount == 2)
        #expect(result.excludedTCPDNSFactCount == 9)
        #expect(result.inputCapacityReached)
    }

    @Test("All N3B2 input coverage counters are propagated verbatim onto the analysis snapshot")
    func propagatesEveryInputCounter() throws {
        let snap = try snapshot(
            [summary(tuple: tupleA, observations: [
                dnsObservation(tuple: tupleA, direction: .aToB, provenance: provenance(1), isTruncated: true),
            ])],
            omittedObservationCount: 42,
            retainedObservationCount: 1,
            excludedTCPDNSFactCount: 17,
            capacityReached: true,
            countersOverflowed: false
        )
        let result = DatagramAssessor().assess(snap)
        #expect(result.inputOmittedObservationCount == 42)
        #expect(result.retainedInputObservationCount == 1)
        #expect(result.excludedTCPDNSFactCount == 17)
        #expect(result.inputCapacityReached)
        #expect(result.findings.count == 1)
    }

    // MARK: Overflow propagation & saturation

    @Test("Input counter overflow is propagated and combined with the assessor's own overflow")
    func inputOverflowPropagates() throws {
        let snap = try snapshot(
            [summary(tuple: tupleA, observations: [
                dnsObservation(tuple: tupleA, direction: .aToB, provenance: provenance(1), isTruncated: true),
            ])],
            countersOverflowed: true
        )
        // The assessor itself did not overflow here, but the input signal is carried.
        #expect(DatagramAssessor().assess(snap).countersOverflowed)
    }

    @Test("saturatingAdd reports overflow and clamps to the maximum without wrapping")
    func saturatingAddSeam() {
        let ordinary = DatagramAssessor.saturatingAdd(1, 2)
        #expect(ordinary.value == 3)
        #expect(!ordinary.overflowed)

        let overflowed = DatagramAssessor.saturatingAdd(.max, 1)
        #expect(overflowed.value == .max)
        #expect(overflowed.overflowed)

        // A second saturation stays clamped — never wraps back toward zero.
        let again = DatagramAssessor.saturatingAdd(overflowed.value, 5)
        #expect(again.value == .max)
        #expect(again.overflowed)
    }

    // MARK: Bounds clamping

    @Test("Zero or negative configuration bounds clamp to one")
    func boundsClampToOne() {
        let clamped = DatagramAssessor.Configuration(maxFindings: 0, maxCitationsPerFinding: -5)
        #expect(clamped.maxFindings == 1)
        #expect(clamped.maxCitationsPerFinding == 1)
    }

    // MARK: Privacy by type

    @Test("A citation carries only session id, direction and provenance — no DNS or ICMP facts")
    func citationCarriesNoDatagramFacts() throws {
        let finding = try #require(try DatagramAssessor().assess(snapshot([
            summary(tuple: tupleA, observations: [
                dnsObservation(tuple: tupleA, direction: .aToB, provenance: provenance(1), isTruncated: true),
            ]),
        ])).findings.first)
        let citation = try #require(finding.citations.first)
        let labels = Mirror(reflecting: citation).children.compactMap(\.label)
        #expect(Set(labels) == ["sessionID", "direction", "provenance"])
        // No decoded DNS/ICMP fact value appears anywhere in the finding tree.
        #expect(!Self.containsForbiddenFactType(finding))
    }

    // MARK: Private

    // Documentation-only endpoints (RFC 5737); the lower-valued IP is canonical `a`.
    private let clientA = IPEndpoint(ip: "192.0.2.10", port: 53)
    private let serverA = IPEndpoint(ip: "203.0.113.5", port: 53)
    private let clientB = IPEndpoint(ip: "198.51.100.20", port: 53)
    private let serverB = IPEndpoint(ip: "203.0.113.6", port: 53)
    private let clientC = IPEndpoint(ip: "198.51.100.30", port: 53)
    private let serverC = IPEndpoint(ip: "203.0.113.7", port: 53)
    private let token = UUID(uuid: (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16))

    private var tupleA: FiveTuple {
        FiveTuple(proto: .udp, source: clientA, destination: serverA)
    }

    private var tupleB: FiveTuple {
        FiveTuple(proto: .udp, source: clientB, destination: serverB)
    }

    private var tupleC: FiveTuple {
        FiveTuple(proto: .udp, source: clientC, destination: serverC)
    }

    /// Recursively asserts no decoded DNS/ICMP fact value survives into an analysis
    /// value — the privacy-by-type guarantee that only typed identity/provenance,
    /// never wire facts, leave this layer.
    private static func containsForbiddenFactType(_ value: Any) -> Bool {
        if value is DNSMessageFacts || value is ICMPMessageFacts || value is DatagramEvidenceKind {
            return true
        }
        for child in Mirror(reflecting: value).children where containsForbiddenFactType(child.value) {
            return true
        }
        return false
    }

    private func sessionID(_ tuple: FiveTuple) -> UUID {
        SessionBuilder.sessionID(for: tuple)
    }

    private func provenance(_ ordinal: UInt64) -> SessionFrameProvenance {
        SessionFrameProvenance(
            ordinal: FrameOrdinal(ordinal),
            timestamp: Date(timeIntervalSince1970: Double(ordinal)),
            capturedLength: 100,
            originalLength: 100,
            linkType: 1,
            locator: SessionEvidenceLocator(sourceToken: token, offset: ordinal)
        )
    }

    /// Builds a real `DNSMessageFacts` by packing the fixed 12-byte header and
    /// decoding it through `PacketBuffer`, so every mapping test exercises the same
    /// wire-fact type production uses. Never fabricates the struct out of band.
    private func dnsFacts(
        transactionID: UInt16 = 0x1234,
        isResponse: Bool = false,
        isTruncated: Bool,
        isAuthoritativeAnswer: Bool = false,
        recursionDesired: Bool = false,
        recursionAvailable: Bool = false,
        authenticData: Bool = false,
        checkingDisabled: Bool = false,
        opcode: UInt8 = 0,
        responseCode: UInt8 = 0,
        questionCount: UInt16 = 0,
        answerCount: UInt16 = 0,
        authorityCount: UInt16 = 0,
        additionalCount: UInt16 = 0
    )
        throws -> DNSMessageFacts
    {
        var flags: UInt16 = 0
        if isResponse {
            flags |= 0x8000
        }
        flags |= (UInt16(opcode) & 0x0F) << 11
        if isAuthoritativeAnswer {
            flags |= 0x0400
        }
        if isTruncated {
            flags |= 0x0200
        }
        if recursionDesired {
            flags |= 0x0100
        }
        if recursionAvailable {
            flags |= 0x0080
        }
        if authenticData {
            flags |= 0x0020
        }
        if checkingDisabled {
            flags |= 0x0010
        }
        flags |= UInt16(responseCode) & 0x000F
        func be(_ value: UInt16) -> [UInt8] {
            [UInt8(value >> 8), UInt8(value & 0xFF)]
        }
        let bytes = be(transactionID) + be(flags) + be(questionCount) + be(answerCount)
            + be(authorityCount) + be(additionalCount)
        return try DNSMessageFacts(dnsHeader: PacketBuffer(bytes))
    }

    private func dnsObservation(
        tuple: FiveTuple,
        direction: ConnectionDirection,
        provenance: SessionFrameProvenance,
        isResponse: Bool = false,
        isTruncated: Bool,
        isAuthoritativeAnswer: Bool = false,
        recursionDesired: Bool = false,
        recursionAvailable: Bool = false,
        authenticData: Bool = false,
        checkingDisabled: Bool = false,
        opcode: UInt8 = 0,
        responseCode: UInt8 = 0,
        questionCount: UInt16 = 0,
        answerCount: UInt16 = 0,
        authorityCount: UInt16 = 0,
        additionalCount: UInt16 = 0
    )
        throws -> DatagramEvidenceObservation
    {
        let facts = try dnsFacts(
            isResponse: isResponse,
            isTruncated: isTruncated,
            isAuthoritativeAnswer: isAuthoritativeAnswer,
            recursionDesired: recursionDesired,
            recursionAvailable: recursionAvailable,
            authenticData: authenticData,
            checkingDisabled: checkingDisabled,
            opcode: opcode,
            responseCode: responseCode,
            questionCount: questionCount,
            answerCount: answerCount,
            authorityCount: authorityCount,
            additionalCount: additionalCount
        )
        return DatagramEvidenceObservation(
            sessionID: sessionID(tuple),
            tuple: tuple,
            direction: direction,
            provenance: provenance,
            kind: .dns(facts)
        )
    }

    private func icmpObservation(
        tuple: FiveTuple,
        direction: ConnectionDirection,
        provenance: SessionFrameProvenance,
        family: ICMPFamily,
        type: UInt8,
        code: UInt8
    )
        -> DatagramEvidenceObservation
    {
        DatagramEvidenceObservation(
            sessionID: sessionID(tuple),
            tuple: tuple,
            direction: direction,
            provenance: provenance,
            kind: .icmp(ICMPMessageFacts(family: family, type: type, code: code))
        )
    }

    private func summary(
        tuple: FiveTuple,
        observations: [DatagramEvidenceObservation],
        lossKnowledge: CaptureLossKnowledge = .noLossReported,
        omittedObservationCount: UInt64 = 0,
        snapLengthTruncationObserved: Bool = false
    )
        -> DatagramEvidenceSummary
    {
        DatagramEvidenceSummary(
            sessionID: sessionID(tuple),
            tuple: tuple,
            observations: observations,
            omittedObservationCount: omittedObservationCount,
            lossKnowledge: lossKnowledge,
            snapLengthTruncationObserved: snapLengthTruncationObserved
        )
    }

    private func snapshot(
        _ summaries: [DatagramEvidenceSummary],
        omittedObservationCount: UInt64 = 0,
        retainedObservationCount: Int? = nil,
        excludedTCPDNSFactCount: UInt64 = 0,
        capacityReached: Bool = false,
        countersOverflowed: Bool = false
    )
        -> DatagramEvidenceTable.Snapshot
    {
        DatagramEvidenceTable.Snapshot(
            summaries: summaries,
            omittedObservationCount: omittedObservationCount,
            retainedObservationCount: retainedObservationCount
                ?? summaries.reduce(0) { $0 + $1.observations.count },
            excludedTCPDNSFactCount: excludedTCPDNSFactCount,
            capacityReached: capacityReached,
            countersOverflowed: countersOverflowed
        )
    }

    /// Three flows whose single TC finding has a distinct earliest cited ordinal:
    /// tupleB at 2, tupleA at 5, tupleC at 8.
    private func threeSessionFindings() throws -> [DatagramEvidenceSummary] {
        try [
            summary(tuple: tupleA, observations: [
                dnsObservation(tuple: tupleA, direction: .aToB, provenance: provenance(5), isTruncated: true),
            ]),
            summary(tuple: tupleB, observations: [
                dnsObservation(tuple: tupleB, direction: .aToB, provenance: provenance(2), isTruncated: true),
            ]),
            summary(tuple: tupleC, observations: [
                dnsObservation(tuple: tupleC, direction: .aToB, provenance: provenance(8), isTruncated: true),
            ]),
        ]
    }

    /// The coverage assigned to a finding on a flow with the given loss / omission /
    /// snap-truncation state, read back through a real assessment.
    private func coverageOf(
        loss: CaptureLossKnowledge,
        omitted: UInt64,
        snapTruncated: Bool
    )
        throws -> AnalysisCoverage?
    {
        let sum = try summary(
            tuple: tupleA,
            observations: [
                dnsObservation(tuple: tupleA, direction: .aToB, provenance: provenance(2), isTruncated: true),
            ],
            lossKnowledge: loss,
            omittedObservationCount: omitted,
            snapLengthTruncationObserved: snapTruncated
        )
        return DatagramAssessor().assess(snapshot([sum])).findings.first?.coverage
    }
}
