import Foundation
import Testing
@testable import Tracexy

// MARK: - Byte helpers

private func be16(_ value: UInt16) -> [UInt8] {
    [UInt8(value >> 8), UInt8(value & 0xFF)]
}

private func be24(_ value: Int) -> [UInt8] {
    [UInt8((value >> 16) & 0xFF), UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]
}

/// The RFC 8446 §4.1.3 HelloRetryRequest sentinel random.
private let helloRetryRandom: [UInt8] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
]

private let zeroRandom = [UInt8](repeating: 0, count: 32)

private func tlsRecordBytes(contentType: UInt8, version: UInt16 = 0x0303, body: [UInt8]) -> [UInt8] {
    [contentType] + be16(version) + be16(UInt16(body.count)) + body
}

private func serverHelloHandshake(
    legacyVersion: UInt16, cipher: UInt16 = 0x1301, random: [UInt8] = zeroRandom, extensions: [UInt8]?
)
    -> [UInt8]
{
    var body = be16(legacyVersion) + random + [0x00]
    body += be16(cipher) + [0x00]
    if let extensions {
        body += be16(UInt16(extensions.count)) + extensions
    }
    return [0x02] + be24(body.count) + body
}

private func serverSupportedVersionsExtension(_ version: UInt16) -> [UInt8] {
    be16(0x002B) + be16(2) + be16(version)
}

private func clientHelloHandshake(
    legacyVersion: UInt16 = 0x0303, offeredVersions: [UInt16] = [0x0304]
)
    -> [UInt8]
{
    var body = be16(legacyVersion) + zeroRandom + [0x00]
    body += be16(2) + be16(0x1301)
    body += [0x01, 0x00]
    var svData: [UInt8] = [UInt8(offeredVersions.count * 2)]
    for version in offeredVersions {
        svData += be16(version)
    }
    let sv = be16(0x002B) + be16(UInt16(svData.count)) + svData
    body += be16(UInt16(sv.count)) + sv
    return [0x01] + be24(body.count) + body
}

// MARK: - TLSFindingTests

/// Coverage of the TLS analysis policy and the findings it supports. Every case
/// that can be is driven through the *real* decoder and the *real* `TLSEvidenceTable`
/// fold, so a rule is proven against wire bytes rather than against hand-built facts.
/// No case asserts an SNI, certificate, key or payload string — none of those reach
/// this layer by design.
struct TLSFindingTests {
    // MARK: Internal

    // MARK: Alerts

    @Test
    func fatalAlertIsAWarningFindingCitingEachRecord() throws {
        // level 2 (fatal), description 40 (handshake_failure).
        let snapshot = assess([
            serverFrame(records: [tlsRecordBytes(contentType: 21, body: [0x02, 0x28])], ordinal: 1),
        ])
        let finding = try #require(snapshot.findings.first)
        #expect(snapshot.findings.count == 1)
        #expect(finding.kind == .tlsFatalAlertObserved)
        #expect(finding.severity == .warning)
        #expect(finding.citations.count == 1)
        #expect(finding.citations.map(\.provenance.ordinal.rawValue) == [1])
        #expect(finding.omittedCitationCount == 0)
    }

    @Test
    func closeNotifyAndUserCanceledAreNotFindings() {
        // description 0 (close_notify) and 90 (user_canceled), both at warning level:
        // an orderly shutdown is not an error and must never be flagged.
        let snapshot = assess([
            clientFrame(records: [tlsRecordBytes(contentType: 21, body: [0x01, 0x00])], ordinal: 1),
            serverFrame(records: [tlsRecordBytes(contentType: 21, body: [0x01, 0x5A])], ordinal: 2),
        ])
        #expect(snapshot.findings.isEmpty)
    }

    @Test
    func fatalCloseNotifyStillReportsAsFatal() {
        // A close_notify at the *fatal* level is not the orderly shutdown shape; the
        // level decides, and only the warning-level rule exempts descriptions.
        let snapshot = assess([
            serverFrame(records: [tlsRecordBytes(contentType: 21, body: [0x02, 0x00])], ordinal: 1),
        ])
        #expect(snapshot.findings.map(\.kind) == [.tlsFatalAlertObserved])
    }

    @Test
    func nonShutdownWarningAlertIsANote() throws {
        // level 1, description 112 (unrecognized_name) — a real warning-level alert.
        let snapshot = assess([
            serverFrame(records: [tlsRecordBytes(contentType: 21, body: [0x01, 0x70])], ordinal: 1),
        ])
        let finding = try #require(snapshot.findings.first)
        #expect(finding.kind == .tlsWarningAlertObserved)
        #expect(finding.severity == .note)
    }

    @Test
    func encryptedAlertBodyProducesNoFindingAtAll() {
        // A TLS 1.2-style encrypted alert is still content type 21, but its body is
        // longer than two bytes, so the decoder publishes no alert fact and this
        // layer has nothing to map. Ciphertext must never be read as level/description.
        let body = [UInt8](repeating: 0x5B, count: 26)
        let packet = decode(serverFrame(records: [tlsRecordBytes(contentType: 21, body: body)], ordinal: 1).frame)
        #expect(packet.tlsRecords.count == 1)
        #expect(packet.tlsRecords[0].alert == nil)
        let snapshot = assess([serverFrame(records: [tlsRecordBytes(contentType: 21, body: body)], ordinal: 1)])
        #expect(snapshot.findings.isEmpty)
    }

    @Test
    func truncatedAlertBodyFailsClosed() {
        // A two-byte alert whose second byte was cut off by the capture: the record
        // declares 2 and only 1 was captured, so no fact and no finding.
        var payload = tlsRecordBytes(contentType: 21, body: [0x02, 0x28])
        payload.removeLast()
        let snapshot = assess([serverFrame(records: [payload], ordinal: 1)])
        #expect(snapshot.findings.isEmpty)
    }

    @Test
    func repeatedFatalAlertsCoalesceIntoOneFindingOldestFirst() throws {
        let snapshot = assess([
            serverFrame(records: [tlsRecordBytes(contentType: 21, body: [0x02, 0x28])], ordinal: 3),
            serverFrame(records: [tlsRecordBytes(contentType: 21, body: [0x02, 0x33])], ordinal: 7),
        ])
        let finding = try #require(snapshot.findings.first)
        #expect(snapshot.findings.count == 1)
        #expect(finding.citations.map(\.provenance.ordinal.rawValue) == [3, 7])
    }

    @Test
    func coalescedRecordsInOneFrameCiteTheirOwnRecordIndex() throws {
        // Two alerts coalesced in one frame: the citation names the exact record.
        let snapshot = assess([
            serverFrame(
                records: [
                    tlsRecordBytes(contentType: 23, body: [0xAA]),
                    tlsRecordBytes(contentType: 21, body: [0x02, 0x28]),
                ],
                ordinal: 4
            ),
        ])
        let finding = try #require(snapshot.findings.first)
        #expect(finding.citations.map(\.recordIndex) == [1])
    }

    // MARK: Deprecated selected version

    @Test
    func serverHelloSelectingTLS10IsAWarningFinding() throws {
        let snapshot = assess([
            serverFrame(
                records: [helloRecord(serverHelloHandshake(legacyVersion: 0x0301, extensions: nil))],
                ordinal: 2
            ),
        ])
        let finding = try #require(snapshot.findings.first)
        #expect(finding.kind == .tlsDeprecatedVersionSelectedObserved)
        #expect(finding.severity == .warning)
        #expect(finding.citations.map(\.provenance.ordinal.rawValue) == [2])
    }

    @Test
    func deprecatedVersionsAreExactlyThoseBelowTLS12() {
        // SSL 3.0 and TLS 1.1 map; TLS 1.2 and a supported_versions-selected TLS 1.3
        // do not. One case per version keeps the boundary explicit.
        for legacy in [UInt16(0x0300), 0x0302] {
            let snapshot = assess([
                serverFrame(
                    records: [helloRecord(serverHelloHandshake(legacyVersion: legacy, extensions: nil))],
                    ordinal: 1
                ),
            ])
            #expect(snapshot.findings.map(\.kind) == [.tlsDeprecatedVersionSelectedObserved])
        }
        let current = assess([
            serverFrame(
                records: [helloRecord(serverHelloHandshake(legacyVersion: 0x0303, extensions: nil))],
                ordinal: 1
            ),
        ])
        #expect(current.findings.isEmpty)
        let modern = assess([
            serverFrame(
                records: [helloRecord(serverHelloHandshake(
                    legacyVersion: 0x0303, extensions: serverSupportedVersionsExtension(0x0304)
                ))],
                ordinal: 1
            ),
        ])
        #expect(modern.findings.isEmpty)
    }

    @Test
    func clientOfferOfADeprecatedVersionIsNeverAFinding() {
        // Client *intent* is not an outcome: offering TLS 1.0 says nothing about what
        // was negotiated, so only the server's selection can map.
        let snapshot = assess([
            clientFrame(
                records: [helloRecord(clientHelloHandshake(legacyVersion: 0x0301, offeredVersions: [0x0301, 0x0303]))],
                ordinal: 1
            ),
            serverFrame(
                records: [helloRecord(serverHelloHandshake(legacyVersion: 0x0303, extensions: nil))],
                ordinal: 2
            ),
        ])
        #expect(snapshot.findings.isEmpty)
    }

    @Test
    func helloRetryRequestNeverClaimsADeprecatedVersion() {
        // The decoder publishes no `selectedVersion` for an HRR, so a legacy-0x0301
        // HRR cannot become a version finding — and one HRR is not a finding either.
        let snapshot = assess([
            serverFrame(
                records: [helloRecord(serverHelloHandshake(
                    legacyVersion: 0x0301, random: helloRetryRandom, extensions: nil
                ))],
                ordinal: 1
            ),
        ])
        #expect(snapshot.findings.isEmpty)
    }

    // MARK: HelloRetryRequest

    @Test
    func oneHelloRetryRequestIsNotAFinding() {
        let snapshot = assess([
            clientFrame(records: [helloRecord(clientHelloHandshake())], ordinal: 1),
            serverFrame(records: [hrrRecord()], ordinal: 2),
            clientFrame(records: [helloRecord(clientHelloHandshake())], ordinal: 3),
            serverFrame(
                records: [helloRecord(serverHelloHandshake(
                    legacyVersion: 0x0303, extensions: serverSupportedVersionsExtension(0x0304)
                ))],
                ordinal: 4
            ),
        ])
        #expect(snapshot.findings.isEmpty)
    }

    @Test
    func twoHelloRetryRequestsInOneDirectionCiteBoth() throws {
        let snapshot = assess([
            clientFrame(records: [helloRecord(clientHelloHandshake())], ordinal: 1),
            serverFrame(records: [hrrRecord()], ordinal: 2),
            clientFrame(records: [helloRecord(clientHelloHandshake())], ordinal: 3),
            serverFrame(records: [hrrRecord()], ordinal: 4),
        ])
        let finding = try #require(snapshot.findings.first)
        #expect(snapshot.findings.count == 1)
        #expect(finding.kind == .tlsRepeatedHelloRetryRequestObserved)
        #expect(finding.severity == .warning)
        #expect(finding.citations.map(\.provenance.ordinal.rawValue) == [2, 4])
    }

    @Test
    func retryRequestsFromOppositeDirectionsDoNotCombine() {
        // One HRR each way is one per handshake direction — never "more than one".
        let snapshot = assess([
            serverFrame(records: [hrrRecord()], ordinal: 1),
            clientFrame(records: [hrrRecord()], ordinal: 2),
        ])
        #expect(snapshot.findings.isEmpty)
    }

    // MARK: Unanswered ClientHello

    @Test
    func clientHelloWithNoReplyIsAWarningFindingCitingTheHello() throws {
        let snapshot = assess([
            clientFrame(records: [helloRecord(clientHelloHandshake())], ordinal: 5),
        ])
        let finding = try #require(snapshot.findings.first)
        #expect(finding.kind == .tlsHandshakeUnansweredObserved)
        #expect(finding.severity == .warning)
        #expect(finding.citations.map(\.provenance.ordinal.rawValue) == [5])
    }

    @Test
    func anyServerHelloCountsAsAReply() {
        for reply in [helloRecord(serverHelloHandshake(legacyVersion: 0x0303, extensions: nil)), hrrRecord()] {
            let snapshot = assess([
                clientFrame(records: [helloRecord(clientHelloHandshake())], ordinal: 1),
                serverFrame(records: [reply], ordinal: 2),
            ])
            #expect(!snapshot.findings.contains { $0.kind == .tlsHandshakeUnansweredObserved })
        }
    }

    @Test
    func anAlertCountsAsAReplySoOnlyTheAlertIsReported() {
        // The hello *was* answered — with a refusal. Reporting "unanswered" as well
        // would make one exchange read as two problems.
        let snapshot = assess([
            clientFrame(records: [helloRecord(clientHelloHandshake())], ordinal: 1),
            serverFrame(records: [tlsRecordBytes(contentType: 21, body: [0x02, 0x28])], ordinal: 2),
        ])
        #expect(snapshot.findings.map(\.kind) == [.tlsFatalAlertObserved])
    }

    @Test
    func unansweredFailsClosedWhenTheFlowOmittedARecord() {
        // A tiny per-summary bound drops the reply; the rule must then stay silent,
        // because the missing hello could be exactly the record that was dropped.
        var table = TLSEvidenceTable(configuration: .init(maxObservationsPerSummary: 1))
        offer(clientFrame(records: [helloRecord(clientHelloHandshake())], ordinal: 1), into: &table)
        offer(
            serverFrame(
                records: [helloRecord(serverHelloHandshake(legacyVersion: 0x0303, extensions: nil))],
                ordinal: 2
            ),
            into: &table
        )
        let snapshot = TLSAssessor().assess(table.snapshot())
        #expect(snapshot.findings.isEmpty)
        #expect(snapshot.inputOmittedObservationCount == 1)
    }

    @Test
    func unansweredFailsClosedUnderSnapLengthTruncation() {
        // A hello observed in a frame captured shorter than the wire: the reply could
        // be in what was cut, so no absence claim.
        var table = TLSEvidenceTable()
        let hello = clientFrame(records: [helloRecord(clientHelloHandshake())], ordinal: 1)
        table.offer(
            decode(hello.frame),
            application: nil,
            provenance: SessionFrameProvenance(
                ordinal: FrameOrdinal(1),
                timestamp: instant(1),
                capturedLength: 64,
                originalLength: 512,
                linkType: LinkType.ethernet
            )
        )
        let snapshot = TLSAssessor().assess(table.snapshot())
        #expect(snapshot.findings.isEmpty)
    }

    @Test
    func unansweredFailsClosedWhenCaptureLossWasReported() {
        var table = TLSEvidenceTable()
        offer(
            clientFrame(records: [helloRecord(clientHelloHandshake())], ordinal: 1),
            into: &table,
            loss: .lossReported
        )
        let snapshot = TLSAssessor().assess(table.snapshot())
        #expect(snapshot.findings.isEmpty)
    }

    @Test
    func unansweredCitesEveryRetainedHello() throws {
        let snapshot = assess([
            clientFrame(records: [helloRecord(clientHelloHandshake())], ordinal: 1),
            clientFrame(records: [helloRecord(clientHelloHandshake())], ordinal: 6),
        ])
        let finding = try #require(snapshot.findings.first)
        #expect(finding.kind == .tlsHandshakeUnansweredObserved)
        #expect(finding.citations.map(\.provenance.ordinal.rawValue) == [1, 6])
    }

    // MARK: Identity, ordering, bounds, purity

    @Test
    func findingIdentityIsStableAcrossAssessments() throws {
        let frames = [serverFrame(records: [tlsRecordBytes(contentType: 21, body: [0x02, 0x28])], ordinal: 1)]
        let first = try #require(assess(frames).findings.first)
        let second = try #require(assess(frames).findings.first)
        #expect(first.id == second.id)
        #expect(first == second)
        // The id is seeded from session + kind only, so it does not depend on which
        // frames happened to be cited.
        let extended = try #require(assess(frames + [
            serverFrame(records: [tlsRecordBytes(contentType: 21, body: [0x02, 0x33])], ordinal: 9),
        ]).findings.first)
        #expect(extended.id == first.id)
    }

    @Test
    func kindRanksAreDistinctAndOrderFindingsSharingAFrame() {
        let kinds: [TLSAnalysisFindingKind] = [
            .tlsFatalAlertObserved,
            .tlsWarningAlertObserved,
            .tlsDeprecatedVersionSelectedObserved,
            .tlsRepeatedHelloRetryRequestObserved,
            .tlsHandshakeUnansweredObserved,
        ]
        #expect(Set(kinds.map(\.rank)).count == kinds.count)
        #expect(Set(kinds.map(\.stableDiscriminator)).count == kinds.count)
    }

    @Test
    func citationsAreCappedWithAnExactOmissionCount() throws {
        let frames = (1 ... 5).map { ordinal in
            serverFrame(records: [tlsRecordBytes(contentType: 21, body: [0x02, 0x28])], ordinal: UInt64(ordinal))
        }
        var table = TLSEvidenceTable()
        for frame in frames {
            offer(frame, into: &table)
        }
        let snapshot = TLSAssessor(configuration: .init(maxCitationsPerFinding: 2)).assess(table.snapshot())
        let finding = try #require(snapshot.findings.first)
        #expect(finding.citations.map(\.provenance.ordinal.rawValue) == [1, 2])
        #expect(finding.omittedCitationCount == 3)
    }

    @Test
    func coveragePropagatesTheFlowsLossKnowledge() throws {
        var table = TLSEvidenceTable()
        offer(
            serverFrame(records: [tlsRecordBytes(contentType: 21, body: [0x02, 0x28])], ordinal: 1),
            into: &table,
            loss: .noLossReported
        )
        let finding = try #require(TLSAssessor().assess(table.snapshot()).findings.first)
        #expect(finding.coverage == .boundedNoKnownOmission)
    }

    @Test
    func emptyEvidenceYieldsTheCanonicalEmptyAnalysis() {
        #expect(TLSAssessor().assess(.empty) == .empty)
    }

    @Test
    func twoFlowsEachKeepTheirOwnFinding() {
        let snapshot = assess([
            serverFrame(records: [tlsRecordBytes(contentType: 21, body: [0x02, 0x28])], ordinal: 1),
            serverFrame(
                records: [tlsRecordBytes(contentType: 21, body: [0x02, 0x28])],
                ordinal: 2,
                clientPort: 44_001
            ),
        ])
        #expect(snapshot.findings.count == 2)
        #expect(Set(snapshot.findings.map(\.sessionID)).count == 2)
        #expect(snapshot.findings.allSatisfy { $0.kind == .tlsFatalAlertObserved })
    }

    @Test
    func nonMappedRecordTypesProduceNothing() {
        // ChangeCipherSpec, Application Data and Heartbeat are ordinary traffic.
        let snapshot = assess([
            clientFrame(records: [tlsRecordBytes(contentType: 20, body: [0x01])], ordinal: 1),
            clientFrame(records: [tlsRecordBytes(contentType: 23, body: [0xAA, 0xBB])], ordinal: 2),
            serverFrame(records: [tlsRecordBytes(contentType: 24, body: [0x01, 0x00, 0x00])], ordinal: 3),
        ])
        #expect(snapshot.findings.isEmpty)
    }

    // MARK: Query projection

    @Test
    func everyFindingKindHasAParserSpelling() {
        let expected: Set<QueryFindingKind> = [
            .tlsFatalAlert, .tlsWarningAlert, .tlsDeprecatedVersion,
            .tlsRepeatedRetryRequest, .tlsHandshakeUnanswered,
        ]
        let named = Set(SessionQueryParser.findingNames.values)
        #expect(expected.isSubset(of: named))
        for name in [
            "tlsFatalAlert",
            "tlsWarningAlert",
            "tlsDeprecatedVersion",
            "tlsRepeatedRetryRequest",
            "tlsHandshakeUnanswered"
        ] {
            #expect(SessionQueryParser.findingNames[name] != nil, "missing spelling \(name)")
        }
    }

    @Test
    func aTLSFindingMatchesItsSessionThroughTheQueryEngine() throws {
        // End to end through the published snapshot: the finding's session id is the
        // one the capture's session projection actually carries.
        let frames = [
            clientFrame(records: [helloRecord(clientHelloHandshake())], ordinal: 1),
            serverFrame(records: [tlsRecordBytes(contentType: 21, body: [0x02, 0x28])], ordinal: 2),
        ]
        var table = TLSEvidenceTable()
        for frame in frames {
            offer(frame, into: &table)
        }
        let evidence = table.snapshot()
        let finding = try #require(TLSAssessor().assess(evidence).findings.first)
        let tuple = try #require(decode(frames[0].frame).fiveTuple)
        #expect(finding.sessionID == SessionBuilder.sessionID(for: tuple))
    }

    // MARK: Private

    /// One synthetic frame plus the ordinal its provenance should carry.
    private struct Frame {
        let frame: [UInt8]
        let ordinal: UInt64
    }

    private let client = "192.0.2.10"
    private let server = "203.0.113.5"

    private func instant(_ ordinal: UInt64) -> Date {
        Date(timeIntervalSince1970: 1_700_000_000 + Double(ordinal))
    }

    private func decode(_ bytes: [UInt8]) -> DecodedPacket {
        PacketDecoder.decode(
            PacketBuffer(bytes), linkType: LinkType.ethernet,
            timestamp: instant(0), originalLength: bytes.count
        )
    }

    /// Wraps a handshake message in a Handshake (22) record.
    private func helloRecord(_ handshake: [UInt8]) -> [UInt8] {
        tlsRecordBytes(contentType: 22, body: handshake)
    }

    private func hrrRecord() -> [UInt8] {
        helloRecord(serverHelloHandshake(
            legacyVersion: 0x0303, random: helloRetryRandom,
            extensions: serverSupportedVersionsExtension(0x0304)
        ))
    }

    private func clientFrame(records: [[UInt8]], ordinal: UInt64, clientPort: UInt16 = 44_000) -> Frame {
        Frame(
            frame: PacketBuilder.ethernetIPv4(
                proto: 6, src: client, dst: server,
                payload: PacketBuilder.tcp(
                    srcPort: clientPort, dstPort: 443, flags: 0x18, payload: records.flatMap { $0 }
                )
            ),
            ordinal: ordinal
        )
    }

    private func serverFrame(records: [[UInt8]], ordinal: UInt64, clientPort: UInt16 = 44_000) -> Frame {
        Frame(
            frame: PacketBuilder.ethernetIPv4(
                proto: 6, src: server, dst: client,
                payload: PacketBuilder.tcp(
                    srcPort: 443, dstPort: clientPort, flags: 0x18, payload: records.flatMap { $0 }
                )
            ),
            ordinal: ordinal
        )
    }

    private func offer(_ frame: Frame, into table: inout TLSEvidenceTable, loss: CaptureLossKnowledge = .unknown) {
        table.offer(
            decode(frame.frame),
            application: nil,
            provenance: SessionFrameProvenance(
                ordinal: FrameOrdinal(frame.ordinal),
                timestamp: instant(frame.ordinal),
                capturedLength: frame.frame.count,
                originalLength: frame.frame.count,
                linkType: LinkType.ethernet
            ),
            loss: loss
        )
    }

    /// Fold the frames through the real evidence table and assess the result.
    private func assess(_ frames: [Frame]) -> TLSAnalysisSnapshot {
        var table = TLSEvidenceTable()
        for frame in frames {
            offer(frame, into: &table)
        }
        return TLSAssessor().assess(table.snapshot())
    }
}
