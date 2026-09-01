import Foundation
import Testing
@testable import Tracexy

// MARK: - SessionEvidencePresentationTests

@Suite("Session evidence presentation")
struct SessionEvidencePresentationTests {
    // MARK: Internal

    @Test("Connection incarnations and shared TLS records share one stable frame timeline")
    func timelinePreservesIncarnationsAndSharedTLS() {
        let firstID = ConnectionID(tuple: tuple, firstOrdinal: FrameOrdinal(1))
        let secondID = ConnectionID(tuple: tuple, firstOrdinal: FrameOrdinal(8))
        let first = summary(
            id: firstID,
            firstOrdinal: 1,
            event: event(firstID, .rst, ordinal: 5, direction: .aToB)
        )
        let second = summary(
            id: secondID,
            firstOrdinal: 8,
            event: event(secondID, .syn, ordinal: 8, direction: .bToA)
        )
        let tls = TLSEvidenceSummary(
            sessionID: SessionBuilder.sessionID(for: tuple),
            tuple: tuple,
            observations: [TLSEvidenceObservation(
                sessionID: SessionBuilder.sessionID(for: tuple),
                tuple: tuple,
                direction: .aToB,
                provenance: provenance(6),
                recordIndex: 0,
                fact: TLSRecordFact(
                    contentType: 23,
                    legacyRecordVersion: 0x0303,
                    declaredBodyLength: 12,
                    capturedBodyLength: 12,
                    handshake: nil
                )
            )],
            omittedObservationCount: 0,
            excludedReassembledRecordCount: 0,
            recoveredTruncationIndicatorCount: 0,
            decoderTruncatedFrameCount: 0,
            lossKnowledge: .unknown,
            snapLengthTruncationObserved: false
        )

        let items = SessionEvidenceItem.timeline(connections: [first, second], tls: tls)

        #expect(items.map(\.ordinal.rawValue) == [5, 6, 8])
        #expect(items.map(\.kind) == [.connection, .tls, .connection])
        #expect(items[0].detail.contains("connection 1 of 2"))
        #expect(items[2].detail.contains("connection 2 of 2"))
        #expect(items[1].title == "TLS Application Data record")
        #expect(items[1].provenance == [provenance(6)])
    }

    @Test("TLS copy distinguishes selected version from legacy framing")
    func tlsSelectedVersionCopyIsExplicit() {
        let fact = TLSRecordFact(
            contentType: 22,
            legacyRecordVersion: 0x0303,
            declaredBodyLength: 90,
            capturedBodyLength: 90,
            handshake: .serverHello(TLSServerHelloFact(
                legacyVersion: 0x0303,
                selectedCipher: 0x1301,
                isHelloRetryRequest: false,
                extensionsComplete: true,
                selectedVersion: 0x0304
            ))
        )
        let observation = TLSEvidenceObservation(
            sessionID: SessionBuilder.sessionID(for: tuple),
            tuple: tuple,
            direction: .bToA,
            provenance: provenance(11),
            recordIndex: 0,
            fact: fact
        )

        let detail = SessionEvidenceCopy.tlsRecordDetail(observation)

        #expect(detail.contains("legacy record version TLS 1.2 (0x0303)"))
        #expect(detail.contains("selected TLS 1.3 (0x0304)"))
        #expect(detail.contains("cipher 0x1301"))
    }

    @Test("Coverage copy keeps unknown, omission, and overflow caveats neutral")
    func coverageCopyIsNeutral() {
        let labels = SessionEvidenceCopy.limitationLabels([
            .eventHistoryTruncated,
            .sequenceGapObserved,
            .counterOverflow,
        ])

        #expect(SessionEvidenceCopy.lossLabel(.unknown) == "Capture loss unknown")
        #expect(labels.contains("Older connection events were omitted"))
        #expect(labels.contains("A sequence-space gap was observed"))
        #expect(labels.contains("A connection counter saturated"))
        #expect(!labels.joined(separator: " ").localizedCaseInsensitiveContains("cause"))
    }

    // MARK: Private

    private var tuple: FiveTuple {
        FiveTuple(
            proto: .tcp,
            source: IPEndpoint(ip: "192.0.2.10", port: 52_000),
            destination: IPEndpoint(ip: "198.51.100.20", port: 443)
        )
    }

    private func provenance(_ ordinal: UInt64) -> SessionFrameProvenance {
        SessionFrameProvenance(
            ordinal: FrameOrdinal(ordinal),
            timestamp: Date(timeIntervalSince1970: Double(ordinal)),
            capturedLength: 96,
            originalLength: 96,
            linkType: LinkType.ethernet,
            locator: SessionEvidenceLocator(sourceToken: UUID(intValue: 9), offset: ordinal * 128)
        )
    }

    private func event(
        _ id: ConnectionID,
        _ kind: ConnectionEventKind,
        ordinal: UInt64,
        direction: ConnectionDirection
    )
        -> ConnectionEvent
    {
        ConnectionEvent(
            connectionID: id,
            kind: kind,
            timestamp: Date(timeIntervalSince1970: Double(ordinal)),
            provenance: provenance(ordinal),
            direction: direction
        )
    }

    private func summary(
        id: ConnectionID,
        firstOrdinal: UInt64,
        event: ConnectionEvent
    )
        -> ConnectionSummary
    {
        ConnectionSummary(
            id: id,
            tuple: tuple,
            firstProvenance: provenance(firstOrdinal),
            lastProvenance: event.provenance[0],
            initiator: nil,
            phase: .closed,
            handshake: .none,
            finDirections: [],
            closeReason: nil,
            packetCount: 1,
            capturedByteTotal: 96,
            originalByteTotal: 96,
            lossKnowledge: .unknown,
            limitations: [],
            events: [event],
            omittedEventCount: 0
        )
    }
}

private extension UUID {
    init(intValue: UInt64) {
        var bytes = [UInt8](repeating: 0, count: 16)
        withUnsafeBytes(of: intValue.bigEndian) { raw in
            bytes.replaceSubrange(8 ..< 16, with: raw)
        }
        self = bytes.withUnsafeBytes { UUID(uuid: $0.load(as: uuid_t.self)) }
    }
}
