import Foundation
import Testing
@testable import Tracexy

@Suite("Follow conversation presentation")
struct FollowConversationPresentationTests {
    // MARK: Internal

    @Test("Find is case-insensitive, ordered and bounded")
    func searchMatches() {
        let text = "Host: Example.test\nhost: example.TEST"
        let ranges = FollowTranscriptSearch.matches(of: "example.test", in: text)
        #expect(ranges.count == 2)
        #expect(ranges.map { String(text[$0]) } == ["Example.test", "example.TEST"])
        #expect(FollowTranscriptSearch.matches(of: "  ", in: text).isEmpty)
        let long = String(repeating: "a", count: FollowTranscriptSearch.maximumMatches + 50)
        #expect(FollowTranscriptSearch.matches(of: "a", in: long).count == FollowTranscriptSearch.maximumMatches)
    }

    @Test("Highlighting never changes the characters shown")
    func highlightKeepsText() {
        let text = "GET /index.html HTTP/1.1"
        let highlighted = FollowTranscriptSearch.highlighted(text, query: "html")
        #expect(String(highlighted.characters) == text)
        #expect(highlighted.runs.count == 3)
        #expect(FollowTranscriptSearch.highlighted(text, query: "").runs.count == 1)
    }

    @Test("DNS rows read the question, the outcome and the pairing")
    func dnsRows() throws {
        let result = try Self.datagramResult()
        let presentation = FollowDatagramPresentation(result: result, mode: .text)
        #expect(presentation.rows.count == 3)

        let query = presentation.rows[0]
        #expect(query.route == "10.0.0.5:50000 → 203.0.113.9:53")
        #expect(query.dnsHeadline == "Query A www.example.test")
        #expect(query.pairing == "Answered in frame 2")
        #expect(query.payload.isEmpty)
        #expect(query.timeLabel == "+0.000 s")

        let response = presentation.rows[1]
        #expect(response.dnsHeadline == "Response NOERROR for A www.example.test")
        #expect(response.dnsAnswers == ["A 192.0.2.80"])
        #expect(response.pairing == "Answers frame 1 after 24.0 ms")

        let unanswered = presentation.rows[2]
        #expect(unanswered.pairing == "No response was observed")
    }

    @Test("Hex mode shows DNS bytes too, under the display bound")
    func hexShowsBytes() throws {
        let result = try Self.datagramResult()
        let presentation = FollowDatagramPresentation(result: result, mode: .hex, maxDisplayBytes: 40)
        #expect(presentation.rows[0].payload.hasPrefix("0000"))
        #expect(presentation.viewOmittedByteCount > 0)
        #expect(presentation.rows.contains { $0.hiddenByteCount > 0 })
    }

    @Test("Response codes use their standard names")
    func responseCodes() {
        #expect(FollowDatagramPresentation.responseCodeName(3) == "NXDOMAIN")
        #expect(FollowDatagramPresentation.responseCodeName(2) == "SERVFAIL")
        #expect(FollowDatagramPresentation.responseCodeName(9) == "RCODE 9")
    }

    @Test("Stream runs carry their first frame for navigation")
    func runSectionsCarryProvenance() {
        let provenance = SessionFrameProvenance(
            ordinal: FrameOrdinal(4), timestamp: nil, capturedLength: 60, originalLength: 60, linkType: 1,
            locator: SessionEvidenceLocator(sourceToken: UUID(), offset: 128)
        )
        let snapshot = FollowStreamDirectionSnapshot(
            anchorSequence: 100,
            runs: [
                FollowStreamRun(
                    sequenceAnchor: 100,
                    firstCaptureOrdinal: 4,
                    bytes: [65, 66],
                    firstProvenance: provenance
                ),
                FollowStreamRun(sequenceAnchor: 200, firstCaptureOrdinal: 6, bytes: [67]),
            ],
            retainedByteCount: 3,
            observedOmittedByteCount: 0,
            matchedFrameCount: 2
        )
        let sections = FollowStreamDirectionPresentation(snapshot: snapshot, mode: .text).runSections
        #expect(sections.map(\.text) == ["AB", "C"])
        #expect(sections.map(\.followsGap) == [false, true])
        #expect(sections.map(\.gapByteCount) == [nil, 98])
        #expect(sections[0].firstProvenance == provenance)
        #expect(sections[1].firstProvenance == nil)
    }

    @Test("Certificate absences are explained only in words that match the reason")
    func certificateAbsences() {
        #expect(TLSCertificateExtraction.encryptedBeforeCertificate.absenceExplanation?.contains("TLS 1.3") == true)
        #expect(TLSCertificateExtraction.certificates([], unparsedCount: 1, omittedCount: 0)
            .absenceExplanation?.contains("could not be read") == true)
        #expect(TLSCertificateExtraction.notTLS.absenceExplanation != nil)
    }

    // MARK: Private

    private static func datagramResult() throws -> FollowDatagramResult {
        let base = Date(timeIntervalSince1970: 1_800_000_000)
        struct Frame {
            let client: Bool
            let id: UInt16
            let flags: UInt16
            let answers: [String]
            let offset: TimeInterval
        }
        let frames = [
            Frame(client: true, id: 0x0A0A, flags: 0x0100, answers: [], offset: 0),
            Frame(client: false, id: 0x0A0A, flags: 0x8180, answers: ["192.0.2.80"], offset: 0.024),
            Frame(client: true, id: 0x0B0B, flags: 0x0100, answers: [], offset: 0.5),
        ]
        let tuple = FiveTuple(
            proto: .udp,
            source: IPEndpoint(ip: "10.0.0.5", port: 50_000),
            destination: IPEndpoint(ip: "203.0.113.9", port: 53)
        )
        let messages = frames.enumerated().map { index, frame in
            let client = frame.client
            let id = frame.id
            let answers = frame.answers
            let offset = frame.offset
            let flags = frame.flags
            let payload = FollowDatagramReaderTests.dnsMessage(
                id: id, flags: flags, name: "www.example.test", answers: answers
            )
            return FollowDatagramMessage(
                direction: client ? .aToB : .bToA,
                provenance: SessionFrameProvenance(
                    ordinal: FrameOrdinal(UInt64(index + 1)),
                    timestamp: base.addingTimeInterval(offset),
                    capturedLength: 80, originalLength: 80, linkType: 1
                ),
                payload: payload,
                capturedPayloadLength: payload.count,
                declaredPayloadLength: payload.count,
                dns: FollowDNSMessage(
                    transactionID: id, isResponse: !client, opcode: 0, responseCode: 0, isTruncated: false,
                    questionName: "www.example.test", questionType: 1,
                    answerRecords: answers.map { "A \($0)" }, omittedAnswerCount: 0
                )
            )
        }
        return FollowDatagramResult(
            identity: PcapFileIdentity(size: 1, modifiedAt: nil, device: 1, inode: 1),
            format: .pcap,
            tuple: tuple,
            messages: FollowDatagramReader.pairDNS(messages),
            omittedMessageCount: 0,
            omittedPayloadByteCount: 0,
            matchedFrameCount: 3,
            scannedFrameCount: 3,
            limitations: [],
            completeness: .complete,
            finalProgress: PcapStreamProgress(bytesConsumed: 1, totalBytes: 1)
        )
    }
}
