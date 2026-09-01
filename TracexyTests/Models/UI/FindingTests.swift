import Foundation
import Testing
@testable import Tracexy

@Suite("Typed finding presentation")
struct FindingTests {
    @Test("Datagram projection preserves identity, evidence accounting and neutral TC copy")
    func datagramProjectionIsExact() {
        let tuple = FiveTuple(
            proto: .udp,
            source: IPEndpoint(ip: "192.0.2.10", port: 53_000),
            destination: IPEndpoint(ip: "198.51.100.53", port: 53)
        )
        let sessionID = SessionBuilder.sessionID(for: tuple)
        let provenance = SessionFrameProvenance(
            ordinal: FrameOrdinal(7),
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            capturedLength: 72,
            originalLength: 72,
            linkType: LinkType.ethernet
        )
        let core = DatagramAnalysisFinding(
            id: SessionBuilder.stableID("finding-test"),
            kind: .dnsTruncationIndicated,
            severity: .note,
            sessionID: sessionID,
            tuple: tuple,
            coverage: .omittedEvidence,
            citations: [DatagramAnalysisCitation(
                sessionID: sessionID,
                direction: .aToB,
                provenance: provenance
            )],
            omittedCitationCount: 2
        )

        let finding = Finding(core, host: "resolver.example")

        #expect(finding.id == core.id)
        #expect(finding.sessionID == sessionID)
        #expect(finding.severity == .note)
        #expect(finding.title == "DNS truncation indicated")
        #expect(finding.coverage == .omittedEvidence)
        #expect(finding.citedObservationCount == 1)
        #expect(finding.omittedCitationCount == 2)
        #expect(finding.citedFrames == [provenance])
        #expect(finding
            .subtitle ==
            "TC bit observed · resolver.example · 1 cited observation · 2 omitted · bounded evidence omitted")
        #expect(!finding.subtitle.localizedCaseInsensitiveContains("failed"))
        #expect(!finding.subtitle.localizedCaseInsensitiveContains("attack"))
    }
}
