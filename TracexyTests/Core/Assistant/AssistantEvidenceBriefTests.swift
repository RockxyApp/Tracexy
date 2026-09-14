import Foundation
import Testing
@testable import Tracexy

// MARK: - AssistantEvidenceBriefTests

@Suite("Assistant brief: forbidden keys, disclosure gating, bounds, coverage and citation stability")
struct AssistantEvidenceBriefTests {
    // MARK: Internal

    /// Every key name that must never appear anywhere in a serialized brief, at
    /// any disclosure setting. The scan is structural — it walks the decoded JSON
    /// rather than searching text — so a nested field cannot slip through.
    static let forbiddenKeys: Set<String> = [
        "bytes",
        "capturedBytes",
        "certificate",
        "credentials",
        "databasePath",
        "decodedLayers",
        "dnsAnswers",
        "dnsQuery",
        "file",
        "filePath",
        "locator",
        "offset",
        "packetBytes",
        "password",
        "path",
        "payload",
        "representativeBytes",
        "sni",
        "sourceToken",
        "token",
        "url",
    ]

    @Test("No forbidden key appears at any disclosure setting")
    func structuralForbiddenKeyScan() throws {
        for disclosure in Self.allDisclosures {
            let build = try AssistantBriefBuilder.build(
                snapshot: AssistantDemoFixture.snapshot(),
                sessionID: AssistantDemoFixture.sessionID,
                projectID: AssistantDemoFixture.projectID,
                disclosure: disclosure
            )
            let json = try build.brief.canonicalJSON()
            let object = try #require(
                try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
            )
            let keys = Self.allKeys(in: object)
            let leaked = keys.intersection(Self.forbiddenKeys)
            #expect(leaked.isEmpty, "Leaked keys: \(leaked.sorted())")

            // The evidence locator's own values must not appear as *values* either.
            #expect(!json.contains("1A2B3C4D-5E6F-4A8B-9C0D-1E2F3A4B5C6D"))
        }
    }

    @Test("Sensitive families are absent by construction under minimum disclosure")
    func minimumDisclosureOmitsSensitiveFamilies() throws {
        let build = try Self.build(disclosure: .minimum)
        let object = try Self.sessionObject(build)
        #expect(object["host"] == nil)
        #expect(object["processName"] == nil)
        #expect(object["sourceEndpoint"] == nil)
        #expect(object["destinationEndpoint"] == nil)
        // Timing is disclosed, so it is present — with explicit nulls when unknown.
        #expect(object["startTime"] != nil)
        #expect(object["duration"] != nil)
    }

    @Test("Each disclosure family gates exactly its own fields")
    func disclosureFamiliesAreIndependent() throws {
        let process = try Self.sessionObject(Self.build(disclosure: .init(includesProcess: true)))
        #expect(process["processName"] as? String == "ExampleClient")
        #expect(process["host"] == nil)
        #expect(process["sourceEndpoint"] == nil)

        let host = try Self.sessionObject(Self.build(disclosure: .init(includesHost: true)))
        #expect(host["host"] as? String == "service.example.com")
        #expect(host["processName"] == nil)

        let endpoints = try Self.sessionObject(Self.build(disclosure: .init(includesEndpoints: true)))
        #expect(endpoints["sourceEndpoint"] as? String == "192.0.2.10:51314")
        #expect(endpoints["destinationEndpoint"] as? String == "203.0.113.42:443")
        #expect(endpoints["host"] == nil)
    }

    @Test("Dedicated SNI and DNS evidence fields are never carried, even with display host disclosed")
    func dedicatedNameEvidenceIsNeverCarried() throws {
        let build = try Self.build(disclosure: .init(
            includesProcess: true,
            includesHost: true,
            includesEndpoints: true
        ))
        let json = try build.brief.canonicalJSON()
        // The fixture session carries SNI and DNS evidence. Only the explicitly
        // disclosed display host may use a derived name; dedicated evidence does not appear.
        #expect(json.contains("service.example.com"))
        #expect(!json.contains("dnsQuery"))
        #expect(!json.contains("\"sni\""))
        #expect(!json.contains("203.0.113.42\","))
    }

    @Test("The redaction statement names what is on and what can never be on")
    func redactionStatementIsComplete() throws {
        let build = try Self.build(disclosure: .init(includesHost: true))
        #expect(build.brief.redaction.includesHost)
        #expect(!build.brief.redaction.includesProcess)
        #expect(build.brief.redaction.neverIncluded == AssistantRedaction.neverIncludedFamilies)
        #expect(build.brief.redaction.neverIncluded.contains("packetBytes"))
        #expect(build.brief.redaction.neverIncluded.contains("evidenceLocators"))
    }

    @Test("Citation ids are deterministic for a stable snapshot and shared across findings")
    func citationIdentityIsStable() throws {
        let first = try Self.build(disclosure: .minimum)
        let second = try Self.build(disclosure: .minimum)
        #expect(try first.brief.canonicalJSON() == (second.brief.canonicalJSON()))
        #expect(first.brief.citations.map(\.id) == second.brief.citations.map(\.id))
        #expect(first.brief.citations.map(\.id) == ["frame-10", "frame-11", "frame-12"])

        // Every citation id a finding references is present in the citation list.
        let known = Set(first.brief.citations.map(\.id))
        for finding in first.brief.findings {
            for id in finding.citationIDs {
                #expect(known.contains(id))
            }
        }
        // And every id resolves to real provenance, for navigation.
        for id in known {
            #expect(first.provenanceByCitationID[id] != nil)
        }
    }

    @Test("A citation carries frame facts but never its locator")
    func citationsCarryNoLocator() throws {
        let build = try Self.build(disclosure: .minimum)
        let citation = try #require(build.brief.citations.first)
        #expect(citation.frameOrdinal == 10)
        #expect(citation.capturedLength == 128)
        #expect(citation.originalLength == 1_514)
        #expect(citation.hasLocalFrame)

        // A frame with no locator is explicitly not navigable, not silently
        // presented as if it were.
        let bare = AssistantCitation(AssistantDemoFixture.provenance(ordinal: 99, hasLocator: false))
        #expect(!bare.hasLocalFrame)
        #expect(bare.id == "frame-99")
    }

    @Test("Capture-level and brief-level coverage are both reported and never conflated")
    func coverageIsPropagated() throws {
        let build = try Self.build(disclosure: .minimum)
        let coverage = build.brief.coverage
        #expect(coverage.connectionOmittedSummaryCount == 7)
        #expect(coverage.connectionPublishedSummaryCount == 1)
        #expect(coverage.briefOmittedConnectionCount == 0)
        #expect(coverage.briefOmittedFindingCount == 0)
        #expect(coverage.briefOmittedCitationCount == 0)
    }

    @Test("A single finding's citations are bounded, and the drop is counted rather than hidden")
    func perFindingCitationsAreBounded() throws {
        let ordinals = (0 ..< (AssistantBriefLimits.maxCitationsPerFinding + 6)).map { UInt64($0 + 100) }
        let build = try AssistantBriefBuilder.build(
            snapshot: AssistantDemoFixture.snapshot(eventOrdinals: [10] + ordinals),
            sessionID: AssistantDemoFixture.sessionID,
            projectID: AssistantDemoFixture.projectID,
            disclosure: .minimum
        )
        let retransmission = try #require(build.brief.findings.first { $0.kind == "retransmissionObserved" })
        #expect(retransmission.citationIDs.count == AssistantBriefLimits.maxCitationsPerFinding)
        #expect(retransmission.briefOmittedCitationCount == 6)
    }

    @Test("Findings and citations are globally bounded, and both drops are counted")
    func globalBoundsAreEnforced() throws {
        let build = try AssistantBriefBuilder.build(
            snapshot: AssistantDemoFixture.crowdedSnapshot(
                connectionCount: AssistantBriefLimits.maxFindings + 8,
                eventsPerConnection: AssistantBriefLimits.maxCitationsPerFinding
            ),
            sessionID: AssistantDemoFixture.sessionID,
            projectID: AssistantDemoFixture.projectID,
            disclosure: .minimum
        )
        #expect(build.brief.findings.count == AssistantBriefLimits.maxFindings)
        #expect(build.brief.coverage.briefOmittedFindingCount == 8)
        #expect(build.brief.citations.count == AssistantBriefLimits.maxCitations)
        #expect(build.brief.coverage.briefOmittedCitationCount > 0)
        #expect(build.brief.connections.count == AssistantBriefLimits.maxConnections)
        #expect(build.brief.coverage.briefOmittedConnectionCount == 12)

        // Every retained citation id still resolves, and the brief still fits.
        for finding in build.brief.findings {
            for id in finding.citationIDs {
                #expect(build.provenanceByCitationID[id] != nil)
            }
        }
        let json = try build.brief.canonicalJSON()
        #expect(json.utf8.count <= AssistantBriefLimits.maxSerializedBytes)
    }

    @Test("Findings carry the assessor's own severity, coverage and omission counts")
    func findingsMirrorTheAssessor() throws {
        let build = try Self.build(disclosure: .minimum)
        let kinds = build.brief.findings.map(\.kind).sorted()
        #expect(kinds == ["resetObserved", "retransmissionObserved"])
        let reset = try #require(build.brief.findings.first { $0.kind == "resetObserved" })
        #expect(reset.severity == "warning")
        #expect(reset.coverage == "omittedEvidence")
        #expect(!reset.citationIDs.isEmpty)
    }

    @Test("A session the snapshot does not contain is a typed failure, never an empty brief")
    func unknownSessionIsATypedFailure() {
        #expect(throws: AssistantBriefError.sessionNotFound) {
            try AssistantBriefBuilder.build(
                snapshot: AssistantDemoFixture.snapshot(),
                sessionID: UUID(),
                projectID: AssistantDemoFixture.projectID,
                disclosure: .minimum
            )
        }
    }

    // MARK: Private

    private static var allDisclosures: [AutomationDisclosure] {
        [
            .minimum,
            .init(includesProcess: true),
            .init(includesHost: true),
            .init(includesEndpoints: true),
            .init(includesProcess: true, includesHost: true, includesEndpoints: true),
        ]
    }

    private static func build(disclosure: AutomationDisclosure) throws -> AssistantBriefBuild {
        try AssistantBriefBuilder.build(
            snapshot: AssistantDemoFixture.snapshot(),
            sessionID: AssistantDemoFixture.sessionID,
            projectID: AssistantDemoFixture.projectID,
            disclosure: disclosure
        )
    }

    private static func sessionObject(_ build: AssistantBriefBuild) throws -> [String: Any] {
        let json = try build.brief.canonicalJSON()
        let object = try #require(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        return try #require(object["session"] as? [String: Any])
    }

    /// Every key name anywhere in the decoded structure.
    private static func allKeys(in value: Any) -> Set<String> {
        if let dictionary = value as? [String: Any] {
            var keys = Set(dictionary.keys)
            for nested in dictionary.values {
                keys.formUnion(allKeys(in: nested))
            }
            return keys
        }
        if let array = value as? [Any] {
            return array.reduce(into: Set<String>()) { $0.formUnion(allKeys(in: $1)) }
        }
        return []
    }
}
