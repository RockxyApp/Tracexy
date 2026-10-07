import Foundation
import Testing
@testable import Tracexy

@Suite("Statistics ▸ Findings summary")
struct FindingsSummaryTests {
    // MARK: Internal

    @Test("Groups by kind, worst severity first, with counts and a finding term")
    func groupsByKind() throws {
        let findings = [
            Self.finding(.dnsNameErrorObserved, severity: .note, session: "a", frames: 1),
            Self.finding(.dnsServerFailureObserved, severity: .warning, session: "b", frames: 2),
            Self.finding(.dnsNameErrorObserved, severity: .note, session: "c", frames: 3),
        ]
        let nodes = FindingsSummary.nodes(of: findings, hosts: Self.hosts)

        #expect(nodes.map(\.detail) == ["dnsServerFailure", "dnsNameError"])
        let nameError = try #require(nodes.last)
        #expect(nameError.isGroup)
        #expect(nameError.term == "finding == dnsNameError")
        #expect(nameError.findingCount == 2)
        #expect(nameError.sessionCount == 2)
        #expect(nameError.citedFrameCount == 4)
        #expect(nameError.children?.map(\.detail) == ["a.example", "c.example"])
        #expect(nameError.children?.allSatisfy { !$0.isGroup && $0.term == nil } == true)
    }

    @Test("Every group term parses as a Session Expression")
    func groupTermsParse() throws {
        let findings = [
            Self.finding(.dnsNameErrorObserved, severity: .note, session: "a", frames: 1),
            Self.finding(.icmpTimeExceededObserved, severity: .note, session: "b", frames: 1),
        ]
        for node in FindingsSummary.nodes(of: findings, hosts: Self.hosts) {
            let term = try #require(node.term)
            _ = try SessionQueryParser().parse(term)
        }
    }

    @Test("Severity floor, search and the flat list")
    func filtersAndFlatList() {
        let findings = [
            Self.finding(.dnsNameErrorObserved, severity: .note, session: "a", frames: 1),
            Self.finding(.dnsServerFailureObserved, severity: .warning, session: "b", frames: 1),
            Self.finding(.dnsNameErrorObserved, severity: .note, session: "c", frames: 1),
        ]
        let warnings = FindingsSummary.nodes(of: findings, hosts: Self.hosts, floor: .warnings)
        #expect(warnings.map(\.detail) == ["dnsServerFailure"])

        let searched = FindingsSummary.nodes(of: findings, hosts: Self.hosts, search: "c.exam")
        #expect(searched.first?.children?.map(\.detail) == ["c.example"])

        let byName = FindingsSummary.nodes(of: findings, hosts: Self.hosts, search: "servfail")
        #expect(byName.isEmpty, "the search reads titles, hosts and expression names, not subtitles")

        let flat = FindingsSummary.nodes(of: findings, hosts: Self.hosts, grouped: false)
        #expect(flat.map(\.detail) == ["b.example", "a.example", "c.example"])
        #expect(flat.allSatisfy { $0.children == nil })
    }

    @Test("Copy writes one tab-separated line per row")
    func copyText() {
        let findings = [Self.finding(.dnsServerFailureObserved, severity: .warning, session: "b", frames: 2)]
        let node = FindingsSummary.nodes(of: findings, hosts: Self.hosts)[0]
        #expect(FindingsSummary.copyText([node]) == "Warning\tDNS server failed or refused\tdnsServerFailure\t1\t1\t2")
    }

    @Test("Every finding kind has an expression name the parser accepts")
    func everyKindHasAName() {
        for kind in QueryFindingKind.allCases {
            let name = SessionQueryParser.findingName(kind)
            #expect(SessionQueryParser.findingNames[name] == kind)
        }
    }

    // MARK: Private

    private static let hosts: [UUID: String] = Dictionary(
        uniqueKeysWithValues: ["a", "b", "c"].map { (sessionTuple($0).sessionID, "\($0).example") }
    )

    private static func sessionTuple(_ name: String) -> (tuple: FiveTuple, sessionID: UUID) {
        let port: UInt16 = switch name {
        case "a": 50_001
        case "b": 50_002
        default: 50_003
        }
        let tuple = FiveTuple(
            proto: .udp,
            source: IPEndpoint(ip: "192.0.2.10", port: port),
            destination: IPEndpoint(ip: "198.51.100.53", port: 53)
        )
        return (tuple, SessionBuilder.sessionID(for: tuple))
    }

    private static func finding(
        _ kind: DatagramAnalysisFindingKind,
        severity: AnalysisSeverity,
        session: String,
        frames: Int
    )
        -> Finding
    {
        let (tuple, sessionID) = sessionTuple(session)
        let citations = (0 ..< frames).map { index in
            DatagramAnalysisCitation(
                sessionID: sessionID,
                direction: .bToA,
                provenance: SessionFrameProvenance(
                    ordinal: FrameOrdinal(UInt64(index + 1)),
                    timestamp: Date(timeIntervalSince1970: 1_700_000_000 + Double(index)),
                    capturedLength: 90,
                    originalLength: 90,
                    linkType: LinkType.ethernet
                )
            )
        }
        let core = DatagramAnalysisFinding(
            id: SessionBuilder.stableID("summary-\(session)-\(kind)"),
            kind: kind,
            severity: severity,
            sessionID: sessionID,
            tuple: tuple,
            coverage: .boundedNoKnownOmission,
            citations: citations,
            omittedCitationCount: 0
        )
        return Finding(core, host: "\(session).example")
    }
}
