import Foundation
import Testing
@testable import Tracexy

/// The finding-contributor seam: with no source installed the findings list is Core
/// analysis alone, exactly as before; an installed source's findings join it for
/// the sessions in view and form their own groups with their own expression.
@MainActor
@Suite("Finding contributors", .serialized)
struct FindingContributingTests {
    // MARK: Internal

    @Test("With no source installed the findings list holds Core analysis findings only")
    func nothingInstalledKeepsCoreFindings() async throws {
        let previous = FindingContributors.installed
        FindingContributors.installed = nil
        defer { FindingContributors.installed = previous }
        let env = try await Self.loadedCoordinator("finding-contributors-none")
        defer { env.isolation.tearDown() }
        let coordinator = env.coordinator

        let findings = coordinator.findings
        try #require(!findings.isEmpty, "the corpus must carry at least one finding")
        #expect(findings.allSatisfy { $0.queryKind != nil })
        let core = coordinator.connectionAnalysisSnapshot.findings.count
            + coordinator.datagramAnalysisSnapshot.findings.count
            + coordinator.tlsAnalysisSnapshot.findings.count
        #expect(findings.count == core)
        for finding in findings {
            let name = try SessionQueryParser.findingName(#require(finding.queryKind))
            #expect(finding.kindName == name)
            #expect(finding.kindExpression == "finding == \(name)")
        }
        let nodes = FindingsSummary.nodes(of: findings, hosts: [:])
        #expect(nodes.allSatisfy { $0.id.hasPrefix("kind.") && $0.term?.hasPrefix("finding == ") == true })
    }

    @Test("An installed source's findings join Core findings for presented sessions and group on their own")
    func installedSourceJoinsFindings() async throws {
        let env = try await Self.loadedCoordinator("finding-contributors-stub")
        defer { env.isolation.tearDown() }
        let coordinator = env.coordinator
        let coreCount = coordinator.findings.count
        let session = try #require(coordinator.presentedSessions.first)
        let kind = ContributedFindingKind(id: "rule-1", label: "Custom", expression: "(tcp or udp)")
        let stub = StubContributor(coordinator: coordinator, findings: [
            Finding(
                id: UUID(), severity: .note, kind: kind, title: "Mine", subtitle: "Detail",
                sessionID: session.id, coverage: .boundedNoKnownOmission
            ),
            // Not a presented session: dropped.
            Finding(
                id: UUID(), severity: .warning, kind: kind, title: "Mine", subtitle: "Detail",
                sessionID: UUID(), coverage: .boundedNoKnownOmission
            ),
        ])
        let previous = FindingContributors.installed
        FindingContributors.installed = stub
        defer { FindingContributors.installed = previous }

        let findings = coordinator.findings
        #expect(findings.count == coreCount + 1)
        let mine = try #require(findings.first { $0.queryKind == nil })
        #expect(mine.sessionID == session.id)
        #expect(mine.kind == .contributed(kind))
        #expect(mine.kindName == "Custom")
        #expect(mine.kindExpression == "(tcp or udp)")
        #expect(mine.citedFrames.isEmpty)
        // Worst severity first: the note sorts after every warning or error.
        let mineIndex = try #require(findings.firstIndex { $0.id == mine.id })
        #expect(findings.prefix(mineIndex).allSatisfy { $0.severity.rawValue <= Finding.Severity.note.rawValue })
        #expect(findings.suffix(from: mineIndex).allSatisfy { $0.severity == .note })

        let nodes = FindingsSummary.nodes(of: findings, hosts: [session.id: session.host])
        let group = try #require(nodes.first { $0.id == "contributed.rule-1" })
        #expect(group.title == "Mine")
        #expect(group.detail == "Custom")
        #expect(group.term == "(tcp or udp)")
        #expect(group.findingCount == 1)
        #expect(nodes.filter { $0.id.hasPrefix("kind.") }.count == Set(findings.compactMap(\.queryKind)).count)
        #expect(FindingsSummary.nodes(of: findings, hosts: [:], search: "custom").map(\.id) == ["contributed.rule-1"])

        // Another coordinator is never given this source's findings.
        let other = try await Self.loadedCoordinator("finding-contributors-other")
        defer { other.isolation.tearDown() }
        #expect(other.coordinator.findings.allSatisfy { $0.queryKind != nil })
    }

    // MARK: Private

    @MainActor
    private final class StubContributor: FindingContributing {
        // MARK: Lifecycle

        init(coordinator: MainContentCoordinator, findings: [Finding]) {
            self.coordinator = coordinator
            self.findings = findings
        }

        // MARK: Internal

        func contributedFindings(for coordinator: MainContentCoordinator) -> [Finding] {
            coordinator === self.coordinator ? findings : []
        }

        // MARK: Private

        private weak var coordinator: MainContentCoordinator?
        private let findings: [Finding]
    }

    private static func loadedCoordinator(
        _ name: String
    )
        async throws -> (isolation: ProjectIsolationEnvironment, coordinator: MainContentCoordinator)
    {
        let isolation = ProjectIsolationEnvironment(name: name)
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let directory = isolation.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("\(name).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: ReplayCorpus.conversationCapturedFrames(), to: url)
        let size = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        coordinator.openSavedCapture(SavedCapture(url: url, name: name, date: Date(), byteCount: size))
        await coordinator.waitForSavedCaptureOpen()
        return (isolation, coordinator)
    }
}
