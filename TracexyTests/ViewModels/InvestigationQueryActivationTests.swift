import Foundation
import Testing
@testable import Tracexy

@MainActor
@Suite("Investigation query activation")
struct InvestigationQueryActivationTests {
    // MARK: Internal

    @Test("A valid draft constrains visibility through cached matched IDs")
    func validDraftConstrainsVisibility() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let host = try #require(coordinator.sessions.first?.host)
        let draft = InvestigationQueryDraft(rows: [
            InvestigationQueryDraftRow(predicate: .hostContains(host)),
        ])

        coordinator.applyInvestigationQuery(draft, in: workspace)
        await coordinator.waitForInvestigationQuery(in: workspace)

        #expect(workspace.acceptedInvestigationDraft == draft)
        #expect(!workspace.isEvaluatingInvestigationQuery)
        #expect(workspace.investigationQueryError == nil)
        #expect(Set(coordinator.visibleSessions(in: workspace).map(\.id)) == workspace.investigationMatchedSessionIDs)
        #expect(coordinator.visibleSessions(in: workspace)
            .allSatisfy { $0.host.localizedCaseInsensitiveContains(host) })
    }

    @Test("An invalid Apply preserves the last accepted query and result")
    func invalidApplyPreservesAcceptedResult() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let accepted = InvestigationQueryDraft(rows: [
            InvestigationQueryDraftRow(predicate: .protocolStackContains(.tcp)),
        ])
        coordinator.applyInvestigationQuery(accepted, in: workspace)
        await coordinator.waitForInvestigationQuery(in: workspace)
        let acceptedIDs = workspace.investigationMatchedSessionIDs

        let invalidRow = InvestigationQueryDraftRow(predicate: .ipEquals("not-an-ip", scope: .either))
        coordinator.applyInvestigationQuery(
            InvestigationQueryDraft(rows: [invalidRow]),
            in: workspace
        )
        await coordinator.waitForInvestigationQuery(in: workspace)

        #expect(workspace.acceptedInvestigationDraft == accepted)
        #expect(workspace.investigationMatchedSessionIDs == acceptedIDs)
        #expect(workspace.investigationQueryError == InvestigationQueryDraftError(
            rowID: invalidRow.id,
            reason: .invalidIPAddress
        ))
    }

    @Test("Investigation IDs compose with existing filters without changing them")
    func composesWithExistingFilters() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let host = try #require(coordinator.sessions.first?.host)
        workspace.hostFilter = host
        let draft = InvestigationQueryDraft(rows: [
            InvestigationQueryDraftRow(predicate: .protocolStackContains(.tcp)),
        ])

        coordinator.applyInvestigationQuery(draft, in: workspace)
        await coordinator.waitForInvestigationQuery(in: workspace)
        let visible = coordinator.visibleSessions(in: workspace)

        #expect(workspace.hostFilter == host)
        #expect(visible.allSatisfy { $0.host == host && $0.protocolStack.contains(.tcp) })
        #expect(Set(visible.map(\.id)).isSubset(of: workspace.investigationMatchedSessionIDs))
    }

    @Test("Indeterminate finding sessions stay outside the default match set")
    func indeterminateIsExplicitlyExcluded() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let draft = InvestigationQueryDraft(rows: [
            InvestigationQueryDraftRow(predicate: .findingKind(.reset)),
        ])

        coordinator.applyInvestigationQuery(draft, in: workspace)
        await coordinator.waitForInvestigationQuery(in: workspace)

        let visibleIDs = Set(coordinator.visibleSessions(in: workspace).map(\.id))
        #expect(visibleIDs == workspace.investigationMatchedSessionIDs)
        #expect(visibleIDs.isDisjoint(with: workspace.investigationIndeterminateSessionIDs))
        #expect(workspace.acceptedInvestigationDraft == draft)
    }

    @Test("Clear capture cancels and retires every capture-local query")
    func clearCaptureRetiresQueries() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let first = coordinator.activeWorkspace
        let second = try coordinator.workspaces.addWorkspace(title: "Second")
        let draft = InvestigationQueryDraft(rows: [
            InvestigationQueryDraftRow(predicate: .hasEvidence(.anyFinding)),
        ])
        coordinator.applyInvestigationQuery(draft, in: first)
        coordinator.applyInvestigationQuery(draft, in: second)

        coordinator.clearSessions()
        await Task.yield()

        for workspace in [first, second] {
            #expect(workspace.acceptedInvestigationDraft == nil)
            #expect(workspace.investigationMatchedSessionIDs.isEmpty)
            #expect(workspace.investigationIndeterminateSessionIDs.isEmpty)
            #expect(workspace.investigationCoverageReasons.isEmpty)
            #expect(!workspace.isEvaluatingInvestigationQuery)
            #expect(workspace.investigationQueryError == nil)
        }
        #expect(coordinator.investigationQueryTasks.isEmpty)
    }

    @Test("Workspace queries remain independent")
    func workspaceIsolation() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let first = coordinator.activeWorkspace
        let second = try coordinator.workspaces.addWorkspace(title: "Second")
        let firstDraft = InvestigationQueryDraft(rows: [
            InvestigationQueryDraftRow(predicate: .protocolStackContains(.tcp)),
        ])
        let secondDraft = InvestigationQueryDraft(rows: [
            InvestigationQueryDraftRow(predicate: .protocolStackContains(.udp)),
        ])

        coordinator.applyInvestigationQuery(firstDraft, in: first)
        coordinator.applyInvestigationQuery(secondDraft, in: second)
        await coordinator.waitForInvestigationQuery(in: first)
        await coordinator.waitForInvestigationQuery(in: second)

        #expect(first.acceptedInvestigationDraft == firstDraft)
        #expect(second.acceptedInvestigationDraft == secondDraft)
        #expect(coordinator.visibleSessions(in: first).allSatisfy { $0.protocolStack.contains(.tcp) })
        #expect(coordinator.visibleSessions(in: second).allSatisfy { $0.protocolStack.contains(.udp) })
    }

    // MARK: Private

    private struct Environment {
        let coordinator: MainContentCoordinator
        let teardown: () -> Void
    }

    private func makeLoadedCoordinator(function: String = #function) async throws -> Environment {
        let suiteName = "com.amunx.tracexy.query-tests.\(function).\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        let coordinator = MainContentCoordinator(
            layoutPreferences: WorkspaceLayoutPreferences(defaults: defaults)
        )
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tracexy-query-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("sample.pcap")
        let frames = SampleCapture.frames(now: Date())
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)

        coordinator.openSavedCapture(
            SavedCapture(url: url, name: "sample", date: Date(), byteCount: frames.count)
        )
        await coordinator.waitForSavedCaptureOpen()
        try #require(!coordinator.sessions.isEmpty)

        return Environment(coordinator: coordinator) {
            defaults.removePersistentDomain(forName: suiteName)
            try? FileManager.default.removeItem(at: directory)
        }
    }
}
