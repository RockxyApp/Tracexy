import Foundation
import Testing
@testable import Tracexy

@MainActor
@Suite("Investigation session-expression activation")
struct InvestigationExpressionActivationTests {
    // MARK: Internal

    @Test("A valid expression Apply constrains visibility through cached matched IDs")
    func validExpressionConstrainsVisibility() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let draft = InvestigationQueryDraft(mode: .expression, expression: "tcp")

        coordinator.applyInvestigationQuery(draft, in: workspace)
        await coordinator.waitForInvestigationQuery(in: workspace)

        #expect(workspace.acceptedInvestigationDraft == draft)
        #expect(!workspace.isEvaluatingInvestigationQuery)
        #expect(workspace.investigationQueryError == nil)
        let visible = coordinator.visibleSessions(in: workspace)
        #expect(Set(visible.map(\.id)) == workspace.investigationMatchedSessionIDs)
        #expect(visible.allSatisfy { $0.protocolStack.contains(.tcp) })
    }

    @Test("A compound protocol and destination-port expression completes")
    func compoundProtocolAndPortExpressionCompletes() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let draft = InvestigationQueryDraft(
            mode: .expression,
            expression: "http and destination.port == 80"
        )

        coordinator.applyInvestigationQuery(draft, in: workspace)
        await coordinator.waitForInvestigationQuery(in: workspace)

        #expect(workspace.acceptedInvestigationDraft == draft)
        #expect(!workspace.isEvaluatingInvestigationQuery)
        #expect(workspace.investigationQueryError == nil)
        #expect(coordinator.visibleSessions(in: workspace).allSatisfy {
            $0.protocolStack.contains(.http) && $0.destinationEndpointValue?.port == 80
        })
    }

    @Test("An unparsable expression preserves the last accepted query and result")
    func invalidExpressionPreservesAcceptedResult() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let accepted = InvestigationQueryDraft(mode: .expression, expression: "tcp")
        coordinator.applyInvestigationQuery(accepted, in: workspace)
        await coordinator.waitForInvestigationQuery(in: workspace)
        let acceptedIDs = workspace.investigationMatchedSessionIDs

        coordinator.applyInvestigationQuery(
            InvestigationQueryDraft(mode: .expression, expression: "ip.addr == 192.0.2.1"),
            in: workspace
        )
        await coordinator.waitForInvestigationQuery(in: workspace)

        #expect(workspace.acceptedInvestigationDraft == accepted)
        #expect(workspace.investigationMatchedSessionIDs == acceptedIDs)
        #expect(workspace.investigationQueryError == InvestigationQueryDraftError(
            rowID: nil,
            reason: .expression(SessionQueryParseError(
                position: 1,
                reason: .unknownName("ip.addr")
            ))
        ))
        #expect(!workspace.isEvaluatingInvestigationQuery)
    }

    @Test("Project retirement keeps the accepted expression and only retires the in-flight run")
    func projectRetirementPreservesAcceptedExpression() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let draft = InvestigationQueryDraft(mode: .expression, expression: "tcp")
        coordinator.applyInvestigationQuery(draft, in: workspace)
        await coordinator.waitForInvestigationQuery(in: workspace)
        let acceptedIDs = workspace.investigationMatchedSessionIDs

        coordinator.cancelInFlightInvestigationQueries()

        #expect(workspace.investigationDraft == draft)
        #expect(workspace.acceptedInvestigationDraft == draft)
        #expect(workspace.investigationMatchedSessionIDs == acceptedIDs)
        #expect(!workspace.isEvaluatingInvestigationQuery)
        #expect(coordinator.investigationQueryTasks.isEmpty)
    }

    @Test("Capture retirement resets the expression draft back to the row default")
    func captureRetirementResetsExpressionDraft() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        coordinator.applyInvestigationQuery(
            InvestigationQueryDraft(mode: .expression, expression: "tcp"),
            in: workspace
        )
        await coordinator.waitForInvestigationQuery(in: workspace)

        coordinator.clearSessions()
        await Task.yield()

        #expect(workspace.investigationDraft.mode == .rows)
        #expect(workspace.investigationDraft.expression.isEmpty)
        #expect(workspace.investigationDraft.combination == .all)
        #expect(workspace.investigationDraft.rows.count == 1)
        #expect(workspace.investigationDraft.rows.first?.isNegated == false)
        #expect(workspace.investigationDraft.rows.first?.predicate == .hostContains(""))
        #expect(workspace.acceptedInvestigationDraft == nil)
        #expect(workspace.investigationMatchedSessionIDs.isEmpty)
        #expect(workspace.investigationQueryError == nil)
        #expect(!workspace.isEvaluatingInvestigationQuery)
    }

    // MARK: Private

    private struct Environment {
        let coordinator: MainContentCoordinator
        let teardown: () -> Void
    }

    private func makeLoadedCoordinator(function: String = #function) async throws -> Environment {
        let isolation = ProjectIsolationEnvironment(name: function)
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tracexy-expression-tests-\(UUID().uuidString)", isDirectory: true)
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
            isolation.tearDown()
            try? FileManager.default.removeItem(at: directory)
        }
    }
}
