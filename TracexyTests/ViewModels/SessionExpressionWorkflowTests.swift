import Foundation
import Testing
@testable import Tracexy

/// "Investigate Sessions Like This" narrows the accepted expression and applies it; a
/// user's Apply of an expression is remembered in the Project's recent list, and a
/// live re-evaluation is not.
@MainActor
@Suite("Session expression workflow")
struct SessionExpressionWorkflowTests {
    @Test("Narrowing applies, records recent, and composes with the accepted expression")
    func narrowingAppliesAndRecords() async throws {
        let isolation = ProjectIsolationEnvironment(name: "expression-workflow")
        defer { isolation.tearDown() }
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let directory = isolation.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("workflow.pcap")
        try PcapWriter.write(
            linkType: LinkType.ethernet, frames: ReplayCorpus.conversationCapturedFrames(), to: url
        )
        let size = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        coordinator.openSavedCapture(SavedCapture(url: url, name: "workflow", date: Date(), byteCount: size))
        await coordinator.waitForSavedCaptureOpen()
        let workspace = coordinator.activeWorkspace
        let tcp = try #require(coordinator.sessions.first { $0.protocolStack.contains(.tcp) })

        let portTerm = try #require(SessionExpressionTerm.sameDestinationPort(tcp.destinationEndpointValue))
        coordinator.investigateSessions(narrowingWith: portTerm)
        await coordinator.waitForInvestigationQuery(in: workspace)
        #expect(workspace.investigationQueryError == nil)
        #expect(workspace.acceptedInvestigationDraft?.expression == portTerm)
        #expect(workspace.investigationMatchedSessionIDs.contains(tcp.id))
        #expect(coordinator.expressionLibrary.recent.first == portTerm)

        coordinator.investigateSessions(narrowingWith: "tcp")
        await coordinator.waitForInvestigationQuery(in: workspace)
        #expect(workspace.acceptedInvestigationDraft?.expression == "\(portTerm) and tcp")
        #expect(workspace.investigationMatchedSessionIDs.allSatisfy { id in
            coordinator.sessions.first { $0.id == id }?.protocolStack.contains(.tcp) == true
        })

        // A live re-evaluation of the accepted query is not a new use of it.
        let before = coordinator.expressionLibrary.recent
        coordinator.refreshActiveInvestigationQueries()
        await coordinator.waitForInvestigationQuery(in: workspace)
        #expect(coordinator.expressionLibrary.recent == before)

        // A rejected expression is neither applied nor remembered.
        coordinator.applySessionExpression("port in {")
        await coordinator.waitForInvestigationQuery(in: workspace)
        #expect(workspace.investigationQueryError != nil)
        #expect(coordinator.expressionLibrary.recent == before)
    }
}
