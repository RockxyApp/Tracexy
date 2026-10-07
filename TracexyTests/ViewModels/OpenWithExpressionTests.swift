import Foundation
import Testing
@testable import Tracexy

/// File ▸ Open… takes an optional Session Expression (Wireshark's read filter)
/// that the capture opens narrowed to; an expression that does not parse is caught
/// in the panel.
@MainActor
struct OpenWithExpressionTests {
    @Test
    func theOpenedCaptureStartsNarrowed() async throws {
        let accessory = CaptureOpenAccessoryView(copiesIntoLibrary: false)
        #expect(accessory.expression == nil && accessory.expressionError == nil)

        let isolation = ProjectIsolationEnvironment(name: "open-with-expression")
        defer { isolation.tearDown() }
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let directory = isolation.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("read-filter.pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: ReplayCorpus.conversationCapturedFrames(), to: url)
        let size = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)

        coordinator.pendingOpenExpression = "tcp"
        coordinator.openSavedCapture(SavedCapture(url: url, name: "read-filter", date: Date(), byteCount: size))
        await coordinator.waitForSavedCaptureOpen()
        await coordinator.waitForInvestigationQuery(in: coordinator.activeWorkspace)
        #expect(coordinator.pendingOpenExpression == nil)
        #expect(coordinator.activeWorkspace.acceptedInvestigationDraft?.expression == "tcp")
        #expect(coordinator.visibleSessions.allSatisfy { $0.protocolStack.contains(.tcp) })
        #expect(coordinator.visibleSessions.count < coordinator.presentedSessions.count)
    }
}
