import Foundation
import Testing
@testable import Tracexy

/// View ▸ Next / Previous Session With a Finding walks the sessions in view in
/// capture order and stops only on flagged ones, without wrapping.
@MainActor
@Suite("Finding navigation")
struct FindingNavigationTests {
    @Test("Steps between flagged sessions in capture order and stops at the ends")
    func stepsBetweenFlaggedSessions() async throws {
        let isolation = ProjectIsolationEnvironment(name: "finding-navigation")
        defer { isolation.tearDown() }
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        #expect(!coordinator.hasAnyFinding)
        #expect(coordinator.sessionWithFinding(.next) == nil)

        let directory = isolation.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("navigation.pcap")
        try PcapWriter.write(
            linkType: LinkType.ethernet, frames: ReplayCorpus.conversationCapturedFrames(), to: url
        )
        let size = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        coordinator.openSavedCapture(SavedCapture(url: url, name: "navigation", date: Date(), byteCount: size))
        await coordinator.waitForSavedCaptureOpen()

        let flagged = Set(coordinator.findings.map(\.sessionID))
        let order = coordinator.visibleSessions.map(\.id).filter { flagged.contains($0) }
        try #require(!order.isEmpty, "the corpus must carry at least one finding")
        #expect(coordinator.hasAnyFinding)

        var visited: [UUID] = []
        while let next = coordinator.sessionWithFinding(.next) {
            coordinator.selectSessionWithFinding(.next)
            #expect(coordinator.activeWorkspace.selectedSessionID == next.id)
            visited.append(next.id)
        }
        #expect(visited == order)
        // No wrap at the end; stepping back retraces the same sessions.
        coordinator.selectSessionWithFinding(.next)
        #expect(coordinator.activeWorkspace.selectedSessionID == order.last)
        var back: [UUID] = []
        while coordinator.sessionWithFinding(.previous) != nil {
            coordinator.selectSessionWithFinding(.previous)
            try back.append(#require(coordinator.activeWorkspace.selectedSessionID))
        }
        #expect(back == Array(order.dropLast().reversed()))
    }
}
