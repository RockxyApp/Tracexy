import Foundation
import Testing
@testable import Tracexy

/// Forward to Next Scope redoes what Back to Previous Scope undid: the redone
/// scope carries its selection, a new drill-in or Reset starts a new branch, any
/// other scope change drops the forward history, and an older capture generation
/// is never reapplied. Selecting a row inside the restored scope keeps it.
@MainActor
@Suite("Session scope forward")
struct SessionScopeForwardTests {
    // MARK: Internal

    @Test("Back then Forward reapplies the drill-in and its selection, and Back works again")
    func forwardRedoesBack() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let sessions = coordinator.presentedSessions
        let origin = try #require(sessions.first)
        let inside = try #require(sessions.last { $0.id != origin.id })
        coordinator.select(origin)
        await coordinator.waitForEvidenceProjection()
        #expect(!coordinator.canGoForwardToNextSessionScope)

        coordinator.selectHost("cdn.fastly.net")
        coordinator.select(inside)
        await coordinator.waitForEvidenceProjection()
        #expect(coordinator.returnToPreviousSessionScope())
        await coordinator.waitForEvidenceProjection()
        #expect(workspace.hostFilter == nil)
        #expect(coordinator.canGoForwardToNextSessionScope)

        #expect(coordinator.goForwardToNextSessionScope())
        await coordinator.waitForEvidenceProjection()
        #expect(workspace.hostFilter == "cdn.fastly.net")
        #expect(workspace.sidebarSelection == .sessions)
        #expect(workspace.selectedSessionID == inside.id)
        #expect(!coordinator.canGoForwardToNextSessionScope)
        #expect(workspace.sessionScopeForwardStack.isEmpty)

        // Forward recorded where it came from, so Back returns there again.
        #expect(coordinator.returnToPreviousSessionScope())
        await coordinator.waitForEvidenceProjection()
        #expect(workspace.hostFilter == nil)
        #expect(workspace.selectedSessionID == origin.id)
        #expect(coordinator.canGoForwardToNextSessionScope)
    }

    @Test("Several Backs are redone in order")
    func forwardRetracesSeveralSteps() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        coordinator.selectHost("api.example.com")
        coordinator.selectProcess("Safari")
        #expect(coordinator.returnToPreviousSessionScope())
        #expect(coordinator.returnToPreviousSessionScope())
        #expect(workspace.hostFilter == nil)
        #expect(workspace.processFilter == nil)

        #expect(coordinator.goForwardToNextSessionScope())
        #expect(workspace.hostFilter == "api.example.com")
        #expect(workspace.processFilter == nil)
        #expect(coordinator.goForwardToNextSessionScope())
        #expect(workspace.processFilter == "Safari")
        #expect(!coordinator.goForwardToNextSessionScope())
    }

    @Test("Selecting a row inside the restored scope keeps Forward")
    func selectionInsideScopeKeepsForward() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        coordinator.selectHost("api.example.com")
        #expect(coordinator.returnToPreviousSessionScope())
        let any = try #require(coordinator.presentedSessions.first)
        coordinator.select(any)
        await coordinator.waitForEvidenceProjection()
        #expect(coordinator.canGoForwardToNextSessionScope)
    }

    @Test("A new drill-in, a Reset, or another scope change drops the forward history")
    func otherScopeChangesDropForward() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace

        coordinator.selectHost("api.example.com")
        #expect(coordinator.returnToPreviousSessionScope())
        coordinator.selectProcess("Safari")
        #expect(workspace.sessionScopeForwardStack.isEmpty)
        #expect(!coordinator.canGoForwardToNextSessionScope)

        #expect(coordinator.returnToPreviousSessionScope())
        #expect(coordinator.canGoForwardToNextSessionScope)
        coordinator.resetSessionFilters()
        #expect(workspace.sessionScopeForwardStack.isEmpty)

        coordinator.selectHost("api.example.com")
        #expect(coordinator.returnToPreviousSessionScope())
        workspace.categoryFilters = [.dns]
        #expect(!coordinator.canGoForwardToNextSessionScope)
        #expect(!coordinator.goForwardToNextSessionScope())
        #expect(workspace.categoryFilters == [.dns])
        #expect(workspace.hostFilter == nil)
        #expect(workspace.sessionScopeForwardStack.isEmpty)
    }

    @Test("An entry from an earlier capture generation is never reapplied")
    func staleGenerationIsDropped() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        coordinator.selectHost("api.example.com")
        #expect(coordinator.returnToPreviousSessionScope())
        coordinator.startGeneration &+= 1
        #expect(!coordinator.canGoForwardToNextSessionScope)
        #expect(!coordinator.goForwardToNextSessionScope())
        #expect(workspace.hostFilter == nil)
    }

    @Test("The menu and the shortcut list name the same command")
    func menuTitleMatchesReference() {
        let entries = KeyboardShortcutReference.groups.flatMap(\.entries)
        #expect(entries.contains { $0.command == SessionScopeForwardAction.title && $0.keys == "⌘]" })
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
            .appendingPathComponent("tracexy-scope-forward-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("sample.pcap")
        let frames = SampleCapture.frames(now: Date())
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        coordinator.openSavedCapture(SavedCapture(url: url, name: "sample", date: Date(), byteCount: frames.count))
        await coordinator.waitForSavedCaptureOpen()
        try #require(coordinator.presentedSessions.count >= 2)
        return Environment(coordinator: coordinator) {
            isolation.tearDown()
            try? FileManager.default.removeItem(at: directory)
        }
    }
}
