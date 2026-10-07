import Foundation
import Testing
@testable import Tracexy

// MARK: - InvestigationViewStateTests

/// A capture file reopens where it was left: the selected session and the applied
/// session expression come back, keyed by content (a renamed copy is recognised),
/// per Project, bounded, and never for a live run.
@MainActor
@Suite("Investigation view state")
struct InvestigationViewStateTests {
    // MARK: Internal

    @Test("The store remembers, forgets, bounds and persists per scope")
    func storeRules() throws {
        let suite = "investigation-view-states-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let store = InvestigationViewStates()
        store.bind(to: defaults)
        let scope = InvestigationNoteScope(rawValue: "capture:abc:10")
        let id = UUID()
        store.remember(InvestigationViewState(selectedSessionID: id, expression: "tcp", updatedAt: Date()), for: scope)
        #expect(store.state(for: scope)?.selectedSessionID == id)

        // Live runs are never remembered.
        let live = InvestigationNoteScope.liveRun()
        store.remember(InvestigationViewState(selectedSessionID: id, expression: nil, updatedAt: Date()), for: live)
        #expect(store.state(for: live) == nil)

        // Persisted through the Project's suite.
        let reloaded = InvestigationViewStates()
        reloaded.bind(to: defaults)
        #expect(reloaded.state(for: scope)?.expression == "tcp")

        // An empty state forgets the capture.
        store.remember(InvestigationViewState(selectedSessionID: nil, expression: nil, updatedAt: Date()), for: scope)
        #expect(store.state(for: scope) == nil)

        // Bounded: the least recently touched capture goes first.
        for index in 0 ... InvestigationViewStates.maximumCaptures {
            store.remember(
                InvestigationViewState(
                    selectedSessionID: UUID(), expression: nil,
                    updatedAt: Date(timeIntervalSince1970: Double(index))
                ),
                for: InvestigationNoteScope(rawValue: "capture:\(index):1")
            )
        }
        #expect(store.states.count == InvestigationViewStates.maximumCaptures)
        #expect(store.states["capture:0:1"] == nil)
    }

    @Test("Reopening a capture, even a renamed copy, restores its selection and expression")
    func reopenRestores() async throws {
        let environment = ProjectIsolationEnvironment(name: "view-state")
        defer { environment.tearDown() }
        let directory = environment.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("conversation.pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: ReplayCorpus.conversationCapturedFrames(), to: url)
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        try await Self.open(url, in: coordinator)
        #expect(coordinator.activeWorkspace.selectedSessionID == nil)
        let session = try #require(coordinator.presentedSessions.last { $0.protocolStack.contains(.tcp) })
        coordinator.select(session)
        coordinator.applySessionExpression("tcp")
        await coordinator.waitForInvestigationQuery(in: coordinator.activeWorkspace)
        coordinator.rememberInvestigationViewState()

        // Leave the capture with nothing selected, so only the restore can bring it back.
        coordinator.activeWorkspace.selectedSessionID = nil
        coordinator.clearInvestigationQuery()

        // A renamed copy has the same content identity.
        let copy = directory.appendingPathComponent("renamed.pcap")
        try FileManager.default.copyItem(at: url, to: copy)
        try await Self.open(copy, in: coordinator)
        await coordinator.waitForInvestigationQuery(in: coordinator.activeWorkspace)
        #expect(coordinator.activeWorkspace.selectedSessionID == session.id)
        #expect(coordinator.activeWorkspace.acceptedInvestigationDraft?.expression == "tcp")
        #expect(coordinator.visibleSessions.allSatisfy { $0.protocolStack.contains(.tcp) })
    }

    @Test("A different capture opens clean")
    func otherCaptureOpensClean() async throws {
        let environment = ProjectIsolationEnvironment(name: "view-state-other")
        defer { environment.tearDown() }
        let directory = environment.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let first = directory.appendingPathComponent("first.pcap")
        let second = directory.appendingPathComponent("second.pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: ReplayCorpus.conversationCapturedFrames(), to: first)
        try PcapWriter.write(
            linkType: LinkType.ethernet,
            frames: ReplayCorpus.tcpConnectionCapturedFrames(),
            to: second
        )
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        try await Self.open(first, in: coordinator)
        let session = try #require(coordinator.presentedSessions.first)
        coordinator.select(session)
        coordinator.rememberInvestigationViewState()

        try await Self.open(second, in: coordinator)
        #expect(coordinator.activeWorkspace.acceptedInvestigationDraft == nil)
        let secondScope = try #require(coordinator.investigationNotes.scope)
        #expect(coordinator.investigationViewStates.state(for: secondScope) == nil)
    }

    // MARK: Private

    private static func open(_ url: URL, in coordinator: MainContentCoordinator) async throws {
        let size = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        coordinator.openSavedCapture(SavedCapture(
            url: url, name: url.deletingPathExtension().lastPathComponent, date: Date(), byteCount: size
        ))
        await coordinator.waitForSavedCaptureOpen()
        await coordinator.waitForInvestigationNoteScope()
        #expect(coordinator.investigationNotes.scope != nil)
    }
}
