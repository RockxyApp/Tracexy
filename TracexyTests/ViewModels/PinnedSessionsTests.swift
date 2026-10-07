import Foundation
import Testing
@testable import Tracexy

/// Pinned sessions stay above the Sessions table whatever the filter shows,
/// as Wireshark pins packets, and belong to the capture they were pinned in.
@MainActor
@Suite("Pinned sessions")
struct PinnedSessionsTests {
    // MARK: Internal

    @Test("Pins keep their order and outlive a filter that hides them")
    func pinsOutliveFilters() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let first = try #require(coordinator.sessions.first)
        let last = try #require(coordinator.sessions.last)
        try #require(first.id != last.id)

        coordinator.togglePinSession(last.id)
        coordinator.togglePinSession(first.id)
        #expect(coordinator.pinnedSessions.map(\.id) == [last.id, first.id])
        #expect(coordinator.isSessionPinned(first.id))

        workspace.hostFilter = "no-such-host.invalid"
        #expect(coordinator.visibleSessions.isEmpty)
        #expect(coordinator.pinnedSessions.map(\.id) == [last.id, first.id])

        // A hidden pin still selects, and its evidence is what the inspector reads.
        coordinator.showPinnedSession(first)
        #expect(workspace.selectedSessionID == first.id)
        #expect(coordinator.selectedSession?.id == first.id)
        #expect(!workspace.isFollowingLiveSessions)

        coordinator.togglePinSession(last.id)
        #expect(coordinator.pinnedSessions.map(\.id) == [first.id])
        coordinator.unpinAllSessions()
        #expect(coordinator.pinnedSessions.isEmpty)
    }

    @Test("Removing a session from view drops its pin from the strip")
    func removedSessionsLeaveTheStrip() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let session = try #require(coordinator.sessions.first)
        coordinator.togglePinSession(session.id)

        coordinator.removeSessionsFromView([session.id])
        #expect(coordinator.pinnedSessions.isEmpty)
        coordinator.restoreRemovedSessions()
        #expect(coordinator.pinnedSessions.map(\.id) == [session.id])
    }

    @Test("Clearing the capture clears its pins")
    func captureBoundaryClearsPins() async throws {
        let environment = try await makeLoadedCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let session = try #require(coordinator.sessions.first)
        coordinator.togglePinSession(session.id)

        coordinator.clearSessions()
        #expect(coordinator.pinnedSessionIDs.isEmpty)
        #expect(coordinator.pinnedSessions.isEmpty)
    }

    @Test("A pin is named by its host, or its destination when the host is unknown")
    func pinTitles() {
        #expect(PinnedSessionsStrip.title(for: Self.session(host: "api.example.com")) == "api.example.com")
        #expect(PinnedSessionsStrip.title(for: Self.session(host: "—")) == "93.184.16.34:443")
    }

    // MARK: Private

    private struct Environment {
        let coordinator: MainContentCoordinator
        let teardown: () -> Void
    }

    private static func session(host: String) -> SessionSummary {
        SessionSummary(
            id: UUID(), startTime: Date(), duration: 0.14, processName: "MyApp", host: host,
            sourceEndpoint: "192.168.1.42:52344", destinationEndpoint: "93.184.16.34:443",
            protocolStack: [.tcp, .tls], status: .ok, latencyMilliseconds: 142, bytesUp: 2_048, bytesDown: 36_864
        )
    }

    private func makeLoadedCoordinator(function: String = #function) async throws -> Environment {
        let isolation = ProjectIsolationEnvironment(name: function)
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tracexy-pin-tests-\(UUID().uuidString)", isDirectory: true)
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
