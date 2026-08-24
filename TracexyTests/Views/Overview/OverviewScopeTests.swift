import Foundation
import Testing
@testable import Tracexy

@MainActor
@Suite("Overview rollup scope")
struct OverviewScopeTests {
    // MARK: Internal

    @Test("Rollups follow the active filter rather than the whole capture")
    func rollupsRespectTheFilter() async throws {
        let env = try await makeLoadedCoordinator()
        defer { env.teardown() }
        let coordinator = env.coordinator

        let allHosts = Set(coordinator.sessions.map(\.host))
        try #require(allHosts.count > 1, "sample capture must span several hosts for this to mean anything")
        try #require(coordinator.topHosts().count > 1)

        let target = try #require(allHosts.min())
        coordinator.activeWorkspace.hostFilter = target

        let expected = coordinator.sessions.filter { $0.host == target }.count
        #expect(coordinator.visibleSessions.count == expected)
        #expect(coordinator.visibleSessions.count < coordinator.sessions.count)

        // The rollup must have narrowed with the list, not stayed capture-wide.
        #expect(coordinator.topHosts().count == 1)
        #expect(coordinator.topHosts().first?.host == target)
    }

    @Test("Protocol counts follow the active filter too")
    func protocolCountsRespectTheFilter() async throws {
        let env = try await makeLoadedCoordinator()
        defer { env.teardown() }
        let coordinator = env.coordinator

        let present = Set(coordinator.sessions.flatMap(\.protocolStack))
        let absentSomewhere = try #require(
            present.first { proto in
                let hosts = Set(coordinator.sessions.filter { $0.protocolStack.contains(proto) }.map(\.host))
                return hosts.count == 1 && Set(coordinator.sessions.map(\.host)).count > 1
            },
            "need a protocol that appears on exactly one host"
        )
        let owningHost = try #require(
            coordinator.sessions.first { $0.protocolStack.contains(absentSomewhere) }?.host
        )
        let otherHost = try #require(coordinator.sessions.first { $0.host != owningHost }?.host)

        #expect(coordinator.count(for: absentSomewhere) > 0)

        // Filter away the only host carrying it — the count must go to zero.
        coordinator.activeWorkspace.hostFilter = otherHost
        #expect(coordinator.count(for: absentSomewhere) == 0)
    }

    @Test("A saved capture reports unknown fidelity, never a clean one")
    func savedCaptureHasNoFidelity() async throws {
        let env = try await makeLoadedCoordinator()
        defer { env.teardown() }

        // A file carries no kernel accounting, so loss during the original
        // capture is unrecoverable and must not read as 100%.
        #expect(env.coordinator.captureStatistics == nil)
    }

    @Test("Opening a saved file records truthful provenance and a real activity aggregation")
    func savedCaptureExposesProvenance() async throws {
        let env = try await makeLoadedCoordinator()
        defer { env.teardown() }
        let coordinator = env.coordinator

        // The Overview labels the exact file it opened rather than guessing.
        #expect(coordinator.isViewingSavedCapture)
        #expect(coordinator.activeSavedCapture?.name == "sample")

        // Frame count and duration come from the real file, not a fabricated total.
        let activity = try #require(coordinator.savedCaptureActivity)
        #expect(activity.totalFrames == coordinator.retainedFrameCount)
        #expect(activity.totalFrames > 0)
        #expect(activity.duration >= 0)
        // A frames-over-time aggregation exists — the saved surface draws this, not
        // the live "waiting for traffic" throughput state.
        #expect(!activity.isEmpty)

        // A file is shown in full: no fidelity, and neither capture-source loss nor
        // local retention eviction is reported for it.
        #expect(coordinator.captureStatistics == nil)
        #expect(coordinator.helperBufferDropCount == 0)
        #expect(coordinator.retainedFrameEvictionCount == 0)
    }

    @Test("Live/new/clear boundaries drop the saved-file identity so it never outlives the capture")
    func clearingDropsSavedProvenance() async throws {
        let env = try await makeLoadedCoordinator()
        defer { env.teardown() }
        let coordinator = env.coordinator

        try #require(coordinator.activeSavedCapture != nil)
        try #require(coordinator.savedCaptureActivity != nil)

        coordinator.clearSessions()

        #expect(coordinator.activeSavedCapture == nil)
        #expect(coordinator.savedCaptureActivity == nil)
        #expect(!coordinator.isViewingSavedCapture)
    }

    @Test("Findings project stable typed Core observations without session heuristics")
    func findingsProjectCoreAnalysisOnly() async throws {
        let env = try await makeLoadedCoordinator()
        defer { env.teardown() }
        let coordinator = env.coordinator

        let core = try #require(
            coordinator.connectionAnalysisSnapshot.findings.first { $0.kind == .resetObserved },
            "sample capture must retain its observed TCP reset"
        )
        let finding = try #require(coordinator.findings.first { $0.id == core.id })
        let sessionID = SessionBuilder.sessionID(for: core.tuple)

        #expect(finding.id == core.id)
        #expect(finding.severity == .warning)
        #expect(finding.title == "TCP reset observed")
        #expect(finding.sessionID == sessionID)
        #expect(finding.coverage == core.coverage)
        #expect(finding.citedObservationCount == core.citations.count)
        #expect(finding.omittedCitationCount == core.omittedCitationCount)

        // Plaintext HTTP, error status, empty DNS answers and latency no longer
        // create presentation-layer findings without an accepted Core rule.
        #expect(coordinator.findings.allSatisfy { $0.title != "Plaintext HTTP" })
        #expect(coordinator.findings.allSatisfy { $0.title != "DNS returned no answer" })
        #expect(coordinator.findings.allSatisfy { $0.title != "High DNS response time" })
    }

    @Test("Findings quick filter covers exactly the projected finding sessions")
    func findingsQuickFilterMatchesFindingSessions() async throws {
        let env = try await makeLoadedCoordinator()
        defer { env.teardown() }
        let coordinator = env.coordinator

        let findingSessionIDs = coordinator.findingSessionIDs
        coordinator.activeWorkspace.categoryFilters = [.security]
        let matchingSessionIDs = Set(coordinator.visibleSessions.map(\.id))

        #expect(!findingSessionIDs.isEmpty)
        #expect(matchingSessionIDs == findingSessionIDs)
    }

    @Test("Removing sessions hides them across presentation surfaces and remains reversible")
    func removedSessionsStayOutOfPresentation() async throws {
        let env = try await makeLoadedCoordinator()
        defer { env.teardown() }
        let coordinator = env.coordinator
        let target = try #require(coordinator.sessions.first)
        let rawCount = coordinator.sessions.count
        let rawBytes = coordinator.totalBytes
        let targetHostCount = coordinator.sessions.filter { $0.host == target.host }.count

        coordinator.select(target)
        coordinator.removeSessionsFromView(Set([target.id]))

        // Removal is a reversible presentation operation, never evidence loss.
        #expect(coordinator.sessions.count == rawCount)
        #expect(coordinator.sessions.contains { $0.id == target.id })
        #expect(coordinator.removedSessionCount == 1)

        // Every UI-facing seam excludes the removed identity and its rollups.
        #expect(!coordinator.presentedSessions.contains { $0.id == target.id })
        #expect(!coordinator.visibleSessions.contains { $0.id == target.id })
        #expect(!coordinator.sessionRows.contains { $0.id == target.id })
        #expect(coordinator.selectedSession == nil)
        #expect(coordinator.activeWorkspace.selectedSessionID == nil)
        #expect(coordinator.totalBytes == rawBytes - target.totalBytes)
        #expect(coordinator.findings.allSatisfy { $0.sessionID != target.id })
        #expect((coordinator.hosts.first { $0.name == target.host }?.count ?? 0) == targetHostCount - 1)

        coordinator.restoreRemovedSessions()

        #expect(coordinator.removedSessionCount == 0)
        #expect(coordinator.presentedSessions.count == rawCount)
        #expect(coordinator.visibleSessions.contains { $0.id == target.id })
        #expect(coordinator.totalBytes == rawBytes)
    }

    @Test("Capture boundaries discard removed-session presentation state")
    func clearDiscardsRemovedSessions() async throws {
        let env = try await makeLoadedCoordinator()
        defer { env.teardown() }
        let coordinator = env.coordinator
        let target = try #require(coordinator.sessions.first)

        coordinator.removeSessionsFromView(Set([target.id]))
        try #require(coordinator.removedSessionCount == 1)

        coordinator.clearSessions()

        #expect(coordinator.removedSessionCount == 0)
        #expect(coordinator.removedSessionIDs.isEmpty)
    }

    // MARK: Private

    private struct Environment {
        let coordinator: MainContentCoordinator
        let teardown: () -> Void
    }

    /// Writes the sample frames to a real `.pcap` and opens it through
    /// `openSavedCapture`, the same path the sidebar uses.
    private func makeLoadedCoordinator(function: String = #function) async throws -> Environment {
        let suiteName = "com.amunx.tracexy.tests.\(function).\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        let coordinator = MainContentCoordinator(
            layoutPreferences: WorkspaceLayoutPreferences(defaults: defaults)
        )

        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tracexy-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("sample.pcap")
        let frames = SampleCapture.frames(now: Date())
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)

        coordinator.openSavedCapture(
            SavedCapture(url: url, name: "sample", date: Date(), byteCount: frames.count)
        )
        await coordinator.waitForSavedCaptureOpen()
        try #require(!coordinator.sessions.isEmpty, "opening the sample capture must produce sessions")

        return Environment(coordinator: coordinator) {
            defaults.removePersistentDomain(forName: suiteName)
            try? FileManager.default.removeItem(at: directory)
        }
    }
}
