import Foundation
import Testing
@testable import Tracexy

// MARK: - HistoryIntegrationTests

@MainActor
@Suite("Terminal History bridge: lifecycle, projection, read model and isolation")
struct HistoryIntegrationTests {
    // MARK: Internal

    // MARK: Availability

    @Test("With no injected store, History is unavailable and every hook is inert")
    func unavailableWithoutStore() async {
        let coordinator = MainContentCoordinator()
        #expect(coordinator.historyAvailability == .unavailable)

        coordinator.refreshHistory()
        #expect(coordinator.historyAvailability == .unavailable)

        // Terminal hooks are no-ops without a store; nothing crashes and no state
        // claims success.
        coordinator.frozenHistoryLifetime = FrozenHistoryLifetime(
            captureID: UUID(), startedAt: Date(), endedAt: Date(), stoppedGeneration: coordinator.startGeneration
        )
        coordinator.persistTerminalLiveHistory(
            sessions: [Self.summary()],
            stoppedGeneration: coordinator.startGeneration,
            completeness: .complete
        )
        await coordinator.waitForHistory()
        #expect(coordinator.historyError == nil)
        #expect(coordinator.captureError == nil)

        coordinator.clearAllHistory()
        #expect(coordinator.historyAvailability == .unavailable)
    }

    @Test("An injected store starts idle and refreshes to a loaded, empty read model")
    func idleThenEmptyLoaded() async throws {
        let store = try SessionStore()
        let coordinator = MainContentCoordinator(sessionStore: store)
        #expect(coordinator.historyAvailability == .idle)

        coordinator.refreshHistory()
        await coordinator.waitForHistory()
        #expect(coordinator.historyAvailability == .loaded)
        #expect(coordinator.historyCaptures.isEmpty)
        #expect(coordinator.historyCaptureCursor == nil)
    }

    // MARK: Synthetic demo composition

    @Test("Demo preparation seeds the injected store and opens History")
    func demoPreparationSeedsAndNavigates() async throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let store = try SessionStore()
        let coordinator = MainContentCoordinator(
            sessionStore: store,
            isHistoryDemoMode: true,
            historyNow: { now }
        )

        await coordinator.prepareHistoryDemo()
        await coordinator.waitForHistory()

        #expect(coordinator.hasPreparedHistoryDemo)
        #expect(coordinator.activeWorkspace.sidebarSelection == .history)
        #expect(coordinator.historyAvailability == .loaded)
        #expect(coordinator.historyCaptures.count == 4)
        #expect(coordinator.historyCaptures.map(\.sessionCount) == [3, 2, 4, 2])
        #expect(coordinator.historyAutoClear == .never)
    }

    @Test("Demo preparation is inert outside the explicit launch mode")
    func demoPreparationCannotTouchProductionComposition() async throws {
        let store = try SessionStore()
        let existing = Self.historyCapture(startedAt: 1_000, endedAt: 2_000)
        try await store.replaceCapture(existing, sessions: [])
        let coordinator = MainContentCoordinator(sessionStore: store)

        await coordinator.prepareHistoryDemo()

        #expect(!coordinator.hasPreparedHistoryDemo)
        #expect(coordinator.activeWorkspace.sidebarSelection == .sessions)
        #expect(try await store.capture(id: existing.captureID) != nil)
    }

    // MARK: Automatic retention lifecycle

    @Test("Launch retention deletes only captures strictly older than the deterministic cutoff")
    func launchRetentionUsesStrictCutoff() async throws {
        let now = Date(timeIntervalSince1970: 2_000)
        let store = try SessionStore()
        let old = Self.historyCapture(startedAt: 1_098, endedAt: 1_099)
        let exact = Self.historyCapture(startedAt: 1_099, endedAt: 1_100)
        let recent = Self.historyCapture(startedAt: 1_100, endedAt: 1_101)
        for capture in [old, exact, recent] {
            try await store.replaceCapture(capture, sessions: [])
        }

        let coordinator = MainContentCoordinator(sessionStore: store, historyNow: { now })
        coordinator.configureHistoryAutoClear(.minutes15)
        await coordinator.waitForHistory()

        #expect(try await store.capture(id: old.captureID) == nil)
        #expect(try await store.capture(id: exact.captureID) != nil)
        #expect(try await store.capture(id: recent.captureID) != nil)
        #expect(coordinator.historyCaptures.map(\.id) == [recent.captureID, exact.captureID])
    }

    @Test("Changing Auto-clear applies immediately while Never invalidates queued cleanup")
    func preferenceChangeAppliesAndNeverInvalidatesQueuedWork() async throws {
        let now = Date(timeIntervalSince1970: 5_000)
        let store = try SessionStore()
        let first = Self.historyCapture(startedAt: 999, endedAt: 1_000)
        try await store.replaceCapture(first, sessions: [])
        let coordinator = MainContentCoordinator(sessionStore: store, historyNow: { now })

        // Both calls occur on MainActor before the queued task can resolve its
        // guarded policy. `.never` therefore makes the stale 15-minute pass inert.
        coordinator.configureHistoryAutoClear(.minutes15)
        coordinator.configureHistoryAutoClear(.never)
        await coordinator.waitForHistory()
        #expect(try await store.capture(id: first.captureID) != nil)

        coordinator.configureHistoryAutoClear(.hour1)
        await coordinator.waitForHistory()
        #expect(try await store.capture(id: first.captureID) == nil)
    }

    @Test("A terminal write commits before the current Auto-clear policy prunes History")
    func terminalWriteThenRetentionOrdering() async throws {
        let now = Date(timeIntervalSince1970: 2_000)
        let store = try SessionStore()
        let coordinator = MainContentCoordinator(sessionStore: store, historyNow: { now })
        coordinator.configureHistoryAutoClear(.minutes15)
        await coordinator.waitForHistory()

        let old = Self.historyCapture(startedAt: 999, endedAt: 1_000)
        try await store.replaceCapture(old, sessions: [])
        let recentID = UUID()
        coordinator.scheduleHistoryWrite(
            store: store,
            input: HistoryRecordProjection.Input(
                captureID: recentID,
                startedAt: 1_499,
                endedAt: 1_500,
                sourceKind: .live,
                completeness: .complete,
                sessions: [Self.summary()],
                maskIPAddresses: false
            )
        )
        await coordinator.waitForHistory()

        #expect(try await store.capture(id: old.captureID) == nil)
        #expect(try await store.capture(id: recentID) != nil)
        #expect(coordinator.historyCaptures.map(\.id) == [recentID])
    }

    @Test("Retention failure stays History-specific and preserves the selected preference")
    func retentionFailureIsVisibleAndIsolated() async throws {
        let url = Self.temporaryURL()
        defer { Self.removeDatabaseFiles(url) }
        let writer = try SessionStore(configuration: .init(location: .file(url)))
        let reader = try SessionStore(configuration: .init(location: .file(url), readOnly: true))
        let coordinator = MainContentCoordinator(
            sessionStore: reader,
            historyNow: { Date(timeIntervalSince1970: 2_000) }
        )

        coordinator.configureHistoryAutoClear(.minutes15)
        await coordinator.waitForHistory()

        #expect(coordinator.historyAutoClear == .minutes15)
        #expect(coordinator.historyRetentionError?.contains("Auto-clear couldn’t update") == true)
        #expect(coordinator.historyNotice == coordinator.historyRetentionError)
        #expect(coordinator.captureError == nil)
        #expect(coordinator.sessions.isEmpty)
        withExtendedLifetime(writer) {}
    }

    // MARK: Live terminal mapping

    @Test("A terminal live publication persists exactly one live capture and refreshes the read model")
    func liveTerminalPersistsAndRefreshes() async throws {
        let store = try SessionStore()
        let coordinator = MainContentCoordinator(sessionStore: store)
        let snapshot = try await Self.liveSnapshot()
        #expect(!snapshot.sessions.isEmpty)

        coordinator.frozenHistoryLifetime = FrozenHistoryLifetime(
            captureID: UUID(),
            startedAt: Date(timeIntervalSince1970: 1_000),
            endedAt: Date(timeIntervalSince1970: 1_005),
            stoppedGeneration: coordinator.startGeneration
        )
        coordinator.publishLiveDetailed(
            snapshot,
            expectedGeneration: coordinator.startGeneration,
            isCapturing: false,
            terminalHistoryCompleteness: .complete
        )
        await Self.settle(coordinator)

        let page = try await store.captures(after: nil, limit: 500)
        #expect(page.captures.count == 1)
        #expect(page.captures.first?.record.sourceKind == .live)
        #expect(page.captures.first?.record.completeness == .complete)
        #expect(page.captures.first?.sessionCount == snapshot.sessions.count)
        // Success refreshed the read model.
        #expect(coordinator.historyAvailability == .loaded)
        #expect(coordinator.historyCaptures.count == 1)
    }

    @Test("A coalesced (isCapturing: true) publication never writes History")
    func noWriteOnCoalescedPublication() async throws {
        let store = try SessionStore()
        let coordinator = MainContentCoordinator(sessionStore: store)
        let snapshot = try await Self.liveSnapshot()

        coordinator.isCapturing = true
        coordinator.frozenHistoryLifetime = FrozenHistoryLifetime(
            captureID: UUID(), startedAt: Date(), endedAt: Date(), stoppedGeneration: coordinator.startGeneration
        )
        coordinator.publishLiveDetailed(
            snapshot,
            expectedGeneration: coordinator.startGeneration,
            isCapturing: true
        )
        await Self.settle(coordinator)

        #expect(try await store.captures(after: nil, limit: 500).captures.isEmpty)
    }

    @Test("Duplicate terminal callbacks for one stopped generation write only once")
    func duplicateTerminalSuppressed() async throws {
        let store = try SessionStore()
        let coordinator = MainContentCoordinator(sessionStore: store)
        let captureID = UUID()
        coordinator.frozenHistoryLifetime = FrozenHistoryLifetime(
            captureID: captureID, startedAt: Date(timeIntervalSince1970: 1),
            endedAt: Date(timeIntervalSince1970: 2), stoppedGeneration: coordinator.startGeneration
        )

        coordinator.persistTerminalLiveHistory(
            sessions: [Self.summary(), Self.summary()],
            stoppedGeneration: coordinator.startGeneration,
            completeness: .complete
        )
        await coordinator.waitForHistory()
        // A duplicate terminal with a different session set must be suppressed.
        coordinator.persistTerminalLiveHistory(
            sessions: [Self.summary()],
            stoppedGeneration: coordinator.startGeneration,
            completeness: .complete
        )
        await coordinator.waitForHistory()

        #expect(try await store.capture(id: captureID)?.sessionCount == 2)
    }

    @Test("A stale terminal generation writes nothing")
    func staleTerminalSuppressed() async throws {
        let store = try SessionStore()
        let coordinator = MainContentCoordinator(sessionStore: store)
        coordinator.frozenHistoryLifetime = FrozenHistoryLifetime(
            captureID: UUID(), startedAt: Date(), endedAt: Date(),
            stoppedGeneration: coordinator.startGeneration
        )
        coordinator.persistTerminalLiveHistory(
            sessions: [Self.summary()],
            stoppedGeneration: coordinator.startGeneration + 1,
            completeness: .complete
        )
        await coordinator.waitForHistory()
        #expect(try await store.captures(after: nil, limit: 500).captures.isEmpty)
    }

    @Test("A terminal live publication preserves an incomplete fidelity decision")
    func liveTerminalPersistsIncomplete() async throws {
        let store = try SessionStore()
        let coordinator = MainContentCoordinator(sessionStore: store)
        let captureID = UUID()
        coordinator.frozenHistoryLifetime = FrozenHistoryLifetime(
            captureID: captureID,
            startedAt: Date(timeIntervalSince1970: 1),
            endedAt: Date(timeIntervalSince1970: 2),
            stoppedGeneration: coordinator.startGeneration
        )

        coordinator.persistTerminalLiveHistory(
            sessions: [Self.summary()],
            stoppedGeneration: coordinator.startGeneration,
            completeness: .incomplete
        )
        await coordinator.waitForHistory()

        #expect(try await store.capture(id: captureID)?.record.completeness == .incomplete)
    }

    @Test("Back-to-back terminal writes form one awaitable ordered chain")
    func terminalWritesAreSerialized() async throws {
        let store = try SessionStore()
        let coordinator = MainContentCoordinator(sessionStore: store)
        let firstID = UUID()
        let secondID = UUID()
        let first = HistoryRecordProjection.Input(
            captureID: firstID,
            startedAt: 1,
            endedAt: 2,
            sourceKind: .live,
            completeness: .complete,
            sessions: [Self.summary()],
            maskIPAddresses: false
        )
        let second = HistoryRecordProjection.Input(
            captureID: secondID,
            startedAt: 3,
            endedAt: 4,
            sourceKind: .saved,
            completeness: .complete,
            sessions: [Self.summary()],
            maskIPAddresses: false
        )

        coordinator.scheduleHistoryWrite(store: store, input: first)
        coordinator.scheduleHistoryWrite(store: store, input: second)
        await coordinator.waitForHistory()

        #expect(try await store.capture(id: firstID) != nil)
        #expect(try await store.capture(id: secondID) != nil)
        #expect(coordinator.historyMutationTask == nil)
        #expect(coordinator.historyCaptures.count == 2)
    }

    // MARK: Saved terminal mapping

    @Test("Opening a saved capture persists exactly one saved, complete capture")
    func savedTerminalMapping() async throws {
        let environment = try Self.makeSavedEnvironment()
        defer { environment.teardown() }
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let capture = try Self.writeCapture(named: "saved", frames: frames, in: environment.directory)

        environment.coordinator.openSavedCapture(capture)
        await environment.coordinator.waitForSavedCaptureOpen()
        await Self.settle(environment.coordinator)

        let page = try await environment.store.captures(after: nil, limit: 500)
        #expect(page.captures.count == 1)
        #expect(page.captures.first?.record.sourceKind == .saved)
        #expect(page.captures.first?.record.completeness == .complete)
        #expect(page.captures.first?.sessionCount == environment.coordinator.sessions.count)
    }

    @Test("Reopening the same file is a distinct History event")
    func reopenIsDistinctEvent() async throws {
        let environment = try Self.makeSavedEnvironment()
        defer { environment.teardown() }
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let capture = try Self.writeCapture(named: "reopen", frames: frames, in: environment.directory)

        environment.coordinator.openSavedCapture(capture)
        await environment.coordinator.waitForSavedCaptureOpen()
        await Self.settle(environment.coordinator)
        environment.coordinator.openSavedCapture(capture)
        await environment.coordinator.waitForSavedCaptureOpen()
        await Self.settle(environment.coordinator)

        // Two opens → two separate History captures with distinct IDs.
        let page = try await environment.store.captures(after: nil, limit: 500)
        #expect(page.captures.count == 2)
        #expect(Set(page.captures.map(\.record.captureID)).count == 2)
    }

    @Test("A truncated tail maps to incomplete completeness")
    func savedTruncatedCompleteness() async throws {
        let environment = try Self.makeSavedEnvironment()
        defer { environment.teardown() }
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let capture = try Self.writeCapture(named: "truncated", frames: frames, in: environment.directory)
        let handle = try FileHandle(forWritingTo: capture.url)
        try handle.seekToEnd()
        try handle.write(contentsOf: Data([0xAA, 0xBB, 0xCC]))
        try handle.close()
        let byteCount = try #require(try capture.url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        let truncated = SavedCapture(url: capture.url, name: capture.name, date: capture.date, byteCount: byteCount)

        environment.coordinator.openSavedCapture(truncated)
        await environment.coordinator.waitForSavedCaptureOpen()
        await Self.settle(environment.coordinator)

        let page = try await environment.store.captures(after: nil, limit: 500)
        #expect(page.captures.first?.record.completeness == .incomplete)
    }

    @Test("An empty saved capture uses the finite deterministic fallback instant")
    func emptySavedFallback() async throws {
        let environment = try Self.makeSavedEnvironment()
        defer { environment.teardown() }
        let capture = try Self.writeCapture(named: "empty", frames: [], in: environment.directory)

        environment.coordinator.openSavedCapture(capture)
        await environment.coordinator.waitForSavedCaptureOpen()
        await Self.settle(environment.coordinator)

        let page = try await environment.store.captures(after: nil, limit: 500)
        let record = try #require(page.captures.first?.record)
        #expect(record.sourceKind == .saved)
        #expect(record.startedAt > 0)
        #expect(record.endedAt == record.startedAt)
        #expect(page.captures.first?.sessionCount == 0)
    }

    // MARK: Privacy masking end-to-end

    @Test("The terminal hook resolves the mask flag and applies export masking")
    func privacyMaskingEndToEnd() async throws {
        let key = SettingsKeys.maskIPs
        let previous = UserDefaults.standard.object(forKey: key)
        UserDefaults.standard.set(true, forKey: key)
        defer {
            if let previous {
                UserDefaults.standard.set(previous, forKey: key)
            } else {
                UserDefaults.standard.removeObject(forKey: key)
            }
        }

        let store = try SessionStore()
        let coordinator = MainContentCoordinator(sessionStore: store)
        let captureID = UUID()
        coordinator.frozenHistoryLifetime = FrozenHistoryLifetime(
            captureID: captureID, startedAt: Date(timeIntervalSince1970: 1),
            endedAt: Date(timeIntervalSince1970: 2), stoppedGeneration: coordinator.startGeneration
        )
        coordinator.persistTerminalLiveHistory(
            sessions: [Self.summary(host: "93.184.216.34", destinationEndpoint: "93.184.216.34:443")],
            stoppedGeneration: coordinator.startGeneration,
            completeness: .complete
        )
        await coordinator.waitForHistory()

        let sessions = try await store.sessions(captureID: captureID, after: nil, limit: 500)
        #expect(sessions.sessions.first?.host == "[masked-ip]")
        #expect(sessions.sessions.first?.destinationEndpoint == "[masked-ip]:443")
    }

    // MARK: Failure isolation

    @Test("A write failure is History-specific and never touches capture state")
    func writeFailureIsIsolated() async throws {
        let url = Self.temporaryURL()
        defer { Self.removeDatabaseFiles(url) }
        let writer = try SessionStore(configuration: .init(location: .file(url)))
        let reader = try SessionStore(configuration: .init(location: .file(url), readOnly: true))
        let coordinator = MainContentCoordinator(sessionStore: reader)

        coordinator.frozenHistoryLifetime = FrozenHistoryLifetime(
            captureID: UUID(), startedAt: Date(), endedAt: Date(),
            stoppedGeneration: coordinator.startGeneration
        )
        coordinator.persistTerminalLiveHistory(
            sessions: [Self.summary()],
            stoppedGeneration: coordinator.startGeneration,
            completeness: .complete
        )
        await coordinator.waitForHistory()

        #expect(coordinator.historyError != nil)
        #expect(coordinator.captureError == nil)
        #expect(coordinator.sessions.isEmpty)
        withExtendedLifetime(writer) {}
    }

    // MARK: Read model + clear isolation

    @Test("Clearing the current capture never deletes durable History; explicit clear does")
    func clearIsolation() async throws {
        let store = try SessionStore()
        let coordinator = MainContentCoordinator(sessionStore: store)
        try await Self.persistOneLive(coordinator, store: store)
        #expect(coordinator.historyCaptures.count == 1)

        // Clearing the current capture must not touch stored History.
        coordinator.clearSessions()
        #expect(try await store.captures(after: nil, limit: 500).captures.count == 1)

        // The explicit whole-history clear does delete it.
        coordinator.clearAllHistory()
        await coordinator.waitForHistory()
        #expect(coordinator.historyAvailability == .loaded)
        #expect(coordinator.historyCaptures.isEmpty)
        #expect(try await store.captures(after: nil, limit: 500).captures.isEmpty)
    }

    @Test("Explicit clear waits for a pending terminal write and removes its committed row")
    func clearSerializesAfterPendingWrite() async throws {
        let store = try SessionStore()
        let coordinator = MainContentCoordinator(sessionStore: store)
        coordinator.scheduleHistoryWrite(
            store: store,
            input: HistoryRecordProjection.Input(
                captureID: UUID(),
                startedAt: 1,
                endedAt: 2,
                sourceKind: .live,
                completeness: .complete,
                sessions: [Self.summary()],
                maskIPAddresses: false
            )
        )
        coordinator.clearAllHistory()
        await coordinator.waitForHistory()

        #expect(try await store.captures(after: nil, limit: 500).captures.isEmpty)
        #expect(coordinator.historyCaptures.isEmpty)
        #expect(coordinator.historyAvailability == .loaded)
    }

    @Test("Selecting a capture loads its bounded ordinal session page")
    func selectionLoadsSessions() async throws {
        let store = try SessionStore()
        let coordinator = MainContentCoordinator(sessionStore: store)
        try await Self.persistOneLive(coordinator, store: store)
        let captureID = try #require(coordinator.historyCaptures.first?.record.captureID)

        coordinator.selectHistoryCapture(captureID)
        await coordinator.waitForHistory()
        #expect(coordinator.historySessionsAvailability == .loaded)
        #expect(!coordinator.historySessions.isEmpty)
        #expect(coordinator.historySessions.count <= MainContentCoordinator.historySessionPageSize)

        coordinator.selectHistoryCapture(nil)
        #expect(coordinator.historySessionsAvailability == .idle)
        #expect(coordinator.historySessions.isEmpty)
    }

    @Test("Refreshing History preserves a selected capture that still exists")
    func refreshPreservesSelection() async throws {
        let store = try SessionStore()
        let coordinator = MainContentCoordinator(sessionStore: store)
        try await Self.persistOneLive(coordinator, store: store)
        let selectedID = try #require(coordinator.historyCaptures.first?.id)

        coordinator.selectHistoryCapture(selectedID)
        await coordinator.waitForHistory()
        #expect(coordinator.selectedHistoryCaptureID == selectedID)
        #expect(!coordinator.historySessions.isEmpty)

        coordinator.refreshHistory()
        await coordinator.waitForHistory()

        #expect(coordinator.selectedHistoryCaptureID == selectedID)
        #expect(coordinator.historySessionsAvailability == .loaded)
        #expect(!coordinator.historySessions.isEmpty)
    }

    @Test("A file-backed store retains History across coordinator restart")
    func restartFromFileBackedStore() async throws {
        let url = Self.temporaryURL()
        defer { Self.removeDatabaseFiles(url) }
        let firstStore = try SessionStore(configuration: .init(location: .file(url)))
        let first = MainContentCoordinator(sessionStore: firstStore)
        try await Self.persistOneLive(first, store: firstStore)
        #expect(try await firstStore.captures(after: nil, limit: 500).captures.count == 1)

        // A fresh coordinator over a fresh store on the same file sees the record.
        let secondStore = try SessionStore(configuration: .init(location: .file(url)))
        let second = MainContentCoordinator(sessionStore: secondStore)
        second.refreshHistory()
        await second.waitForHistory()
        #expect(second.historyCaptures.count == 1)
        withExtendedLifetime(firstStore) {}
    }

    // MARK: Private

    private struct SavedEnvironment {
        let coordinator: MainContentCoordinator
        let store: SessionStore
        let directory: URL
        let teardown: () -> Void
    }

    /// Persist one terminal live capture and settle the read model.
    private static func persistOneLive(_ coordinator: MainContentCoordinator, store: SessionStore) async throws {
        coordinator.frozenHistoryLifetime = FrozenHistoryLifetime(
            captureID: UUID(), startedAt: Date(timeIntervalSince1970: 1),
            endedAt: Date(timeIntervalSince1970: 2), stoppedGeneration: coordinator.startGeneration
        )
        coordinator.persistTerminalLiveHistory(
            sessions: [summary(), summary()],
            stoppedGeneration: coordinator.startGeneration,
            completeness: .complete
        )
        await coordinator.waitForHistory()
    }

    /// One real off-main investigation snapshot from the shared corpus, with no
    /// capture backend started.
    private static func liveSnapshot() async throws -> InvestigationSnapshot {
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        await engine.ingest(ReplayCorpus.tcpConnectionCapturedFrames(), linkType: LinkType.ethernet, epoch: 1)
        return try #require(await engine.investigationSnapshot(epoch: 1))
    }

    /// Let a queued `publishLiveDetailed` main task run, then await the terminal
    /// write and its triggered read-model refresh.
    private static func settle(_ coordinator: MainContentCoordinator) async {
        for _ in 0 ..< 50 {
            await Task.yield()
        }
        await coordinator.waitForHistory()
    }

    private static func makeSavedEnvironment(function: String = #function) throws -> SavedEnvironment {
        let suiteName = "com.amunx.tracexy.history.\(function).\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tracexy-history-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let store = try SessionStore()
        let coordinator = MainContentCoordinator(
            layoutPreferences: WorkspaceLayoutPreferences(defaults: defaults),
            sessionStore: store
        )
        return SavedEnvironment(coordinator: coordinator, store: store, directory: directory) {
            defaults.removePersistentDomain(forName: suiteName)
            try? FileManager.default.removeItem(at: directory)
        }
    }

    private static func writeCapture(
        named name: String,
        frames: [CapturedFrame],
        in directory: URL
    )
        throws -> SavedCapture
    {
        let url = directory.appendingPathComponent("\(name).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        let byteCount = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        return SavedCapture(url: url, name: name, date: Date(), byteCount: byteCount)
    }

    private static func summary(
        host: String = "example.com",
        destinationEndpoint: String = "93.184.216.34:443"
    )
        -> SessionSummary
    {
        SessionSummary(
            id: UUID(),
            startTime: Date(timeIntervalSince1970: 1_000),
            duration: 5,
            processName: "curl",
            host: host,
            sourceEndpoint: "10.0.0.1:5000",
            destinationEndpoint: destinationEndpoint,
            protocolStack: [.tcp, .tls],
            status: .ok,
            latencyMilliseconds: 12.5,
            bytesUp: 100,
            bytesDown: 200
        )
    }

    private static func historyCapture(
        captureID: UUID = UUID(),
        startedAt: Double,
        endedAt: Double
    )
        -> HistoryCaptureRecord
    {
        HistoryCaptureRecord(
            captureID: captureID,
            startedAt: startedAt,
            endedAt: endedAt,
            sourceKind: .live,
            completeness: .complete
        )
    }

    private static func temporaryURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("history-integration-\(UUID().uuidString).sqlite")
    }

    private static func removeDatabaseFiles(_ url: URL) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            try? FileManager.default.removeItem(at: URL(fileURLWithPath: url.path + suffix))
        }
    }
}
