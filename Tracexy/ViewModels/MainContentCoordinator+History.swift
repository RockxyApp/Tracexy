import Foundation

// MARK: - LiveHistoryLifetime

/// The durable identity of a *running* live capture. Minted once on confirmed
/// backend start and keyed by the capture generation for that attempt — never used
/// as the persistent database key itself, because a generation repeats across
/// launches. Only the `captureID` reaches storage.
nonisolated struct LiveHistoryLifetime: Sendable, Equatable {
    /// Durable capture identity, stable across launches. Minted at start, not at
    /// the terminal callback, so duplicate terminal callbacks share one identity.
    let captureID: UUID
    /// The capture generation this identity belongs to, used to match the exact
    /// attempt at stop.
    let captureGeneration: Int
    /// When the backend confirmed start. Frozen at stop, so the terminal hook
    /// never reads the UI timer.
    let startedAt: Date
}

// MARK: - FrozenHistoryLifetime

/// The frozen terminal inputs captured at stop, before the UI timer is cleared.
/// The terminal publication hook consumes exactly the entry whose
/// ``stoppedGeneration`` matches its published generation.
nonisolated struct FrozenHistoryLifetime: Sendable, Equatable {
    let captureID: UUID
    let startedAt: Date
    let endedAt: Date
    /// The post-stop generation the terminal publication runs under.
    let stoppedGeneration: Int
}

// MARK: - HistoryTerminalToken

/// A per-capture terminal-write token. Inserting it into a set is the atomic
/// "mark scheduled before asynchronous work" step: a duplicate/stale terminal
/// callback for the same capture cannot schedule a second write.
nonisolated enum HistoryTerminalToken: Hashable, Sendable {
    case live(generation: Int)
    case saved(requestID: Int)
}

// MARK: - HistoryAvailability

/// The bounded read model's coarse, distinguishable state. `loaded` includes the
/// empty case (a loaded page with zero rows) so the UI never confuses "no History
/// yet" with "still loading" or "store unavailable".
nonisolated enum HistoryAvailability: Sendable, Equatable {
    /// No persistent store is composed (tests, or a failed production factory).
    case unavailable
    /// A store exists but nothing has been loaded yet.
    case idle
    case loading
    /// A page loaded successfully (possibly empty).
    case loaded
    case failed(String)
}

// MARK: - History terminal persistence

@MainActor
extension MainContentCoordinator {
    /// One newest-first capture page size; well within the store's 1...500 bound.
    static let historyCapturePageSize = 100
    /// One ordinal-ascending session page size; well within the store's bound.
    static let historySessionPageSize = 200

    /// The most relevant recoverable History notice. Retention has precedence so
    /// the Privacy pane and History surface can explain the action the user most
    /// recently requested without overwriting unrelated read/write diagnostics.
    var historyNotice: String? {
        historyRetentionError ?? historyError
    }

    /// Dismiss the currently visible History notice wherever it is presented.
    func dismissHistoryNotice() {
        if historyRetentionError != nil {
            historyRetentionError = nil
        } else {
            historyError = nil
        }
    }

    // MARK: Synthetic demo preparation

    /// Reset the explicitly injected in-memory demo store, then navigate to the
    /// populated History surface. Production composition never enables this path.
    /// The launch guard makes a SwiftUI task remount inert instead of replacing a
    /// demo state the operator is actively testing.
    func prepareHistoryDemo() async {
        guard isHistoryDemoMode, !hasPreparedHistoryDemo else {
            return
        }
        hasPreparedHistoryDemo = true
        guard let store = sessionStore else {
            historyError = "Synthetic History is unavailable because no isolated store was composed."
            historyAvailability = .unavailable
            return
        }

        do {
            try await HistoryDemoFixture.reset(into: store, now: historyNow())
            historyError = nil
            historyRetentionError = nil
            activeWorkspace.sidebarSelection = .history
            refreshHistory()
        } catch {
            let message = "Couldn’t prepare synthetic History — \(Self.describe(error))"
            historyError = message
            historyAvailability = .failed(message)
            activeWorkspace.sidebarSelection = .history
        }
    }

    // MARK: Automatic retention policy

    /// Adopt the persisted/user-selected policy and immediately evaluate it at a
    /// documented lifecycle boundary. `.never` invalidates queued automatic work
    /// but never attempts to undo a retention transaction that already began.
    func configureHistoryAutoClear(_ selection: AutoClear) {
        historyAutoClear = selection
        historyRetentionError = nil
        historyRetentionRequestID &+= 1
        guard selection.retentionInterval != nil else {
            return
        }
        scheduleAutomaticHistoryRetention(expectedRetentionRequestID: historyRetentionRequestID)
    }

    /// Map the UI preference to the store's settings-agnostic age policy. The
    /// store deletes records strictly older than this cutoff, so a capture whose
    /// end timestamp equals the cutoff remains retained.
    static func historyRetentionPolicy(
        autoClear: AutoClear,
        now: Date
    )
        -> HistoryRetentionPolicy?
    {
        guard let interval = autoClear.retentionInterval else {
            return nil
        }
        return HistoryRetentionPolicy(
            oldestAllowedEndDate: now.timeIntervalSince1970 - interval
        )
    }

    // MARK: Lifetime tracking

    /// Mint one durable History identity for a confirmed live start. Any prior
    /// live/frozen identity is retired first so only the current attempt persists.
    func beginLiveHistoryLifetime(captureGeneration: Int) {
        guard sessionStore != nil else {
            return
        }
        liveHistoryLifetime = LiveHistoryLifetime(
            captureID: UUID(),
            captureGeneration: captureGeneration,
            startedAt: Date()
        )
        frozenHistoryLifetime = nil
    }

    /// Freeze the running identity for the exact stopped generation, before the UI
    /// timer is cleared. Does nothing if the running lifetime does not match the
    /// capture generation that just stopped (for example, a start that never
    /// confirmed), so a failed start never creates History.
    func freezeLiveHistoryLifetime(captureGeneration: Int, stoppedGeneration: Int) {
        guard let lifetime = liveHistoryLifetime,
              lifetime.captureGeneration == captureGeneration else
        {
            return
        }
        frozenHistoryLifetime = FrozenHistoryLifetime(
            captureID: lifetime.captureID,
            startedAt: lifetime.startedAt,
            endedAt: Date(),
            stoppedGeneration: stoppedGeneration
        )
        liveHistoryLifetime = nil
    }

    /// Retire any live/frozen identity at a clear/new/start boundary. Durable
    /// History rows are untouched — that deletion is a separate explicit action.
    func retireLiveHistoryLifetime() {
        liveHistoryLifetime = nil
        frozenHistoryLifetime = nil
    }

    /// Recovery retires an unconfirmed stop's callbacks without creating a second
    /// capture or changing its frozen timestamps. Only its publication token moves.
    func rebaseFrozenHistoryLifetime(from stoppedToken: Int, to recoveryToken: Int) {
        guard let frozen = frozenHistoryLifetime, frozen.stoppedGeneration == stoppedToken else {
            return
        }
        frozenHistoryLifetime = FrozenHistoryLifetime(
            captureID: frozen.captureID,
            startedAt: frozen.startedAt,
            endedAt: frozen.endedAt,
            stoppedGeneration: recoveryToken
        )
    }

    // MARK: Terminal write hooks

    /// Persist the terminated live capture exactly once, consuming the frozen
    /// lifetime for `stoppedGeneration`. Guards on store presence, a matching
    /// frozen identity, and a first-time terminal token so duplicate terminal
    /// callbacks cannot write twice.
    func persistTerminalLiveHistory(
        sessions: [SessionSummary],
        stoppedGeneration: Int,
        completeness: HistoryCompleteness
    ) {
        guard let store = sessionStore,
              let frozen = frozenHistoryLifetime,
              frozen.stoppedGeneration == stoppedGeneration,
              scheduledHistoryTerminals.insert(.live(generation: stoppedGeneration)).inserted else
        {
            return
        }
        let input = HistoryRecordProjection.Input(
            captureID: frozen.captureID,
            startedAt: frozen.startedAt.timeIntervalSince1970,
            endedAt: frozen.endedAt.timeIntervalSince1970,
            sourceKind: .live,
            completeness: completeness,
            sessions: sessions,
            maskIPAddresses: PrivacySettingsResolver
                .exportPolicy(defaults: activeProjectDefaults).maskIPAddresses
        )
        scheduleHistoryWrite(store: store, input: input)
    }

    /// Persist an opened saved capture exactly once, after atomic adoption. Start
    /// and end derive from the accepted session min/max, with one finite
    /// deterministic fallback for an empty capture; completeness maps directly from
    /// the loader result. No path or file identity is persisted.
    func persistTerminalSavedHistory(result: SavedCaptureLoadResult, request: SavedCaptureOpenRequest) {
        guard let store = sessionStore,
              scheduledHistoryTerminals.insert(.saved(requestID: request.id)).inserted else
        {
            return
        }
        let instants = Self.historyInstants(
            for: result.sessions,
            fallback: request.historyOpenedAt.timeIntervalSince1970
        )
        let completeness: HistoryCompleteness = switch result.completeness {
        case .complete: .complete
        case .incompleteTruncatedTail: .incomplete
        }
        let input = HistoryRecordProjection.Input(
            captureID: request.historyCaptureID,
            startedAt: instants.startedAt,
            endedAt: instants.endedAt,
            sourceKind: .saved,
            completeness: completeness,
            sessions: result.sessions,
            maskIPAddresses: PrivacySettingsResolver
                .exportPolicy(defaults: activeProjectDefaults).maskIPAddresses
        )
        scheduleHistoryWrite(store: store, input: input)
    }

    /// Derive `(startedAt, endedAt)` from the accepted sessions' min start and max
    /// end. An empty capture uses a single finite deterministic fallback instant so
    /// the persisted ordering invariant still holds.
    static func historyInstants(
        for sessions: [SessionSummary],
        fallback: Double
    )
        -> (startedAt: Double, endedAt: Double)
    {
        guard !sessions.isEmpty else {
            let instant = fallback.isFinite ? fallback : 0
            return (instant, instant)
        }
        var minStart = Double.greatestFiniteMagnitude
        var maxEnd = -Double.greatestFiniteMagnitude
        for session in sessions {
            let start = session.startTime.timeIntervalSince1970
            let end = start + max(0, session.duration)
            minStart = min(minStart, start)
            maxEnd = max(maxEnd, end)
        }
        return (minStart, maxEnd)
    }

    /// Project (off `@MainActor`) and write asynchronously. Success refreshes the
    /// read model; failure sets a distinct recoverable History error and never
    /// mutates sessions, capture state or ``captureError``, nor claims success.
    func scheduleHistoryWrite(store: SessionStore, input: HistoryRecordProjection.Input) {
        let previous = historyMutationTask
        let retentionRequestID = historyRetentionRequestID
        historyMutationRequestID &+= 1
        let requestID = historyMutationRequestID
        historyMutationTask = Task.detached(priority: .utility) { [weak self] in
            await previous?.value
            let output = HistoryRecordProjection.project(input)
            do {
                try await store.replaceCapture(output.capture, sessions: output.sessions)
            } catch is CancellationError {
                await self?.finishHistoryMutation(requestID: requestID, refreshesHistory: true)
                return
            } catch {
                await self?.finishHistoryMutation(
                    requestID: requestID,
                    historyError: "Couldn’t save this capture to History — \(Self.describe(error))",
                    refreshesHistory: true
                )
                return
            }

            // If Settings changed while the write was pending, that change has
            // already enqueued its own pass behind this task. Skip the stale policy
            // here so a longer interval or `.never` cannot be overruled.
            guard let policy = await self?.automaticHistoryRetentionPolicy(
                expectedRetentionRequestID: retentionRequestID
            ) else {
                await self?.finishHistoryMutation(requestID: requestID, refreshesHistory: true)
                return
            }

            do {
                _ = try await store.applyRetention(policy)
                await self?.finishHistoryMutation(
                    requestID: requestID,
                    clearsRetentionError: true,
                    refreshesHistory: true
                )
            } catch is CancellationError {
                await self?.finishHistoryMutation(requestID: requestID, refreshesHistory: true)
            } catch {
                await self?.finishHistoryMutation(
                    requestID: requestID,
                    retentionError: Self.retentionFailureMessage(error),
                    refreshesHistory: true
                )
            }
        }
    }

    /// Enqueue one age-policy pass behind every already scheduled History
    /// mutation. The request guard is checked only after the queue reaches this
    /// operation, so a later Settings change can make stale queued work inert.
    private func scheduleAutomaticHistoryRetention(expectedRetentionRequestID: Int) {
        guard let store = sessionStore else {
            return
        }
        let previous = historyMutationTask
        historyMutationRequestID &+= 1
        let requestID = historyMutationRequestID
        historyMutationTask = Task.detached(priority: .utility) { [weak self] in
            await previous?.value
            guard let policy = await self?.automaticHistoryRetentionPolicy(
                expectedRetentionRequestID: expectedRetentionRequestID
            ) else {
                await self?.finishHistoryMutation(requestID: requestID, refreshesHistory: true)
                return
            }
            do {
                _ = try await store.applyRetention(policy)
                await self?.finishHistoryMutation(
                    requestID: requestID,
                    clearsRetentionError: true,
                    refreshesHistory: true
                )
            } catch is CancellationError {
                await self?.finishHistoryMutation(requestID: requestID, refreshesHistory: true)
            } catch {
                await self?.finishHistoryMutation(
                    requestID: requestID,
                    retentionError: Self.retentionFailureMessage(error),
                    refreshesHistory: true
                )
            }
        }
    }

    /// Resolve policy only when the queued request still represents the current
    /// preference. The clock is read at execution time, not enqueue time, so a
    /// long pending write cannot make the cutoff stale.
    private func automaticHistoryRetentionPolicy(
        expectedRetentionRequestID: Int
    )
        -> HistoryRetentionPolicy?
    {
        guard historyRetentionRequestID == expectedRetentionRequestID else {
            return nil
        }
        return Self.historyRetentionPolicy(autoClear: historyAutoClear, now: historyNow())
    }

    // MARK: Read model

    /// Load the newest-first first page. Usable from `idle` or `failed` (retry).
    func refreshHistory() {
        guard let store = sessionStore else {
            historyAvailability = .unavailable
            return
        }
        let preservedSelection = selectedHistoryCaptureID
        historyTask?.cancel()
        historyRequestID &+= 1
        let requestID = historyRequestID
        historyAvailability = .loading
        historyCaptures = []
        historyCaptureCursor = nil

        historyTask = Task { @MainActor [weak self] in
            do {
                let page = try await store.captures(after: nil, limit: Self.historyCapturePageSize)
                guard let self, self.historyRequestID == requestID else {
                    return
                }
                self.historyCaptures = page.captures
                self.historyCaptureCursor = page.nextCursor
                self.historyAvailability = .loaded
                self.historyTask = nil
                if let preservedSelection,
                   page.captures.contains(where: { $0.id == preservedSelection })
                {
                    // Refresh the selected capture's immutable session page without
                    // surprising the user by jumping back to the newest capture.
                    self.selectHistoryCapture(preservedSelection)
                } else {
                    // The selected row no longer exists in the refreshed first page
                    // (including after Clear). Let the view select the new first row.
                    self.selectHistoryCapture(nil)
                }
            } catch is CancellationError {
            } catch {
                guard let self, self.historyRequestID == requestID else {
                    return
                }
                let message = "Couldn’t load History — \(Self.describe(error))"
                self.historyAvailability = .failed(message)
                self.historyTask = nil
                // A restored initial session read may be waiting for this refresh
                // to re-select its capture. Failure must settle that orphaned slot
                // too, without interrupting an independently running session read.
                if self.historySessionsAvailability == .loading, self.historySessionTask == nil {
                    self.historySessionsAvailability = .failed(message)
                }
            }
        }
    }

    /// Retry after a failure — identical to a refresh.
    func retryHistory() {
        refreshHistory()
    }

    /// Restart the first-page History reads a Project change interrupted.
    ///
    /// ``invalidateOutgoingProjectWork()`` cancels this Project's in-flight reads,
    /// so its bucket parks `.loading` with no reader behind it. Nothing on the
    /// History surface would ever start one again: its `task` reads only from
    /// `.idle`, and it auto-selects a capture only when *nothing* is selected — so
    /// a restored Project would sit on a spinner until the user pressed Refresh.
    /// Demoting the parked state to `.idle` is not enough either, because a capture
    /// list that had already loaded keeps its restored selection and would leave
    /// that selection's interrupted session page unread.
    ///
    /// Only interrupted *first* pages are restarted. `loadMore` appends behind
    /// `.loaded`, so an interrupted page append is never restarted and no
    /// already-loaded page or cursor is discarded. Reads run against the restored
    /// Project's own store, and no retention or write is performed here: a Project
    /// change is not a History mutation boundary.
    func resumeInterruptedHistoryReads() {
        guard sessionStore != nil else {
            // No store to read from: say so instead of leaving either surface on a
            // spinner that nothing will ever resolve.
            if historyAvailability == .loading {
                historyAvailability = .unavailable
            }
            if historySessionsAvailability == .loading {
                historySessionsAvailability = .unavailable
            }
            return
        }
        if historyAvailability == .loading {
            // A successful refresh re-selects the preserved capture, which restarts
            // that capture's session page too — so this covers both interruptions.
            refreshHistory()
        } else if historySessionsAvailability == .loading, let captureID = selectedHistoryCaptureID {
            selectHistoryCapture(captureID)
        }
    }

    /// Append the next newest-first page when one exists and no read is in flight.
    func loadMoreHistoryCaptures() {
        guard let store = sessionStore,
              historyAvailability == .loaded,
              historyTask == nil,
              let cursor = historyCaptureCursor else
        {
            return
        }
        let requestID = historyRequestID
        historyTask = Task { @MainActor [weak self] in
            do {
                let page = try await store.captures(after: cursor, limit: Self.historyCapturePageSize)
                guard let self, self.historyRequestID == requestID else {
                    return
                }
                self.historyCaptures.append(contentsOf: page.captures)
                self.historyCaptureCursor = page.nextCursor
                self.historyTask = nil
            } catch is CancellationError {
            } catch {
                guard let self, self.historyRequestID == requestID else {
                    return
                }
                self.historyError = "Couldn’t load more History — \(Self.describe(error))"
                self.historyTask = nil
            }
        }
    }

    /// Select a capture and load its first ordinal-ascending session page. Passing
    /// `nil` clears the selection without a read.
    func selectHistoryCapture(_ captureID: UUID?) {
        historySessionTask?.cancel()
        historySessionTask = nil
        historySessionRequestID &+= 1
        selectedHistoryCaptureID = captureID
        historySessions = []
        historySessionCursor = nil

        guard let store = sessionStore, let captureID else {
            historySessionsAvailability = .idle
            return
        }
        let requestID = historySessionRequestID
        historySessionsAvailability = .loading
        historySessionTask = Task { @MainActor [weak self] in
            do {
                let page = try await store.sessions(
                    captureID: captureID,
                    after: nil,
                    limit: Self.historySessionPageSize
                )
                guard let self, self.historySessionRequestID == requestID else {
                    return
                }
                self.historySessions = page.sessions
                self.historySessionCursor = page.nextCursor
                self.historySessionsAvailability = .loaded
                self.historySessionTask = nil
            } catch is CancellationError {
            } catch {
                guard let self, self.historySessionRequestID == requestID else {
                    return
                }
                self.historySessionsAvailability = .failed(
                    "Couldn’t load these sessions — \(Self.describe(error))"
                )
                self.historySessionTask = nil
            }
        }
    }

    /// Append the next ordinal-ascending session page for the selected capture.
    func loadMoreHistorySessions() {
        guard let store = sessionStore,
              let captureID = selectedHistoryCaptureID,
              historySessionsAvailability == .loaded,
              historySessionTask == nil,
              let cursor = historySessionCursor else
        {
            return
        }
        let requestID = historySessionRequestID
        historySessionTask = Task { @MainActor [weak self] in
            do {
                let page = try await store.sessions(
                    captureID: captureID,
                    after: cursor,
                    limit: Self.historySessionPageSize
                )
                guard let self, self.historySessionRequestID == requestID else {
                    return
                }
                self.historySessions.append(contentsOf: page.sessions)
                self.historySessionCursor = page.nextCursor
                self.historySessionTask = nil
            } catch is CancellationError {
            } catch {
                guard let self, self.historySessionRequestID == requestID else {
                    return
                }
                self.historyError = "Couldn’t load more sessions — \(Self.describe(error))"
                self.historySessionTask = nil
            }
        }
    }

    /// Explicit whole-history clear (confirmed by the UI in N4c2). Deletes every
    /// stored capture group via a zero-retention pass, then refreshes. It never
    /// touches the current capture's sessions or capture state, and it never
    /// activates Auto Clear.
    func clearAllHistory() {
        // A clear started while the Project boundary is settling would run against
        // a store that is about to be swapped, or race the terminal write a
        // stopping capture still owes.
        guard let store = sessionStore, !isProjectBoundaryBusy else {
            return
        }
        historyTask?.cancel()
        historySessionTask?.cancel()
        selectHistoryCapture(nil)
        historyRequestID &+= 1
        historySessionRequestID &+= 1
        historyAvailability = .loading
        let previous = historyMutationTask
        historyMutationRequestID &+= 1
        let requestID = historyMutationRequestID
        historyMutationTask = Task.detached(priority: .utility) { [weak self] in
            await previous?.value
            do {
                _ = try await store.applyRetention(HistoryRetentionPolicy(maxCaptureCount: 0))
                await self?.finishHistoryMutation(requestID: requestID, refreshesHistory: true)
            } catch is CancellationError {
                await self?.finishHistoryMutation(requestID: requestID, refreshesHistory: true)
            } catch {
                await self?.finishHistoryMutation(
                    requestID: requestID,
                    historyError: "Couldn’t clear History — \(Self.describe(error))",
                    refreshesHistory: false,
                    failedAvailability: true
                )
            }
        }
    }

    /// Test/diagnostic seam: await any in-flight terminal write (and the read-model
    /// refresh it triggers) plus the current read tasks, without timing sleeps.
    func waitForHistory() async {
        // A terminal write may schedule a refresh, and a clear task schedules a
        // second refresh task when deletion commits. Re-read each handle until
        // the chain is actually idle rather than awaiting only the first snapshot.
        while let task = historyMutationTask {
            await task.value
        }
        while let task = historyTask {
            await task.value
        }
        while let task = historySessionTask {
            await task.value
        }
    }

    // MARK: Private

    private func finishHistoryMutation(
        requestID: Int,
        historyError: String? = nil,
        retentionError: String? = nil,
        clearsRetentionError: Bool = false,
        refreshesHistory: Bool,
        failedAvailability: Bool = false
    ) {
        if let historyError {
            self.historyError = historyError
        }
        if let retentionError {
            historyRetentionError = retentionError
        } else if clearsRetentionError {
            historyRetentionError = nil
        }
        guard historyMutationRequestID == requestID else {
            return
        }
        historyMutationTask = nil
        if failedAvailability {
            historyAvailability = .failed(historyError ?? "Couldn’t update History.")
        } else if refreshesHistory {
            refreshHistory()
        }
    }

    nonisolated private static func retentionFailureMessage(_ error: Error) -> String {
        "Auto-clear couldn’t update local History — \(describe(error)). "
            + "Your preference is still saved; cleanup will retry at the next History boundary."
    }

    nonisolated private static func describe(_ error: Error) -> String {
        if let error = error as? HistoryStoreError {
            return String(describing: error)
        }
        return error.localizedDescription
    }
}
