import Foundation

// MARK: - SavedCaptureOpenRequest

/// One user intent to open a saved capture. The monotonically increasing ID is
/// authoritative; URL equality is not enough because the same file can be opened
/// again after replacement.
nonisolated struct SavedCaptureOpenRequest: Sendable {
    let id: Int
    /// One durable History identity minted when this request is created. Reopening
    /// the same file is a new local History event, so each request gets its own
    /// UUID; no path or file identity is ever persisted.
    let historyCaptureID: UUID
    /// The local History-event instant for this request. Used only when the file
    /// contains no session timestamps; it avoids fabricating a Unix-epoch capture.
    let historyOpenedAt: Date
    let capture: SavedCapture
}

// MARK: - SavedCaptureProgressRelay

/// A latest-value relay with at most one MainActor delivery task queued. A fast
/// stream can emit progress for millions of tiny records without accumulating one
/// UI task per callback; intermediate values collapse while the terminal remains
/// monotonic and authoritative.
nonisolated private final class SavedCaptureProgressRelay: @unchecked Sendable {
    // MARK: Lifecycle

    init(coordinator: MainContentCoordinator, requestID: Int) {
        self.coordinator = coordinator
        self.requestID = requestID
    }

    // MARK: Internal

    func submit(_ progress: PcapStreamProgress) {
        lock.lock()
        latest = progress
        guard !deliveryScheduled else {
            lock.unlock()
            return
        }
        deliveryScheduled = true
        lock.unlock()
        scheduleDelivery()
    }

    // MARK: Private

    private weak var coordinator: MainContentCoordinator?
    private let requestID: Int
    private let lock = NSLock()
    private var latest: PcapStreamProgress?
    private var deliveryScheduled = false

    private func scheduleDelivery() {
        Task { @MainActor [weak self] in
            self?.deliverOne()
        }
    }

    @MainActor
    private func deliverOne() {
        lock.lock()
        let progress = latest
        latest = nil
        lock.unlock()

        if let progress {
            coordinator?.publishSavedCaptureProgress(progress, requestID: requestID)
        }

        lock.lock()
        if latest == nil {
            deliveryScheduled = false
            lock.unlock()
        } else {
            lock.unlock()
            scheduleDelivery()
        }
    }
}

// MARK: - Saved capture opening

@MainActor
extension MainContentCoordinator {
    /// Opens a saved PCAP/PCAPNG as an off-main, final-only transaction.
    ///
    /// The current workspace remains usable while parsing. When live capture is
    /// active, the request waits behind its final drain; the loader cannot start
    /// until that boundary calls ``resumePendingSavedCaptureOpenAfterLiveDrain``.
    func openSavedCapture(_ capture: SavedCapture) {
        cancelFollowStream(clearResult: true)
        cancelSavedCaptureOpen(clearPublishedEvidence: false)
        savedCaptureOpenRequestID &+= 1
        let request = SavedCaptureOpenRequest(
            id: savedCaptureOpenRequestID,
            historyCaptureID: UUID(),
            historyOpenedAt: Date(),
            capture: capture
        )
        pendingSavedCaptureOpen = request
        isOpeningSavedCapture = true
        savedCaptureOpenProgress = PcapStreamProgress(bytesConsumed: 0, totalBytes: UInt64(max(capture.byteCount, 0)))
        captureError = nil

        if isCapturing || isStarting {
            stopCapture()
        } else {
            // Even an already-stopped capture can have one ordered ingest task
            // finishing. Wait for that exact task rather than sleeping/polling.
            queuePendingSavedCaptureOpenAfterCurrentIngest()
        }
    }

    /// Imports an external `.pcap` file into the captures folder and opens it.
    ///
    /// Lossless and idempotent: a source that is already the managed file is
    /// refreshed and reopened in place, and a name collision with a different
    /// external file replaces the old copy only after the new one is fully
    /// staged, so a failed import never destroys existing capture data.
    func importCapture(from source: URL) {
        guard let directory = Self.capturesDirectory() else {
            return
        }
        let destination: URL
        do {
            destination = try CaptureImporter.importCapture(from: source, intoDirectory: directory)
        } catch {
            captureError = "Couldn’t import “\(source.lastPathComponent)”: \(error.localizedDescription)"
            return
        }
        refreshSavedCaptures()
        if let imported = savedCaptures.first(where: { $0.url == destination }) {
            openSavedCapture(imported)
        }
    }

    /// Rescans the captures folder and rebuilds `savedCaptures`, newest first.
    func refreshSavedCaptures() {
        guard let directory = Self.capturesDirectory(),
              let urls = try? FileManager.default.contentsOfDirectory(
                  at: directory,
                  includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey]
              ) else
        {
            savedCaptures = []
            return
        }
        savedCaptures = urls
            .filter { ["pcap", "pcapng"].contains($0.pathExtension.lowercased()) }
            .map { url in
                let values = try? url.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey])
                return SavedCapture(
                    url: url,
                    name: url.deletingPathExtension().lastPathComponent,
                    date: values?.contentModificationDate ?? .distantPast,
                    byteCount: values?.fileSize ?? 0
                )
            }
            .sorted { $0.date > $1.date }
    }

    /// Test/diagnostic seam for the exact task handles; no timing sleeps needed.
    func waitForSavedCaptureOpen() async {
        let boundary = savedCaptureBoundaryTask
        await boundary?.value
        let loader = savedCaptureOpenTask
        await loader?.value
    }

    func waitForSelectedSavedCaptureEvidence() async {
        let task = selectedSessionEvidenceTask
        await task?.value
    }

    var savedCaptureOpenFraction: Double? {
        guard let progress = savedCaptureOpenProgress, progress.totalBytes > 0 else {
            return nil
        }
        return min(max(Double(progress.bytesConsumed) / Double(progress.totalBytes), 0), 1)
    }

    /// Bytes the Inspector may render for this session. Live summaries already
    /// own their bounded representative bytes; saved summaries use only the one
    /// lazily reloaded selected frame.
    func evidenceBytes(for session: SessionSummary) -> [UInt8] {
        guard isViewingSavedCapture else {
            return session.representativeBytes
        }
        guard selectedSessionEvidenceID == session.id else {
            return []
        }
        return selectedSessionEvidenceBytes
    }

    /// Starts one exact-read for the selected saved session. A selection change,
    /// new open, clear, or live start cancels and retires the previous read.
    func loadSelectedSavedCaptureEvidence() {
        selectedSessionEvidenceTask?.cancel()
        selectedSessionEvidenceRequestID &+= 1
        let requestID = selectedSessionEvidenceRequestID
        selectedSessionEvidenceBytes = []
        selectedSessionEvidenceID = nil
        selectedSessionEvidenceError = nil
        isLoadingSelectedSessionEvidence = false

        guard isViewingSavedCapture,
              let sessionID = activeWorkspace.selectedSessionID,
              let reference = savedCaptureEvidence[sessionID],
              let url = savedCaptureEvidenceURL else
        {
            return
        }

        isLoadingSelectedSessionEvidence = true
        let task = Task.detached(priority: .userInitiated) { [weak self] in
            do {
                let bytes = try CaptureEvidenceReader.read(reference, from: url)
                try Task.checkCancellation()
                await self?.finishSelectedEvidenceLoad(
                    bytes: bytes,
                    sessionID: sessionID,
                    requestID: requestID
                )
            } catch is CancellationError {
                await self?.finishCancelledEvidenceLoad(requestID: requestID)
            } catch {
                await self?.finishSelectedEvidenceFailure(
                    error.localizedDescription,
                    sessionID: sessionID,
                    requestID: requestID
                )
            }
        }
        selectedSessionEvidenceTask = task
    }

    /// Cancels pending/active saved work. Published saved state remains intact
    /// while another file opens unless the caller is a real capture boundary.
    func cancelSavedCaptureOpen(clearPublishedEvidence: Bool) {
        pendingSavedCaptureOpen = nil
        savedCaptureBoundaryTask?.cancel()
        savedCaptureBoundaryTask = nil
        savedCaptureOpenTask?.cancel()
        savedCaptureOpenTask = nil
        savedCaptureOpenRequestID &+= 1
        isOpeningSavedCapture = false
        savedCaptureOpenProgress = nil

        selectedSessionEvidenceTask?.cancel()
        selectedSessionEvidenceTask = nil
        selectedSessionEvidenceRequestID &+= 1
        isLoadingSelectedSessionEvidence = false
        selectedSessionEvidenceError = nil

        // A capture/source/clear/new-open boundary also retires the evidence-navigation
        // projection and any raw cited-frame state so neither outlives its source.
        clearEvidenceNavigation()

        if clearPublishedEvidence {
            savedCaptureEvidence = [:]
            savedCaptureEvidenceURL = nil
            selectedSessionEvidenceID = nil
            selectedSessionEvidenceBytes = []
        }
    }

    /// Called only after the final live helper batch has been folded/spooled, or
    /// after the direct/current ingest chain has drained.
    func resumePendingSavedCaptureOpenAfterLiveDrain() {
        guard let request = pendingSavedCaptureOpen,
              request.id == savedCaptureOpenRequestID else
        {
            return
        }
        beginSavedCaptureOpen(request)
    }

    // MARK: Private

    func queuePendingSavedCaptureOpenAfterCurrentIngest() {
        let previous = ingestChain
        let requestID = savedCaptureOpenRequestID
        let task = Task { @MainActor [weak self] in
            await previous?.value
            guard let self,
                  !Task.isCancelled,
                  self.savedCaptureOpenRequestID == requestID,
                  !self.isCapturing,
                  !self.isStarting else
            {
                return
            }
            self.savedCaptureBoundaryTask = nil
            self.resumePendingSavedCaptureOpenAfterLiveDrain()
        }
        savedCaptureBoundaryTask = task
    }

    private func beginSavedCaptureOpen(_ request: SavedCaptureOpenRequest) {
        guard request.id == savedCaptureOpenRequestID else {
            return
        }
        pendingSavedCaptureOpen = nil
        savedCaptureBoundaryTask = nil

        let expectedStartGeneration = startGeneration
        let retainedCapacity = CaptureSettingsResolver.retainCapacity()
        let progressRelay = SavedCaptureProgressRelay(coordinator: self, requestID: request.id)
        let task = Task.detached(priority: .userInitiated) { [weak self] in
            do {
                let loader = try SavedCaptureStreamLoader(
                    contentsOf: request.capture.url,
                    configuration: .init(retainedCapacity: retainedCapacity)
                )
                let result = try loader.load { progress in
                    progressRelay.submit(progress)
                }
                try Task.checkCancellation()
                await self?.adoptSavedCaptureResult(
                    result,
                    request: request,
                    expectedStartGeneration: expectedStartGeneration
                )
            } catch is CancellationError {
                await self?.finishCancelledSavedCaptureOpen(requestID: request.id)
            } catch {
                await self?.failSavedCaptureOpen(
                    message: "Couldn’t open “\(request.capture.name)”: \(error.localizedDescription)",
                    requestID: request.id
                )
            }
        }
        savedCaptureOpenTask = task
    }

    fileprivate func publishSavedCaptureProgress(_ progress: PcapStreamProgress, requestID: Int) {
        guard requestID == savedCaptureOpenRequestID, isOpeningSavedCapture else {
            return
        }
        if let current = savedCaptureOpenProgress,
           progress.bytesConsumed < current.bytesConsumed
        {
            return
        }
        savedCaptureOpenProgress = progress
    }

    private func adoptSavedCaptureResult(
        _ result: SavedCaptureLoadResult,
        request: SavedCaptureOpenRequest,
        expectedStartGeneration: Int
    ) {
        guard request.id == savedCaptureOpenRequestID else {
            return
        }
        guard startGeneration == expectedStartGeneration,
              !isCapturing,
              !isStarting else
        {
            finishCancelledSavedCaptureOpen(requestID: request.id)
            return
        }

        // Retire late live publication only at the atomic adoption boundary. If
        // loading fails, the fully drained live snapshot remains eligible instead
        // of losing its final helper batch merely because an open was attempted.
        startGeneration &+= 1
        resetSessionEngineForSavedCapture(token: startGeneration)
        currentLinkType = result.defaultLinkType
        captureStatistics = nil
        helperBufferDropCount = 0
        retainedFrames = result.retainedTail
        removedSessionIDs.removeAll()
        clearAllInvestigationQueries()
        sessions = result.sessions
        // Adopt the loader's connection snapshot *and* its exact connection and
        // datagram analyses atomically alongside the sessions, under the same
        // request/start-generation guards. All come from the one accepted load
        // result, so they always match. A failed or superseded open never reaches
        // here, so a previously valid session/connection/analysis set is preserved
        // intact.
        adoptInvestigation(InvestigationSnapshot(
            sessions: result.sessions,
            connections: result.connections,
            datagramEvidence: result.datagramEvidence,
            tlsEvidence: result.tlsEvidence,
            connectionAnalysis: result.connectionAnalysis,
            datagramAnalysis: result.datagramAnalysis
        ))
        throughputSamples = []
        pendingChartBytes = 0
        isViewingSavedCapture = true
        activeSavedCapture = request.capture
        savedCaptureActivity = result.activity
        savedCaptureEvidence = result.evidence
        savedCaptureEvidenceURL = request.capture.url
        stoppedCaptureReadyGeneration = nil
        selectedSessionEvidenceBytes = []
        selectedSessionEvidenceID = nil
        selectedSessionEvidenceError = nil
        isLoadingSelectedSessionEvidence = false
        captureError = nil
        savedCaptureWarning = switch result.completeness {
        case .complete:
            nil
        case .incompleteTruncatedTail:
            "This file ends with an incomplete record. Complete earlier sessions were recovered."
        }
        savedCaptureOpenProgress = result.finalProgress
        isOpeningSavedCapture = false
        savedCaptureOpenTask = nil

        for workspace in workspaces.workspaces {
            workspace.selectedSessionID = nil
        }
        selectSidebarItem(.sessions)
        followLatestVisibleSession(acceptedSessionIDs: Set(sessions.map(\.id)))
        loadSelectedSavedCaptureEvidence()
        // The auto-followed selection was set after `adoptInvestigation` above, so
        // rebuild the projection for whatever row Follow Live landed on.
        refreshSelectedSessionEvidenceProjection()

        // The single saved History write hook: only after both the request and
        // start-generation guards above passed and the result was atomically
        // adopted. Reopening the same file is a new History event (fresh UUID).
        persistTerminalSavedHistory(result: result, request: request)
    }

    private func failSavedCaptureOpen(message: String, requestID: Int) {
        guard requestID == savedCaptureOpenRequestID else {
            return
        }
        captureError = message
        isOpeningSavedCapture = false
        savedCaptureOpenProgress = nil
        savedCaptureOpenTask = nil
    }

    private func finishCancelledSavedCaptureOpen(requestID: Int) {
        guard requestID == savedCaptureOpenRequestID else {
            return
        }
        isOpeningSavedCapture = false
        savedCaptureOpenProgress = nil
        savedCaptureOpenTask = nil
    }

    private func finishSelectedEvidenceLoad(bytes: [UInt8], sessionID: UUID, requestID: Int) {
        guard requestID == selectedSessionEvidenceRequestID,
              activeWorkspace.selectedSessionID == sessionID,
              isViewingSavedCapture else
        {
            return
        }
        selectedSessionEvidenceBytes = bytes
        selectedSessionEvidenceID = sessionID
        selectedSessionEvidenceError = nil
        isLoadingSelectedSessionEvidence = false
        selectedSessionEvidenceTask = nil
    }

    private func finishCancelledEvidenceLoad(requestID: Int) {
        guard requestID == selectedSessionEvidenceRequestID else {
            return
        }
        isLoadingSelectedSessionEvidence = false
        selectedSessionEvidenceTask = nil
    }

    private func finishSelectedEvidenceFailure(_ message: String, sessionID: UUID, requestID: Int) {
        guard requestID == selectedSessionEvidenceRequestID,
              activeWorkspace.selectedSessionID == sessionID else
        {
            return
        }
        selectedSessionEvidenceError = message
        isLoadingSelectedSessionEvidence = false
        selectedSessionEvidenceTask = nil
    }
}

// MARK: - Live detailed publication

@MainActor
extension MainContentCoordinator {
    /// The stage-separated capture-loss knowledge for the current live batch,
    /// sampled on the main actor from the accounting observed so far.
    ///
    /// Any nonzero helper-buffer drop, or any kernel/interface drop in a present
    /// `CaptureStatistics` sample, is `.lossReported`. A present sample with no
    /// drops is `.noLossReported`. With no statistics and no reported helper loss
    /// it is `.unknown`. UI-retention eviction is deliberately excluded — it is a
    /// memory bound, never capture loss.
    var currentCaptureLoss: CaptureLossKnowledge {
        if helperBufferDropCount > 0 {
            return .lossReported
        }
        guard let statistics = captureStatistics else {
            return .unknown
        }
        return statistics.totalDropped > 0 ? .lossReported : .noLossReported
    }

    /// Enrich a live investigation snapshot with app-side process attribution,
    /// then publish its sessions, connection snapshot, connection analysis and
    /// datagram analysis together on the next runloop turn.
    ///
    /// Both analyses are taken verbatim from the ``InvestigationSnapshot`` the live
    /// actor already assessed off-main; neither is re-derived here. Process
    /// attribution stays here (main actor, off the decode/group path): it reads the
    /// local socket table, an app concern, and only ever touches the copied session
    /// summaries — never the connection or analysis evidence. The assignment hops
    /// one runloop turn so it can't reload an `NSTableView` reentrantly from inside
    /// a click currently being handled, and it re-checks the capture generation
    /// *and* the expected capture state so a late generation publishes no half.
    func publishLiveDetailed(
        _ snapshot: InvestigationSnapshot,
        expectedGeneration: Int,
        isCapturing expectedCaptureState: Bool,
        terminalHistoryCompleteness: HistoryCompleteness? = nil
    ) {
        ProcessResolver.shared.refresh()
        var built = snapshot.sessions
        for index in built.indices where built[index].processName == nil {
            if let app = ProcessResolver.shared.appName(
                forEndpoints: built[index].sourceEndpoint, built[index].destinationEndpoint
            ) {
                built[index].processName = app
            }
        }
        let applied = built
        let publishedSnapshot = snapshot.replacingSessions(with: applied)
        Task { @MainActor in
            guard self.startGeneration == expectedGeneration,
                  self.isCapturing == expectedCaptureState else
            {
                return
            }
            let previousIDs = Set(self.sessions.map(\.id))
            self.sessions = applied
            self.adoptInvestigation(publishedSnapshot)
            self.stoppedCaptureReadyGeneration = expectedCaptureState ? nil : expectedGeneration
            let acceptedSessionIDs = Set(applied.lazy.map(\.id).filter { !previousIDs.contains($0) })
            self.followLatestVisibleSession(acceptedSessionIDs: acceptedSessionIDs)
            // The single live History write hook: only after the accepted immutable
            // terminal (`isCapturing: false`) adoption, never on coalesced live
            // publications. Duplicate/stale terminal callbacks are suppressed inside.
            if !expectedCaptureState {
                self.persistTerminalLiveHistory(
                    sessions: applied,
                    stoppedGeneration: expectedGeneration,
                    completeness: terminalHistoryCompleteness ?? .incomplete
                )
            }
        }
    }
}
