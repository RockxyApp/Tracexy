import Foundation

// MARK: - SavedCaptureLoadOperation

/// Off-main loading operation, injectable for deterministic cancellation tests.
/// Production always uses the same bounded streaming parser.
nonisolated struct SavedCaptureLoadOperation: Sendable {
    static let streaming = Self { url, capacity, timeCorrection, progress in
        try SavedCaptureStreamLoader(
            contentsOf: url,
            configuration: .init(retainedCapacity: capacity, timeCorrection: timeCorrection)
        ).load(onProgress: progress)
    }

    var run: @Sendable (
        URL, Int, CaptureTimeCorrection?, @Sendable (PcapStreamProgress) -> Void
    )
        async throws -> SavedCaptureLoadResult
}

// MARK: - SavedCaptureReferenceProbe

/// The potentially blocking reference-path probe runs in detached Library
/// refresh or saved-open tasks. Injectable for deterministic source tests.
nonisolated struct SavedCaptureReferenceProbe: Sendable {
    static let live = Self { $0.currentAvailability() }

    var run: @Sendable (CaptureReference) -> CaptureSourceAvailability
}

// MARK: - SavedCaptureOpeningOperations

nonisolated struct SavedCaptureOpeningOperations: Sendable {
    var load: SavedCaptureLoadOperation = .streaming
    var probe: SavedCaptureReferenceProbe = .live
    var refreshTask: Task<Void, Never>?
    var refreshRequestID = 0
    var activeProbeTask: Task<Void, Never>?
    var activeProbeRequestID = 0
}

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
    let preservesCaptureLocalState: Bool
}

// MARK: - CoordinatorProgressRelay

/// A latest-value relay with at most one MainActor delivery task queued. A fast
/// stream can emit progress for millions of tiny records — or a copy for every
/// chunk of a large file — without accumulating one UI task per callback;
/// intermediate values collapse while the terminal remains monotonic and
/// authoritative. `deliver` names which request state the value belongs to, so
/// the saved-open and import pipelines share one bound without sharing state.
nonisolated final class CoordinatorProgressRelay: @unchecked Sendable {
    // MARK: Lifecycle

    init(
        coordinator: MainContentCoordinator,
        requestID: Int,
        deliver: @escaping @Sendable @MainActor (MainContentCoordinator, PcapStreamProgress, Int) -> Void
    ) {
        self.coordinator = coordinator
        self.requestID = requestID
        self.deliver = deliver
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
    private let deliver: @Sendable @MainActor (MainContentCoordinator, PcapStreamProgress, Int) -> Void
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

        if let progress, let coordinator {
            deliver(coordinator, progress, requestID)
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
    /// Saved-opening activation uses the coordinator's shared engine reset while
    /// optionally retaining capture-local state across an in-memory Time Shift.
    func resetSessionEngineForSavedCapture(token: Int, preservingCaptureLocalTools: Bool = false) {
        resetSessionEngine(token: token, preservingCaptureLocalTools: preservingCaptureLocalTools)
    }

    var canTimeShiftSavedCapture: Bool {
        isViewingSavedCapture && activeSavedCapture != nil && adoptedSavedCaptureIdentity != nil
            && !activeSavedCaptureChangedOnDisk && !isOpeningSavedCapture
            && !isCaptureSourceHeld && timeShiftTask == nil
    }

    var canUndoTimeShift: Bool {
        canTimeShiftSavedCapture && activeSavedCapture?.timeCorrection != nil
    }

    func presentTimeShiftSheet() {
        guard canTimeShiftSavedCapture else {
            return
        }
        timeShiftError = nil
        isTimeShiftPresented = true
    }

    func cancelTimeShiftResolution() {
        timeShiftRequestID &+= 1
        timeShiftTask?.cancel()
        timeShiftTask = nil
        isTimeShiftPresented = false
    }

    func applyTimeShift(_ request: CaptureTimeCorrectionRequest) {
        guard canTimeShiftSavedCapture,
              let capture = activeSavedCapture,
              let identity = adoptedSavedCaptureIdentity else
        {
            return
        }
        timeShiftRequestID &+= 1
        let requestID = timeShiftRequestID
        let generation = startGeneration
        let projectID = activeRuntime.projectID
        let worker = Task.detached(priority: .userInitiated) {
            if case let .shiftBy(seconds) = request, let existing = capture.timeCorrection {
                return try existing.addingShift(seconds)
            }
            return try request.resolved(in: capture.url, expectedIdentity: identity)
        }
        timeShiftTask = Task { @MainActor [weak self] in
            defer {
                if self?.timeShiftRequestID == requestID {
                    self?.timeShiftTask = nil
                }
            }
            do {
                let correction = try await withTaskCancellationHandler {
                    try await worker.value
                } onCancel: {
                    worker.cancel()
                }
                // A newer request owning the sheet is not this one's business, so
                // it retires in silence.
                guard let self, self.timeShiftRequestID == requestID else {
                    return
                }
                // Still the current request, but the capture moved while it
                // resolved. Applying the correction would retime a file nobody
                // asked about; leaving the sheet open with a re-enabled Apply and
                // no message is what used to happen.
                guard self.startGeneration == generation,
                      self.activeRuntime.projectID == projectID,
                      self.activeSavedCapture?.id == capture.id,
                      self.adoptedSavedCaptureIdentity?.matches(identity) == true else
                {
                    self.timeShiftError = String(
                        localized: "The capture changed while the time shift was being resolved. Try again."
                    )
                    return
                }
                self.openSavedCapture(
                    capture.withTimeCorrection(correction), preservingCaptureLocalState: true
                )
                self.isTimeShiftPresented = false
                self.timeShiftError = nil
            } catch is CancellationError {
                // A newer source request retired this resolution.
            } catch {
                guard let self, self.timeShiftRequestID == requestID else {
                    return
                }
                self.timeShiftError = error.localizedDescription
            }
        }
    }

    func undoTimeShift() {
        guard canUndoTimeShift, let capture = activeSavedCapture else {
            return
        }
        timeShiftRequestID &+= 1
        timeShiftTask?.cancel()
        timeShiftTask = nil
        openSavedCapture(capture.withTimeCorrection(nil), preservingCaptureLocalState: true)
        isTimeShiftPresented = false
    }

    var savedCaptureLoadOperation: SavedCaptureLoadOperation {
        get { savedCaptureOpeningOperations.load }
        set { savedCaptureOpeningOperations.load = newValue }
    }

    var savedCaptureReferenceProbe: SavedCaptureReferenceProbe {
        get { savedCaptureOpeningOperations.probe }
        set { savedCaptureOpeningOperations.probe = newValue }
    }

    /// Opens a saved PCAP/PCAPNG as an off-main, final-only transaction.
    ///
    /// The current workspace remains usable while parsing. When live capture is
    /// active, the request waits behind its final drain; the loader cannot start
    /// until that boundary calls ``resumePendingSavedCaptureOpenAfterLiveDrain``.
    func openSavedCapture(_ capture: SavedCapture, preservingCaptureLocalState: Bool = false) {
        guard hasHydratedProjects, activeRuntime.projectID != nil else {
            captureError = "Load or repair Projects before opening capture data."
            return
        }
        // A Project transition is about to swap the Library, spool and store this
        // request would publish into. It is refused rather than started and then
        // silently discarded at the boundary. A stop's own final drain is *not* a
        // refusal: waiting behind it is exactly this method's contract.
        guard !projectTransitionStatus.isPending else {
            captureError = "Tracexy is switching Projects. Open “\(capture.name)” again in a moment."
            return
        }
        // Adopting a load resets the engine and the live spool, so an accepted Save
        // or an in-flight export still reading that source refuses the open here
        // rather than having its evidence reset out from under it.
        if let held = captureSourceHoldMessage {
            captureError = held
            return
        }
        // Recheck in the detached load task: opening a slow reference must not
        // block the window before this request can show progress or be replaced.
        unavailableReferencedCapture = nil
        cancelFollowStream(clearResult: true)
        cancelSavedCaptureOpen(clearPublishedEvidence: false)
        savedCaptureOpenRequestID &+= 1
        let request = SavedCaptureOpenRequest(
            id: savedCaptureOpenRequestID,
            historyCaptureID: UUID(),
            historyOpenedAt: Date(),
            capture: capture,
            preservesCaptureLocalState: preservingCaptureLocalState
        )
        pendingSavedCaptureOpen = request
        isOpeningSavedCapture = true
        savedCaptureOpenProgress = PcapStreamProgress(bytesConsumed: 0, totalBytes: UInt64(max(capture.byteCount, 0)))
        captureError = nil

        if isCapturing || isStarting {
            stopCapture()
        } else if !isFinalDrainPending {
            // Even an already-stopped capture can have one ordered ingest task
            // finishing. Wait for that exact task rather than sleeping/polling.
            queuePendingSavedCaptureOpenAfterCurrentIngest()
        }
    }

    /// Rescans the *active Project's* captures folder and rebuilds
    /// `savedCaptures`, newest first. Each Project has its own Library folder, so
    /// saving or trashing a capture in one never changes another's list.
    func refreshSavedCaptures() {
        savedCaptureOpeningOperations.refreshTask?.cancel()
        savedCaptureOpeningOperations.refreshRequestID &+= 1
        let requestID = savedCaptureOpeningOperations.refreshRequestID
        guard let directory = capturesDirectory(),
              let urls = try? FileManager.default.contentsOfDirectory(
                  at: directory,
                  includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey]
              ) else
        {
            savedCaptures = []
            return
        }
        var items: [SavedCapture] = []
        var references: [(URL, CaptureReference)] = []
        for url in urls {
            let ext = url.pathExtension.lowercased()
            if CaptureImporter.libraryPathExtensions.contains(ext) {
                let values = try? url.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey])
                items.append(SavedCapture(
                    url: url,
                    name: url.deletingPathExtension().lastPathComponent,
                    date: values?.contentModificationDate ?? .distantPast,
                    byteCount: values?.fileSize ?? 0
                ))
            } else if ext == CaptureReference.pathExtension,
                      let reference = try? CaptureReference.read(from: url)
            {
                // A damaged sidecar is skipped rather than shown as a phantom
                // capture; the file stays for the user to inspect or trash.
                items.append(SavedCapture(
                    url: reference.url,
                    name: reference.displayName,
                    date: reference.addedAt,
                    byteCount: Int(clamping: reference.identity.size),
                    reference: reference,
                    sidecarURL: url,
                    availability: .checking
                ))
                references.append((url, reference))
            }
        }
        savedCaptures = items.sorted { $0.date > $1.date }
        noteActiveSavedCaptureAvailability()
        guard !references.isEmpty else {
            savedCaptureOpeningOperations.refreshTask = nil
            return
        }
        let originProjectID = activeRuntime.projectID
        let probe = savedCaptureReferenceProbe
        let candidates = references
        savedCaptureOpeningOperations.refreshTask = Task.detached(priority: .utility) { [weak self] in
            for (sidecar, reference) in candidates {
                if Task.isCancelled {
                    break
                }
                let availability = probe.run(reference)
                if Task.isCancelled {
                    break
                }
                await self?.publishSavedCaptureAvailability(
                    availability, sidecar: sidecar, reference: reference,
                    originProjectID: originProjectID, requestID: requestID
                )
            }
            await self?.finishSavedCaptureAvailabilityRefresh(requestID: requestID)
        }
    }

    func waitForSavedCaptureAvailabilityRefresh() async {
        await savedCaptureOpeningOperations.refreshTask?.value
    }

    private func publishSavedCaptureAvailability(
        _ availability: CaptureSourceAvailability,
        sidecar: URL,
        reference: CaptureReference,
        originProjectID: UUID?,
        requestID: Int
    ) {
        guard activeRuntime.projectID == originProjectID,
              savedCaptureOpeningOperations.refreshRequestID == requestID,
              let index = savedCaptures.firstIndex(where: { $0.id == sidecar }),
              savedCaptures[index].reference == reference,
              savedCaptures[index].availability == .checking else
        {
            return
        }
        savedCaptures[index] = savedCaptures[index].withAvailability(availability)
    }

    private func finishSavedCaptureAvailabilityRefresh(requestID: Int) {
        guard savedCaptureOpeningOperations.refreshRequestID == requestID else {
            return
        }
        savedCaptureOpeningOperations.refreshTask = nil
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
            savedCaptureFileIdentity = nil
            selectedSessionEvidenceID = nil
            selectedSessionEvidenceBytes = []
        }
    }

    /// Called only after the final live helper batch has been folded/spooled, or
    /// after the direct/current ingest chain has drained.
    func resumePendingSavedCaptureOpenAfterLiveDrain() {
        guard !isFinalDrainPending, !projectTransitionStatus.isPending,
              let request = pendingSavedCaptureOpen,
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
                  !self.isFinalDrainPending,
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
        let retainedCapacity = CaptureSettingsResolver.retainCapacity(defaults: activeProjectDefaults)
        let originProjectID = activeRuntime.projectID
        let operation = savedCaptureLoadOperation
        let referenceProbe = savedCaptureReferenceProbe
        let progressRelay = CoordinatorProgressRelay(
            coordinator: self,
            requestID: request.id
        ) { coordinator, progress, id in
            coordinator.publishSavedCaptureProgress(progress, requestID: id)
        }
        let task = Task.detached(priority: .userInitiated) { [weak self] in
            do {
                var verifiedRequest = request
                if let reference = request.capture.reference {
                    let availability = referenceProbe.run(reference)
                    try Task.checkCancellation()
                    guard availability.isReadable else {
                        await self?.finishUnavailableSavedCaptureOpen(
                            request: request, availability: availability,
                            originProjectID: originProjectID, expectedStartGeneration: expectedStartGeneration
                        )
                        return
                    }
                    verifiedRequest = SavedCaptureOpenRequest(
                        id: request.id, historyCaptureID: request.historyCaptureID,
                        historyOpenedAt: request.historyOpenedAt,
                        capture: request.capture.withAvailability(.available),
                        preservesCaptureLocalState: request.preservesCaptureLocalState
                    )
                }
                let result = try await operation.run(
                    request.capture.url, retainedCapacity, request.capture.timeCorrection
                ) { progress in
                    progressRelay.submit(progress)
                }
                try Task.checkCancellation()
                if let reference = request.capture.reference,
                   !result.identity.matches(reference.identity)
                {
                    await self?.finishUnavailableSavedCaptureOpen(
                        request: request, availability: .changed,
                        originProjectID: originProjectID, expectedStartGeneration: expectedStartGeneration
                    )
                    return
                }
                await self?.adoptSavedCaptureResult(
                    result,
                    request: verifiedRequest,
                    expectedStartGeneration: expectedStartGeneration,
                    originProjectID: originProjectID
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

    private func finishUnavailableSavedCaptureOpen(
        request: SavedCaptureOpenRequest,
        availability: CaptureSourceAvailability,
        originProjectID: UUID?,
        expectedStartGeneration: Int
    ) {
        guard activeRuntime.projectID == originProjectID,
              request.id == savedCaptureOpenRequestID else
        {
            return
        }
        guard startGeneration == expectedStartGeneration, !isCapturing, !isStarting else {
            finishCancelledSavedCaptureOpen(requestID: request.id)
            return
        }
        let capture = request.capture.withAvailability(availability)
        if let index = savedCaptures.firstIndex(where: { $0.id == capture.id }) {
            savedCaptures[index] = capture
        }
        unavailableReferencedCapture = capture
        isOpeningSavedCapture = false
        savedCaptureOpenProgress = nil
        savedCaptureOpenTask = nil
        pendingOpenExpression = nil
    }

    private func publishSavedCaptureProgress(_ progress: PcapStreamProgress, requestID: Int) {
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
        expectedStartGeneration: Int,
        originProjectID: UUID?
    ) {
        // A load that finishes after a Project change belongs to the Project that
        // asked for it. Adopting it into another Project would publish one
        // Project's sessions, evidence and History event under another's identity.
        guard activeRuntime.projectID == originProjectID else {
            return
        }
        guard request.id == savedCaptureOpenRequestID else {
            return
        }
        // A Save accepted while this load was running owns the current source, and
        // the adoption below resets the engine and spool it is copying. Refuse the
        // adoption instead — the load is retired with a visible reason, and the
        // capture the user asked to keep stays intact.
        if let held = captureSourceHoldMessage {
            failSavedCaptureOpen(
                message: "Couldn’t open “\(request.capture.name)” — \(held)",
                requestID: request.id
            )
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
        let frameReload: (shouldReload: Bool, firstOrdinal: Int)? = if request.preservesCaptureLocalState {
            retireCaptureLocalToolsForTimeShift(
                from: activeSavedCapture?.timeCorrection, to: request.capture.timeCorrection
            )
        } else {
            nil
        }
        resetSessionEngineForSavedCapture(
            token: startGeneration, preservingCaptureLocalTools: request.preservesCaptureLocalState
        )
        currentLinkType = result.defaultLinkType
        captureStatistics = nil
        helperBufferDropCount = 0
        retainedFrames = result.retainedTail
        if !request.preservesCaptureLocalState {
            clearCaptureLocalSessionMarks()
            clearAllInvestigationQueries()
        }
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
            segmentSeries: result.segmentSeries,
            connectionAnalysis: result.connectionAnalysis,
            datagramAnalysis: result.datagramAnalysis,
            tlsAnalysis: result.tlsAnalysis,
            trafficTimeline: result.trafficTimeline
        ))
        throughputSamples = []
        pendingChartBytes = 0
        isViewingSavedCapture = true
        activeSavedCapture = request.capture
        if request.capture.isReferenced,
           let index = savedCaptures.firstIndex(where: { $0.id == request.capture.id })
        {
            savedCaptures[index] = request.capture
        }
        savedCaptureActivity = result.activity
        savedCaptureMetadata = result.metadata
        savedCaptureProperties = result.properties
        savedCaptureNameResolutionRecords = result.nameResolutionRecords
        // The adopted result was read from the file as it is now.
        activeSavedCaptureChangedOnDisk = false
        unavailableReferencedCapture = nil
        savedCaptureEvidence = result.evidence
        savedCaptureEvidenceURL = request.capture.url
        savedCaptureFileIdentity = result.identity
        refreshInvestigationNoteScope()
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
            if request.preservesCaptureLocalState {
                if let selected = workspace.selectedSessionID,
                   !result.sessions.contains(where: { $0.id == selected })
                {
                    workspace.selectedSessionID = nil
                }
            } else {
                workspace.selectedSessionID = nil
            }
        }
        if !request.preservesCaptureLocalState {
            selectSidebarItem(.sessions)
            followLatestVisibleSession(acceptedSessionIDs: Set(sessions.map(\.id)))
        }
        loadSelectedSavedCaptureEvidence()
        // The auto-followed selection was set after `adoptInvestigation` above, so
        // rebuild the projection for whatever row Follow Live landed on.
        refreshSelectedSessionEvidenceProjection()
        if let frameReload, frameReload.shouldReload {
            loadAllFrames(force: true, retainedFrameStartOrdinal: frameReload.firstOrdinal)
        }

        // The single saved History write hook: only after both the request and
        // start-generation guards above passed and the result was atomically
        // adopted. Reopening the same file is a new History event (fresh UUID).
        persistTerminalSavedHistory(result: result, request: request)
        if let expression = pendingOpenExpression {
            pendingOpenExpression = nil
            applySessionExpression(expression)
        }
        if allFrames.pendingReveal != nil {
            loadAllFrames(force: true)
        }
    }

    private func failSavedCaptureOpen(message: String, requestID: Int) {
        guard requestID == savedCaptureOpenRequestID else {
            return
        }
        captureError = message
        isOpeningSavedCapture = false
        savedCaptureOpenProgress = nil
        savedCaptureOpenTask = nil
        pendingOpenExpression = nil
    }

    private func finishCancelledSavedCaptureOpen(requestID: Int) {
        guard requestID == savedCaptureOpenRequestID else {
            return
        }
        isOpeningSavedCapture = false
        savedCaptureOpenProgress = nil
        savedCaptureOpenTask = nil
        pendingOpenExpression = nil
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
    ///
    /// The deferred publication is returned so the final-drain boundary can await
    /// the *actual* adoption and terminal History enqueue rather than treating the
    /// scheduling of this task as the end of the capture.
    @discardableResult
    func publishLiveDetailed(
        _ snapshot: InvestigationSnapshot,
        expectedGeneration: Int,
        isCapturing expectedCaptureState: Bool,
        terminalHistoryCompleteness: HistoryCompleteness? = nil
    )
        -> Task<Void, Never>
    {
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
        return Task { @MainActor in
            let stoppedSourceHasFrames = expectedCaptureState ? false : await self.liveCaptureSpool.hasFrames()
            guard self.startGeneration == expectedGeneration,
                  self.isCapturing == expectedCaptureState else
            {
                return
            }
            let previousIDs = Set(self.sessions.map(\.id))
            self.sessions = applied
            self.adoptInvestigation(publishedSnapshot)
            self.stoppedCaptureReadyGeneration = stoppedSourceHasFrames ? expectedGeneration : nil
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
                self.finishLiveFileSet()
            }
        }
    }
}
