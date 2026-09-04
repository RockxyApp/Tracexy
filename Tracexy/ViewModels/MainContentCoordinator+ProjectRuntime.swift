import Foundation

// MARK: - ProjectRuntimeError

nonisolated enum ProjectRuntimeError: Error, Equatable, Sendable {
    case settingsUnavailable
    case projectNotFound

    // MARK: Internal

    var userFacingDescription: String {
        switch self {
        case .settingsUnavailable:
            "Tracexy couldn’t open this Project’s private settings store, so it did not take any capture data in for it."
        case .projectNotFound:
            "That Project is no longer available."
        }
    }
}

// MARK: - Per-Project runtime buckets and the single lifecycle path

@MainActor
extension MainContentCoordinator {
    /// Intake is refused until ownership is bound, while that ownership changes,
    /// while a stopped capture still owes its exact final tail, and while an
    /// accepted Save or session export still owns the current capture source.
    ///
    /// Start mints a new generation and resets the engine and spool, so every one
    /// of these is a refusal *before* any side effect: an owed drain would otherwise
    /// be superseded and its final tail discarded, and a queued Save would be left
    /// copying a source that has already been reset underneath it.
    var captureStartBlockedMessage: String? {
        if projectTransitionStatus.isPending || pendingProjectSwitchConfirmation != nil {
            return "Capture can’t start while Tracexy is switching Projects. Try again in a moment."
        }
        guard activeRuntime.projectID != nil else {
            return "Capture can’t start until Projects finish loading."
        }
        if isFinalDrainPending {
            return "Capture can’t start until the capture you stopped has finished writing its last packets. "
                + "Try again in a moment."
        }
        return captureSourceHoldMessage
    }

    /// True while an accepted Save or an in-flight session export still owns the
    /// current capture source.
    ///
    /// This is the explicit source-use gate: while it is set, every *destructive*
    /// source mutation — Clear, Start, adopting another saved capture, an import
    /// that replaces a Library file, and trashing one — is refused, because each
    /// resets or removes exactly the bytes the accepted operation is copying.
    /// Deliberately not gated: Stop (settling a live capture is how an owed source
    /// reaches its final boundary) and a Project change (which waits for the queued
    /// save instead of racing it).
    var isCaptureSourceHeld: Bool {
        pendingCaptureIOTask != nil || isExportingSession
    }

    /// The refusal above in the user's words, or `nil` when nothing owns the source.
    var captureSourceHoldMessage: String? {
        if isExportingSession {
            return "Finish or cancel the session export before changing the capture source."
        }
        if pendingCaptureIOTask != nil {
            return "Tracexy is still saving this capture. Try again once the save has finished."
        }
        return nil
    }

    /// Resolve this Project's preference, falling back to an active real interface.
    static func resolvedDefaultInterface(defaults: UserDefaults) -> String {
        let interfaces = NetworkInterfaces.available()
        let preferred = defaults.string(forKey: SettingsKeys.defaultInterface)
        if let preferred, !preferred.isEmpty, interfaces.contains(where: { $0.id == preferred }) {
            return preferred
        }
        let active = interfaces.first { !$0.isLoopback && $0.isUp && $0.ipv4 != nil }
        let anyReal = interfaces.first { !$0.isLoopback }
        return active?.id ?? anyReal?.id ?? "en0"
    }

    // MARK: Bucket construction

    /// Build the complete runtime a Project owns: its preferences suite, its own
    /// History database, its own managed capture folder, its own live spool, and a
    /// fresh workspace store seeded from that Project's layout preferences.
    ///
    /// A Project whose settings suite cannot be created is *not* given a fallback
    /// to the shared domain — construction fails and the caller stays on the
    /// outgoing Project, so no data is ever taken in for an unresolved identity.
    ///
    /// Storage preparation is `async` because opening a Project's SQLite History
    /// and creating its Library folder is file I/O; it is prepared off the main
    /// actor from a Sendable descriptor rather than blocking every switch on it.
    func makeProjectRuntime(for project: Project) async throws -> ProjectRuntimeState {
        let isLegacyOwner = projectStore.legacyDataOwnerProjectID == project.id
        let location = projectDataProvider.location(
            forProject: project.id,
            isLegacyOwner: isLegacyOwner
        )
        guard let defaults = projectDataProvider.makeSettingsDefaults(at: location) else {
            throw ProjectRuntimeError.settingsUnavailable
        }

        // Composition-injected resources describe the pre-Projects data, so they
        // belong to the legacy owner and to no one else. A second Project always
        // gets its own store and spool.
        let canConsumeInjected = !hasBoundInitialRuntime && isLegacyOwner
        var store: SessionStore?
        var historyUnavailableReason: String?
        if canConsumeInjected, let injected = injectedSessionStore {
            store = injected
        } else {
            switch await projectDataProvider.makeSessionStore(at: location) {
            case let .ready(opened):
                store = opened
            case let .unavailable(reason):
                historyUnavailableReason = reason
            }
        }
        let spool = (canConsumeInjected ? injectedLiveCaptureSpool : nil)
            ?? projectDataProvider.makeLiveCaptureSpool(at: location)

        let capturesDirectory = await projectDataProvider.prepareCapturesDirectory(at: location)
        let preferences = WorkspaceLayoutPreferences(defaults: defaults)
        let runtime = ProjectRuntimeState(
            projectID: project.id,
            location: location,
            settingsDefaults: defaults,
            layoutPreferences: preferences,
            workspaces: WorkspaceStore(
                maxWorkspaces: policy.maxWorkspaceTabs,
                layoutPreferences: preferences,
                defaults: defaults
            ),
            sessionStore: store,
            historyUnavailableReason: historyUnavailableReason,
            liveCaptureSpool: spool,
            capturesDirectory: capturesDirectory,
            captureInterface: Self.resolvedDefaultInterface(defaults: defaults)
        )
        runtime.loadPreferenceBackedState()
        return runtime
    }

    /// Bind the launch runtime to the *hydrated* active Project rather than to the
    /// provisional identity the seed catalog carries.
    func bindInitialProjectRuntime() async throws {
        let project = projectStore.activeProject
        let runtime = try await makeProjectRuntime(for: project)
        hasBoundInitialRuntime = true
        projectRuntimes[project.id] = runtime
        adoptProjectRuntime(runtime)
    }

    // MARK: Park and adopt

    /// Copy the coordinator's live state back into the active Project's bucket.
    /// The bucket keeps the *actual* store/spool/workspace instances, so nothing is
    /// re-derived from portable configuration when the Project comes back.
    func parkActiveProjectRuntime() {
        let runtime = activeRuntime
        runtime.sessions = sessions
        runtime.investigationSnapshot = investigationSnapshot
        runtime.retainedFrames = retainedFrames
        runtime.throughputSamples = throughputSamples
        runtime.pendingChartBytes = pendingChartBytes
        runtime.captureInterface = captureInterface
        runtime.captureError = captureError
        runtime.captureStatistics = captureStatistics
        runtime.helperBufferDropCount = helperBufferDropCount
        runtime.currentLinkType = currentLinkType
        runtime.removedSessionIDs = removedSessionIDs
        // The token itself is generation-scoped and never travels; only the fact
        // that this Project's stopped spool had reached its exact final boundary.
        runtime.isStoppedCaptureReady = stoppedCaptureReadyGeneration == startGeneration
            && stoppedCaptureReadyGeneration != nil

        runtime.savedCaptures = savedCaptures
        runtime.isViewingSavedCapture = isViewingSavedCapture
        runtime.activeSavedCapture = activeSavedCapture
        runtime.savedCaptureActivity = savedCaptureActivity
        runtime.savedCaptureWarning = savedCaptureWarning
        runtime.savedCaptureEvidence = savedCaptureEvidence
        runtime.savedCaptureEvidenceURL = savedCaptureEvidenceURL
        runtime.selectedSessionEvidenceID = selectedSessionEvidenceID
        runtime.selectedSessionEvidenceBytes = selectedSessionEvidenceBytes
        runtime.selectedSessionEvidenceError = selectedSessionEvidenceError

        runtime.pinnedHosts = pinnedHosts
        runtime.focusSets = focusSets
        runtime.mutedHosts = mutedHosts
        runtime.mutedProtocols = mutedProtocols
        runtime.hiddenSourceApps = hiddenSourceApps
        runtime.hiddenSourceDomains = hiddenSourceDomains
        runtime.hiddenSourceIPs = hiddenSourceIPs

        runtime.sessionStore = sessionStore
        runtime.historyAvailability = historyAvailability
        runtime.historyCaptures = historyCaptures
        runtime.historyCaptureCursor = historyCaptureCursor
        runtime.selectedHistoryCaptureID = selectedHistoryCaptureID
        runtime.historySessions = historySessions
        runtime.historySessionCursor = historySessionCursor
        runtime.historySessionsAvailability = historySessionsAvailability
        runtime.historyAutoClear = historyAutoClear
        runtime.historyError = historyError
        runtime.historyRetentionError = historyRetentionError
        runtime.scheduledHistoryTerminals = scheduledHistoryTerminals
    }

    /// Make `runtime` the coordinator's live state.
    func adoptProjectRuntime(_ runtime: ProjectRuntimeState) {
        activeRuntime = runtime
        workspaces = runtime.workspaces
        layoutPreferences = runtime.layoutPreferences
        activeProjectDefaults = runtime.settingsDefaults
        activeCapturesDirectory = runtime.capturesDirectory
        liveCaptureSpool = runtime.liveCaptureSpool
        sessionStore = runtime.sessionStore

        // Every generation/request token is globally monotonic and is never
        // restored to an older counter. Bumping once here retires any async work
        // still stamped with the outgoing Project's token, and the restored
        // stopped-readiness marker is rebased onto the new token while the spool's
        // own opaque locator identities stay exactly as they were.
        startGeneration &+= 1
        stoppedCaptureReadyGeneration = runtime.isStoppedCaptureReady ? startGeneration : nil

        captureInterface = runtime.captureInterface
        captureError = runtime.captureError
        captureStatistics = runtime.captureStatistics
        helperBufferDropCount = runtime.helperBufferDropCount
        currentLinkType = runtime.currentLinkType
        retainedFrames = runtime.retainedFrames
        throughputSamples = runtime.throughputSamples
        pendingChartBytes = runtime.pendingChartBytes
        removedSessionIDs = runtime.removedSessionIDs
        isCapturing = false
        isStarting = false
        captureStartedAt = nil

        savedCaptures = runtime.savedCaptures
        isViewingSavedCapture = runtime.isViewingSavedCapture
        activeSavedCapture = runtime.activeSavedCapture
        savedCaptureActivity = runtime.savedCaptureActivity
        savedCaptureWarning = runtime.savedCaptureWarning
        savedCaptureEvidence = runtime.savedCaptureEvidence
        savedCaptureEvidenceURL = runtime.savedCaptureEvidenceURL
        selectedSessionEvidenceID = runtime.selectedSessionEvidenceID
        selectedSessionEvidenceBytes = runtime.selectedSessionEvidenceBytes
        selectedSessionEvidenceError = runtime.selectedSessionEvidenceError
        isLoadingSelectedSessionEvidence = false
        isOpeningSavedCapture = false
        savedCaptureOpenProgress = nil

        pinnedHosts = runtime.pinnedHosts
        focusSets = runtime.focusSets
        mutedHosts = runtime.mutedHosts
        mutedProtocols = runtime.mutedProtocols
        hiddenSourceApps = runtime.hiddenSourceApps
        hiddenSourceDomains = runtime.hiddenSourceDomains
        hiddenSourceIPs = runtime.hiddenSourceIPs

        historyAvailability = runtime.historyAvailability
        historyCaptures = runtime.historyCaptures
        historyCaptureCursor = runtime.historyCaptureCursor
        selectedHistoryCaptureID = runtime.selectedHistoryCaptureID
        historySessions = runtime.historySessions
        historySessionCursor = runtime.historySessionCursor
        historySessionsAvailability = runtime.historySessionsAvailability
        historyAutoClear = runtime.historyAutoClear
        historyError = runtime.historyError ?? runtime.historyUnavailableReason
        historyRetentionError = runtime.historyRetentionError
        scheduledHistoryTerminals = runtime.scheduledHistoryTerminals
        liveHistoryLifetime = nil
        frozenHistoryLifetime = nil

        // Sessions last: the `didSet` rebuilds correlation, and the immutable
        // snapshot adoption refreshes this Project's accepted queries and the
        // selected session's evidence projection from its own restored selection.
        sessions = runtime.sessions
        adoptInvestigation(runtime.investigationSnapshot)
        refreshSavedCaptures()
        // A read this Project had in flight when it was parked was cancelled with
        // the rest of its Project-scoped work, so restart exactly those first pages
        // against the store this Project owns.
        resumeInterruptedHistoryReads()
    }

    /// Retire every in-flight, Project-scoped async job before the store, spool and
    /// preferences references are swapped. Durable History writes are *not*
    /// cancelled here — the transition awaits them first.
    func invalidateOutgoingProjectWork() {
        suspendProjectWorkspaceObservation()

        cancelFollowStream(clearResult: true)
        cancelSavedCaptureOpen(clearPublishedEvidence: false)
        // Cancel evaluation only. A Project boundary is not a capture boundary:
        // clearing here would erase the outgoing Project's structured drafts and
        // accepted results — user state its own workspaces are keeping for it.
        cancelInFlightInvestigationQueries()

        historyTask?.cancel()
        historyTask = nil
        historyRequestID &+= 1
        historySessionTask?.cancel()
        historySessionTask = nil
        historySessionRequestID &+= 1
        historyRetentionRequestID &+= 1
    }

    // MARK: The one lifecycle path

    /// Accept a Project change. Returns `true` when the change was applied or an
    /// asynchronous transition was started, `false` when it was rejected or needs
    /// the native Stop-and-Switch confirmation first.
    @discardableResult
    func beginProjectTransition(_ kind: ProjectSwitchConfirmationRequest.Kind) -> Bool {
        guard !projectTransitionStatus.isPending, pendingProjectSwitchConfirmation == nil else {
            return false
        }
        guard projectStore.isMutable else {
            lastProjectOperationError = .storeNotReady
            return false
        }
        guard hasHydratedProjects, activeRuntime.projectID != nil else {
            lastProjectOperationError = .storeNotReady
            return false
        }
        // A session export has already read this Project's spool and is holding a
        // modal panel. Gate explicitly instead of swapping the reference under it.
        guard !isExportingSession else {
            retryableProjectTransition = kind
            projectTransitionStatus = .failed(
                "Finish or cancel the session export before changing Projects."
            )
            return false
        }
        if case let .deleteProject(id) = kind, id != projectStore.activeProjectID {
            return startProjectTransition(kind)
        }
        if isCapturing || isStarting {
            pendingProjectSwitchConfirmation = ProjectSwitchConfirmationRequest(
                id: UUID(),
                kind: kind,
                outgoingProjectName: projectStore.activeProject.name,
                destinationDescription: destinationDescription(for: kind)
            )
            return false
        }
        return startProjectTransition(kind)
    }

    func confirmPendingProjectSwitch() {
        guard let request = pendingProjectSwitchConfirmation else {
            return
        }
        pendingProjectSwitchConfirmation = nil
        _ = startProjectTransition(request.kind)
    }

    /// Cancel leaves the outgoing Project entirely untouched: the capture keeps
    /// running and no catalog mutation has been attempted.
    func cancelPendingProjectSwitch() {
        pendingProjectSwitchConfirmation = nil
    }

    func retryProjectTransition() {
        guard let kind = retryableProjectTransition else {
            return
        }
        retryableProjectTransition = nil
        projectTransitionStatus = .idle
        _ = beginProjectTransition(kind)
    }

    func dismissProjectTransitionFailure() {
        retryableProjectTransition = nil
        projectTransitionStatus = .idle
    }

    /// Test/diagnostic seam: await the asynchronous half of a transition without
    /// timing sleeps. Returns `false` when the transition ended in a failure.
    @discardableResult
    func waitForProjectTransition() async -> Bool {
        if let task = projectTransitionTask {
            _ = await task.value
        }
        return projectTransitionStatus == .idle
    }

    // MARK: Private

    private func destinationDescription(for kind: ProjectSwitchConfirmationRequest.Kind) -> String {
        switch kind {
        case let .switchProject(id):
            projectStore.projects.first { $0.id == id }?.name ?? String(localized: "another Project")
        case let .createProject(name):
            name
        case let .importProject(project):
            project.name
        case let .deleteProject(id):
            projectStore.projects.first { $0.id == id }?.name ?? String(localized: "that Project")
        }
    }

    /// Validate the change and *hold* it, then finish it asynchronously.
    ///
    /// The outgoing Project's own workspace configuration is written first — it is
    /// the last catalog mutation that still belongs to the Project being left. The
    /// candidate catalog is then prepared without being published, which freezes
    /// every other catalog and workspace mutation for the rest of the transition.
    /// Nothing else moves until the destination's storage is resolved and the
    /// candidate has been written durably.
    private func startProjectTransition(_ kind: ProjectSwitchConfirmationRequest.Kind) -> Bool {
        // Confirmation can outlive its initial eligibility check. An export may
        // have acquired the source while that sheet was open, so recheck at the
        // actual acceptance boundary before freezing or mutating the catalog.
        guard !isExportingSession else {
            retryableProjectTransition = kind
            projectTransitionStatus = .failed(
                "Finish or cancel the session export before changing Projects."
            )
            return false
        }
        preparedProjectTransition = nil
        guard flushProjectWorkspaceSnapshot() else {
            return false
        }
        let prepared: PreparedProjectCatalogTransition
        do {
            prepared = try projectStore.prepareTransition(Self.catalogTransition(for: kind))
        } catch let error as ProjectMutationError {
            lastProjectOperationError = error
            return false
        } catch {
            projectTransferErrorMessage = error.localizedDescription
            return false
        }
        // A surviving autosave debounce would only fail against the frozen catalog.
        suspendProjectWorkspaceObservation()
        preparedProjectTransition = prepared
        lastProjectOperationError = nil
        projectTransferErrorMessage = nil
        projectTransitionStatus = .pending
        retryableProjectTransition = kind
        // Retire producers before draining their write queues. A saved loader
        // finishing during destination preparation must not enqueue a late write
        // against the outgoing store after its queue was already drained.
        if prepared.destinationProject.id != activeRuntime.projectID {
            cancelSavedCaptureOpen(clearPublishedEvidence: false)
        }

        let outgoingName = projectStore.activeProject.name
        let drainAtAcceptance = pendingFinalDrainOperationID
        let originProjectID = activeRuntime.projectID
        projectTransitionTask = Task { @MainActor [weak self] in
            guard let self else {
                return false
            }
            defer {
                self.projectTransitionTask = nil
                self.preparedProjectTransition = nil
            }
            let applied = await self.finishProjectTransition(
                prepared,
                kind: kind,
                outgoingName: outgoingName,
                drainAtAcceptance: drainAtAcceptance,
                originProjectID: originProjectID
            )
            if applied {
                self.projectTransitionStatus = .idle
                self.retryableProjectTransition = nil
            } else if self.projectTransitionStatus.isPending {
                self.projectTransitionStatus = .failed(
                    self.projectOperationErrorMessage
                        ?? "Tracexy couldn’t change Projects. Nothing was discarded."
                )
            }
            return applied
        }
        return true
    }

    /// The one durable application of a prepared Project change:
    /// settle outgoing work → resolve destination storage → persist the candidate
    /// → publish catalog and runtime together. Every entry point (switch, create,
    /// import, delete-active) goes through exactly this.
    ///
    /// Each failure step leaves the outgoing Project active with its catalog,
    /// runtime and data untouched, and offers a retry. Because the catalog is only
    /// ever published after a successful write, a delete can never remove the
    /// Project a failed transition has to fall back to.
    private func finishProjectTransition(
        _ prepared: PreparedProjectCatalogTransition,
        kind: ProjectSwitchConfirmationRequest.Kind,
        outgoingName: String,
        drainAtAcceptance: Int?,
        originProjectID: UUID?
    )
        async -> Bool
    {
        // 1. Everything the outgoing Project still owes must settle first.
        let changesActiveProject = prepared.destinationProject.id != activeRuntime.projectID
        if changesActiveProject, isCapturing || isStarting {
            stopCapture()
        }
        if changesActiveProject, let operationID = pendingFinalDrainOperationID ?? drainAtAcceptance {
            let drained = await waitForFinalCaptureDrain(
                timeout: projectTransitionDrainTimeout,
                operationID: operationID
            )
            guard drained else {
                return failProjectTransition(
                    prepared,
                    kind: kind,
                    originProjectID: originProjectID,
                    message: "The capture helper didn’t confirm its final drain, so Tracexy stayed in "
                        + "“\(outgoingName)”. Nothing was discarded — recover the helper in "
                        + "Settings → Helper, then try again."
                )
            }
        }
        if changesActiveProject {
            await drainOutgoingProjectIO()
        }

        // 2. Resolve the destination's storage *before* anything is published, so a
        //    Project whose data Tracexy cannot own never becomes active.
        var runtime = projectRuntimes[prepared.destinationProject.id]
        let isFreshRuntime = runtime == nil
        if isFreshRuntime, prepared.destinationProject.id != activeRuntime.projectID {
            do {
                runtime = try await makeProjectRuntime(for: prepared.destinationProject)
            } catch {
                return failProjectTransition(
                    prepared,
                    kind: kind,
                    originProjectID: originProjectID,
                    message: (error as? ProjectRuntimeError)?.userFacingDescription
                        ?? error.localizedDescription
                )
            }
        }

        // 3. Write the candidate. Only a durable write publishes it; a failure
        //    leaves both the in-memory catalog and the file on disk as they were.
        do {
            try await projectStore.commitPreparedTransition(prepared)
        } catch {
            return failProjectTransition(
                prepared,
                kind: kind,
                originProjectID: originProjectID,
                message: "Tracexy couldn’t save the Project catalog, so it stayed in "
                    + "“\(outgoingName)”. Nothing was discarded — try again."
            )
        }

        // 4. Publish. The catalog is durable now, so the runtime swap happens in
        //    this same main-actor turn with no suspension in between.
        if let deletedProjectID = prepared.deletedProjectID {
            // Only the in-memory bucket is released. The deleted Project's History
            // database and Library folder stay exactly where they are. Unsaved
            // spool evidence is released with its deleted runtime.
            projectRuntimes.removeValue(forKey: deletedProjectID)
        }
        if let runtime, runtime !== activeRuntime {
            if isFreshRuntime {
                // A Project is hydrated from its durable configuration exactly once,
                // when its bucket is first built. A Project that has been open in
                // this app session keeps its real workspace instances — selection,
                // drafts, query results and layout — instead of being rebuilt.
                hydratePersistedWorkspaces(of: prepared.destinationProject, into: runtime)
                projectRuntimes[prepared.destinationProject.id] = runtime
            }
            parkActiveProjectRuntime()
            invalidateOutgoingProjectWork()
            adoptProjectRuntime(runtime)
        }
        resumeProjectWorkspaceObservation()
        lastProjectOperationError = nil
        projectTransferErrorMessage = nil
        return true
    }

    /// Unwind a transition that could not be completed. Nothing was published, so
    /// this releases the catalog freeze, rebuilds the outgoing Project's retired
    /// selection-scoped evidence, re-arms autosave and offers a retry.
    private func failProjectTransition(
        _ prepared: PreparedProjectCatalogTransition,
        kind: ProjectSwitchConfirmationRequest.Kind,
        originProjectID: UUID?,
        message: String
    )
        -> Bool
    {
        projectStore.discardPreparedTransition(prepared)
        restoreSelectedEvidenceAfterFailedTransition(originProjectID: originProjectID)
        resumeProjectWorkspaceObservation()
        retryableProjectTransition = kind
        projectTransitionStatus = .failed(message)
        return false
    }

    /// Accepting a transition retires the outgoing Project's selection-scoped
    /// evidence work before the destination is prepared. When the transition then
    /// fails, nothing was published: that selection is still the live one, so its
    /// projection and lazily-read saved bytes are rebuilt here rather than leaving
    /// the still-selected session with no evidence at all.
    ///
    /// Guarded by the origin Project so a failure that somehow lands after a
    /// successful publication cannot rebuild one Project's evidence inside another.
    /// Both rebuilds bump their own monotonic request ids, which retires the loader
    /// results the acceptance step cancelled. Session ids, the immutable snapshot,
    /// query drafts and accepted results are untouched — they were never cleared.
    private func restoreSelectedEvidenceAfterFailedTransition(originProjectID: UUID?) {
        guard activeRuntime.projectID == originProjectID,
              activeWorkspace.selectedSessionID != nil else
        {
            return
        }
        loadSelectedSavedCaptureEvidence()
        refreshSelectedSessionEvidenceProjection()
    }

    /// Wait for the outgoing Project's own durable work — the managed capture save
    /// and the serialized History mutation tail — to settle against the store and
    /// spool that produced it.
    ///
    /// Each queue is drained until its monotonic request identity stops advancing,
    /// so a write queued behind the one being awaited is awaited too rather than
    /// being silently abandoned after a fixed number of turns. New capture I/O and
    /// History mutations are refused while the transition is pending, so this
    /// terminates.
    private func drainOutgoingProjectIO() async {
        var awaitedSave = -1
        while let save = pendingCaptureIOTask, captureIORequestID != awaitedSave {
            awaitedSave = captureIORequestID
            await save.value
        }
        var awaitedMutation = -1
        while let mutation = historyMutationTask, historyMutationRequestID != awaitedMutation {
            awaitedMutation = historyMutationRequestID
            await mutation.value
        }
    }

    private static func catalogTransition(
        for kind: ProjectSwitchConfirmationRequest.Kind
    )
        -> ProjectCatalogTransition
    {
        switch kind {
        case let .switchProject(id): .select(id)
        case let .createProject(name): .create(name: name)
        case let .importProject(project): .adopt(project)
        case let .deleteProject(id): .delete(id)
        }
    }
}
