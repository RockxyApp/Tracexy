import Foundation

// MARK: - All Frames

/// View ▸ All Frames: every frame of the capture, rescanned on demand from the same
/// stable sources the Frames facet accepts (the open saved file, identity-checked, or
/// a byte-identical copy of the stopped live spool). A growing live spool is refused.
@MainActor
extension MainContentCoordinator {
    /// Why the capture's frames cannot be listed now, or `nil` when they can.
    var allFramesUnavailableReason: String? {
        if isCapturing || isStarting {
            return String(localized: "Stop the live capture to list its frames.")
        }
        if isViewingSavedCapture {
            return savedCaptureEvidenceURL != nil && adoptedSavedCaptureIdentity != nil
                ? nil : String(localized: "The saved capture source is unavailable.")
        }
        guard !sessions.isEmpty else {
            return String(localized: "Open a capture file or stop a live capture to list its frames.")
        }
        return stoppedCaptureReadyGeneration == startGeneration
            ? nil : String(localized: "The stopped capture is still being finalized.")
    }

    func loadAllFrames(force: Bool = false) {
        let state = allFrames
        if !force, state.list != nil || state.isLoading {
            return
        }
        state.cancel(clearList: true)
        if let reason = allFramesUnavailableReason {
            state.error = reason
            return
        }
        let requestID = state.requestID
        let generation = startGeneration
        let relay = CoordinatorProgressRelay(coordinator: self, requestID: requestID) { coordinator, progress, id in
            guard id == coordinator.allFrames.requestID, coordinator.allFrames.isLoading else {
                return
            }
            if let current = coordinator.allFrames.progress, progress.bytesConsumed < current.bytesConsumed {
                return
            }
            coordinator.allFrames.progress = progress
        }
        state.isLoading = true
        let savedURL = isViewingSavedCapture ? savedCaptureEvidenceURL : nil
        let savedIdentity = adoptedSavedCaptureIdentity
        let spool = liveCaptureSpool
        let columns = packetDetailOptions.frameColumns
        state.task = Task.detached(priority: .userInitiated) { [weak self] in
            let temporaryURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("tracexy-all-frames-\(UUID().uuidString).pcapng")
            defer { try? FileManager.default.removeItem(at: temporaryURL) }
            do {
                let source = try await Self.frameToolSource(
                    savedURL: savedURL, savedIdentity: savedIdentity, spool: spool, temporaryURL: temporaryURL
                )
                let scanner = try CaptureFrameListScanner(
                    contentsOf: source.url, expectedIdentity: source.identity, sourceToken: source.token,
                    configuration: .init(columns: columns)
                )
                let list = try scanner.scan(onProgress: relay.submit)
                try Task.checkCancellation()
                await self?.finishAllFrames(list, requestID: requestID, generation: generation)
            } catch is CancellationError {
                await self?.finishAllFrames(nil, requestID: requestID, generation: generation)
            } catch {
                await self?.failAllFrames(error, requestID: requestID, generation: generation)
            }
        }
    }

    /// The stable file the frame tools rescan: the open saved capture itself, or a
    /// byte-identical copy of the stopped live spool written to `temporaryURL`.
    nonisolated static func frameToolSource(
        savedURL: URL?,
        savedIdentity: PcapFileIdentity?,
        spool: LiveCaptureSpool,
        temporaryURL: URL
    )
        async throws -> (url: URL, identity: PcapFileIdentity, token: UUID)
    {
        if let savedURL, let savedIdentity {
            return (savedURL, savedIdentity, SavedCaptureStreamLoader.sourceToken(for: savedIdentity))
        }
        guard let token = await spool.currentSourceToken() else {
            throw FollowStreamError.identityMismatch
        }
        try await spool.copy(to: temporaryURL)
        let handle = try FileHandle(forReadingFrom: temporaryURL)
        let identity = PcapFileIdentity.snapshot(of: handle)
        try handle.close()
        return (temporaryURL, identity, token)
    }

    /// Find Packet: the numbers of the frames whose bytes or details match `query`,
    /// read off the main actor from the same stable source All Frames lists.
    func findFrames(matching query: FrameSearchQuery) async throws -> [UInt64] {
        if let reason = allFramesUnavailableReason {
            throw FrameSearchQuery.Invalid(message: reason)
        }
        let savedURL = isViewingSavedCapture ? savedCaptureEvidenceURL : nil
        let savedIdentity = adoptedSavedCaptureIdentity
        let spool = liveCaptureSpool
        return try await Task.detached(priority: .userInitiated) {
            let temporaryURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("tracexy-find-\(UUID().uuidString).pcapng")
            defer { try? FileManager.default.removeItem(at: temporaryURL) }
            let source = try await Self.frameToolSource(
                savedURL: savedURL, savedIdentity: savedIdentity, spool: spool, temporaryURL: temporaryURL
            )
            return try FrameContentSearch.matches(in: source.url, expectedIdentity: source.identity, query: query)
        }.value
    }

    /// Go to frame `ordinal` as a click on its All Frames row would, listing the
    /// frames first when they are not listed yet. Returns why it cannot, if it cannot.
    @discardableResult
    func goToFrame(_ ordinal: UInt64) -> String? {
        guard let list = allFrames.list, !allFrames.isLoading else {
            allFrames.pendingReveal = ordinal
            loadAllFrames()
            return nil
        }
        guard let row = list.rows.first(where: { $0.ordinal == ordinal }), revealFrame(row) else {
            return String(localized: "Frame \(ordinal.formatted())'s session is not in view.")
        }
        return nil
    }

    /// A row's double-click: select its session in the full table and load that
    /// exact frame in Layers. A frame whose session is not in view (or that belongs
    /// to none) cannot be shown there, and says so.
    @discardableResult
    func revealFrame(_ row: CaptureFrameRow) -> Bool {
        guard let sessionID = row.sessionID, let session = visibleSessions.first(where: { $0.id == sessionID }) else {
            return false
        }
        openSessionsPreservingScope()
        // Open the inspector first, so the row is scrolled into the table's final,
        // shorter viewport rather than into one the inspector then covers.
        if activeWorkspace.inspectorLayout == .hidden {
            toggleInspectorBottom()
        }
        select(session)
        inspectCitedFrame(sessionID: session.id, provenance: row.provenance)
        return true
    }

    /// Clears what the frame tools hold about the capture being replaced: its frame
    /// list, marks, ignores and comments, a time reference naming one of its frames,
    /// the bytes Show Packet Bytes shows, and the pending Decode Again prompt (a
    /// capture decoded from here on uses the current Decode As rules).
    func retireCaptureLocalTools() {
        sessionTimeDisplay.frameReference = nil
        sessionTimeDisplay.selectedFrame = nil
        packetBytesInspection.subject = nil
        allFrames.cancel(clearList: true)
        exportObjects.cancel(clearLists: true)
        decodeAs.needsRedecode = false
    }

    // MARK: Private

    private func finishAllFrames(_ list: CaptureFrameList?, requestID: Int, generation: Int) {
        guard requestID == allFrames.requestID, generation == startGeneration else {
            return
        }
        allFrames.isLoading = false
        allFrames.progress = nil
        allFrames.task = nil
        if let list {
            allFrames.list = list
            // `-g N` at launch: go to that frame once it is listed.
            if let ordinal = allFrames.pendingReveal {
                allFrames.pendingReveal = nil
                if let row = list.rows.first(where: { $0.ordinal == ordinal }), !revealFrame(row) {
                    captureError = String(localized: "Frame \(ordinal.formatted())'s session is not in view.")
                }
            }
        }
    }

    private func failAllFrames(_ error: any Error, requestID: Int, generation: Int) {
        guard requestID == allFrames.requestID, generation == startGeneration else {
            return
        }
        allFrames.isLoading = false
        allFrames.progress = nil
        allFrames.task = nil
        allFrames.error = if case FollowStreamError.identityMismatch = error {
            String(localized: "The capture file changed on disk. Reload the capture, then list its frames again.")
        } else {
            String(localized: "Couldn’t list the capture’s frames: \(error.localizedDescription)")
        }
    }
}
