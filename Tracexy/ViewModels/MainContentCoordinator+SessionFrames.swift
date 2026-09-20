import Foundation

// MARK: - Frames facet

/// The selected session's frame list, rescanned on demand from the same stable
/// sources Follow Stream accepts: the open saved file (identity-checked against
/// the adopted evidence) or a byte-identical copy of the stopped live spool. A
/// growing active spool is refused. Results are adopted behind request-id,
/// generation and selection guards, and cleared at every source boundary.
@MainActor
extension MainContentCoordinator {
    /// Why the Frames facet cannot scan right now, or `nil` when it can.
    var sessionFramesUnavailableReason: String? {
        guard let sessionID = activeWorkspace.selectedSessionID,
              presentedSessions.contains(where: { $0.id == sessionID }) else
        {
            return "Select a session to list its frames."
        }
        if isCapturing || isStarting {
            return "Stop the live capture to list this session’s frames."
        }
        if isViewingSavedCapture {
            guard savedCaptureEvidenceURL != nil, adoptedSavedCaptureIdentity != nil else {
                return "The saved capture source for this session is unavailable."
            }
            return nil
        }
        guard stoppedCaptureReadyGeneration == startGeneration else {
            return sessions.isEmpty
                ? "No stable capture source is available."
                : "The stopped capture is still being finalized."
        }
        return nil
    }

    /// Whether the Frames tab should be offered for the selected session.
    var hasSessionFrameSource: Bool {
        guard activeWorkspace.selectedSessionID != nil, !isCapturing, !isStarting else {
            return false
        }
        if isViewingSavedCapture {
            return savedCaptureEvidenceURL != nil
        }
        return stoppedCaptureReadyGeneration == startGeneration && !sessions.isEmpty
    }

    var sessionFramesFraction: Double? {
        guard let progress = sessionFramesProgress, progress.totalBytes > 0 else {
            return nil
        }
        return min(max(Double(progress.bytesConsumed) / Double(progress.totalBytes), 0), 1)
    }

    /// Start one scan for the selected session. A result for the same session and
    /// source is kept; anything else is replaced.
    func loadSelectedSessionFrames(force: Bool = false) {
        guard let sessionID = activeWorkspace.selectedSessionID else {
            cancelSessionFrames(clearResult: true)
            return
        }
        if !force, let result = sessionFramesResult, result.sessionID == sessionID {
            return
        }
        if !force, isLoadingSessionFrames, sessionFramesTask != nil, loadingSessionFramesSessionID == sessionID {
            return
        }
        cancelSessionFrames(clearResult: true)
        if let reason = sessionFramesUnavailableReason {
            sessionFramesError = reason
            return
        }
        sessionFramesRequestID &+= 1
        let requestID = sessionFramesRequestID
        let expectedGeneration = startGeneration
        let client = sessions.first(where: { $0.id == sessionID })?.sourceEndpointValue
        let relay = CoordinatorProgressRelay(coordinator: self, requestID: requestID) { coordinator, progress, id in
            guard id == coordinator.sessionFramesRequestID, coordinator.isLoadingSessionFrames else {
                return
            }
            if let current = coordinator.sessionFramesProgress, progress.bytesConsumed < current.bytesConsumed {
                return
            }
            coordinator.sessionFramesProgress = progress
        }
        isLoadingSessionFrames = true
        loadingSessionFramesSessionID = sessionID
        sessionFramesProgress = nil
        sessionFramesError = nil

        if isViewingSavedCapture, let url = savedCaptureEvidenceURL, let identity = adoptedSavedCaptureIdentity {
            let token = SavedCaptureStreamLoader.sourceToken(for: identity)
            sessionFramesTask = Task.detached(priority: .userInitiated) { [weak self] in
                do {
                    let scanner = try SessionFrameScanner(
                        contentsOf: url, expectedIdentity: identity, sessionID: sessionID,
                        sourceToken: token, clientEndpoint: client
                    )
                    let result = try scanner.scan(onProgress: relay.submit)
                    try Task.checkCancellation()
                    await self?.finishSessionFrames(
                        result, requestID: requestID, expectedGeneration: expectedGeneration, expectedSavedURL: url
                    )
                } catch is CancellationError {
                    await self?.finishCancelledSessionFrames(requestID: requestID)
                } catch {
                    await self?.failSessionFrames(
                        Self.sessionFramesMessage(for: error), requestID: requestID,
                        expectedGeneration: expectedGeneration
                    )
                }
            }
        } else {
            let spool = liveCaptureSpool
            sessionFramesTask = Task.detached(priority: .userInitiated) { [weak self] in
                let temporaryURL = FileManager.default.temporaryDirectory
                    .appendingPathComponent("tracexy-frames-\(UUID().uuidString).pcapng")
                defer { try? FileManager.default.removeItem(at: temporaryURL) }
                do {
                    try Task.checkCancellation()
                    guard let token = await spool.currentSourceToken() else {
                        throw FollowStreamError.identityMismatch
                    }
                    try await spool.copy(to: temporaryURL)
                    try Task.checkCancellation()
                    let handle = try FileHandle(forReadingFrom: temporaryURL)
                    let identity = PcapFileIdentity.snapshot(of: handle)
                    try handle.close()
                    let scanner = try SessionFrameScanner(
                        contentsOf: temporaryURL, expectedIdentity: identity, sessionID: sessionID,
                        sourceToken: token, clientEndpoint: client
                    )
                    let result = try scanner.scan(onProgress: relay.submit)
                    try Task.checkCancellation()
                    await self?.finishSessionFrames(
                        result, requestID: requestID, expectedGeneration: expectedGeneration, expectedSavedURL: nil
                    )
                } catch is CancellationError {
                    await self?.finishCancelledSessionFrames(requestID: requestID)
                } catch {
                    await self?.failSessionFrames(
                        Self.sessionFramesMessage(for: error), requestID: requestID,
                        expectedGeneration: expectedGeneration
                    )
                }
            }
        }
    }

    func cancelSessionFrames(clearResult: Bool) {
        sessionFramesTask?.cancel()
        sessionFramesTask = nil
        sessionFramesRequestID &+= 1
        isLoadingSessionFrames = false
        loadingSessionFramesSessionID = nil
        sessionFramesProgress = nil
        sessionFramesError = nil
        if clearResult {
            sessionFramesResult = nil
        }
    }

    /// Test/diagnostic seam for the exact task handle.
    func waitForSessionFrames() async {
        let task = sessionFramesTask
        await task?.value
    }

    /// A row in the Frames facet: load that exact frame into Layers/Hex through
    /// the guarded cited-frame path.
    func inspectSessionFrame(_ frame: SessionFrameReference) {
        guard let sessionID = activeWorkspace.selectedSessionID,
              sessionFramesResult?.sessionID == sessionID else
        {
            return
        }
        inspectCitedFrame(sessionID: sessionID, provenance: frame.provenance)
    }

    // MARK: Private

    private func finishSessionFrames(
        _ result: SessionFramesResult,
        requestID: Int,
        expectedGeneration: Int,
        expectedSavedURL: URL?
    ) {
        guard requestID == sessionFramesRequestID,
              startGeneration == expectedGeneration,
              activeWorkspace.selectedSessionID == result.sessionID else
        {
            return
        }
        if let expectedSavedURL {
            guard isViewingSavedCapture, savedCaptureEvidenceURL == expectedSavedURL else {
                return
            }
        } else {
            guard !isViewingSavedCapture, !isCapturing, !isStarting,
                  stoppedCaptureReadyGeneration == expectedGeneration else
            {
                return
            }
        }
        sessionFramesResult = result
        sessionFramesProgress = result.finalProgress
        sessionFramesError = nil
        isLoadingSessionFrames = false
        loadingSessionFramesSessionID = nil
        sessionFramesTask = nil
    }

    private func finishCancelledSessionFrames(requestID: Int) {
        guard requestID == sessionFramesRequestID else {
            return
        }
        isLoadingSessionFrames = false
        loadingSessionFramesSessionID = nil
        sessionFramesProgress = nil
        sessionFramesTask = nil
    }

    private func failSessionFrames(_ message: String, requestID: Int, expectedGeneration: Int) {
        guard requestID == sessionFramesRequestID, startGeneration == expectedGeneration else {
            return
        }
        sessionFramesError = message
        isLoadingSessionFrames = false
        loadingSessionFramesSessionID = nil
        sessionFramesProgress = nil
        sessionFramesTask = nil
    }

    private static func sessionFramesMessage(for error: any Error) -> String {
        if case FollowStreamError.identityMismatch = error {
            return "The capture file changed on disk. Reload the capture, then list the frames again."
        }
        return "Couldn’t list this session’s frames: \(error.localizedDescription)"
    }
}
