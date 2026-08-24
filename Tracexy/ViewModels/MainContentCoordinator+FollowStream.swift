import Foundation

// MARK: - FollowStreamProgressRelay

/// Coalesces a fast stable-source scan to at most one queued MainActor delivery.
/// Intermediate progress may collapse; the reader's terminal callback remains
/// authoritative. No bytes or partial reconstruction cross this relay.
nonisolated private final class FollowStreamProgressRelay: @unchecked Sendable {
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
            coordinator?.publishFollowStreamProgress(progress, requestID: requestID)
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

// MARK: - Follow Stream activation

@MainActor
extension MainContentCoordinator {
    /// Whether the selected session has a finite, stable local source that the
    /// explicit Follow Stream action can scan now. This is presentation guidance,
    /// not a substitute for the guards repeated when a request starts and ends.
    var followStreamUnavailableReason: String? {
        guard let sessionID = activeWorkspace.selectedSessionID,
              let session = presentedSessions.first(where: { $0.id == sessionID }) else
        {
            return "Select a session to follow its TCP stream."
        }
        guard session.protocolStack.contains(.tcp) else {
            return "Follow Stream is available for TCP sessions."
        }
        guard selectedFollowStreamTuple(sessionID: sessionID) != nil else {
            return "The bounded connection evidence for this TCP session is no longer retained."
        }
        if isCapturing || isStarting {
            return "Stop the live capture before following this stream."
        }
        if isViewingSavedCapture {
            guard savedCaptureEvidenceURL != nil,
                  savedCaptureEvidence[sessionID] != nil else
            {
                return "The saved capture source for this session is unavailable."
            }
            return nil
        }
        guard stoppedCaptureReadyGeneration == startGeneration else {
            return sessions.isEmpty
                ? "No stable capture source is available."
                : "The stopped capture is still finalizing its local source."
        }
        return nil
    }

    var followStreamFraction: Double? {
        guard let progress = followStreamProgress, progress.totalBytes > 0 else {
            return nil
        }
        return min(max(Double(progress.bytesConsumed) / Double(progress.totalBytes), 0), 1)
    }

    /// Starts one explicit, selection-scoped scan. Saved files are identity-checked
    /// against the evidence adopted at open; stopped-live data is first copied to
    /// an unexposed immutable temporary PCAPNG after the final-ingest generation is
    /// ready. A growing active spool is deliberately rejected.
    func followSelectedTCPStream() {
        cancelFollowStream(clearResult: true)
        followStreamRequestID &+= 1
        let requestID = followStreamRequestID

        guard followStreamUnavailableReason == nil,
              let sessionID = activeWorkspace.selectedSessionID,
              let tuple = selectedFollowStreamTuple(sessionID: sessionID) else
        {
            followStreamError = followStreamUnavailableReason
            return
        }

        let expectedGeneration = startGeneration
        let relay = FollowStreamProgressRelay(coordinator: self, requestID: requestID)
        isLoadingFollowStream = true
        followStreamProgress = nil
        followStreamError = nil

        if isViewingSavedCapture,
           let url = savedCaptureEvidenceURL,
           let identity = savedCaptureEvidence[sessionID]?.identity
        {
            followStreamTask = makeSavedFollowStreamTask(
                url: url,
                identity: identity,
                tuple: tuple,
                sessionID: sessionID,
                requestID: requestID,
                expectedGeneration: expectedGeneration,
                relay: relay
            )
        } else {
            followStreamTask = makeStoppedLiveFollowStreamTask(
                tuple: tuple,
                sessionID: sessionID,
                requestID: requestID,
                expectedGeneration: expectedGeneration,
                relay: relay
            )
        }
    }

    func cancelFollowStream(clearResult: Bool) {
        followStreamTask?.cancel()
        followStreamTask = nil
        followStreamRequestID &+= 1
        isLoadingFollowStream = false
        followStreamProgress = nil
        followStreamError = nil
        if clearResult {
            followStreamResult = nil
        }
    }

    /// Test/diagnostic seam for the exact task handle; no wall-clock sleep needed.
    func waitForFollowStream() async {
        let task = followStreamTask
        await task?.value
    }

    // MARK: Internal activation callbacks

    func publishFollowStreamProgress(_ progress: PcapStreamProgress, requestID: Int) {
        guard requestID == followStreamRequestID, isLoadingFollowStream else {
            return
        }
        if let current = followStreamProgress,
           progress.bytesConsumed < current.bytesConsumed
        {
            return
        }
        followStreamProgress = progress
    }

    // MARK: Private

    private func selectedFollowStreamTuple(sessionID: UUID) -> FiveTuple? {
        connectionSnapshot.summaries.lazy
            .map(\.tuple)
            .first { tuple in
                tuple.proto == .tcp && SessionBuilder.sessionID(for: tuple) == sessionID
            }
    }

    private func makeSavedFollowStreamTask(
        url: URL,
        identity: PcapFileIdentity,
        tuple: FiveTuple,
        sessionID: UUID,
        requestID: Int,
        expectedGeneration: Int,
        relay: FollowStreamProgressRelay
    )
        -> Task<Void, Never>
    {
        Task.detached(priority: .userInitiated) { [weak self] in
            do {
                let reader = try FollowStreamReader(
                    contentsOf: url,
                    expectedIdentity: identity,
                    tuple: tuple
                )
                let result = try reader.read(onProgress: relay.submit)
                try Task.checkCancellation()
                await self?.finishFollowStream(
                    result,
                    sessionID: sessionID,
                    requestID: requestID,
                    expectedGeneration: expectedGeneration,
                    expectedSavedURL: url
                )
            } catch is CancellationError {
                await self?.finishCancelledFollowStream(requestID: requestID)
            } catch {
                await self?.finishFollowStreamFailure(
                    Self.followStreamMessage(for: error),
                    sessionID: sessionID,
                    requestID: requestID,
                    expectedGeneration: expectedGeneration
                )
            }
        }
    }

    private func makeStoppedLiveFollowStreamTask(
        tuple: FiveTuple,
        sessionID: UUID,
        requestID: Int,
        expectedGeneration: Int,
        relay: FollowStreamProgressRelay
    )
        -> Task<Void, Never>
    {
        let spool = liveCaptureSpool
        return Task.detached(priority: .userInitiated) { [weak self] in
            let temporaryURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("tracexy-follow-\(UUID().uuidString).pcapng")
            defer { try? FileManager.default.removeItem(at: temporaryURL) }
            do {
                try Task.checkCancellation()
                try await spool.copy(to: temporaryURL)
                try Task.checkCancellation()

                let handle = try FileHandle(forReadingFrom: temporaryURL)
                let identity = PcapFileIdentity.snapshot(of: handle)
                try handle.close()
                let reader = try FollowStreamReader(
                    contentsOf: temporaryURL,
                    expectedIdentity: identity,
                    tuple: tuple
                )
                let result = try reader.read(onProgress: relay.submit)
                try Task.checkCancellation()
                await self?.finishFollowStream(
                    result,
                    sessionID: sessionID,
                    requestID: requestID,
                    expectedGeneration: expectedGeneration,
                    expectedSavedURL: nil
                )
            } catch is CancellationError {
                await self?.finishCancelledFollowStream(requestID: requestID)
            } catch {
                await self?.finishFollowStreamFailure(
                    Self.followStreamMessage(for: error),
                    sessionID: sessionID,
                    requestID: requestID,
                    expectedGeneration: expectedGeneration
                )
            }
        }
    }

    private func finishFollowStream(
        _ result: FollowStreamResult,
        sessionID: UUID,
        requestID: Int,
        expectedGeneration: Int,
        expectedSavedURL: URL?
    ) {
        guard requestID == followStreamRequestID,
              startGeneration == expectedGeneration,
              activeWorkspace.selectedSessionID == sessionID else
        {
            return
        }
        if let expectedSavedURL {
            guard isViewingSavedCapture, savedCaptureEvidenceURL == expectedSavedURL else {
                return
            }
        } else {
            guard !isViewingSavedCapture,
                  !isCapturing,
                  !isStarting,
                  stoppedCaptureReadyGeneration == expectedGeneration else
            {
                return
            }
        }
        followStreamResult = result
        followStreamProgress = result.finalProgress
        followStreamError = nil
        isLoadingFollowStream = false
        followStreamTask = nil
    }

    private func finishCancelledFollowStream(requestID: Int) {
        guard requestID == followStreamRequestID else {
            return
        }
        isLoadingFollowStream = false
        followStreamProgress = nil
        followStreamTask = nil
    }

    private func finishFollowStreamFailure(
        _ message: String,
        sessionID: UUID,
        requestID: Int,
        expectedGeneration: Int
    ) {
        guard requestID == followStreamRequestID,
              startGeneration == expectedGeneration,
              activeWorkspace.selectedSessionID == sessionID else
        {
            return
        }
        followStreamResult = nil
        followStreamError = message
        isLoadingFollowStream = false
        followStreamTask = nil
    }

    nonisolated private static func followStreamMessage(for error: Error) -> String {
        if let error = error as? FollowStreamError {
            switch error {
            case .identityMismatch:
                return "The capture source changed before the stream scan completed."
            case .tupleNotTCP:
                return "Follow Stream is available for TCP sessions."
            }
        }
        if let localized = error as? LocalizedError,
           let description = localized.errorDescription
        {
            return description
        }
        return error.localizedDescription
    }
}
