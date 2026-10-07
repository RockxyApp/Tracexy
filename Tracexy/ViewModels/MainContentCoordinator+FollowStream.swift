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

// MARK: - FollowOutcome

/// What one follow request produced: a reconstructed TCP byte stream or a UDP
/// conversation's datagrams. Private to the activation workflow, which publishes
/// each into its own coordinator slot.
nonisolated private enum FollowOutcome: Sendable {
    case stream(FollowStreamResult)
    case datagrams(FollowDatagramResult)

    // MARK: Internal

    var finalProgress: PcapStreamProgress {
        switch self {
        case let .stream(result): result.finalProgress
        case let .datagrams(result): result.finalProgress
        }
    }
}

// MARK: - FollowTarget

/// The conversation a follow request reads: the canonical tuple, whose protocol
/// picks the reader.
nonisolated private struct FollowTarget: Sendable {
    let tuple: FiveTuple

    /// Run the matching reader over a stable file. Pure and synchronous; the caller
    /// owns the detached task and every guard.
    func read(
        url: URL,
        identity: PcapFileIdentity,
        sourceToken: UUID?,
        onProgress: (PcapStreamProgress) -> Void
    )
        throws -> FollowOutcome
    {
        if tuple.proto == .udp {
            let reader = try FollowDatagramReader(
                contentsOf: url, expectedIdentity: identity, tuple: tuple, sourceToken: sourceToken
            )
            return try .datagrams(reader.read(onProgress: onProgress))
        }
        let reader = try FollowStreamReader(
            contentsOf: url, expectedIdentity: identity, tuple: tuple, sourceToken: sourceToken
        )
        return try .stream(reader.read(onProgress: onProgress))
    }
}

// MARK: - Follow Stream activation

@MainActor
extension MainContentCoordinator {
    /// Whether the selected session has a finite, stable local source that the
    /// explicit Follow action can scan now. This is presentation guidance, not a
    /// substitute for the guards repeated when a request starts and ends.
    var followStreamUnavailableReason: String? {
        guard let sessionID = activeWorkspace.selectedSessionID,
              let session = presentedSessions.first(where: { $0.id == sessionID }) else
        {
            return "Select a session to follow its conversation."
        }
        guard session.protocolStack.contains(.tcp) || session.protocolStack.contains(.udp) else {
            return "Follow is available for TCP and UDP sessions."
        }
        guard selectedFollowTarget(sessionID: sessionID) != nil else {
            return session.protocolStack.contains(.tcp)
                ? "The bounded connection evidence for this TCP session is no longer retained."
                : "The endpoints of this UDP session are not known."
        }
        if isCapturing || isStarting {
            return "Stop the live capture before following this conversation."
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

    /// Whether the selected session would be followed as datagrams (UDP) rather
    /// than as a reconstructed byte stream (TCP).
    var followsSelectedSessionAsDatagrams: Bool {
        guard let sessionID = activeWorkspace.selectedSessionID,
              let session = presentedSessions.first(where: { $0.id == sessionID }) else
        {
            return false
        }
        return !session.protocolStack.contains(.tcp) && session.protocolStack.contains(.udp)
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
    /// ready. A growing active spool is deliberately rejected. TCP sessions are
    /// reconstructed as byte streams; UDP sessions are listed datagram by datagram.
    func followSelectedStream() {
        cancelFollowStream(clearResult: true)
        followStreamRequestID &+= 1
        let requestID = followStreamRequestID

        guard followStreamUnavailableReason == nil,
              let sessionID = activeWorkspace.selectedSessionID,
              let target = selectedFollowTarget(sessionID: sessionID) else
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
            followStreamTask = makeSavedFollowTask(
                url: url,
                identity: identity,
                target: target,
                sessionID: sessionID,
                requestID: requestID,
                expectedGeneration: expectedGeneration,
                relay: relay
            )
        } else {
            followStreamTask = makeStoppedLiveFollowTask(
                target: target,
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
            followDatagramResult = nil
        }
    }

    /// Open the exact frame a follow transcript cites (a TCP run's first frame or
    /// one datagram) through the guarded cited-frame path. A provenance without a
    /// locator lands on the explicit unavailable state, never a substitute frame.
    func inspectFollowedFrame(_ provenance: SessionFrameProvenance) {
        guard let sessionID = activeWorkspace.selectedSessionID else {
            return
        }
        inspectCitedFrame(sessionID: sessionID, provenance: provenance)
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

    private func selectedFollowTarget(sessionID: UUID) -> FollowTarget? {
        if let tuple = connectionSnapshot.summaries.lazy
            .map(\.tuple)
            .first(where: { $0.proto == .tcp && SessionBuilder.sessionID(for: $0) == sessionID })
        {
            return FollowTarget(tuple: tuple)
        }
        // A UDP session has no connection summary; its identity is the canonical
        // tuple of its two endpoints, checked against the session id so a stale or
        // mismatched endpoint pair can never pick another conversation.
        guard let session = presentedSessions.first(where: { $0.id == sessionID }),
              !session.protocolStack.contains(.tcp),
              session.protocolStack.contains(.udp),
              let source = session.sourceEndpointValue,
              let destination = session.destinationEndpointValue else
        {
            return nil
        }
        let tuple = FiveTuple(proto: .udp, source: source, destination: destination)
        return SessionBuilder.sessionID(for: tuple) == sessionID ? FollowTarget(tuple: tuple) : nil
    }

    private func makeSavedFollowTask(
        url: URL,
        identity: PcapFileIdentity,
        target: FollowTarget,
        sessionID: UUID,
        requestID: Int,
        expectedGeneration: Int,
        relay: FollowStreamProgressRelay
    )
        -> Task<Void, Never>
    {
        let token = SavedCaptureStreamLoader.sourceToken(for: identity)
        return Task.detached(priority: .userInitiated) { [weak self] in
            do {
                let outcome = try target.read(
                    url: url, identity: identity, sourceToken: token, onProgress: relay.submit
                )
                try Task.checkCancellation()
                await self?.finishFollow(
                    outcome,
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

    private func makeStoppedLiveFollowTask(
        target: FollowTarget,
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
                // The copy is byte-identical, so its payload offsets are the spool's
                // own and the spool's token makes each cited frame navigable.
                let token = await spool.currentSourceToken()
                try await spool.copy(to: temporaryURL)
                try Task.checkCancellation()

                let handle = try FileHandle(forReadingFrom: temporaryURL)
                let identity = PcapFileIdentity.snapshot(of: handle)
                try handle.close()
                let outcome = try target.read(
                    url: temporaryURL, identity: identity, sourceToken: token, onProgress: relay.submit
                )
                try Task.checkCancellation()
                await self?.finishFollow(
                    outcome,
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

    private func finishFollow(
        _ outcome: FollowOutcome,
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
        switch outcome {
        case let .stream(result):
            followStreamResult = result
            followDatagramResult = nil
        case let .datagrams(result):
            followDatagramResult = result
            followStreamResult = nil
        }
        followStreamProgress = outcome.finalProgress
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
        followDatagramResult = nil
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
            case .tupleNotUDP:
                return "Follow Conversation is available for UDP sessions."
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
