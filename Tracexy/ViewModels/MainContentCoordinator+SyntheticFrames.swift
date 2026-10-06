import Foundation

#if DEBUG

// MARK: - Synthetic frames

@MainActor
extension MainContentCoordinator {
    /// Adopts `frames` as the open capture through the real spool and session
    /// fold, with no capture device. A Debug-build demo launch uses it to fill its
    /// isolated runtime with synthetic evidence. Returns `false` when there is
    /// nothing to adopt or the fold yields no snapshot.
    func adoptSyntheticFrames(_ frames: [CapturedFrame], linkType: UInt32) async throws -> Bool {
        guard !frames.isEmpty, !isCapturing, !isStarting else {
            return false
        }
        let token = startGeneration
        resetSessionEngine(token: token)
        await ingestChain?.value
        let appended = try await liveCaptureSpool.append(frames, defaultLinkType: linkType, epoch: token)
        let locators: [SessionEvidenceLocator]? = if case let .appended(values) = appended,
                                                     values.count == frames.count
        {
            values
        } else {
            nil
        }
        await sessionEngine.ingest(
            frames,
            linkType: linkType,
            epoch: token,
            locators: locators,
            loss: .noLossReported
        )
        guard let snapshot = await sessionEngine.investigationSnapshot(epoch: token) else {
            return false
        }
        retainedFrames.reset()
        appendRetainedFrames(frames)
        currentLinkType = linkType
        sessions = snapshot.sessions
        adoptInvestigation(snapshot)
        return true
    }
}
#endif
