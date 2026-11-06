import Foundation

@MainActor
extension MainContentCoordinator {
    func requestAllFramesSelection(ordinal: UInt64, sourceToken: UUID) async throws {
        let requestID = UUID()
        allFrames.externalSelectionRequestID = requestID
        allFrames.externalSelectionRequest = nil
        var published = false
        defer {
            if !published, allFrames.externalSelectionRequestID == requestID {
                allFrames.externalSelectionRequestID = nil
            }
        }
        guard ordinal > 0, allFramesUnavailableReason == nil else {
            throw CancellationError()
        }
        let projectID = projectStore.activeProjectID
        let generation = startGeneration
        let frameListRequestID = allFrames.requestID
        let savedIdentity = isViewingSavedCapture ? adoptedSavedCaptureIdentity : nil
        let savedURL = isViewingSavedCapture ? savedCaptureEvidenceURL : nil
        guard isViewingSavedCapture == (savedIdentity != nil) else {
            throw CancellationError()
        }
        if let savedIdentity {
            guard let savedURL,
                  SavedCaptureStreamLoader.sourceToken(for: savedIdentity) == sourceToken,
                  try await Self.currentFileIdentity(at: savedURL) == savedIdentity else
            {
                throw CancellationError()
            }
        } else {
            let spool = liveCaptureSpool
            guard await spool.currentSourceToken() == sourceToken,
                  liveCaptureSpool === spool else
            {
                throw CancellationError()
            }
        }
        guard generation == startGeneration, projectID == projectStore.activeProjectID,
              savedIdentity == (isViewingSavedCapture ? adoptedSavedCaptureIdentity : nil),
              savedURL == (isViewingSavedCapture ? savedCaptureEvidenceURL : nil),
              allFrames.requestID == frameListRequestID,
              allFrames.externalSelectionRequestID == requestID,
              allFramesUnavailableReason == nil else
        {
            throw CancellationError()
        }
        allFrames.externalSelectionRequest = AllFramesExternalSelectionRequest(
            id: requestID, ordinal: ordinal, projectID: projectID, generation: generation,
            sourceToken: sourceToken, savedIdentity: savedIdentity, frameListRequestID: frameListRequestID
        )
        published = true
    }

    func validatesAllFramesSelection(_ request: AllFramesExternalSelectionRequest) async -> Bool {
        guard request.projectID == projectStore.activeProjectID,
              request.id == allFrames.externalSelectionRequestID,
              request.generation == startGeneration,
              allFramesUnavailableReason == nil,
              request.savedIdentity == (isViewingSavedCapture ? adoptedSavedCaptureIdentity : nil) else
        {
            return false
        }
        if let identity = request.savedIdentity {
            guard let url = isViewingSavedCapture ? savedCaptureEvidenceURL : nil,
                  SavedCaptureStreamLoader.sourceToken(for: identity) == request.sourceToken else
            {
                return false
            }
            let currentIdentity = try? await Self.currentFileIdentity(at: url)
            guard currentIdentity == identity else {
                return false
            }
            return request.id == allFrames.externalSelectionRequestID
                && request.projectID == projectStore.activeProjectID
                && request.generation == startGeneration
                && savedCaptureEvidenceURL == url
                && adoptedSavedCaptureIdentity == identity
                && allFramesUnavailableReason == nil
        }
        let spool = liveCaptureSpool
        let currentToken = await spool.currentSourceToken()
        return currentToken == request.sourceToken
            && liveCaptureSpool === spool
            && request.id == allFrames.externalSelectionRequestID
            && request.projectID == projectStore.activeProjectID
            && request.generation == startGeneration
            && adoptedSavedCaptureIdentity == nil
            && allFramesUnavailableReason == nil
    }

    nonisolated private static func currentFileIdentity(at url: URL) async throws -> PcapFileIdentity {
        try await Task.detached(priority: .utility) {
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            return PcapFileIdentity.snapshot(of: handle)
        }.value
    }
}
