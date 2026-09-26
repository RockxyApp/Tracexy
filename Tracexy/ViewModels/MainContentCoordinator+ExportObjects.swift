import Foundation

// MARK: - File ▸ Export Objects

@MainActor
extension MainContentCoordinator {
    /// Reads the streams of the open capture (or a stopped live capture's copy) that
    /// carry `kind`'s protocol and lists its objects. Loads each kind once; `force`
    /// rescans.
    func loadExportObjects(_ kind: CaptureObjectKind, force: Bool = false) {
        let state = exportObjects
        if state.kind != kind || state.isLoading {
            state.cancel(clearLists: false)
        }
        state.kind = kind
        if !force, state.list != nil {
            return
        }
        state.lists[kind] = nil
        if let reason = allFramesUnavailableReason {
            state.error = reason
            return
        }
        let (streams, connections) = CaptureObjectScanner.inputs(kind, in: presentedSessions, from: sessions)
        let requestID = state.requestID
        let generation = startGeneration
        state.isLoading = true
        let savedURL = isViewingSavedCapture ? savedCaptureEvidenceURL : nil
        let savedIdentity = adoptedSavedCaptureIdentity
        let spool = liveCaptureSpool
        state.task = Task.detached(priority: .userInitiated) { [weak self] in
            let temporaryURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("tracexy-objects-\(UUID().uuidString).pcapng")
            defer { try? FileManager.default.removeItem(at: temporaryURL) }
            do {
                let source = try await Self.frameToolSource(
                    savedURL: savedURL, savedIdentity: savedIdentity, spool: spool, temporaryURL: temporaryURL
                )
                let list = try CaptureObjectScanner.scan(
                    kind, contentsOf: source.url, expectedIdentity: source.identity, streams: streams,
                    connections: connections, sourceToken: source.token
                ) { done, total in
                    Task { @MainActor [weak self] in
                        guard let self, requestID == exportObjects.requestID else {
                            return
                        }
                        exportObjects.progress = (done, total)
                    }
                }
                try Task.checkCancellation()
                await self?.finishExportObjects(
                    list,
                    kind: kind,
                    error: nil,
                    requestID: requestID,
                    generation: generation
                )
            } catch is CancellationError {
                await self?.finishExportObjects(
                    nil,
                    kind: kind,
                    error: nil,
                    requestID: requestID,
                    generation: generation
                )
            } catch {
                await self?.finishExportObjects(
                    nil, kind: kind, error: error.localizedDescription, requestID: requestID, generation: generation
                )
            }
        }
    }

    /// Selects the object's session in the main window.
    @discardableResult
    func revealExportedObject(_ object: CaptureObject) -> Bool {
        guard let session = visibleSessions.first(where: { $0.id == object.sessionID }) else {
            return false
        }
        openSessionsPreservingScope()
        select(session)
        return true
    }

    private func finishExportObjects(
        _ list: CaptureObjectList?,
        kind: CaptureObjectKind,
        error: String?,
        requestID: Int,
        generation: Int
    ) {
        guard requestID == exportObjects.requestID, generation == startGeneration else {
            return
        }
        exportObjects.isLoading = false
        exportObjects.progress = nil
        exportObjects.task = nil
        exportObjects.lists[kind] = list
        exportObjects.error = error
    }
}
