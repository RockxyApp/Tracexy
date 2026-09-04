import Foundation

// MARK: - CaptureMutationError

nonisolated enum CaptureMutationError: LocalizedError {
    case sourceInUse(String)

    // MARK: Internal

    var errorDescription: String? {
        switch self {
        case let .sourceInUse(reason): reason
        }
    }
}

// MARK: - CaptureSaveOperation

/// Capture I/O is injectable without changing source ownership or queue ordering.
nonisolated struct CaptureSaveOperation: Sendable {
    static let copy = Self { source, spool, destination in
        if let source {
            try await Task.detached(priority: .userInitiated) {
                try FileManager.default.copyItem(at: source, to: destination)
            }.value
        } else {
            try await spool.copy(to: destination)
        }
    }

    var run: @Sendable (URL?, LiveCaptureSpool, URL) async throws -> Void
}

// MARK: - Capture persistence

extension MainContentCoordinator {
    /// Removes a managed capture from the Library through the recoverable macOS
    /// Trash. If the file is currently open, its decoded in-memory view is also
    /// cleared so the workspace cannot keep presenting a capture that no longer
    /// exists in the Library.
    func moveSavedCaptureToTrash(_ capture: SavedCapture) throws {
        // An accepted Save or an in-flight export may be reading exactly this file,
        // or writing beside it. Removing it underneath them is refused.
        if let held = captureSourceHoldMessage {
            throw CaptureMutationError.sourceInUse(held)
        }
        guard hasHydratedProjects, !isProjectBoundaryBusy,
              let directory = capturesDirectory(),
              capture.url.deletingLastPathComponent().standardizedFileURL == directory.standardizedFileURL else
        {
            throw CocoaError(.fileWriteNoPermission)
        }
        try FileManager.default.trashItem(at: capture.url, resultingItemURL: nil)
        if activeSavedCapture?.url.standardizedFileURL == capture.url.standardizedFileURL {
            clearSessions()
        }
        refreshSavedCaptures()
    }

    /// Saves the complete current capture into the *active Project's* managed
    /// Library folder. Live frames come from that Project's disk-backed pcapng
    /// spool, not the bounded UI retention window.
    ///
    /// The spool and destination Project are captured *before* the first `await`,
    /// so a Project change that lands mid-copy can neither redirect the write nor
    /// make it read the incoming Project's spool. The task handle is published so
    /// the Project lifecycle path can wait for it before swapping references — and
    /// so ``isCaptureSourceHeld`` freezes destructive source mutations for exactly
    /// as long as this save, and any save queued behind it, still needs its source.
    func saveCurrentCapture() {
        // A save started while the Project boundary is settling would read a spool
        // that has not reached its exact final boundary, or one that is about to be
        // swapped for another Project's.
        guard hasHydratedProjects, !retainedFrames.isEmpty,
              !isProjectBoundaryBusy,
              let directory = capturesDirectory() else
        {
            return
        }
        let stamp = Self.fileStampFormatter.string(from: Date())
        let savedSource = activeSavedCapture?.url
        let fileExtension = savedSource?.pathExtension ?? "pcapng"
        let baseURL = directory.appendingPathComponent("Capture \(stamp).\(fileExtension)")
        let url = pendingCaptureIOTask != nil || FileManager.default.fileExists(atPath: baseURL.path)
            ? directory.appendingPathComponent("Capture \(stamp)-\(UUID().uuidString).\(fileExtension)")
            : baseURL
        // Spool, destination and origin Project are captured before the first
        // `await`, so a Project change landing mid-copy can neither redirect the
        // write nor make it read the incoming Project's evidence.
        let pendingIngest = ingestChain
        let spool = liveCaptureSpool
        let operation = captureSaveOperation
        let originProjectID = activeRuntime.projectID
        let originGeneration = startGeneration
        let previousSave = pendingCaptureIOTask
        captureIORequestID &+= 1
        let requestID = captureIORequestID
        pendingCaptureIOTask = Task { @MainActor [weak self] in
            await previousSave?.value
            await pendingIngest?.value
            var failure: String?
            var warning: String?
            do {
                try await operation.run(savedSource, spool, url)
                if savedSource == nil {
                    warning = await spool.incompletenessReason()
                }
            } catch {
                failure = "Couldn’t save capture: \(error.localizedDescription)"
            }
            guard let self else {
                return
            }
            // Only the newest request may clear the shared handle. Clearing it
            // unconditionally would hide a save already queued behind this one from
            // the Project transition that must wait for it.
            if self.captureIORequestID == requestID {
                self.pendingCaptureIOTask = nil
            }
            // A result that arrives after the Project changed belongs to the
            // Project that started it, and must not touch the one on screen.
            guard self.activeRuntime.projectID == originProjectID else {
                return
            }
            self.refreshSavedCaptures()
            self.reportCaptureIOOutcome(
                failure: failure,
                warning: warning.map {
                    "Saved the recoverable capture prefix. Later frames are missing because "
                        + "the local spool failed — \($0)"
                },
                didWrite: failure == nil,
                originProjectID: originProjectID,
                originGeneration: originGeneration
            )
        }
    }

    /// Stop may advance the publication generation while Save/export still owns
    /// the same source. Its failure or incompleteness warning remains relevant to
    /// that Project; a successful copy must not clear a newer Stop diagnostic.
    func reportCaptureIOOutcome(
        failure: String?,
        warning: String?,
        didWrite: Bool,
        originProjectID: UUID?,
        originGeneration: Int
    ) {
        guard activeRuntime.projectID == originProjectID else {
            return
        }
        if let failure {
            captureError = failure
        } else if let warning {
            captureError = warning
        } else if didWrite, startGeneration == originGeneration {
            captureError = nil
        }
    }

    /// Complete source for session export. A saved file is re-read directly; a
    /// live capture is read from its spool after queued ingests have completed.
    /// The spool reference is taken before awaiting so an export can never read a
    /// different Project's evidence than the one it was started from.
    func completeCaptureForExport() async throws -> (
        linkType: UInt32,
        frames: [CapturedFrame],
        incompletenessReason: String?
    ) {
        let spool = liveCaptureSpool
        let savedSource = activeSavedCapture?.url
        await ingestChain?.value
        if let savedSource {
            let capture = try await Task.detached(priority: .userInitiated) {
                try CaptureFileReader.read(contentsOf: savedSource)
            }.value
            return (capture.linkType, capture.frames, nil)
        }
        let capture = try await spool.capture()
        return await (
            capture.linkType,
            capture.frames,
            spool.incompletenessReason()
        )
    }
}
