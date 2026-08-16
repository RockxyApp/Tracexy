import Foundation

// MARK: - Capture persistence

extension MainContentCoordinator {
    /// Removes a managed capture from the Library through the recoverable macOS
    /// Trash. If the file is currently open, its decoded in-memory view is also
    /// cleared so the workspace cannot keep presenting a capture that no longer
    /// exists in the Library.
    func moveSavedCaptureToTrash(_ capture: SavedCapture) throws {
        try FileManager.default.trashItem(at: capture.url, resultingItemURL: nil)
        if activeSavedCapture?.url.standardizedFileURL == capture.url.standardizedFileURL {
            clearSessions()
        }
        refreshSavedCaptures()
    }

    /// Saves the complete current capture under Application Support. Live frames
    /// come from the disk-backed pcapng spool, not the bounded UI retention window.
    func saveCurrentCapture() {
        guard !retainedFrames.isEmpty, let directory = Self.capturesDirectory() else {
            return
        }
        let stamp = Self.fileStampFormatter.string(from: Date())
        let savedSource = activeSavedCapture?.url
        let fileExtension = savedSource?.pathExtension ?? "pcapng"
        let url = directory.appendingPathComponent("Capture \(stamp).\(fileExtension)")
        let pendingIngest = ingestChain
        Task { @MainActor [weak self] in
            guard let self else {
                return
            }
            await pendingIngest?.value
            do {
                if let savedSource {
                    try await Task.detached(priority: .userInitiated) {
                        try FileManager.default.copyItem(at: savedSource, to: url)
                    }.value
                } else {
                    try await self.liveCaptureSpool.copy(to: url)
                }
                if let warning = await self.liveCaptureSpool.incompletenessReason() {
                    self.captureError = "Saved the recoverable capture prefix. Later frames are missing because "
                        + "the local spool failed — \(warning)"
                } else {
                    self.captureError = nil
                }
                self.refreshSavedCaptures()
            } catch {
                self.captureError = "Couldn’t save capture: \(error.localizedDescription)"
            }
        }
    }

    /// Complete source for session export. A saved file is re-read directly; a
    /// live capture is read from its spool after queued ingests have completed.
    func completeCaptureForExport() async throws -> (
        linkType: UInt32,
        frames: [CapturedFrame],
        incompletenessReason: String?
    ) {
        await ingestChain?.value
        if let activeSavedCapture {
            let capture = try await Task.detached(priority: .userInitiated) {
                try CaptureFileReader.read(contentsOf: activeSavedCapture.url)
            }.value
            return (capture.linkType, capture.frames, nil)
        }
        let capture = try await liveCaptureSpool.capture()
        return await (
            capture.linkType,
            capture.frames,
            liveCaptureSpool.incompletenessReason()
        )
    }
}
