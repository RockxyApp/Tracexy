import Foundation

@MainActor
extension MainContentCoordinator {
    /// A capture read in this process — the direct libpcap path or a named pipe —
    /// with no helper to ask for a final batch.
    var usesInProcessCapture: Bool {
        Self.forceDirectCapture || PipeCapture.isPipe(activeCaptureConfiguration?.interface)
    }

    /// The capture source as the toolbar and empty list name it: an interface's
    /// name, or a pipe's file name (its full path is in Manage Interfaces).
    var captureSourceName: String {
        PipeCapture.isPipe(captureInterface) ? (captureInterface as NSString).lastPathComponent : captureInterface
    }

    /// Starts reading the named pipe `configuration.interface` names, through the
    /// same ingest, History and stop path as a direct capture. The writer closing
    /// the pipe stops the capture as Stop would.
    func startPipe(_ configuration: CaptureConfiguration) {
        let token = startGeneration
        do {
            try pipeCapture.start(
                path: configuration.interface,
                onBatch: { [weak self] frames, linkType in
                    Task { @MainActor in self?.ingest(frames, linkType: linkType) }
                },
                onReadFailure: { [weak self] message in
                    Task { @MainActor in self?.captureSourceDidFail(message, captureToken: token) }
                },
                onEnd: { [weak self] in
                    Task { @MainActor in
                        guard let self, self.isCapturing, self.startGeneration == token else {
                            return
                        }
                        self.stopCapture()
                    }
                }
            )
        } catch {
            handleCaptureError((error as? PipeCapture.Failure)?.message ?? error.localizedDescription)
            return
        }
        isCapturing = true
        isStarting = false
        captureStartedAt = Date()
        captureStatistics = nil
        beginLiveHistoryLifetime(captureGeneration: startGeneration)
    }
}
