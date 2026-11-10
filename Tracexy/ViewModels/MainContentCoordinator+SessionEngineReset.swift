import Foundation

@MainActor
extension MainContentCoordinator {
    /// Clears the engine and adopts a new capture generation. Enqueued on the
    /// ingest chain so it is ordered ahead of subsequent ingests; older in-flight
    /// work carries the previous token and is dropped by the engine's epoch guard.
    func resetSessionEngine(
        token: Int,
        fileSet: LiveCaptureSpool.FileSetPolicy? = nil,
        preservingCaptureLocalTools: Bool = false
    ) {
        if !preservingCaptureLocalTools {
            retireCaptureLocalTools()
        }
        let engine = sessionEngine
        let spool = liveCaptureSpool
        // The runtime this reset belongs to, captured before the first `await`. A
        // queued reset can outlive a Project change, and its spool failure describes
        // the Project that owns that spool — never the one now on screen.
        let origin = activeRuntime
        let previous = ingestChain
        ingestChain = Task { @MainActor in
            await previous?.value
            await engine.reset(epoch: token)
            do {
                try await spool.reset(epoch: token, fileSet: fileSet)
            } catch {
                let message = "Capture spool unavailable — \(error.localizedDescription)"
                if self.activeRuntime !== origin {
                    // Already parked: report it into its own Project's bucket so the
                    // failure is still there when that Project comes back.
                    origin.captureError = message
                } else if self.startGeneration == token {
                    self.captureError = message
                }
            }
        }
    }
}
