import Foundation

// MARK: - Capture ▸ Restart

extension MainContentCoordinator {
    /// Whether Capture ▸ Restart can run: a live capture is running.
    var canRestartCapture: Bool {
        isCapturing && !isStarting
    }

    /// Capture ▸ Restart (Wireshark's ⌘R): stop the running capture, let it finish
    /// writing its last packets, then start again with the same settings. The new
    /// capture replaces what the list showed, exactly as Stop then Start would.
    /// Abandoned if the Project changes or the stop does not settle in time.
    func restartCapture() {
        guard canRestartCapture else {
            return
        }
        let projectID = activeRuntime.projectID
        stopCapture()
        Task { @MainActor [weak self] in
            // Stop settles asynchronously (a final drain may be owed); poll briefly
            // for the moment Start would be accepted.
            for _ in 0 ..< 200 {
                guard let self, activeRuntime.projectID == projectID else {
                    return
                }
                if !isCapturing, !isStarting, captureStartBlockedMessage == nil {
                    startCapture()
                    return
                }
                try? await Task.sleep(for: .milliseconds(50))
            }
            self?.captureError = String(
                localized: "Couldn’t restart the capture: the stopped capture did not finish in time. Start it again."
            )
        }
    }

    /// Capture ▸ Refresh Interfaces (Wireshark's F5): interface lists read the
    /// system again, so an adapter added since they were shown appears.
    func refreshInterfaces() {
        interfaceListToken &+= 1
    }
}
