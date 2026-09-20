import AppKit
import Foundation

// MARK: - Get Info (⌘I)

/// The Get Info window's inputs and its one on-demand computation (digests).
/// The window is a regular auxiliary window bound to the capture it was opened
/// for; it reads this snapshot and never computes.
@MainActor
extension MainContentCoordinator {
    /// `nil` when nothing is open — the menu item is disabled and the window shows
    /// its closed state.
    var captureInfoSnapshot: CaptureInfoSnapshot? {
        if isViewingSavedCapture, let capture = activeSavedCapture {
            return CaptureInfoSnapshot(
                title: capture.name,
                source: .saved(capture),
                fileURL: capture.url,
                properties: savedCaptureProperties,
                activity: savedCaptureActivity,
                metadata: savedCaptureMetadata,
                sessionCount: sessions.count,
                visibleSessionCount: presentedSessions.count,
                warning: savedCaptureWarning,
                captureStartedAt: nil,
                hashState: captureHashState
            )
        }
        guard isCapturing || captureStartedAt != nil || !sessions.isEmpty else {
            return nil
        }
        return CaptureInfoSnapshot(
            title: String(localized: "Live capture on \(captureInterface)"),
            source: .live(interface: captureInterface),
            fileURL: nil,
            properties: nil,
            activity: nil,
            metadata: nil,
            sessionCount: sessions.count,
            visibleSessionCount: presentedSessions.count,
            warning: nil,
            captureStartedAt: captureStartedAt,
            hashState: .idle
        )
    }

    var canShowCaptureInfo: Bool {
        captureInfoSnapshot != nil
    }

    /// A stable token for the capture the Info window is bound to. Changes when a
    /// different capture is adopted, so the window re-binds instead of showing a
    /// stale mix.
    var captureInfoIdentityToken: String {
        if let capture = activeSavedCapture, isViewingSavedCapture {
            return "saved:\(capture.id.path)"
        }
        return "live:\(startGeneration)"
    }

    func beginCaptureHash() {
        guard case let .saved(capture)? = captureInfoSnapshot?.source, !captureHashState.isComputing else {
            return
        }
        captureHashTask?.cancel()
        captureHashRequestID &+= 1
        let requestID = captureHashRequestID
        captureHashState = .computing(fraction: nil)
        let url = capture.url
        let expected = savedCaptureEvidence.values.first?.identity
        let relay = CoordinatorProgressRelay(coordinator: self, requestID: requestID) { coordinator, progress, id in
            guard id == coordinator.captureHashRequestID, coordinator.captureHashState.isComputing else {
                return
            }
            let fraction = progress.totalBytes > 0 ? Double(progress.bytesConsumed) / Double(progress.totalBytes) : nil
            coordinator.captureHashState = .computing(fraction: fraction)
        }
        captureHashTask = Task.detached(priority: .utility) { [weak self] in
            let outcome = Result {
                try CaptureHasher.digests(of: url, expectedIdentity: expected, onProgress: relay.submit)
            }
            await self?.finishCaptureHash(outcome, requestID: requestID)
        }
    }

    func cancelCaptureHash() {
        captureHashTask?.cancel()
        captureHashTask = nil
        captureHashRequestID &+= 1
        if captureHashState.isComputing {
            captureHashState = .idle
        }
    }

    func resetCaptureHash() {
        captureHashTask?.cancel()
        captureHashTask = nil
        captureHashRequestID &+= 1
        captureHashState = .idle
    }

    func copyCaptureInfoReport() {
        guard let snapshot = captureInfoSnapshot else {
            return
        }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(CaptureInfoReport.text(for: snapshot), forType: .string)
    }

    // MARK: Private

    private func finishCaptureHash(_ outcome: Result<CaptureFileDigests, any Error>, requestID: Int) {
        guard requestID == captureHashRequestID else {
            return
        }
        captureHashTask = nil
        switch outcome {
        case let .success(digests):
            captureHashState = .done(digests)
        case .failure(is CancellationError):
            captureHashState = .idle
        case let .failure(error):
            captureHashState = .failed(error.localizedDescription)
        }
    }
}
