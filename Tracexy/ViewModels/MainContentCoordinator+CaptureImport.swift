import AppKit
import Foundation

// MARK: - CaptureImportOperation

nonisolated struct CaptureImportOperation: Sendable {
    static let copy = Self { source, directory, progress in
        let worker = Task.detached(priority: .userInitiated) {
            try Task.checkCancellation()
            return try CaptureImporter.importCapture(
                from: source, intoDirectory: directory, onProgress: progress
            )
        }
        return try await withTaskCancellationHandler {
            try await worker.value
        } onCancel: {
            worker.cancel()
        }
    }

    var run: @Sendable (URL, URL, @escaping @Sendable (PcapStreamProgress) -> Void) async throws -> URL
}

// MARK: - Capture import

@MainActor
extension MainContentCoordinator {
    var isImportingCapture: Bool {
        pendingCaptureImportTask != nil
    }

    var captureImportFraction: Double? {
        guard let progress = captureImportProgress, progress.totalBytes > 0 else {
            return nil
        }
        return min(Double(progress.bytesConsumed) / Double(progress.totalBytes), 1)
    }

    /// File and sidebar share this native picker. Content recognition happens off-main.
    func presentCaptureImportPanel() {
        guard let origin = activeRuntime.projectID, captureImportRefusal == nil else {
            captureError = captureImportRefusal ?? "Load or repair Projects before importing capture data."
            return
        }
        let panel = NSOpenPanel()
        // No extension gate: even an extensionless capture must be selectable.
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.prompt = String(localized: "Import")
        panel
            .message =
            String(
                localized: "Choose PCAP, PCAPNG, a gzip-compressed capture, or a TCP Viewer session. Tracexy checks the file’s contents rather than its name."
            )
        guard panel.runModal() == .OK, let source = panel.url else {
            return
        }
        importCapture(from: source, originProjectID: origin)
    }

    func importCapture(from source: URL, originProjectID: UUID? = nil) {
        if let originProjectID, originProjectID != activeRuntime.projectID {
            captureError = "Tracexy switched Projects while the import panel was open. Import again in the intended Project."
            return
        }
        if let refusal = captureImportRefusal {
            captureError = refusal
            return
        }
        guard let origin = activeRuntime.projectID, let directory = capturesDirectory() else {
            return
        }
        cancelSavedCaptureOpen(clearPublishedEvidence: false)
        captureImportRequestID &+= 1
        let requestID = captureImportRequestID
        let operation = captureImportOperation
        let relay = CoordinatorProgressRelay(coordinator: self, requestID: requestID) { coordinator, progress, id in
            coordinator.publishCaptureImportProgress(progress, requestID: id)
        }
        let scoped = source.startAccessingSecurityScopedResource()
        captureImportName = source.lastPathComponent
        captureImportProgress = nil
        isCancellingCaptureImport = false
        captureError = nil
        // Reveal progress without clearing search or any existing evidence.
        activeWorkspace.sidebarSelection = .sessions
        pendingCaptureImportTask = Task { @MainActor [weak self] in
            defer {
                if scoped {
                    source.stopAccessingSecurityScopedResource()
                }
            }
            var destination: URL?
            var failure: String?
            do {
                destination = try await operation.run(source, directory, relay.submit)
            } catch is CancellationError {
                // Cancellation is a normal outcome; the worker cleans its staging file.
            } catch {
                failure = "Couldn’t import “\(source.lastPathComponent)”: \(error.localizedDescription)"
            }
            guard let self, self.captureImportRequestID == requestID else {
                return
            }
            let cancelled = self.isCancellingCaptureImport || Task.isCancelled
            let holdMessage = self.captureSourceHoldMessage
            self.pendingCaptureImportTask = nil
            self.captureImportProgress = nil
            self.captureImportName = nil
            self.isCancellingCaptureImport = false
            guard self.activeRuntime.projectID == origin else {
                return
            }
            self.refreshSavedCaptures()
            if self.captureError == holdMessage {
                self.captureError = nil
            }
            if let failure, !cancelled {
                self.captureError = failure
            }
            // Publication may win a late cancellation; keep the complete Library
            // copy, but never auto-open it after cancellation or a Project change.
            guard !cancelled, !self.projectTransitionStatus.isPending,
                  let destination,
                  let capture = self.savedCaptures.first(where: { $0.url == destination }) else
            {
                return
            }
            self.openSavedCapture(capture)
        }
    }

    func cancelCaptureImport() {
        guard let task = pendingCaptureImportTask else {
            return
        }
        isCancellingCaptureImport = true
        task.cancel()
        // The source hold remains until the worker's cleanup completes.
    }

    func waitForCaptureImport() async {
        await pendingCaptureImportTask?.value
    }

    private func publishCaptureImportProgress(_ progress: PcapStreamProgress, requestID: Int) {
        guard requestID == captureImportRequestID, isImportingCapture,
              !isCancellingCaptureImport else
        {
            return
        }
        if let current = captureImportProgress, progress.bytesConsumed < current.bytesConsumed {
            return
        }
        captureImportProgress = progress
    }

    private var captureImportRefusal: String? {
        if let held = captureSourceHoldMessage {
            return held
        }
        guard hasHydratedProjects, activeRuntime.projectID != nil else {
            return "Load or repair Projects before importing capture data."
        }
        guard !isProjectBoundaryBusy else {
            return "Tracexy is finishing the current capture change. Import again in a moment."
        }
        guard capturesDirectory() != nil else {
            return "This Project’s capture Library isn’t available. Repair the Project, then import again."
        }
        return nil
    }
}
