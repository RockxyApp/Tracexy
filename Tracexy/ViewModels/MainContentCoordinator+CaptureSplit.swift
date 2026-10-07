import AppKit
import Foundation
import UniformTypeIdentifiers

// MARK: - Split Capture

/// File ▸ Split Capture…: write the open saved capture as a file set — a new file
/// every N frames or N seconds, optionally time-shifted — then open its first file,
/// where File ▸ Next File in Set walks the rest. The source is only read.
@MainActor
extension MainContentCoordinator {
    var canSplitCapture: Bool {
        isViewingSavedCapture && canExportFrames && captureSplitTask == nil
    }

    func presentSplitCapture() {
        guard canSplitCapture else {
            return
        }
        isSplitCapturePresented = true
    }

    /// Ask where the set goes; the name typed becomes the files' common prefix.
    func presentSplitSavePanel(options: CaptureSplitOptions) {
        guard canSplitCapture else {
            return
        }
        let save = NSSavePanel()
        save.canCreateDirectories = true
        save.nameFieldLabel = String(localized: "Prefix:")
        let base = activeSavedCapture?.name ?? "capture"
        save.nameFieldStringValue = base + "-part"
        save
            .message =
            String(localized: "Each file is named prefix_00001_date.pcapng, so File ▸ Next File in Set walks them.")
        guard save.runModal() == .OK, let chosen = save.url else {
            return
        }
        let prefix = chosen.deletingPathExtension().lastPathComponent
        splitCapture(into: chosen.deletingLastPathComponent(), prefix: prefix, options: options)
    }

    /// The panel-free route for tests and automation.
    func splitCapture(into directory: URL, prefix: String, options: CaptureSplitOptions) {
        guard canSplitCapture, let source = savedCaptureEvidenceURL else {
            return
        }
        let projectID = activeRuntime.projectID
        captureSplitTask = Task { @MainActor [weak self] in
            let outcome: Result<CaptureSplitSummary, Error> = await Task.detached(priority: .userInitiated) {
                Result {
                    try CaptureSplitter.split(source: source, into: directory, prefix: prefix, options: options)
                }
            }.value
            guard let self else {
                return
            }
            self.captureSplitTask = nil
            switch outcome {
            case let .success(summary):
                guard self.activeRuntime.projectID == projectID, let first = summary.files.first else {
                    return
                }
                let size = (try? first.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
                self.openSavedCapture(SavedCapture(
                    url: first, name: first.deletingPathExtension().lastPathComponent, date: Date(), byteCount: size
                ))
                await self.waitForSavedCaptureOpen()
                if self.savedCaptureWarning == nil {
                    self.savedCaptureWarning = Self.splitNote(summary)
                }
            case let .failure(error):
                if !(error is CancellationError) {
                    self.captureError = "Couldn’t split the capture: \(error.localizedDescription)"
                }
            }
        }
    }

    /// Test seam: await the in-flight split, if any.
    func waitForCaptureSplit() async {
        await captureSplitTask?.value
    }

    nonisolated static func splitNote(_ summary: CaptureSplitSummary) -> String? {
        var notes: [String] = []
        if summary.sourceTruncated {
            notes.append("the source ended mid-frame")
        }
        if summary.omittedFrameCommentCount > 0 {
            notes.append("\(summary.omittedFrameCommentCount.formatted()) frame comment(s) were not carried over")
        }
        let written = "Split into \(summary.files.count.formatted()) files; this is the first."
        return notes.isEmpty ? written : written + " Note: " + notes.joined(separator: "; ") + "."
    }
}
