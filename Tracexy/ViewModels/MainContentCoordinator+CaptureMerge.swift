import AppKit
import Foundation
import UniformTypeIdentifiers

// MARK: - Merge Captures

/// File ▸ Merge Captures…: choose two or more captures, name the merged PCAPNG, and
/// open it. The merge runs off the main actor; the sources are only read.
@MainActor
extension MainContentCoordinator {
    var canMergeCaptures: Bool {
        captureMergeTask == nil && !isCapturing && !isStarting && !isProjectBoundaryBusy
    }

    func presentMergeCapturesPanel() {
        guard canMergeCaptures else {
            return
        }
        let open = NSOpenPanel()
        open.allowsMultipleSelection = true
        open.canChooseDirectories = false
        open.allowedContentTypes = ["pcap", "pcapng", "cap"].compactMap { UTType(filenameExtension: $0) }
        open.prompt = String(localized: "Choose")
        open.message = String(localized: "Choose two or more captures to merge in capture-time order.")
        guard open.runModal() == .OK else {
            return
        }
        let sources = open.urls
        guard sources.count >= 2 else {
            captureError = CaptureMergeError.needsTwoSources.localizedDescription
            return
        }
        let save = NSSavePanel()
        save.allowedContentTypes = UTType(filenameExtension: "pcapng").map { [$0] } ?? []
        save.canCreateDirectories = true
        save.nameFieldStringValue = String(localized: "Merged capture.pcapng")
        save.message = String(localized: "Each frame keeps the name of the file it came from.")
        guard save.runModal() == .OK, let destination = save.url else {
            return
        }
        mergeCaptures(sources, to: destination)
    }

    /// Merge `sources` into `destination` and open the result. The panel-free route
    /// for tests and automation.
    func mergeCaptures(_ sources: [URL], to destination: URL) {
        guard canMergeCaptures else {
            return
        }
        let projectID = activeRuntime.projectID
        captureMergeTask = Task { @MainActor [weak self] in
            let outcome: Result<CaptureMergeSummary, Error> = await Task.detached(priority: .userInitiated) {
                Result { try CaptureMerger.merge(sources: sources, to: destination) }
            }.value
            guard let self else {
                return
            }
            self.captureMergeTask = nil
            switch outcome {
            case let .success(summary):
                guard self.activeRuntime.projectID == projectID else {
                    return
                }
                let size = (try? destination.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
                self.openSavedCapture(SavedCapture(
                    url: destination,
                    name: destination.deletingPathExtension().lastPathComponent,
                    date: Date(),
                    byteCount: size
                ))
                // Shown the way any saved-capture caveat is, once the file is open.
                await self.waitForSavedCaptureOpen()
                if self.savedCaptureWarning == nil, let warning = Self.mergeWarning(summary) {
                    self.savedCaptureWarning = warning
                }
            case let .failure(error):
                if !(error is CancellationError) {
                    self.captureError = "Couldn’t merge the captures: \(error.localizedDescription)"
                }
            }
        }
    }

    /// Test seam: await the in-flight merge, if any.
    func waitForCaptureMerge() async {
        await captureMergeTask?.value
    }

    nonisolated static func mergeWarning(_ summary: CaptureMergeSummary) -> String? {
        var notes: [String] = []
        if !summary.truncatedSources.isEmpty {
            notes.append("\(ListFormatter.localizedString(byJoining: summary.truncatedSources)) ended mid-frame")
        }
        if summary.omittedFrameCommentCount > 0 {
            notes.append("\(summary.omittedFrameCommentCount.formatted()) frame comment(s) were not carried over")
        }
        return notes.isEmpty ? nil : "Merged, but " + notes.joined(separator: "; ") + "."
    }
}
