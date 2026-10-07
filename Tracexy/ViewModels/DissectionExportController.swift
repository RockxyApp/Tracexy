import AppKit
import Foundation
import Observation
import UniformTypeIdentifiers

// MARK: - DissectionExportController

/// File ▸ Export Packet Dissections…: every frame's decode tree, as plain text or
/// JSON (see ``DissectionExporter``) — the frames of the sessions in view, or the
/// whole capture when nothing is filtered out. On the same terms as Export Frames:
/// a saved or stopped live capture, the privacy acknowledgement, and an outcome
/// reported where capture I/O outcomes go.
@MainActor
@Observable
final class DissectionExportController {
    static let shared = DissectionExportController()

    private(set) var isExporting = false

    func export(from coordinator: MainContentCoordinator) {
        guard !isExporting else {
            return
        }
        guard coordinator.canExportFrames else {
            coordinator.captureError = coordinator.captureSourceHoldMessage
                ?? String(localized: "Open a saved capture or stop the live capture before exporting dissections.")
            return
        }
        let privacy = PrivacySettingsResolver.exportPolicy(defaults: coordinator.activeProjectDefaults)
        if privacy.hasProtections, !Self.confirmUnmaskedDetails() {
            return
        }
        let panel = NSSavePanel()
        panel.title = String(localized: "Export Packet Dissections")
        panel.message = String(localized: "Each frame's layers and fields, as Layers shows them.")
        let accessory = FormatAccessory(panel: panel)
        panel.accessoryView = accessory.view
        panel.nameFieldStringValue = "Dissections.txt"
        panel.allowedContentTypes = [.plainText]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let output = panel.url else {
            return
        }
        let format = accessory.format
        let originProjectID = coordinator.activeRuntime.projectID
        let originGeneration = coordinator.startGeneration
        let filtered = coordinator.visibleSessions.count != coordinator.sessions.count
        let sessions = filtered ? Set(coordinator.visibleSessions.map(\.id)) : nil
        let savedURL = coordinator.isViewingSavedCapture ? coordinator.savedCaptureEvidenceURL : nil
        let savedIdentity = coordinator.adoptedSavedCaptureIdentity
        let spool = coordinator.liveCaptureSpool
        isExporting = true
        Task { [weak coordinator] in
            var failure: String?
            var warning: String?
            var didWrite = false
            do {
                let summary = try await Task
                    .detached(priority: .userInitiated) { () throws -> DissectionExporter.Summary in
                        let temporary = FileManager.default.temporaryDirectory
                            .appendingPathComponent("tracexy-dissections-\(UUID().uuidString)")
                        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
                        defer { try? FileManager.default.removeItem(at: temporary) }
                        let source = try await MainContentCoordinator.frameToolSource(
                            savedURL: savedURL, savedIdentity: savedIdentity, spool: spool,
                            temporaryURL: temporary.appendingPathComponent("capture.pcapng")
                        )
                        let staged = temporary.appendingPathComponent("out")
                        FileManager.default.createFile(atPath: staged.path, contents: nil)
                        let handle = try FileHandle(forWritingTo: staged)
                        let summary = try DissectionExporter.export(
                            from: source.url, expectedIdentity: source.identity, sessions: sessions, format: format
                        ) { try handle.write(contentsOf: $0) }
                        try handle.close()
                        // Published only once complete, replacing what the save panel agreed to replace.
                        if FileManager.default.fileExists(atPath: output.path) {
                            try FileManager.default.removeItem(at: output)
                        }
                        try FileManager.default.moveItem(at: staged, to: output)
                        return summary
                    }.value
                didWrite = true
                if summary.writtenFrameCount == 0 {
                    warning = String(localized: "No frame of the sessions in view was found, so the file is empty.")
                }
            } catch is CancellationError {
                // Nothing was published: the file is moved into place only at the end.
            } catch {
                failure = String(localized: "Couldn’t export the dissections: \(error.localizedDescription)")
            }
            isExporting = false
            coordinator?.reportCaptureIOOutcome(
                failure: failure, warning: warning, didWrite: didWrite,
                originProjectID: originProjectID, originGeneration: originGeneration
            )
        }
    }
}

// MARK: - Confirmation

private extension DissectionExportController {
    /// With Privacy protections on: dissections carry no packet bytes, but they do
    /// spell out every decoded address, name and URL, and masking is not applied.
    static func confirmUnmaskedDetails() -> Bool {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = String(localized: "Export unmasked packet details?")
        alert.informativeText = String(localized: """
        Dissections list every decoded field, including IP addresses, host names and URLs. Packet bytes are not \
        written, but IP masking is not applied. Export only if you intend to handle the file as sensitive data.
        """)
        alert.addButton(withTitle: String(localized: "Export Dissections"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        return alert.runModal() == .alertFirstButtonReturn
    }
}

// MARK: - FormatAccessory

/// The save panel's Format pop-up: plain text or JSON, keeping the name's extension
/// in step with the choice.
@MainActor
private final class FormatAccessory: NSObject {
    // MARK: Lifecycle

    init(panel: NSSavePanel) {
        self.panel = panel
        let label = NSTextField(labelWithString: String(localized: "Format:"))
        let row = NSStackView(views: [label, popUp])
        row.orientation = .horizontal
        row.spacing = 8
        row.edgeInsets = NSEdgeInsets(top: 8, left: 16, bottom: 8, right: 16)
        view = row
        super.init()
        popUp.addItems(withTitles: [String(localized: "Plain Text"), String(localized: "JSON")])
        popUp.target = self
        popUp.action = #selector(formatChanged)
        popUp.setAccessibilityLabel(String(localized: "Format"))
    }

    // MARK: Internal

    let view: NSView

    var format: DissectionExporter.Format {
        popUp.indexOfSelectedItem == 1 ? .json : .text
    }

    // MARK: Private

    private let popUp = NSPopUpButton()
    private weak var panel: NSSavePanel?

    @objc
    private func formatChanged() {
        guard let panel else {
            return
        }
        let json = format == .json
        panel.allowedContentTypes = [json ? .json : .plainText]
        let base = (panel.nameFieldStringValue as NSString).deletingPathExtension
        panel.nameFieldStringValue = base + (json ? ".json" : ".txt")
    }
}
