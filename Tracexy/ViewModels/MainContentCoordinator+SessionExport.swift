import AppKit
import Foundation

// MARK: - Session export

extension MainContentCoordinator {
    /// Toolbar export is selection-scoped. The inexpensive presentation gate is
    /// intentionally separate from frame matching, which happens only after the
    /// user activates an export command.
    var canExportSelectedSession: Bool {
        selectedSession != nil && canSaveCapture && !isExportingSession
    }

    /// Cheap presentation gate for row menus. Packet matching is deliberately
    /// deferred until activation because reading and decoding the complete capture belongs
    /// off the main actor.
    func canExport(_: SessionSummary) -> Bool {
        canSaveCapture && !isExportingSession
    }

    func exportSelectedSession(as format: SessionExportFormat) {
        guard let selectedSession else {
            return
        }
        exportSession(selectedSession, as: format)
    }

    /// Presents one local save panel for all session export entry points. Both the
    /// toolbar menu and row context menu route here, so scope, serialization,
    /// filename, errors, and privacy behavior cannot drift apart.
    func exportSession(_ session: SessionSummary, as format: SessionExportFormat) {
        guard !isExportingSession else {
            return
        }
        let configuredPrivacy = PrivacySettingsResolver.exportPolicy()
        guard let exportPrivacy = confirmedPrivacyPolicy(
            for: format,
            configuredPrivacy: configuredPrivacy
        ) else {
            return
        }
        setSessionExporting(true)

        Task { [weak self] in
            defer { self?.setSessionExporting(false) }
            do {
                guard let self else {
                    return
                }
                let capture = try await self.completeCaptureForExport()
                let artifact = try await Task.detached(priority: .userInitiated) {
                    let sessionFrames = SessionExporter.frames(
                        matching: session.id,
                        in: capture.frames,
                        defaultLinkType: capture.linkType
                    )
                    return try SessionExporter.artifact(
                        for: session,
                        frames: sessionFrames,
                        defaultLinkType: capture.linkType,
                        format: format,
                        privacy: exportPrivacy
                    )
                }.value
                let panel = NSSavePanel()
                panel.title = format.title
                // Supply a basename and let the selected UTType append exactly
                // one extension. Passing a full custom-extension filename makes
                // NSSavePanel append that extension a second time on some macOS
                // releases.
                panel.nameFieldStringValue = URL(fileURLWithPath: artifact.suggestedFileName)
                    .deletingPathExtension()
                    .lastPathComponent
                panel.allowedContentTypes = [artifact.contentType]
                panel.canCreateDirectories = true
                panel.isExtensionHidden = false
                guard panel.runModal() == .OK, let url = panel.url else {
                    return
                }
                try await Task.detached(priority: .userInitiated) {
                    try artifact.data.write(to: url, options: .atomic)
                }.value
                if let warning = capture.incompletenessReason {
                    self.captureError = "Exported the recoverable session prefix. Later frames are missing because "
                        + "the local spool failed — \(warning)"
                } else {
                    self.captureError = nil
                }
            } catch {
                self?.captureError = "Couldn’t export session: \(error.localizedDescription)"
            }
        }
    }

    /// Native session documents can enforce the configured protections by
    /// omitting raw frames. Pcap formats are evidence-preserving byte streams, so
    /// exporting one while protections are active requires an explicit, per-action
    /// acknowledgement and then deliberately uses the unprotected policy.
    private func confirmedPrivacyPolicy(
        for format: SessionExportFormat,
        configuredPrivacy: SessionExportPrivacyPolicy
    )
        -> SessionExportPrivacyPolicy?
    {
        guard format != .session, configuredPrivacy.hasProtections else {
            return configuredPrivacy
        }

        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Export unprotected packet data?"
        alert.informativeText = """
        \(format.fileExtension.uppercased()) files preserve the exact captured packet bytes. \
        Redacting payloads, stripping credentials, and masking IP addresses cannot be applied to this raw format. \
        Export only if you intend to handle the file as sensitive data.
        """
        alert.addButton(withTitle: "Export Raw Capture")
        alert.addButton(withTitle: "Cancel")
        return alert.runModal() == .alertFirstButtonReturn ? .none : nil
    }
}
