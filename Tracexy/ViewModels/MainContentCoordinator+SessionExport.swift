import AppKit
import Foundation

// MARK: - Session export

extension MainContentCoordinator {
    /// Toolbar export is selection-scoped. The inexpensive presentation gate is
    /// intentionally separate from frame matching, which happens only after the
    /// user activates an export command.
    var canExportSelectedSession: Bool {
        selectedSession != nil && canExport()
    }

    /// Cheap presentation gate for row menus. Packet matching is deliberately
    /// deferred until activation because reading and decoding the complete capture belongs
    /// off the main actor.
    func canExport(_: SessionSummary) -> Bool {
        canExport()
    }

    /// An export reads the complete capture from the active Project's spool. While
    /// the Project boundary is settling that spool has not reached its exact final
    /// boundary, or is about to be replaced, so export is refused rather than
    /// serving a partial or another Project's capture.
    func canExport() -> Bool {
        canSaveCapture && !isExportingSession && !isProjectBoundaryBusy
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
        guard !isExportingSession, !isProjectBoundaryBusy else {
            return
        }
        let configuredPrivacy = PrivacySettingsResolver.exportPolicy(defaults: activeProjectDefaults)
        // The raw-capture acknowledgement below is modal, so it spins the run loop:
        // Start, Clear and Open can all be activated while it is up. The export owns
        // its capture source from *here*, before the first reentrant presentation,
        // rather than from the moment the user confirms.
        setSessionExporting(true)
        guard let exportPrivacy = confirmedPrivacyPolicy(
            for: format,
            configuredPrivacy: configuredPrivacy
        ) else {
            setSessionExporting(false)
            return
        }
        // The source identity this export was started against, captured before any
        // asynchronous work so a late result can never describe another Project's
        // or another capture generation's source.
        let originProjectID = activeRuntime.projectID
        let originGeneration = startGeneration

        Task { @MainActor [weak self] in
            guard let self else {
                return
            }
            defer { self.setSessionExporting(false) }
            var failure: String?
            var warning: String?
            var didWrite = false
            do {
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
                didWrite = true
                warning = capture.incompletenessReason
            } catch {
                failure = "Couldn’t export session: \(error.localizedDescription)"
            }
            self.reportCaptureIOOutcome(
                failure: failure,
                warning: warning.map {
                    "Exported the recoverable session prefix. Later frames are missing because "
                        + "the local spool failed — \($0)"
                },
                didWrite: didWrite,
                originProjectID: originProjectID,
                originGeneration: originGeneration
            )
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
            return Self.resolvedExportPrivacyPolicy(
                for: format,
                configuredPrivacy: configuredPrivacy,
                didConfirmRawExport: false
            )
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
        return Self.resolvedExportPrivacyPolicy(
            for: format,
            configuredPrivacy: configuredPrivacy,
            didConfirmRawExport: alert.runModal() == .alertFirstButtonReturn
        )
    }

    /// Pure decision seam for the modal confirmation above. Keeping Optional
    /// cancellation distinct from the permissive policy prevents Swift from
    /// resolving `.none` as `Optional.none` on the confirmed branch.
    nonisolated static func resolvedExportPrivacyPolicy(
        for format: SessionExportFormat,
        configuredPrivacy: SessionExportPrivacyPolicy,
        didConfirmRawExport: Bool
    )
        -> SessionExportPrivacyPolicy?
    {
        guard format != .session, configuredPrivacy.hasProtections else {
            return configuredPrivacy
        }
        return didConfirmRawExport ? SessionExportPrivacyPolicy.none : nil
    }
}
