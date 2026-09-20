import AppKit
import Foundation

// MARK: - Export Frames…

/// File ▸ Export Frames…: scope × format × options in one save panel, then a
/// streaming, cancellable export from the stable source. Session-row export
/// presets route here with a preselected scope.
@MainActor
extension MainContentCoordinator {
    var isExportingFrames: Bool {
        frameExportTask != nil
    }

    var frameExportFraction: Double? {
        guard let progress = frameExportProgress, progress.totalBytes > 0 else {
            return nil
        }
        return min(Double(progress.bytesConsumed) / Double(progress.totalBytes), 1)
    }

    /// Export needs a stable source: the open saved file, or a stopped live
    /// capture whose spool reached its final boundary.
    var canExportFrames: Bool {
        guard !isCaptureSourceHeld, !isProjectBoundaryBusy, !isCapturing, !isStarting else {
            return false
        }
        if isViewingSavedCapture {
            return savedCaptureEvidenceURL != nil && (activeSavedCapture?.isReadable ?? false)
        }
        return stoppedCaptureReadyGeneration == startGeneration && !sessions.isEmpty
    }

    /// Present the panel. `preselectedSessions` (a row's Export preset) selects the
    /// "Selected session" scope; otherwise the whole capture is preselected.
    func presentFrameExportPanel(preselectedSessions: Set<UUID>? = nil) {
        guard canExportFrames else {
            captureError = captureSourceHoldMessage ?? "Open a saved capture or stop the live capture before exporting frames."
            return
        }
        let context = frameExportContext(preselectedSessions: preselectedSessions)
        let originProjectID = activeRuntime.projectID
        let originGeneration = startGeneration
        setSessionExporting(true)
        let configuredPrivacy = PrivacySettingsResolver.exportPolicy(defaults: activeProjectDefaults)
        if configuredPrivacy.hasProtections, !presentRawExportAcknowledgement(formatName: "PCAP and PCAPNG") {
            setSessionExporting(false)
            return
        }
        guard let choice = FrameExportPanel(context: context).run() else {
            setSessionExporting(false)
            return
        }
        guard activeRuntime.projectID == originProjectID, startGeneration == originGeneration, canExportFrames else {
            setSessionExporting(false)
            captureError = "The capture changed while the export panel was open. Export again."
            return
        }
        runFrameExport(choice, originProjectID: originProjectID, originGeneration: originGeneration)
    }

    /// The panel-free route (tests and automation): export with an explicit
    /// destination, scope and options. Holds the source exactly as the panel does.
    func exportFrames(to url: URL, scope: FrameExportScope, options: FrameExportOptions) {
        guard canExportFrames else {
            captureError = captureSourceHoldMessage ?? "Open a saved capture or stop the live capture before exporting frames."
            return
        }
        setSessionExporting(true)
        runFrameExport(
            FrameExportPanel.Choice(url: url, scope: scope, options: options),
            originProjectID: activeRuntime.projectID,
            originGeneration: startGeneration
        )
    }

    func cancelFrameExport() {
        guard let task = frameExportTask else {
            return
        }
        isCancellingFrameExport = true
        task.cancel()
    }

    /// Test/diagnostic seam.
    func waitForFrameExport() async {
        let task = frameExportTask
        await task?.value
    }

    /// The panel's inputs, derived once from coordinator state: scope choices with
    /// best-effort estimates, whether PCAP is representable, and the time bounds.
    func frameExportContext(preselectedSessions: Set<UUID>?) -> FrameExportPanel.Context {
        let properties = savedCaptureProperties
        var scopes: [FrameExportPanel.Context.ScopeChoice] = []
        scopes.append(.init(
            scope: .wholeCapture,
            title: String(localized: "Whole capture"),
            frameEstimate: properties?.totalFrames ?? savedCaptureActivity?.totalFrames
        ))
        let visible = Set(presentedSessions.map(\.id))
        if visible.count != sessions.count, !visible.isEmpty {
            scopes.append(.init(
                scope: .sessions(visible),
                title: String(localized: "Sessions in view (\(visible.count.formatted()))"),
                frameEstimate: nil
            ))
        }
        let selected = preselectedSessions ?? activeWorkspace.selectedSessionID.map { [$0] }
        if let selected, !selected.isEmpty {
            scopes.append(.init(
                scope: .sessions(selected),
                title: selected.count == 1
                    ? String(localized: "Selected session")
                    : String(localized: "Selected sessions (\(selected.count.formatted()))"),
                frameEstimate: nil
            ))
        }
        var bounds: ClosedRange<Date>?
        if let first = properties?.firstTimestamp, let last = properties?.lastTimestamp, first <= last {
            bounds = first ... last
            scopes.append(.init(
                scope: .timeRange(start: first, end: last),
                title: String(localized: "Time range"),
                frameEstimate: nil
            ))
        }
        let initialIndex = preselectedSessions != nil ? scopes.firstIndex { choice in
            if case let .sessions(ids) = choice.scope, ids == preselectedSessions {
                return true
            }
            return false
        } ?? 0 : 0

        var pcapReason: String?
        if let metadata = savedCaptureMetadata {
            if metadata.hasMixedLinkTypes {
                pcapReason = String(localized: "the capture mixes link types")
            } else if metadata.untimedFrameCount > 0 {
                pcapReason = String(localized: "some frames carry no capture time")
            }
        }
        let averageBytes: Int = if let activity = savedCaptureActivity, activity.totalFrames > 0 {
            max(1, activity.totalBytes / activity.totalFrames)
        } else {
            512
        }
        let sourceIsPcapng: Bool = if case .pcapng = properties?.container {
            true
        } else {
            !isViewingSavedCapture
        }
        let stem = activeSavedCapture?.name ?? String(localized: "Capture on \(captureInterface)")
        return FrameExportPanel.Context(
            baseName: preselectedSessions != nil ? "\(stem) – session" : stem,
            scopes: scopes,
            initialScopeIndex: initialIndex,
            timeBounds: bounds,
            sourceIsPcapng: sourceIsPcapng,
            pcapUnavailableReason: pcapReason,
            averageFrameBytes: averageBytes
        )
    }

    // MARK: Private

    private func runFrameExport(_ choice: FrameExportPanel.Choice, originProjectID: UUID?, originGeneration: Int) {
        frameExportRequestID &+= 1
        let requestID = frameExportRequestID
        frameExportName = choice.url.lastPathComponent
        frameExportProgress = nil
        isCancellingFrameExport = false
        let relay = CoordinatorProgressRelay(coordinator: self, requestID: requestID) { coordinator, progress, id in
            guard id == coordinator.frameExportRequestID, coordinator.isExportingFrames else {
                return
            }
            coordinator.frameExportProgress = progress
        }
        let savedSource = isViewingSavedCapture ? savedCaptureEvidenceURL : nil
        let identity = adoptedSavedCaptureIdentity
        let spool = liveCaptureSpool

        frameExportTask = Task { @MainActor [weak self] in
            var failure: String?
            var warning: String?
            var didWrite = false
            do {
                let summary = try await Task.detached(priority: .userInitiated) { () throws -> FrameExportSummary in
                    if let savedSource {
                        return try CaptureFrameExporter.export(
                            from: savedSource, expectedIdentity: identity, scope: choice.scope,
                            options: choice.options, to: choice.url, onProgress: relay.submit
                        )
                    }
                    let temporaryURL = FileManager.default.temporaryDirectory
                        .appendingPathComponent("tracexy-frame-export-\(UUID().uuidString).pcapng")
                    defer { try? FileManager.default.removeItem(at: temporaryURL) }
                    try await spool.copy(to: temporaryURL)
                    return try CaptureFrameExporter.export(
                        from: temporaryURL, scope: choice.scope, options: choice.options,
                        to: choice.url, onProgress: relay.submit
                    )
                }.value
                didWrite = true
                warning = Self.frameExportWarning(summary)
            } catch is CancellationError {
                // Cancelled: the exporter removed its partial file.
            } catch {
                failure = "Couldn’t export frames: \(error.localizedDescription)"
            }
            guard let self, self.frameExportRequestID == requestID else {
                return
            }
            self.frameExportTask = nil
            self.frameExportProgress = nil
            self.frameExportName = nil
            self.isCancellingFrameExport = false
            self.setSessionExporting(false)
            self.reportCaptureIOOutcome(
                failure: failure, warning: warning, didWrite: didWrite,
                originProjectID: originProjectID, originGeneration: originGeneration
            )
        }
    }

    nonisolated static func frameExportWarning(_ summary: FrameExportSummary) -> String? {
        var notes: [String] = []
        if summary.omittedFrameOptionCount > 0 {
            notes.append("\(summary.omittedFrameOptionCount.formatted()) frame comment(s) could not be copied")
        }
        if summary.omittedInterfaceOptionCount > 0 {
            notes.append("\(summary.omittedInterfaceOptionCount.formatted()) interface option(s) were omitted")
        }
        if case .incompleteTruncatedTail = summary.completeness {
            notes.append("the source ends mid-record, so the export holds every complete frame")
        }
        guard !notes.isEmpty else {
            return nil
        }
        return "Exported \(summary.writtenFrameCount.formatted()) frames; " + notes.joined(separator: "; ") + "."
    }
}
