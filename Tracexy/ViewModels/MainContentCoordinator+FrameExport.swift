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
        return stoppedCaptureReadyGeneration == startGeneration
    }

    /// Present the panel. `preselectedSessions` (a row's Export preset) selects the
    /// "Selected session" scope; otherwise the whole capture is preselected.
    func presentFrameExportPanel(
        preselectedSessions: Set<UUID>? = nil,
        preselectedFrameOrdinals: Set<UInt64>? = nil,
        prefersMarkedFrames: Bool = false,
        prefersAppliedFrameExpression: Bool = false
    ) {
        guard canExportFrames else {
            captureError = captureSourceHoldMessage ?? "Open a saved capture or stop the live capture before exporting frames."
            return
        }
        let context = frameExportContext(
            preselectedSessions: preselectedSessions,
            preselectedFrameOrdinals: preselectedFrameOrdinals,
            prefersMarkedFrames: prefersMarkedFrames,
            prefersAppliedFrameExpression: prefersAppliedFrameExpression
        )
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
        continueFrameExportAfterPanel(
            choice, originProjectID: originProjectID, originGeneration: originGeneration
        )
    }

    /// The panel-free route (tests and automation): export with an explicit
    /// destination, scope and options. Holds the source exactly as the panel does.
    func exportFrames(
        to url: URL,
        scope: FrameExportScope,
        options: FrameExportOptions,
        includesNotes: Bool = false
    ) {
        guard canExportFrames else {
            captureError = captureSourceHoldMessage ?? "Open a saved capture or stop the live capture before exporting frames."
            return
        }
        setSessionExporting(true)
        runFrameExport(
            FrameExportPanel.Choice(url: url, scope: scope, options: options, includesNotes: includesNotes),
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

    /// Resume after the modal save panel. `canExportFrames` is intentionally false
    /// here because this export itself holds the source while the panel is open.
    func continueFrameExportAfterPanel(
        _ choice: FrameExportPanel.Choice,
        originProjectID: UUID?,
        originGeneration: Int
    ) {
        guard activeRuntime.projectID == originProjectID,
              startGeneration == originGeneration,
              isExportingSession,
              !isProjectBoundaryBusy,
              !isCapturing,
              !isStarting else
        {
            setSessionExporting(false)
            captureError = "The capture changed while the export panel was open. Export again."
            return
        }
        runFrameExport(choice, originProjectID: originProjectID, originGeneration: originGeneration)
    }

    /// Test/diagnostic seam.
    func waitForFrameExport() async {
        let task = frameExportTask
        await task?.value
    }

    /// The panel's inputs, derived once from coordinator state: scope choices with
    /// best-effort estimates, whether PCAP is representable, and the time bounds.
    func frameExportContext(
        preselectedSessions: Set<UUID>?,
        preselectedFrameOrdinals: Set<UInt64>? = nil,
        prefersMarkedFrames: Bool = false,
        prefersAppliedFrameExpression: Bool = false
    )
        -> FrameExportPanel.Context
    {
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
        // Frames marked in View ▸ All Frames, Wireshark's "Marked packets only".
        if !allFrames.marked.isEmpty {
            scopes.append(.init(
                scope: .frames(allFrames.marked),
                title: String(localized: "Marked frames (\(allFrames.marked.count.formatted()))"),
                frameEstimate: allFrames.marked.count
            ))
        }
        if let preselectedFrameOrdinals, !preselectedFrameOrdinals.isEmpty {
            scopes.append(.init(
                scope: .frames(preselectedFrameOrdinals),
                title: String(localized: "Selected frames (\(preselectedFrameOrdinals.count.formatted()))"),
                frameEstimate: preselectedFrameOrdinals.count
            ))
        }
        if let expression = allFrames.acceptedFrameExpression {
            scopes.append(.init(
                scope: .frameExpression(expression),
                title: String(localized: "Frames matching the applied Frame Expression"),
                frameEstimate: allFrames.captureExpressionCoverage?.matchingCount
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
        let initialIndex = preselectedSessions != nil || preselectedFrameOrdinals != nil
            || prefersMarkedFrames || prefersAppliedFrameExpression
            ? scopes.firstIndex { choice in
                if case let .sessions(ids) = choice.scope, ids == preselectedSessions {
                    return true
                }
                if let preselectedFrameOrdinals,
                   case let .frames(ordinals) = choice.scope,
                   ordinals == preselectedFrameOrdinals
                {
                    return true
                }
                if prefersMarkedFrames, case .frames = choice.scope {
                    return true
                }
                if prefersAppliedFrameExpression, case .frameExpression = choice.scope {
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
        // A measurement or nothing. The panel omits the size rather than render a
        // substituted figure as if it had been measured.
        let averageBytes: Int? = if let activity = savedCaptureActivity, activity.totalFrames > 0 {
            max(1, activity.totalBytes / activity.totalFrames)
        } else {
            nil
        }
        let sourceIsPcapng: Bool = if case .pcapng = properties?.container {
            true
        } else {
            !isViewingSavedCapture
        }
        let stem = activeSavedCapture?.name ?? String(localized: "Capture on \(captureInterface)")
        let baseName: String = if let preselectedFrameOrdinals, preselectedFrameOrdinals.count == 1,
                                  let ordinal = preselectedFrameOrdinals.first
        {
            "\(stem) – frame \(ordinal.formatted())"
        } else if preselectedSessions != nil {
            "\(stem) – session"
        } else {
            stem
        }
        var context = FrameExportPanel.Context(
            baseName: baseName,
            scopes: scopes,
            initialScopeIndex: initialIndex,
            timeBounds: bounds,
            sourceIsPcapng: sourceIsPcapng,
            pcapUnavailableReason: pcapReason,
            averageFrameBytes: averageBytes
        )
        // Session notes and frame comments both travel under the notes checkbox.
        context.noteCount = investigationNotes.annotatedSessionIDs.count + allFrames.frameComments.count
        context.nameCount = frameExportNameRecords().count
        context.ignoredFrameOrdinals = allFrames.ignored
        return context
    }

    /// Each noted session's notes as one packet comment for its first exported
    /// frame: the session note, then finding notes, one per line.
    func frameExportSessionFrameComments() -> [UUID: String] {
        let titles = Dictionary(findings.map { ($0.id, $0.title) }, uniquingKeysWith: { first, _ in first })
        var comments: [UUID: String] = [:]
        for sessionID in investigationNotes.annotatedSessionIDs {
            let lines = investigationNotes.notes(onSession: sessionID).map { note in
                switch note.target {
                case .session:
                    "Tracexy note: \(note.text)"
                case let .finding(id, _):
                    "Tracexy note on \u{201C}\(titles[id] ?? "finding")\u{201D}: \(note.text)"
                }
            }
            if !lines.isEmpty {
                comments[sessionID] = lines.joined(separator: "\n")
            }
        }
        return comments
    }

    /// The notes on the sessions `scope` exports, as capture comments: each names
    /// the session (and the finding, for a finding note) so it reads on its own in
    /// another tool. A time range takes the sessions whose known span meets it.
    func frameExportNoteComments(for scope: FrameExportScope) -> [String] {
        let annotated = investigationNotes.annotatedSessionIDs
        guard !annotated.isEmpty else {
            return []
        }
        // One membership pass over the frame rows, not one search per session:
        // the repeated `contains` was quadratic on the main actor and stalled the
        // window between pressing Save and the export's own progress.
        let framedSessionIDs = frameScopeSessionIDs(scope)
        let included = presentedSessions.filter { session in
            guard annotated.contains(session.id) else {
                return false
            }
            switch scope {
            case .wholeCapture:
                return true
            case let .sessions(ids):
                return ids.contains(session.id)
            case let .timeRange(start, end):
                guard let begin = session.startTime else {
                    return false
                }
                return begin <= end && begin.addingTimeInterval(session.duration ?? 0) >= start
            case .frames:
                return framedSessionIDs.contains(session.id)
            case .frameExpression:
                // Per-session notes are added only to matching packets by the
                // streaming exporter; do not copy unrelated notes into comments.
                return false
            }
        }
        let titles = Dictionary(findings.map { ($0.id, $0.title) }, uniquingKeysWith: { first, _ in first })
        return included.flatMap { session in
            let subject = "\(session.host) (\(session.sourceEndpoint) to \(session.destinationEndpoint))"
            return investigationNotes.notes(onSession: session.id).map { note in
                switch note.target {
                case .session:
                    "Tracexy note on \(subject): \(note.text)"
                case let .finding(id, _):
                    "Tracexy note on the finding \u{201C}\(titles[id] ?? "finding")\u{201D} in \(subject): \(note.text)"
                }
            }
        }
    }

    // MARK: Private

    /// Sessions that own any frame in a `.frames` scope, gathered in a single pass
    /// over the marked ordinals and the listed rows. Empty for every other scope.
    private func frameScopeSessionIDs(_ scope: FrameExportScope) -> Set<UUID> {
        guard case let .frames(ordinals) = scope else {
            return []
        }
        var ids = Set<UUID>()
        for (ordinal, sessionID) in allFrames.markedSessionIDs where ordinals.contains(ordinal) {
            ids.insert(sessionID)
        }
        for row in allFrames.list?.rows ?? [] where ordinals.contains(row.ordinal) {
            if let sessionID = row.sessionID {
                ids.insert(sessionID)
            }
        }
        return ids
    }

    private func runFrameExport(_ choice: FrameExportPanel.Choice, originProjectID: UUID?, originGeneration: Int) {
        if let captureComment = choice.captureComment {
            guard choice.options.format == .pcapng,
                  !choice.options.anonymizesAddresses,
                  captureComment.utf8.count <= FrameExportOptions.maximumCommentBytes else
            {
                captureError = String(
                    localized: "The additional capture comment needs PCAPNG without address replacement and must be no more than \(FrameExportOptions.maximumCommentBytes.formatted()) UTF-8 bytes."
                )
                setSessionExporting(false)
                return
            }
        }
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
        var options = choice.options
        if options.format == .pcapng {
            if let captureComment = choice.captureComment {
                options.captureComments.insert(captureComment, at: 0)
            }
            if choice.includesNotes {
                options.captureComments.append(contentsOf: frameExportNoteComments(for: choice.scope))
                options.sessionFrameComments = frameExportSessionFrameComments()
                // Comments written on frames in View ▸ All Frames, as Wireshark saves its
                // packet comments into the file.
                options.frameComments = allFrames.frameComments
            }
            if let correction = choice.timeCorrectionRequest {
                options.timeCorrection = correction
                options.captureComments.insert(correction.provenanceComment, at: 0)
            }
            if let correction = activeSavedCapture?.timeCorrection {
                options.baseTimeCorrection = correction
                if choice.timeCorrectionRequest == nil {
                    options.captureComments.insert(correction.request.provenanceComment, at: 0)
                }
            }
        }
        if choice.includesNames, options.format == .pcapng {
            options.nameRecords = frameExportNameRecords()
        }
        let exportOptions = options

        frameExportTask = Task { @MainActor [weak self] in
            var failure: String?
            var warning: String?
            var didWrite = false
            do {
                try Task.checkCancellation()
                let worker = Task.detached(priority: .userInitiated) { () throws -> FrameExportSummary in
                    if let savedSource {
                        return try CaptureFrameExporter.export(
                            from: savedSource, expectedIdentity: identity, scope: choice.scope,
                            options: exportOptions, to: choice.url, onProgress: relay.submit
                        )
                    }
                    let temporaryURL = FileManager.default.temporaryDirectory
                        .appendingPathComponent("tracexy-frame-export-\(UUID().uuidString).pcapng")
                    defer { try? FileManager.default.removeItem(at: temporaryURL) }
                    try Task.checkCancellation()
                    guard let ordinalOffset = await spool.currentSegmentFrameOrdinalOffset() else {
                        throw FrameExportError.frameOrdinalOverflow
                    }
                    let scope = try choice.scope.addingFrameOrdinalOffset(ordinalOffset)
                    var options = exportOptions
                    try options.addFrameOrdinalOffset(ordinalOffset)
                    try await spool.copyWholeCapture(to: temporaryURL)
                    try Task.checkCancellation()
                    return try CaptureFrameExporter.export(
                        from: temporaryURL, scope: scope, options: options,
                        to: choice.url, onProgress: relay.submit
                    )
                }
                let summary = try await withTaskCancellationHandler {
                    try await worker.value
                } onCancel: {
                    worker.cancel()
                }
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
            guard didWrite, choice.timeCorrectionRequest != nil,
                  self.activeRuntime.projectID == originProjectID,
                  self.startGeneration == originGeneration,
                  !self.isProjectBoundaryBusy else
            {
                return
            }
            let values = try? choice.url.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey])
            self.openSavedCapture(SavedCapture(
                url: choice.url,
                name: choice.url.deletingPathExtension().lastPathComponent,
                date: values?.contentModificationDate ?? Date(),
                byteCount: values?.fileSize ?? 0
            ))
        }
    }

    /// Each address with each name the capture's DNS/mDNS answers or the Project
    /// gave it, once, for the exported file's Name Resolution Block.
    func frameExportNameRecords() -> [FrameExportNameRecord] {
        var seen: Set<String> = []
        return resolvedAddressRows.compactMap { row in
            guard seen.insert("\(row.address)|\(row.name)").inserted else {
                return nil
            }
            return FrameExportNameRecord(address: row.address, name: row.name)
        }
    }

    nonisolated static func frameExportWarning(_ summary: FrameExportSummary) -> String? {
        var notes: [String] = []
        if summary.excludedIgnoredFrameCount > 0 {
            notes.append(
                "\(summary.excludedIgnoredFrameCount.formatted()) ignored frame(s) were excluded from the selected export scope"
            )
        }
        if summary.omittedFrameOptionCount > 0 {
            notes.append("\(summary.omittedFrameOptionCount.formatted()) packet option list(s) could not be copied")
        }
        if summary.omittedInterfaceOptionCount > 0 {
            notes.append("\(summary.omittedInterfaceOptionCount.formatted()) interface option(s) were omitted")
        }
        if summary.omittedSectionOptionCount > 0 {
            notes.append("\(summary.omittedSectionOptionCount.formatted()) section option(s) were omitted or truncated")
        }
        if summary.sourceMetadataInventoryTruncated {
            notes
                .append(
                    "The source container inventory was bounded; some section or interface metadata may not have been copied"
                )
        }
        if case .incompleteTruncatedTail = summary.completeness {
            notes.append("the source ends mid-record, so the export holds every complete frame")
        }
        if summary.unanonymizedFrameCount > 0 {
            notes.append(
                "\(summary.unanonymizedFrameCount.formatted()) frame(s) were left out because their addresses "
                    + "could not be replaced safely"
            )
        }
        if summary.unstrippedFrameCount > 0 {
            notes.append(
                "\(summary.unstrippedFrameCount.formatted()) frame(s) were left out because they carry no inner "
                    + "packet of the kind chosen under Headers"
            )
        }
        if summary.removedDuplicateCount > 0 {
            notes.append("\(summary.removedDuplicateCount.formatted()) duplicate frame(s) were left out")
        }
        if summary.truncatedFrameCount > 0 {
            notes.append("\(summary.truncatedFrameCount.formatted()) frame(s) were cut to the byte limit")
        }
        if summary.unknownExpressionFrameCount > 0 {
            notes.append(
                "\(summary.unknownExpressionFrameCount.formatted()) frame(s) were omitted because the expression result was unknown"
            )
        }
        if summary.replacedAddressCount > 0 {
            notes.append(
                "\(summary.replacedAddressCount.formatted()) addresses were replaced in packet headers; payloads such as "
                    + "DNS answers and HTTP headers were not changed"
            )
        }
        guard !notes.isEmpty else {
            return nil
        }
        return "Exported \(summary.writtenFrameCount.formatted()) frames; " + notes.joined(separator: "; ") + "."
    }
}
