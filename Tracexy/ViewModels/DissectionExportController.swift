import AppKit
import Foundation
import Observation
import UniformTypeIdentifiers

// MARK: - DissectionExportController

/// File ▸ Export Packet Dissections…: supported text sections, summary CSV or
/// JSON (see ``DissectionExporter``) for the chosen capture frame scope. On
/// the same terms as Export Frames:
/// a saved or stopped live capture, the privacy acknowledgement, and an outcome
/// reported where capture I/O outcomes go.
@MainActor
@Observable
final class DissectionExportController {
    static let shared = DissectionExportController()

    private(set) var isExporting = false

    private(set) var isPrinting = false

    static func dissectionExportWarning(
        summary: DissectionExporter.Summary,
        markedOnly: Bool,
        hasFrameSelection: Bool,
        hasFrameExpression: Bool
    )
        -> String?
    {
        if summary.writtenFrameCount == 0 {
            if summary.unknownExpressionFrameCount > 0, summary.excludedIgnoredFrameCount > 0 {
                return String(
                    localized: "No frames were written. \(summary.unknownExpressionFrameCount.formatted()) frame(s) could not be evaluated and \(summary.excludedIgnoredFrameCount.formatted()) ignored frame(s) were excluded."
                )
            }
            if summary.excludedIgnoredFrameCount > 0 {
                return String(
                    localized: "No frames were written. \(summary.excludedIgnoredFrameCount.formatted()) ignored frame(s) were excluded from the selected scope."
                )
            }
            if hasFrameExpression {
                if summary.unknownExpressionFrameCount > 0 {
                    return String(
                        localized: "No frame matched the applied Frame Expression. \(summary.unknownExpressionFrameCount.formatted()) frame(s) could not be evaluated."
                    )
                }
                return String(localized: "No frame matched the applied Frame Expression.")
            }
            if markedOnly {
                return String(localized: "No marked frame was found in this capture; the export has no frame rows.")
            }
            if !hasFrameSelection {
                return String(
                    localized: "No frame of the sessions in view was found; the export has no frame rows."
                )
            }
            return String(localized: "No frame in the selected capture range was found; the export has no frame rows.")
        }
        if summary.unknownExpressionFrameCount > 0, summary.excludedIgnoredFrameCount > 0 {
            return String(
                localized: "\(summary.unknownExpressionFrameCount.formatted()) frame(s) could not be evaluated and \(summary.excludedIgnoredFrameCount.formatted()) ignored frame(s) were excluded."
            )
        }
        if summary.excludedIgnoredFrameCount > 0 {
            return String(
                localized: "\(summary.excludedIgnoredFrameCount.formatted()) ignored frame(s) were excluded from the selected scope."
            )
        }
        guard summary.unknownExpressionFrameCount > 0 else {
            return nil
        }
        return String(
            localized: "\(summary.unknownExpressionFrameCount.formatted()) frame(s) could not be evaluated and were left out."
        )
    }

    /// Print the chosen bounded packet view for the sessions currently in view.
    /// The bounded text is prepared off-main and shown to AppKit only after the
    /// entire stable capture has passed the exporter's integrity checks.
    func printDissections(
        from coordinator: MainContentCoordinator,
        markedOnly: Bool = false,
        firstToLastMarked: Bool = false,
        frameSelection: FrameOrdinalSelection? = nil,
        frameExpression: FrameExpression? = nil,
        layout: DissectionExporter.TextLayout = .details
    ) {
        guard !isPrinting else {
            return
        }
        guard coordinator.canExportFrames else {
            coordinator.captureError = coordinator.captureSourceHoldMessage
                ?? String(localized: "Open a saved capture or stop the live capture before printing dissections.")
            return
        }
        let marks = coordinator.allFrames.marked
        let markedFrames = markedOnly ? marks : nil
        let markedRange: ClosedRange<UInt64>? = if firstToLastMarked,
                                                   let first = marks.min(), let last = marks.max()
        {
            first ... last
        } else {
            nil
        }
        if markedOnly || firstToLastMarked, marks.isEmpty {
            coordinator
                .captureError = String(localized: "Mark frames in All Frames before printing marked packet views.")
            return
        }
        let originProjectID = coordinator.activeRuntime.projectID
        let originGeneration = coordinator.startGeneration
        let filtered = coordinator.visibleSessions.count != coordinator.sessions.count
        let sessions = markedOnly || firstToLastMarked || frameSelection != nil || frameExpression != nil ? nil :
            (filtered ? Set(coordinator.visibleSessions.map(\.id)) : nil)
        let savedURL = coordinator.isViewingSavedCapture ? coordinator.savedCaptureEvidenceURL : nil
        let savedIdentity = coordinator.adoptedSavedCaptureIdentity
        let spool = coordinator.liveCaptureSpool
        // A Time Shift belongs to the saved file it was resolved against; a live
        // spool has none, so the overlay is taken only when a saved source is read.
        let timeCorrection = savedURL == nil ? nil : coordinator.activeSavedCapture?.timeCorrection
        coordinator.setSessionExporting(true)
        let ignored = coordinator.allFrames.ignored
        guard let excludedFrameOrdinals = Self.chooseIgnoredFrameExclusion(ignored) else {
            coordinator.setSessionExporting(false)
            return
        }
        let privacy = PrivacySettingsResolver.exportPolicy(defaults: coordinator.activeProjectDefaults)
        if layout.contains(.bytes), !Self.confirmRawBytesForPrinting() {
            coordinator.setSessionExporting(false)
            return
        }
        if !layout.contains(.bytes), privacy.hasProtections,
           !Self.confirmUnmaskedDetails(forPrinting: true, summaries: layout == .summary)
        {
            coordinator.setSessionExporting(false)
            return
        }
        guard coordinator.activeRuntime.projectID == originProjectID,
              coordinator.startGeneration == originGeneration,
              !coordinator.isProjectBoundaryBusy,
              !coordinator.isCapturing,
              !coordinator.isStarting else
        {
            coordinator.setSessionExporting(false)
            coordinator
                .captureError = String(localized: "The capture changed while the print options were open. Print again.")
            return
        }
        isPrinting = true
        Task { [weak coordinator] in
            var failure: String?
            var warning: String?
            do {
                let printResult = try await Task.detached(priority: .userInitiated) {
                    () throws -> (String, Int, Int) in
                    let temporary = FileManager.default.temporaryDirectory
                        .appendingPathComponent("tracexy-print-dissections-\(UUID().uuidString)")
                    try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
                    defer { try? FileManager.default.removeItem(at: temporary) }
                    let source = try await MainContentCoordinator.frameToolSource(
                        savedURL: savedURL, savedIdentity: savedIdentity, spool: spool,
                        temporaryURL: temporary.appendingPathComponent("capture.pcapng")
                    )
                    var output = Data()
                    let summary = try DissectionExporter.export(
                        from: source.url, expectedIdentity: source.identity, sessions: sessions,
                        frameOrdinals: markedFrames, frameRange: markedRange,
                        frameSelection: frameSelection, frameExpression: frameExpression,
                        excludedFrameOrdinals: excludedFrameOrdinals, format: .text,
                        textLayout: layout, timeCorrection: timeCorrection
                    ) { chunk in
                        let maximumTextBytes = 8 * 1_024 * 1_024
                        guard chunk.count <= maximumTextBytes,
                              output.count <= maximumTextBytes - chunk.count else
                        {
                            throw PrintError.tooLarge
                        }
                        output.append(chunk)
                    }
                    guard summary.writtenFrameCount > 0 else {
                        if summary.excludedIgnoredFrameCount > 0 {
                            if summary.unknownExpressionFrameCount > 0 {
                                throw PrintError.noExpressionMatches(
                                    unknownFrameCount: summary.unknownExpressionFrameCount,
                                    excludedIgnoredFrameCount: summary.excludedIgnoredFrameCount
                                )
                            }
                            throw PrintError.noFramesAfterIgnoring(summary.excludedIgnoredFrameCount)
                        }
                        if frameExpression != nil {
                            throw PrintError.noExpressionMatches(unknownFrameCount: summary.unknownExpressionFrameCount)
                        }
                        throw PrintError.noFrames
                    }
                    guard let text = String(data: output, encoding: .utf8) else {
                        throw PrintError.invalidText
                    }
                    return (text, summary.unknownExpressionFrameCount, summary.excludedIgnoredFrameCount)
                }.value
                guard coordinator?.activeRuntime.projectID == originProjectID,
                      coordinator?.startGeneration == originGeneration,
                      coordinator?.isProjectBoundaryBusy == false,
                      coordinator?.isCapturing == false,
                      coordinator?.isStarting == false else
                {
                    isPrinting = false
                    coordinator?.setSessionExporting(false)
                    // Preparation can finish after the capture moved on. Printing
                    // the stale text would be wrong, but so is dropping the user's
                    // request without a word, so the same Project hears why.
                    coordinator?.reportCaptureIOOutcome(
                        failure: String(
                            localized: "The capture changed while the packet views were being prepared. Print again."
                        ),
                        warning: nil, didWrite: false,
                        originProjectID: originProjectID, originGeneration: originGeneration
                    )
                    return
                }
                let (printedText, unknownFrameCount, excludedIgnoredFrameCount) = printResult
                if try Self.printPreparedText(printedText) {
                    warning = Self.printWarning(
                        unknownFrameCount: unknownFrameCount,
                        excludedIgnoredFrameCount: excludedIgnoredFrameCount
                    )
                }
            } catch is CancellationError {
                // No print panel is shown when preparation is cancelled.
            } catch {
                failure =
                    String(localized: "Couldn’t prepare packet views for printing: \(error.localizedDescription)")
            }
            isPrinting = false
            coordinator?.setSessionExporting(false)
            if let failure {
                coordinator?.reportCaptureIOOutcome(
                    failure: failure, warning: nil, didWrite: false,
                    originProjectID: originProjectID, originGeneration: originGeneration
                )
            } else if let warning {
                coordinator?.reportCaptureIOOutcome(
                    failure: nil, warning: warning, didWrite: false,
                    originProjectID: originProjectID, originGeneration: originGeneration
                )
            }
        }
    }

    func printCustomPacketViews(from coordinator: MainContentCoordinator) {
        guard coordinator.canExportFrames else {
            coordinator.captureError = coordinator.captureSourceHoldMessage
                ?? String(localized: "Open a saved capture or stop the live capture before printing dissections.")
            return
        }
        let originProjectID = coordinator.activeRuntime.projectID
        let originGeneration = coordinator.startGeneration
        coordinator.setSessionExporting(true)
        let alert = NSAlert()
        alert.messageText = String(localized: "Print Packet Views")
        alert.informativeText = String(localized: "Choose the packet sections to include for sessions in view.")
        let summary = NSButton(checkboxWithTitle: String(localized: "Packet summary lines"), target: nil, action: nil)
        let details = NSButton(checkboxWithTitle: String(localized: "Decoded packet details"), target: nil, action: nil)
        let bytes = NSButton(checkboxWithTitle: String(localized: "Captured packet bytes"), target: nil, action: nil)
        details.state = .on
        let sections = NSStackView(views: [summary, details, bytes])
        sections.orientation = .vertical
        sections.alignment = .leading
        sections.spacing = 6
        alert.accessoryView = sections
        alert.addButton(withTitle: String(localized: "Continue"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else {
            coordinator.setSessionExporting(false)
            return
        }
        var layout: DissectionExporter.TextLayout = []
        if summary.state == .on {
            layout.insert(.summary)
        }
        if details.state == .on {
            layout.insert(.details)
        }
        if bytes.state == .on {
            layout.insert(.bytes)
        }
        guard !layout.isEmpty else {
            coordinator.setSessionExporting(false)
            coordinator.captureError = String(localized: "Choose at least one packet section before printing.")
            return
        }
        guard coordinator.activeRuntime.projectID == originProjectID,
              coordinator.startGeneration == originGeneration,
              coordinator.isExportingSession,
              !coordinator.isProjectBoundaryBusy,
              !coordinator.isCapturing,
              !coordinator.isStarting else
        {
            coordinator.setSessionExporting(false)
            coordinator
                .captureError = String(localized: "The capture changed while the print options were open. Print again.")
            return
        }
        coordinator.setSessionExporting(false)
        printDissections(from: coordinator, layout: layout)
    }

    func printFrameRange(
        from coordinator: MainContentCoordinator,
        layout: DissectionExporter.TextLayout
    ) {
        guard coordinator.canExportFrames else {
            coordinator.captureError = coordinator.captureSourceHoldMessage
                ?? String(localized: "Open a saved capture or stop the live capture before printing dissections.")
            return
        }
        let originProjectID = coordinator.activeRuntime.projectID
        let originGeneration = coordinator.startGeneration
        coordinator.setSessionExporting(true)
        let alert = NSAlert()
        alert.messageText = String(localized: "Print Capture Frame Range")
        alert
            .informativeText =
            String(
                localized: "Enter capture frame numbers, for example 5,10-15,20-. The scope is capture-wide and uses original frame numbers."
            )
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
        field.placeholderString = "5,10-15,20-"
        field.setAccessibilityLabel(String(localized: "Capture frame range"))
        alert.accessoryView = field
        alert.addButton(withTitle: String(localized: "Continue"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else {
            coordinator.setSessionExporting(false)
            return
        }
        guard let selection = FrameOrdinalSelection.parse(field.stringValue) else {
            coordinator.setSessionExporting(false)
            coordinator.captureError = String(localized: "Enter positive frame numbers and ranges such as 5,10-15,20-.")
            return
        }
        guard coordinator.activeRuntime.projectID == originProjectID,
              coordinator.startGeneration == originGeneration,
              coordinator.isExportingSession,
              !coordinator.isProjectBoundaryBusy,
              !coordinator.isCapturing,
              !coordinator.isStarting else
        {
            coordinator.setSessionExporting(false)
            coordinator
                .captureError = String(localized: "The capture changed while the print options were open. Print again.")
            return
        }
        coordinator.setSessionExporting(false)
        printDissections(from: coordinator, frameSelection: selection, layout: layout)
    }

    func exportFrameRange(from coordinator: MainContentCoordinator) {
        guard coordinator.canExportFrames else {
            coordinator.captureError = coordinator.captureSourceHoldMessage
                ?? String(localized: "Open a saved capture or stop the live capture before exporting dissections.")
            return
        }
        let originProjectID = coordinator.activeRuntime.projectID
        let originGeneration = coordinator.startGeneration
        coordinator.setSessionExporting(true)
        let alert = NSAlert()
        alert.messageText = String(localized: "Export Capture Frame Range")
        alert.informativeText = String(
            localized: "Enter capture frame numbers, for example 5,10-15,20-. The scope is capture-wide and uses original frame numbers."
        )
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
        field.placeholderString = "5,10-15,20-"
        field.setAccessibilityLabel(String(localized: "Capture frame range"))
        alert.accessoryView = field
        alert.addButton(withTitle: String(localized: "Continue"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else {
            coordinator.setSessionExporting(false)
            return
        }
        guard let selection = FrameOrdinalSelection.parse(field.stringValue) else {
            coordinator.setSessionExporting(false)
            coordinator.captureError = String(localized: "Enter positive frame numbers and ranges such as 5,10-15,20-.")
            return
        }
        guard coordinator.activeRuntime.projectID == originProjectID,
              coordinator.startGeneration == originGeneration,
              coordinator.isExportingSession,
              !coordinator.isProjectBoundaryBusy,
              !coordinator.isCapturing,
              !coordinator.isStarting else
        {
            coordinator.setSessionExporting(false)
            coordinator
                .captureError =
                String(localized: "The capture changed while the export options were open. Export again.")
            return
        }
        coordinator.setSessionExporting(false)
        export(from: coordinator, frameSelection: selection)
    }

    func exportFirstToLastMarked(from coordinator: MainContentCoordinator) {
        guard let first = coordinator.allFrames.marked.min(),
              let last = coordinator.allFrames.marked.max() else
        {
            coordinator
                .captureError = String(localized: "Mark frames in All Frames before exporting marked packet views.")
            return
        }
        let selection = FrameOrdinalSelection(intervals: [.init(first: first, last: last)])
        export(from: coordinator, frameSelection: selection)
    }

    func export(
        from coordinator: MainContentCoordinator,
        frameSelection: FrameOrdinalSelection? = nil,
        markedOnly: Bool = false,
        frameExpression: FrameExpression? = nil
    ) {
        guard !isExporting else {
            return
        }
        guard coordinator.canExportFrames else {
            coordinator.captureError = coordinator.captureSourceHoldMessage
                ?? String(localized: "Open a saved capture or stop the live capture before exporting dissections.")
            return
        }
        let markedFrames = markedOnly ? coordinator.allFrames.marked : nil
        if markedOnly, markedFrames?.isEmpty == true {
            coordinator
                .captureError = String(localized: "Mark frames in All Frames before exporting marked packet views.")
            return
        }
        let originProjectID = coordinator.activeRuntime.projectID
        let originGeneration = coordinator.startGeneration
        let filtered = coordinator.visibleSessions.count != coordinator.sessions.count
        let sessions = frameSelection == nil && !markedOnly && frameExpression == nil && filtered
            ? Set(coordinator.visibleSessions.map(\.id)) : nil
        let savedURL = coordinator.isViewingSavedCapture ? coordinator.savedCaptureEvidenceURL : nil
        let savedIdentity = coordinator.adoptedSavedCaptureIdentity
        let spool = coordinator.liveCaptureSpool
        // A Time Shift belongs to the saved file it was resolved against; a live
        // spool has none, so the overlay is taken only when a saved source is read.
        let timeCorrection = savedURL == nil ? nil : coordinator.activeSavedCapture?.timeCorrection
        let appliedFieldColumns = Array(
            coordinator.packetDetailOptions.frameColumns.prefix(PacketDetailOptions.maximumFrameColumns)
        )
        // Freeze the source and selection across both modal panels and the worker.
        coordinator.setSessionExporting(true)
        let panel = NSSavePanel()
        panel.title = String(localized: "Export Packet Dissections")
        let singleFrameOrdinal = frameSelection.flatMap { selection -> UInt64? in
            guard selection.intervals.count == 1,
                  let interval = selection.intervals.first,
                  interval.last == interval.first else
            {
                return nil
            }
            return interval.first
        }
        panel.message = if let singleFrameOrdinal {
            String(localized: "Export the dissection for frame \(singleFrameOrdinal.formatted()) from this capture.")
        } else if frameExpression != nil {
            String(localized: "Export frames matching the applied Frame Expression across this capture.")
        } else {
            String(localized: "Choose a format and supported packet sections from this capture.")
        }
        let ignoredFrameOrdinals = coordinator.allFrames.ignored
        let accessory = FormatAccessory(
            panel: panel, ignoredFrameOrdinals: ignoredFrameOrdinals, appliedFieldColumns: appliedFieldColumns
        )
        panel.accessoryView = accessory.view
        panel.nameFieldStringValue = "Dissections.txt"
        panel.allowedContentTypes = [.plainText]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let output = panel.url else {
            coordinator.setSessionExporting(false)
            return
        }
        let format = accessory.format
        let textLayout = accessory.textLayout
        let includeRawFieldBytes = accessory.includesRawFieldBytes
        let includeAppliedFieldColumns = accessory.includesAppliedFieldColumns
        let includeTimestampPreamble = accessory.includesTimestampPreamble
        let excludedFrameOrdinals = accessory.excludesIgnoredFrames ? ignoredFrameOrdinals : []
        if format == .text, textLayout.isEmpty {
            coordinator
                .captureError = String(localized: "Choose at least one plain-text packet section before exporting.")
            coordinator.setSessionExporting(false)
            return
        }
        if (format == .text && textLayout.contains(.bytes))
            || (format == .json && includeRawFieldBytes)
        {
            guard Self.confirmRawBytesForExport(fieldBytes: format == .json && includeRawFieldBytes) else {
                coordinator.setSessionExporting(false)
                return
            }
        } else {
            let privacy = PrivacySettingsResolver.exportPolicy(defaults: coordinator.activeProjectDefaults)
            if privacy.hasProtections, !Self.confirmUnmaskedDetails() {
                coordinator.setSessionExporting(false)
                return
            }
        }
        guard coordinator.activeRuntime.projectID == originProjectID,
              coordinator.startGeneration == originGeneration,
              coordinator.packetDetailOptions.frameColumns == appliedFieldColumns,
              !coordinator.isProjectBoundaryBusy,
              !coordinator.isCapturing,
              !coordinator.isStarting else
        {
            coordinator.setSessionExporting(false)
            coordinator
                .captureError =
                String(
                    localized: "The capture, Project, or applied field columns changed while the export panel was open. Export again."
                )
            return
        }
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
                        return try DissectionExportFileWriter.export(
                            from: source.url, expectedIdentity: source.identity,
                            sessions: sessions, frameOrdinals: markedFrames,
                            frameSelection: frameSelection, frameExpression: frameExpression,
                            excludedFrameOrdinals: excludedFrameOrdinals, format: format,
                            textLayout: textLayout, includeRawFieldBytes: includeRawFieldBytes,
                            appliedFieldColumns: includeAppliedFieldColumns ? appliedFieldColumns : [],
                            includeTimestampPreamble: includeTimestampPreamble,
                            timeCorrection: timeCorrection, to: output
                        )
                    }.value
                didWrite = true
                warning = Self.dissectionExportWarning(
                    summary: summary, markedOnly: markedOnly,
                    hasFrameSelection: frameSelection != nil, hasFrameExpression: frameExpression != nil
                )
            } catch is CancellationError {
                // Nothing was published: the file is moved into place only at the end.
            } catch {
                failure = String(localized: "Couldn’t export the dissections: \(error.localizedDescription)")
            }
            isExporting = false
            coordinator?.setSessionExporting(false)
            coordinator?.reportCaptureIOOutcome(
                failure: failure, warning: warning, didWrite: didWrite,
                originProjectID: originProjectID, originGeneration: originGeneration
            )
        }
    }
}

// MARK: - Confirmation

private extension DissectionExportController {
    /// What a completed print left out, or nil when it carried everything.
    static func printWarning(unknownFrameCount: Int, excludedIgnoredFrameCount: Int) -> String? {
        let parts = [
            unknownFrameCount > 0
                ?
                String(
                    localized: "\(unknownFrameCount.formatted()) frame(s) could not be evaluated and were left out."
                )
                : nil,
            excludedIgnoredFrameCount > 0
                ? String(localized: "\(excludedIgnoredFrameCount.formatted()) ignored frame(s) were excluded.")
                : nil,
        ].compactMap { $0 }
        return parts.isEmpty ? nil : parts.joined(separator: " ")
    }

    static func printPreparedText(_ printedText: String) throws -> Bool {
        let panel = NSPrintPanel()
        guard panel.runModal(with: NSPrintInfo.shared) != NSCancelButton else {
            return false
        }
        let printInfo = panel.printInfo
        let imageableBounds = printInfo.imageablePageBounds
        let pageWidth = max(1, imageableBounds.width)
        let view = NSTextView(frame: NSRect(x: 0, y: 0, width: pageWidth, height: 1))
        view.string = printedText.trimmingCharacters(in: .newlines)
        view.isEditable = false
        view.font = NSFont.monospacedSystemFont(ofSize: 9, weight: .regular)
        view.textContainer?.widthTracksTextView = true
        view.textContainer?.heightTracksTextView = false
        view.textContainer?.containerSize = NSSize(width: view.bounds.width, height: .greatestFiniteMagnitude)
        if let layoutManager = view.layoutManager, let textContainer = view.textContainer {
            layoutManager.ensureLayout(for: textContainer)
            let contentHeight = ceil(layoutManager.usedRect(for: textContainer).height)
                + view.textContainerInset.height * 2
            let pageHeight = max(1, imageableBounds.height)
            guard contentHeight <= 500 * pageHeight else {
                throw PrintError.tooTall
            }
            view.setFrameSize(NSSize(width: pageWidth, height: max(1, contentHeight)))
        }
        let operation = NSPrintOperation(view: view, printInfo: printInfo)
        operation.showsPrintPanel = false
        return operation.run()
    }

    static func chooseIgnoredFrameExclusion(_ ignored: Set<UInt64>) -> Set<UInt64>? {
        guard !ignored.isEmpty else {
            return []
        }
        let checkbox = NSButton(
            checkboxWithTitle: String(localized: "Exclude ignored frames"), target: nil, action: nil
        )
        checkbox.setAccessibilityLabel(String(localized: "Exclude ignored frames"))
        checkbox.toolTip = String(
            localized: "Omit frames currently marked Ignore from the selected print scope. Packet decoding still reads them to retain later context."
        )
        let alert = NSAlert()
        alert.messageText = String(localized: "Print Packet Views")
        alert.informativeText = String(localized: "Choose whether ignored frames appear in this printout.")
        alert.accessoryView = checkbox
        alert.addButton(withTitle: String(localized: "Continue"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else {
            return nil
        }
        return checkbox.state == .on ? ignored : []
    }

    static func confirmRawBytesForExport(fieldBytes: Bool = false) -> Bool {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = fieldBytes
            ? String(localized: "Export raw field bytes?")
            : String(localized: "Export raw packet bytes?")
        alert.informativeText = String(localized: """
        Captured bytes can contain credentials, message content, and other private data. \
        The selected output may also include unmasked addresses, host names, and URLs. \
        Handle the exported file as sensitive data.
        """)
        alert.addButton(withTitle: fieldBytes
            ? String(localized: "Export Field Bytes")
            : String(localized: "Export Bytes"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        return alert.runModal() == .alertFirstButtonReturn
    }

    static func confirmRawBytesForPrinting() -> Bool {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = String(localized: "Print raw packet bytes?")
        alert.informativeText = String(localized: """
        Packet bytes can contain credentials, message content, and other private data. The macOS print panel can send \
        them to a printer or save them as a PDF. Continue only if you intend to handle the output as sensitive data.
        """)
        alert.addButton(withTitle: String(localized: "Print Bytes"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        return alert.runModal() == .alertFirstButtonReturn
    }

    /// With Privacy protections on: non-byte packet views can spell out decoded
    /// addresses, names and URLs without masking.
    static func confirmUnmaskedDetails(forPrinting: Bool = false, summaries: Bool = false) -> Bool {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = summaries ? String(localized: "Print unmasked packet summaries?") :
            (forPrinting ? String(localized: "Print unmasked packet details?") :
                String(localized: "Export unmasked packet views?"))
        alert
            .informativeText = summaries ?
            String(localized: """
            Printed summaries can include addresses, names and protocol information. Packet bytes are not included, \
            but IP masking is not applied. Handle the pages or PDF as sensitive data.
            """) :
            (forPrinting
                ? String(localized: """
                Printed dissections list decoded fields, including IP addresses, host names and URLs. Packet bytes \
                are not included, but IP masking is not applied. Print only if you intend to handle the pages or PDF \
                as sensitive data.
                """)
                : String(localized: """
                Packet summaries or dissections can include addresses, host names, URLs and protocol information. \
                Packet bytes are not written, but IP masking is not applied. Handle the exported file as sensitive data.
                """))
        alert
            .addButton(withTitle: summaries ? String(localized: "Print Summaries") :
                (forPrinting ? String(localized: "Print Dissections") : String(localized: "Export Packet Views")))
        alert.addButton(withTitle: String(localized: "Cancel"))
        return alert.runModal() == .alertFirstButtonReturn
    }
}

// MARK: - PrintError

private enum PrintError: LocalizedError {
    case tooLarge
    case tooTall
    case noFrames
    case noFramesAfterIgnoring(Int)
    case noExpressionMatches(unknownFrameCount: Int, excludedIgnoredFrameCount: Int = 0)
    case invalidText

    // MARK: Internal

    var errorDescription: String? {
        switch self {
        case .tooLarge: String(
                localized: "The packet view exceeds the 8 MiB print limit. Narrow the print scope."
            )
        case .tooTall: String(
                localized: "The packet view exceeds the print layout limit. Narrow the print scope."
            )
        case .noFrames: String(localized: "No frames matched the selected print scope.")
        case let .noFramesAfterIgnoring(count):
            String(
                localized: "No frames were printed. \(count.formatted()) ignored frame(s) were excluded from the selected scope."
            )
        case let .noExpressionMatches(unknownFrameCount, excludedIgnoredFrameCount):
            if unknownFrameCount > 0 {
                if excludedIgnoredFrameCount > 0 {
                    String(
                        localized: "No frames were printed. \(unknownFrameCount.formatted()) frame(s) could not be evaluated and \(excludedIgnoredFrameCount.formatted()) ignored frame(s) were excluded."
                    )
                } else {
                    String(
                        localized: "No frame matched the applied Frame Expression. \(unknownFrameCount.formatted()) frame(s) could not be evaluated."
                    )
                }
            } else {
                String(localized: "No frame matched the applied Frame Expression.")
            }
        case .invalidText: String(localized: "The packet view could not be read as UTF-8.")
        }
    }
}

// MARK: - FormatAccessory

/// The save panel's format and plain-text section controls. At least one text
/// section stays selected; CSV and JSON use their fixed supported projections.
@MainActor
private final class FormatAccessory: NSObject {
    // MARK: Lifecycle

    init(panel: NSSavePanel, ignoredFrameOrdinals: Set<UInt64>, appliedFieldColumns: [FieldKey]) {
        self.panel = panel
        self.ignoredFrameOrdinals = ignoredFrameOrdinals
        self.appliedFieldColumns = appliedFieldColumns
        let label = NSTextField(labelWithString: String(localized: "Format:"))
        let row = NSStackView(views: [label, popUp])
        row.orientation = .horizontal
        row.spacing = 8
        let stack = NSStackView(views: [
            row, summaryCheck, detailsCheck, bytesCheck, timestampPreambleCheck,
            rawFieldBytesCheck, appliedFieldColumnsCheck,
            ignoredFramesCheck,
        ])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 4
        stack.edgeInsets = NSEdgeInsets(top: 8, left: 16, bottom: 8, right: 16)
        view = stack
        super.init()
        popUp.addItems(withTitles: [
            String(localized: "Plain Text"), String(localized: "Summary CSV"), String(localized: "JSON"),
        ])
        popUp.target = self
        popUp.action = #selector(formatChanged)
        popUp.setAccessibilityLabel(String(localized: "Format"))
        detailsCheck.state = .on
        timestampPreambleCheck.state = .off
        timestampPreambleCheck.isHidden = true
        timestampPreambleCheck.setAccessibilityLabel(String(localized: "Include timestamp before hex dump"))
        ignoredFramesCheck.isHidden = ignoredFrameOrdinals.isEmpty
        ignoredFramesCheck.setAccessibilityLabel(String(localized: "Exclude ignored frames"))
        ignoredFramesCheck.toolTip = String(
            localized: "Omit frames currently marked Ignore from the selected export scope. Packet decoding still reads them to retain later context."
        )
        rawFieldBytesCheck.state = .off
        rawFieldBytesCheck.isHidden = format != .json
        rawFieldBytesCheck.setAccessibilityLabel(String(localized: "Include raw field bytes"))
        rawFieldBytesCheck.toolTip = String(
            localized: "Include exact captured hex for fields with contiguous byte mappings. Unmapped and oversized fields are identified; a raw-data acknowledgement is required."
        )
        rawFieldBytesCheck.target = self
        rawFieldBytesCheck.action = #selector(formatChanged)
        appliedFieldColumnsCheck.state = .off
        appliedFieldColumnsCheck.isHidden = format != .csv || appliedFieldColumns.isEmpty
        appliedFieldColumnsCheck.setAccessibilityLabel(String(localized: "Include applied field columns"))
        appliedFieldColumnsCheck.toolTip = String(
            localized: "Append the applied All Frames field columns before Info, using the current Project's configured order. Repeated values are comma-joined."
        )
        appliedFieldColumnsCheck.target = self
        appliedFieldColumnsCheck.action = #selector(formatChanged)
        for checkbox in [summaryCheck, detailsCheck, bytesCheck] {
            checkbox.target = self
            checkbox.action = #selector(sectionChanged(_:))
        }
    }

    // MARK: Internal

    let view: NSView

    var excludesIgnoredFrames: Bool {
        !ignoredFramesCheck.isHidden && ignoredFramesCheck.state == .on
    }

    var format: DissectionExporter.Format {
        switch popUp.indexOfSelectedItem {
        case 1: .csv
        case 2: .json
        default: .text
        }
    }

    var textLayout: DissectionExporter.TextLayout {
        var selection: DissectionExporter.TextLayout = []
        if summaryCheck.state == .on {
            selection.insert(.summary)
        }
        if detailsCheck.state == .on {
            selection.insert(.details)
        }
        if bytesCheck.state == .on {
            selection.insert(.bytes)
        }
        return selection
    }

    var includesRawFieldBytes: Bool {
        !rawFieldBytesCheck.isHidden && rawFieldBytesCheck.state == .on
    }

    var includesAppliedFieldColumns: Bool {
        !appliedFieldColumnsCheck.isHidden && appliedFieldColumnsCheck.state == .on
    }

    var includesTimestampPreamble: Bool {
        !timestampPreambleCheck.isHidden && timestampPreambleCheck.state == .on
    }

    // MARK: Private

    private let popUp = NSPopUpButton()
    private let summaryCheck = NSButton(
        checkboxWithTitle: String(localized: "Packet summary lines"),
        target: nil,
        action: nil
    )
    private let detailsCheck = NSButton(
        checkboxWithTitle: String(localized: "Decoded packet details"),
        target: nil,
        action: nil
    )
    private let bytesCheck = NSButton(
        checkboxWithTitle: String(localized: "Captured packet bytes"),
        target: nil,
        action: nil
    )
    private let timestampPreambleCheck = NSButton(
        checkboxWithTitle: String(localized: "Include timestamp preamble"), target: nil, action: nil
    )
    private let rawFieldBytesCheck = NSButton(
        checkboxWithTitle: String(localized: "Include raw field bytes"), target: nil, action: nil
    )
    private let appliedFieldColumnsCheck = NSButton(
        checkboxWithTitle: String(localized: "Include applied field columns"), target: nil, action: nil
    )
    private let ignoredFramesCheck = NSButton(
        checkboxWithTitle: String(localized: "Exclude ignored frames"), target: nil, action: nil
    )
    private let ignoredFrameOrdinals: Set<UInt64>
    private let appliedFieldColumns: [FieldKey]
    private weak var panel: NSSavePanel?

    @objc
    private func sectionChanged(_ sender: NSButton) {
        if textLayout.isEmpty {
            sender.state = .on
        }
        formatChanged()
    }

    @objc
    private func formatChanged() {
        guard let panel else {
            return
        }
        let type: UTType = switch format {
        case .text: .plainText
        case .csv: .commaSeparatedText
        case .json: .json
        }
        let textEnabled = format == .text
        summaryCheck.isEnabled = textEnabled
        detailsCheck.isEnabled = textEnabled
        bytesCheck.isEnabled = textEnabled
        timestampPreambleCheck.isHidden = format != .text || bytesCheck.state != .on
        timestampPreambleCheck.setAccessibilityLabel(String(localized: "Include timestamp before hex dump"))
        timestampPreambleCheck.toolTip = String(
            localized: "Prefix each captured-byte hex dump with the frame's UTC timestamp, or 'unknown' when no timestamp was captured."
        )
        timestampPreambleCheck.target = self
        timestampPreambleCheck.action = #selector(formatChanged)
        rawFieldBytesCheck.isHidden = format != .json
        appliedFieldColumnsCheck.isHidden = format != .csv || appliedFieldColumns.isEmpty
        panel.allowedContentTypes = [type]
        let base = (panel.nameFieldStringValue as NSString).deletingPathExtension
        panel.nameFieldStringValue = base + (type.preferredFilenameExtension.map { ".\($0)" } ?? ".txt")
    }
}
