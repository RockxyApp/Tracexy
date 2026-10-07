import AppKit
import Foundation
import UniformTypeIdentifiers

// MARK: - Investigation export (sessions/findings table, report)

@MainActor
extension MainContentCoordinator {
    /// Whether there is anything in view to export.
    var canExportInvestigation: Bool {
        !visibleSessions.isEmpty && !isProjectBoundaryBusy
    }

    /// Snapshot what is on screen now: the sessions in view, their findings, notes, and
    /// the scope that produced them.
    func investigationExportInput(now: Date = Date()) -> InvestigationExportInput {
        let sessions = visibleSessions
        let inView = Set(sessions.map(\.id))
        let viewFindings = findings.filter { inView.contains($0.sessionID) }
        let findingsBySession = Dictionary(grouping: viewFindings, by: \.sessionID)
        let hosts = Dictionary(sessions.map { ($0.id, $0.host) }, uniquingKeysWith: { first, _ in first })
        let workspace = activeWorkspace
        let expression = workspace.acceptedInvestigationDraft.flatMap { draft in
            draft.mode == .expression ? draft.expression.trimmingCharacters(in: .whitespacesAndNewlines) : nil
        }
        let input = InvestigationExportInput(
            captureName: activeSavedCapture?.url.deletingPathExtension().lastPathComponent
                ?? (isCapturing ? "Live capture" : "Capture"),
            generatedAt: now,
            totalSessionCount: presentedSessions.count,
            expression: expression?.isEmpty == false ? expression : nil,
            // Anything narrowing the view other than a session expression: pills,
            // search, sidebar scopes, rules, or a row-built query.
            hasOtherFilters: sessions.count < presentedSessions.count
                && (expression == nil || Self.hasFiltersBesidesExpression(workspace)),
            sessions: sessions.map { session in
                InvestigationExportInput.SessionEntry(
                    session: session,
                    findingTitles: (findingsBySession[session.id] ?? []).map(\.title),
                    notes: exportedNotes(for: session)
                )
            },
            findings: viewFindings.map { finding in
                InvestigationExportInput.FindingEntry(
                    id: finding.id,
                    sessionID: finding.sessionID,
                    severity: finding.severity.exportName,
                    title: finding.title,
                    detail: finding.subtitle,
                    citedFrameOrdinals: finding.citedFrames.map(\.ordinal.rawValue),
                    omittedCitationCount: finding.omittedCitationCount,
                    sessionHost: hosts[finding.sessionID] ?? ""
                )
            }
        )
        return investigationExportMasksAddresses ? input.maskingAddresses() : input
    }

    /// Privacy ▸ Mask IP addresses for the active Project.
    var investigationExportMasksAddresses: Bool {
        PrivacySettingsResolver.exportPolicy(defaults: activeProjectDefaults).maskIPAddresses
    }

    private static func hasFiltersBesidesExpression(_ workspace: WorkspaceState) -> Bool {
        workspace.sidebarSelection.protocolFilter != nil
            || workspace.isSearchActive
            || !workspace.categoryFilters.isEmpty
            || workspace.hostFilter != nil
            || workspace.processFilter != nil
            || workspace.ipFilter != nil
            || !workspace.aggregateProtocolFilters.isEmpty
            || workspace.aggregateDestinationFilter != nil
            || workspace.aggregateRequiresFindings
            || !workspace.activeFilterRules.isEmpty
    }

    /// File ▸ Export Investigation: write the sessions in view (and their findings)
    /// as the chosen file after a Save panel. Nothing leaves the Mac unless the user
    /// sends the file on.
    func exportInvestigation(_ kind: InvestigationExportKind) {
        guard canExportInvestigation else {
            return
        }
        let input = investigationExportInput()
        let originProjectID = activeRuntime.projectID
        let originGeneration = startGeneration
        let panel = NSSavePanel()
        panel.title = "Export \(kind.fileStem)"
        panel.nameFieldStringValue = "\(input.captureName) \(kind.fileStem)"
        panel.allowedContentTypes = [UTType(filenameExtension: kind.fileExtension) ?? .data]
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        let hasNotes = input.sessions.contains { !$0.notes.isEmpty }
        panel.message = switch (hasNotes, investigationExportMasksAddresses) {
        case (false, false): String(localized: "Exports the \(input.sessions.count) sessions in view.")
        case (
            true,
            false
        ): String(localized: "Exports the \(input.sessions.count) sessions in view, including your notes.")
        case (
            false,
            true
        ): String(localized: "Exports the \(input.sessions.count) sessions in view, with IP addresses masked.")
        case (
            true,
            true
        ): String(
                localized: "Exports the \(input.sessions.count) sessions in view, including your notes, with IP addresses masked."
            )
        }
        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }
        Task { @MainActor [weak self] in
            var failure: String?
            do {
                try await Task.detached(priority: .userInitiated) {
                    try InvestigationExport.data(for: kind, input: input).write(to: url, options: .atomic)
                }.value
            } catch {
                failure = "Couldn’t export: \(error.localizedDescription)"
            }
            self?.reportCaptureIOOutcome(
                failure: failure,
                warning: nil,
                didWrite: failure == nil,
                originProjectID: originProjectID,
                originGeneration: originGeneration
            )
        }
    }
}

extension Finding.Severity {
    /// A stable, lower-case spelling for exported files.
    var exportName: String {
        switch self {
        case .error: "error"
        case .warning: "warning"
        case .note: "note"
        }
    }
}
