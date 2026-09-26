import Foundation

// MARK: - InvestigationExportKind

/// What File ▸ Export Investigation writes for the sessions currently in view.
nonisolated enum InvestigationExportKind: String, CaseIterable, Identifiable {
    case sessionsCSV
    case sessionsJSON
    case findingsCSV
    case report

    // MARK: Internal

    var id: String {
        rawValue
    }

    var menuTitle: String {
        switch self {
        case .sessionsCSV: "Sessions as CSV…"
        case .sessionsJSON: "Sessions and Findings as JSON…"
        case .findingsCSV: "Findings as CSV…"
        case .report: "Investigation Report…"
        }
    }

    var fileExtension: String {
        switch self {
        case .sessionsCSV,
             .findingsCSV: "csv"
        case .sessionsJSON: "json"
        case .report: "md"
        }
    }

    var fileStem: String {
        switch self {
        case .sessionsCSV: "Sessions"
        case .sessionsJSON: "Investigation"
        case .findingsCSV: "Findings"
        case .report: "Investigation Report"
        }
    }
}

// MARK: - InvestigationExportInput

/// Everything an export describes, captured on the main actor at the moment the
/// user asked, so the file says exactly what was on screen then.
nonisolated struct InvestigationExportInput: Sendable {
    struct SessionEntry: Sendable {
        let session: SessionSummary
        let findingTitles: [String]
        let notes: [SessionExportNote]
    }

    struct FindingEntry: Sendable {
        let id: UUID
        let sessionID: UUID
        let severity: String
        let title: String
        let detail: String
        let citedFrameOrdinals: [UInt64]
        let omittedCitationCount: UInt64
        let sessionHost: String
    }

    let captureName: String
    let generatedAt: Date
    let totalSessionCount: Int
    /// The accepted session expression narrowing the view, if any.
    let expression: String?
    /// Whether pills, search, sidebar scopes or rules also narrow the view.
    let hasOtherFilters: Bool
    let sessions: [SessionEntry]
    let findings: [FindingEntry]

    /// The same input with every IP literal replaced by ``PrivacyMask/placeholder``
    /// (endpoints keep their ports) — Privacy ▸ Mask IP addresses, applied to every
    /// text an Investigation export writes: hosts, endpoints, notes, finding text,
    /// the expression and the capture name.
    func maskingAddresses() -> Self {
        func mask(_ text: String) -> String {
            PrivacyMask.maskingAddresses(in: text)
        }
        return InvestigationExportInput(
            captureName: mask(captureName),
            generatedAt: generatedAt,
            totalSessionCount: totalSessionCount,
            expression: expression.map(mask),
            hasOtherFilters: hasOtherFilters,
            sessions: sessions.map { entry in
                var session = entry.session
                session.host = mask(session.host)
                session.sourceEndpoint = PrivacyMask.maskingEndpoint(session.sourceEndpoint)
                session.destinationEndpoint = PrivacyMask.maskingEndpoint(session.destinationEndpoint)
                session.sni = session.sni.map(mask)
                session.dnsQuery = session.dnsQuery.map(mask)
                session.dnsAnswers = session.dnsAnswers.map(mask)
                return SessionEntry(
                    session: session,
                    findingTitles: entry.findingTitles.map(mask),
                    notes: entry.notes.map { note in
                        SessionExportNote(
                            subject: note.subject, findingTitle: note.findingTitle.map(mask),
                            text: mask(note.text), updatedAt: note.updatedAt
                        )
                    }
                )
            },
            findings: findings.map { finding in
                FindingEntry(
                    id: finding.id, sessionID: finding.sessionID, severity: finding.severity,
                    title: mask(finding.title), detail: mask(finding.detail),
                    citedFrameOrdinals: finding.citedFrameOrdinals,
                    omittedCitationCount: finding.omittedCitationCount,
                    sessionHost: mask(finding.sessionHost)
                )
            }
        )
    }
}

// MARK: - InvestigationExport

/// Pure serialization of the sessions and findings in view. CSV follows RFC 4180 and
/// guards every capture-derived text cell against spreadsheet formula injection; JSON
/// uses sorted keys; the report is plain Markdown. Absent values stay absent: an
/// unknown start time is an empty cell or `null`, never zero.
nonisolated enum InvestigationExport {
    // MARK: Internal

    static let sessionHeader = [
        "session_id", "start_time_utc", "duration_s", "protocols", "status", "host", "process",
        "source", "destination", "bytes_up", "bytes_down", "packets_up", "packets_down", "latency_ms", "findings",
        "has_note",
    ]

    static let findingHeader = [
        "finding_id", "session_id", "severity", "title", "detail", "session_host", "cited_frames",
        "omitted_citations",
    ]

    /// Sessions beyond this many are left out of the report's session table (the CSV
    /// and JSON exports carry every session in view).
    static let reportSessionRowLimit = 500

    static func data(for kind: InvestigationExportKind, input: InvestigationExportInput) throws -> Data {
        switch kind {
        case .sessionsCSV: sessionsCSV(input)
        case .findingsCSV: findingsCSV(input)
        case .sessionsJSON: try json(input)
        case .report: Data(report(input).utf8)
        }
    }

    static func sessionsCSV(_ input: InvestigationExportInput) -> Data {
        var rows = [AutomationExport.encodeRow(sessionHeader)]
        for entry in input.sessions {
            rows.append(AutomationExport.encodeRow(sessionRow(entry)))
        }
        return Data((rows.joined(separator: "\r\n") + "\r\n").utf8)
    }

    static func findingsCSV(_ input: InvestigationExportInput) -> Data {
        var rows = [AutomationExport.encodeRow(findingHeader)]
        for finding in input.findings {
            rows.append(AutomationExport.encodeRow([
                finding.id.uuidString,
                finding.sessionID.uuidString,
                finding.severity,
                safe(finding.title),
                safe(finding.detail),
                safe(finding.sessionHost),
                finding.citedFrameOrdinals.map(String.init).joined(separator: " "),
                String(finding.omittedCitationCount),
            ]))
        }
        return Data((rows.joined(separator: "\r\n") + "\r\n").utf8)
    }

    static func json(_ input: InvestigationExportInput) throws -> Data {
        let document = JSONDocument(
            formatVersion: 1,
            generatedAt: iso(input.generatedAt),
            capture: input.captureName,
            scope: .init(
                sessionsInView: input.sessions.count,
                sessionsInCapture: input.totalSessionCount,
                expression: input.expression,
                otherFiltersApplied: input.hasOtherFilters
            ),
            sessions: input.sessions.map { entry in
                let session = entry.session
                return .init(
                    id: session.id.uuidString,
                    startTimeUTC: session.startTime.map(iso),
                    durationSeconds: session.duration,
                    protocols: session.protocolStack.map(\.label),
                    status: session.status.rawValue,
                    host: session.host,
                    process: session.processName,
                    source: session.sourceEndpoint,
                    destination: session.destinationEndpoint,
                    bytesUp: session.bytesUp,
                    bytesDown: session.bytesDown,
                    packetsUp: session.packetsUp,
                    packetsDown: session.packetsDown,
                    latencyMilliseconds: session.latencyMilliseconds,
                    notes: entry.notes.isEmpty ? nil : entry.notes
                )
            },
            findings: input.findings.map { finding in
                .init(
                    id: finding.id.uuidString,
                    sessionID: finding.sessionID.uuidString,
                    severity: finding.severity,
                    title: finding.title,
                    detail: finding.detail,
                    citedFrames: finding.citedFrameOrdinals,
                    omittedCitations: finding.omittedCitationCount
                )
            }
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(document)
    }

    /// A readable Markdown account of the investigation in view: scope, findings with
    /// their cited frames, the investigator's notes, and the sessions.
    static func report(_ input: InvestigationExportInput) -> String {
        var lines: [String] = []
        lines.append("# Investigation: \(input.captureName)")
        lines.append("")
        lines.append("Generated \(iso(input.generatedAt)) by Tracexy.")
        lines.append("")
        lines.append("## Scope")
        lines.append("")
        lines.append("- Sessions in this report: \(input.sessions.count) of \(input.totalSessionCount)")
        if let expression = input.expression {
            lines.append("- Session expression: `\(expression.replacingOccurrences(of: "`", with: "'"))`")
        }
        if input.hasOtherFilters {
            lines.append("- Other filters in the workspace also narrowed the view.")
        }
        lines.append("")

        lines.append("## Findings (\(input.findings.count))")
        lines.append("")
        if input.findings.isEmpty {
            lines.append("No findings were reported for the sessions in this report.")
        } else {
            lines.append("| Severity | Finding | Session | Cited frames |")
            lines.append("| --- | --- | --- | --- |")
            for finding in input.findings {
                var frames = finding.citedFrameOrdinals.map(String.init).joined(separator: ", ")
                if finding.omittedCitationCount > 0 {
                    frames += " (+\(finding.omittedCitationCount) not listed)"
                }
                lines.append(
                    "| \(cell(finding.severity)) | \(cell(finding.title)) | \(cell(finding.sessionHost)) | \(frames) |"
                )
            }
        }
        lines.append("")
        lines.append(
            "A finding is an observation backed by the frames it cites. A session without a finding is "
                + "not proof that nothing happened: the capture may not hold the evidence."
        )
        lines.append("")

        let annotated = input.sessions.filter { !$0.notes.isEmpty }
        if !annotated.isEmpty {
            lines.append("## Notes")
            lines.append("")
            for entry in annotated {
                let session = entry.session
                lines
                    .append("### \(heading(session.host)) (\(session.sourceEndpoint) → \(session.destinationEndpoint))")
                lines.append("")
                for note in entry.notes {
                    if let title = note.findingTitle {
                        lines.append("On “\(title)”:")
                        lines.append("")
                    }
                    lines.append(contentsOf: note.text.split(separator: "\n", omittingEmptySubsequences: false)
                        .map { "> \($0)" })
                    lines.append("")
                }
            }
        }

        lines.append("## Sessions")
        lines.append("")
        lines.append("| Start (UTC) | Host | Source | Destination | Protocols | Bytes up | Bytes down | Findings |")
        lines.append("| --- | --- | --- | --- | --- | ---: | ---: | ---: |")
        for entry in input.sessions.prefix(reportSessionRowLimit) {
            let session = entry.session
            let row = [
                session.startTime.map(iso) ?? "unknown",
                cell(session.host),
                cell(session.sourceEndpoint),
                cell(session.destinationEndpoint),
                cell(session.protocolStack.map(\.label).joined(separator: " ")),
                String(session.bytesUp),
                String(session.bytesDown),
                String(entry.findingTitles.count),
            ]
            lines.append("| " + row.joined(separator: " | ") + " |")
        }
        if input.sessions.count > reportSessionRowLimit {
            lines.append("")
            lines.append(
                "\(input.sessions.count - reportSessionRowLimit) more sessions are in view; "
                    + "export Sessions as CSV for all of them."
            )
        }
        lines.append("")
        return lines.joined(separator: "\n")
    }

    // MARK: Private

    private struct JSONDocument: Encodable {
        struct Scope: Encodable {
            let sessionsInView: Int
            let sessionsInCapture: Int
            let expression: String?
            let otherFiltersApplied: Bool
        }

        struct Session: Encodable {
            let id: String
            let startTimeUTC: String?
            let durationSeconds: Double?
            let protocols: [String]
            let status: String
            let host: String
            let process: String?
            let source: String
            let destination: String
            let bytesUp: Int
            let bytesDown: Int
            let packetsUp: Int
            let packetsDown: Int
            let latencyMilliseconds: Double?
            let notes: [SessionExportNote]?
        }

        struct FindingValue: Encodable {
            let id: String
            let sessionID: String
            let severity: String
            let title: String
            let detail: String
            let citedFrames: [UInt64]
            let omittedCitations: UInt64
        }

        let formatVersion: Int
        let generatedAt: String
        let capture: String
        let scope: Scope
        let sessions: [Session]
        let findings: [FindingValue]
    }

    private static func sessionRow(_ entry: InvestigationExportInput.SessionEntry) -> [String] {
        let session = entry.session
        let start: String = session.startTime.map(iso) ?? ""
        let duration: String = session.duration.map { String($0) } ?? ""
        let latency: String = session.latencyMilliseconds.map { String($0) } ?? ""
        let protocols: String = session.protocolStack.map(\.label).joined(separator: " ")
        let process: String = session.processName ?? ""
        let findings: String = entry.findingTitles.joined(separator: "; ")
        var row: [String] = [session.id.uuidString, start, duration, protocols, session.status.rawValue]
        row += [safe(session.host), safe(process), safe(session.sourceEndpoint), safe(session.destinationEndpoint)]
        row += [
            String(session.bytesUp),
            String(session.bytesDown),
            String(session.packetsUp),
            String(session.packetsDown)
        ]
        row += [latency, safe(findings)]
        row.append(entry.notes.isEmpty ? "false" : "true")
        return row
    }

    private static func iso(_ date: Date) -> String {
        date.formatted(Date.ISO8601FormatStyle(includingFractionalSeconds: true))
    }

    private static func safe(_ text: String) -> String {
        AutomationExport.spreadsheetSafe(text)
    }

    /// A Markdown table cell: pipes and line breaks would break the row.
    private static func cell(_ text: String) -> String {
        text.replacingOccurrences(of: "|", with: "\\|")
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: " ")
    }

    private static func heading(_ text: String) -> String {
        text.replacingOccurrences(of: "\n", with: " ").replacingOccurrences(of: "#", with: "")
    }
}
