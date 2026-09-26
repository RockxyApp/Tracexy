import Foundation

// MARK: - TracexyCommandLine

/// The read-only command line built into the app binary: the same fold, analysis,
/// Session Expression and export code the window uses, run over one capture file
/// and printed to standard output (raw bytes too, for `objects --body` and `follow
/// --format raw`). It never captures, never writes a file, never
/// touches a Project, History, Library or setting, and opens no network port.
///
/// It runs only when the first argument is one of its commands, which LaunchServices
/// never passes, so a normal app launch is unaffected.
///
///     tracexy summary  <capture> [--json]
///     tracexy sessions <capture> [--expression <text>] [--format csv|json]
///     tracexy findings <capture> [--expression <text>] [--format csv|json] [--fail-on note|warning]
///     tracexy stats    <capture> --tap <name> [--tap <name>…] [--expression <text>] [--format text|csv|json]
///     tracexy frames   <capture> [--expression <text>] [--format text|csv|json] [--details]
///     tracexy objects  <capture> [--type http|imf|tftp|ftp-data|x509af] [--expression <text>]
///                      [--format text|csv|json] [--body <n>]
///     tracexy follow   <capture> --expression <text> [--format ascii|hex|raw|c|yaml]
///     tracexy info     <capture> [--format text|json]
///     tracexy select   <capture> [--frames <list>] [--expression <text>] [--dedupe] [--snaplen <n>]
///                      [--time-shift <seconds>] [--comment <text>] > out.pcapng
///     tracexy merge    <capture> <capture>… > merged.pcapng
///     tracexy glossary [--format text|json]
///
/// Exit status: 0 success; 1 the capture could not be read; 2 usage or expression
/// error; 3 `--fail-on` matched at least one finding.
enum TracexyCommandLine {
    // MARK: Internal

    enum Command: String, CaseIterable {
        case summary
        case sessions
        case findings
        case stats
        case frames
        case objects
        case follow
        case info
        case select
        case merge
        case glossary
        case help
    }

    struct Invocation: Equatable {
        var command: Command
        var file: URL?
        var expression: String?
        var format: Format = .csv
        var json = false
        var failOn: Finding.Severity?
        var taps: [StatisticsTap] = []
        /// `objects --body <n>`: the object to print, 1-based.
        var objectNumber: Int?
        /// `objects --type`: which Export Objects list, by tshark's name.
        var objectKind: CaptureObjectKind = .http
        var followFormat: FollowStreamExport.Format = .ascii
        /// `merge`: every capture after the first.
        var moreFiles: [URL] = []
        /// `select --frames`: frame numbers, 1-based.
        var frames: Set<UInt64>?
        /// `select --dedupe`: drop a frame identical to one of the previous five.
        var removesDuplicates = false
        /// `select --snaplen`: keep at most this many bytes of each frame.
        var snapLength: Int?
        /// `select --comment`: capture comments for the output's section header.
        var comments: [String] = []
        /// `select --time-shift`: seconds added to every frame's time.
        var timeShift: TimeInterval = 0
        /// `frames --details`: each frame's whole decode tree instead of the list.
        var details = false
        /// `frames --column Protocol:Field`: decode-tree fields added as columns.
        var columns: [FieldKey] = []
    }

    enum Format: String {
        case csv
        case json
        case text
    }

    struct UsageError: Error, Equatable {
        let message: String
    }

    static let usage = """
    Usage:
      tracexy summary  <capture> [--json]
      tracexy sessions <capture> [--expression <text>] [--format csv|json]
      tracexy findings <capture> [--expression <text>] [--format csv|json] [--fail-on note|warning]
      tracexy stats    <capture> --tap <name> [--tap <name>…] [--expression <text>] [--format text|csv|json]
      tracexy frames   <capture> [--expression <text>] [--format text|csv|json] [--details] [--column Proto:Field]
      tracexy objects  <capture> [--type http|imf|tftp|ftp-data|x509af] [--expression <text>]
                       [--format text|csv|json] [--body <n>]
      tracexy follow   <capture> --expression <text> [--format ascii|hex|raw|c|yaml]
      tracexy info     <capture> [--format text|json]
      tracexy select   <capture> [--frames 1-100,250] [--expression <text>] [--dedupe] [--snaplen <n>]
                       [--time-shift <seconds>] [--comment <text>] > out.pcapng
      tracexy merge    <capture> <capture>… > merged.pcapng
      tracexy glossary [--format text|json]

    Reads one PCAP or PCAPNG file (gzip or LZ4 compressed too) with the same analysis as the Tracexy window and prints the
    result. Nothing is written, captured or sent. --expression takes a Session Expression, e.g.
      finding == retransmission and port == 443
    Statistics (--tap, tshark -z spellings accepted): \(StatisticsTap.names).
    info is capinfos: format, frames, times, interfaces and SHA-256. select and merge write PCAPNG to standard output,
    so a file exists only where the shell redirects it.
    Exit status: 0 ok, 1 unreadable capture, 2 usage or expression error, 3 --fail-on matched.
    """

    /// The exit status when `arguments` (as `CommandLine.arguments`) ask for the
    /// command line, else `nil` so the app launches normally.
    static func runIfRequested(
        _ arguments: [String],
        output: (String) -> Void = { FileHandle.standardOutput.write(Data($0.utf8)) },
        errors: (String) -> Void = { FileHandle.standardError.write(Data($0.utf8)) },
        data: (Data) -> Void = { FileHandle.standardOutput.write($0) }
    )
        -> Int32?
    {
        guard arguments.count >= 2, Command(rawValue: arguments[1]) != nil else {
            return nil
        }
        do {
            let invocation = try parse(Array(arguments.dropFirst()))
            return try run(invocation, output: output, data: data)
        } catch let error as UsageError {
            errors("tracexy: \(error.message)\n\n\(usage)\n")
            return 2
        } catch {
            errors("tracexy: \(error.localizedDescription)\n")
            return 1
        }
    }

    static func parse(_ arguments: [String]) throws -> Invocation {
        guard let first = arguments.first, let command = Command(rawValue: first) else {
            throw UsageError(message: "Choose a command.")
        }
        var invocation = Invocation(command: command)
        guard command != .help else {
            return invocation
        }
        if command == .glossary {
            return try glossaryInvocation(arguments)
        }
        var index = 1
        func value(for option: String) throws -> String {
            index += 1
            guard index < arguments.count else {
                throw UsageError(message: "\(option) needs a value.")
            }
            return arguments[index]
        }
        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "--expression",
                 "-e":
                invocation.expression = try value(for: argument)
            case "--format",
                 "-f":
                let text = try value(for: argument)
                if command == .follow {
                    guard let format = followFormats[text] else {
                        throw UsageError(message: "--format takes ascii, hex, raw, c or yaml for follow.")
                    }
                    invocation.followFormat = format
                    break
                }
                guard let format = Format(rawValue: text), ![.summary, .select, .merge].contains(command),
                      format != .text || [.stats, .frames, .objects, .info].contains(command),
                      format != .csv || command != .info else
                {
                    throw UsageError(
                        message: "--format takes csv or json for sessions and findings, text too for stats, frames and objects."
                    )
                }
                invocation.format = format
            case "--tap",
                 "-z":
                let text = try value(for: argument)
                guard command == .stats, let tap = StatisticsTap(text) else {
                    throw UsageError(message: "--tap takes one of: \(StatisticsTap.names).")
                }
                invocation.taps.append(tap)
            case "--frames":
                let text = try value(for: argument)
                guard command == .select, let frames = Self.frameList(text) else {
                    throw UsageError(message: "--frames takes frame numbers and ranges such as 1-100,250, for select.")
                }
                invocation.frames = frames
            case "--snaplen",
                 "-s":
                let text = try value(for: argument)
                guard command == .select, let length = Int(text),
                      FrameExportOptions.truncationRange.contains(length) else
                {
                    throw UsageError(message: "--snaplen takes a byte count from 14 to 262144, for select.")
                }
                invocation.snapLength = length
            case "--time-shift",
                 "-t":
                let text = try value(for: argument)
                guard command == .select, let seconds = TimeInterval(text), seconds.isFinite,
                      abs(seconds) <= 3_153_600_000 else
                {
                    throw UsageError(message: "--time-shift takes seconds, such as -3600 or 0.25, for select.")
                }
                invocation.timeShift = seconds
            case "--comment":
                let text = try value(for: argument)
                guard command == .select, !text.isEmpty else {
                    throw UsageError(message: "--comment takes text, for select.")
                }
                invocation.comments.append(text)
            case "--details",
                 "-V":
                guard command == .frames else {
                    throw UsageError(message: "--details applies to frames.")
                }
                invocation.details = true
            case "--column":
                try invocation.columns.append(column(value(for: argument), command: command))
            case "--dedupe":
                guard command == .select else {
                    throw UsageError(message: "--dedupe applies to select.")
                }
                invocation.removesDuplicates = true
            case "--type":
                let text = try value(for: argument)
                guard command == .objects, let kind = CaptureObjectKind(rawValue: text.lowercased()) else {
                    throw UsageError(message: "--type takes http, imf, tftp, ftp-data or x509af, for objects.")
                }
                invocation.objectKind = kind
            case "--body":
                let text = try value(for: argument)
                guard command == .objects, let number = Int(text), number > 0 else {
                    throw UsageError(message: "--body takes an object number, for objects.")
                }
                invocation.objectNumber = number
            case "--json":
                guard command == .summary else {
                    throw UsageError(message: "--json applies to summary; use --format json.")
                }
                invocation.json = true
            case "--fail-on":
                let text = try value(for: argument)
                guard command == .findings, let severity = Finding.Severity(cliName: text) else {
                    throw UsageError(message: "--fail-on takes note or warning, for findings.")
                }
                invocation.failOn = severity
            default:
                guard !argument.hasPrefix("-"), invocation.file == nil || command == .merge else {
                    throw UsageError(message: "Unexpected argument “\(argument.prefix(64))”.")
                }
                if invocation.file == nil {
                    invocation.file = URL(fileURLWithPath: argument)
                } else {
                    invocation.moreFiles.append(URL(fileURLWithPath: argument))
                }
            }
            index += 1
        }
        guard invocation.file != nil else {
            throw UsageError(message: "Name the capture file to read.")
        }
        if invocation.expression != nil, [.summary, .info, .merge].contains(command) {
            throw UsageError(message: "--expression does not apply to summary, info or merge.")
        }
        if command == .merge, invocation.moreFiles.isEmpty {
            throw UsageError(message: "merge needs two or more captures.")
        }
        if command == .select, invocation.frames != nil, invocation.expression != nil {
            throw UsageError(message: "select takes --frames or --expression, not both.")
        }
        if command == .info, !arguments.contains("--format"), !arguments.contains("-f") {
            invocation.format = .text
        }
        if command == .follow, invocation.expression == nil {
            throw UsageError(message: "follow needs --expression naming exactly one TCP session.")
        }
        if [.frames, .objects].contains(command), !arguments.contains("--format"), !arguments.contains("-f") {
            invocation.format = .text
        }
        if command == .stats {
            guard !invocation.taps.isEmpty else {
                throw UsageError(message: "Name a statistic with --tap: \(StatisticsTap.names).")
            }
            if !arguments.contains("--format"), !arguments.contains("-f") {
                invocation.format = .text
            }
        }
        return invocation
    }

    static func run(
        _ invocation: Invocation,
        output: (String) -> Void,
        data: (Data) -> Void = { FileHandle.standardOutput.write($0) }
    )
        throws -> Int32
    {
        if invocation.command == .glossary {
            output(glossary(invocation.format))
            return 0
        }
        guard invocation.command != .help, let file = invocation.file else {
            output(usage + "\n")
            return 0
        }
        // The expression is checked before the file is read, so a typo fails fast.
        let engine = InvestigationQueryEngine()
        var compiled: CompiledInvestigationQuery?
        if let text = invocation.expression {
            do {
                compiled = try engine.compile(SessionQueryParser().parse(text))
            } catch let error as SessionQueryParseError {
                throw UsageError(message: "The expression was not accepted: \(error.message)")
            } catch let error as QueryValidationError {
                throw UsageError(message: "The expression was not accepted: \(error.message)")
            }
        }
        if invocation.command == .objects || invocation.command == .follow {
            return try runExtraction(invocation, file: file, compiled: compiled, output: output, data: data)
        }
        if [.info, .select, .merge].contains(invocation.command) {
            return try runFileVerb(invocation, file: file, compiled: compiled, output: output, data: data)
        }
        let loaded = try load(file)
        let snapshot = InvestigationSnapshot(
            sessions: loaded.sessions,
            connections: loaded.connections,
            datagramEvidence: loaded.datagramEvidence,
            tlsEvidence: loaded.tlsEvidence,
            segmentSeries: loaded.segmentSeries,
            connectionAnalysis: loaded.connectionAnalysis,
            datagramAnalysis: loaded.datagramAnalysis,
            tlsAnalysis: loaded.tlsAnalysis,
            trafficTimeline: loaded.trafficTimeline
        )
        let sessions = try compiled.map { try engine.evaluate($0, over: snapshot).matched } ?? loaded.sessions
        let findings = Self.findings(of: snapshot, among: sessions)

        switch invocation.command {
        case .summary:
            try output(invocation.json
                ? summaryJSON(file: file, loaded: loaded, findings: findings)
                : summaryText(file: file, loaded: loaded, findings: findings))
            return 0
        case .sessions,
             .findings:
            let input = exportInput(
                file: file, total: loaded.sessions.count, expression: invocation.expression,
                sessions: sessions, findings: findings
            )
            let kind: InvestigationExportKind = switch (invocation.command, invocation.format) {
            case (.sessions, .csv): .sessionsCSV
            case (.findings, .csv): .findingsCSV
            default: .sessionsJSON
            }
            let data = try InvestigationExport.data(for: kind, input: input)
            output(String(bytes: data, encoding: .utf8) ?? "")
            if let threshold = invocation.failOn,
               findings.contains(where: { $0.severity.rawValue <= threshold.rawValue })
            {
                return 3
            }
            return 0
        case .stats:
            let frames = try invocation.taps.contains(where: \.needsFrames)
                ? frameRows(file: file, sessions: sessions, limited: compiled != nil) : []
            let tables = invocation.taps.map {
                $0.table(sessions: sessions, findings: findings, snapshot: snapshot, frames: frames)
            }
            switch invocation.format {
            case .text:
                output(tables.map(\.text).joined(separator: "\n"))
            case .csv:
                output(tables.map(\.csv).joined(separator: "\n"))
            case .json:
                let data = try JSONSerialization.data(
                    withJSONObject: tables.map(\.jsonObject), options: [.prettyPrinted, .sortedKeys]
                )
                output((String(bytes: data, encoding: .utf8) ?? "") + "\n")
            }
            return 0
        case .frames where invocation.details:
            guard invocation.format != .csv else {
                throw UsageError(message: "--details prints text or json.")
            }
            try withExpandedCapture(file) { url in
                _ = try DissectionExporter.export(
                    from: url, sessions: compiled == nil ? nil : Set(sessions.map(\.id)),
                    format: invocation.format == .json ? .json : .text, to: data
                )
            }
            return 0
        case .frames:
            let table = try framesTable(
                file: file, sessions: sessions, limited: compiled != nil, columns: invocation.columns
            )
            switch invocation.format {
            case .text: output(table.text)
            case .csv: output(table.csv)
            case .json:
                let data = try JSONSerialization.data(
                    withJSONObject: table.jsonObject,
                    options: [.prettyPrinted, .sortedKeys]
                )
                output((String(bytes: data, encoding: .utf8) ?? "") + "\n")
            }
            return 0
        case .help,
             .glossary,
             .objects,
             .follow,
             .info,
             .select,
             .merge:
            return 0
        }
    }

    // MARK: Private

    /// `frames --column Protocol:Field`.
    private static func column(_ text: String, command: Command) throws -> FieldKey {
        guard command == .frames, let key = fieldKey(text) else {
            throw UsageError(message: "--column takes Protocol:Field, such as TCP:Window, for frames.")
        }
        return key
    }

    /// `glossary` takes only `--format text|json`.
    private static func glossaryInvocation(_ arguments: [String]) throws -> Invocation {
        var invocation = Invocation(command: .glossary)
        invocation.format = .text
        if let index = arguments.firstIndex(where: { $0 == "--format" || $0 == "-f" }) {
            guard index + 1 < arguments.count, let format = Format(rawValue: arguments[index + 1]),
                  [.text, .json].contains(format) else
            {
                throw UsageError(message: "--format takes text or json for glossary.")
            }
            invocation.format = format
        }
        return invocation
    }

    /// A gzip or LZ4 container is expanded into a temporary directory first, with
    /// the same bounded importer the app uses; the source is only read.
    private static func load(_ file: URL) throws -> SavedCaptureLoadResult {
        let handle = try FileHandle(forReadingFrom: file)
        let header = try [UInt8](handle.read(upToCount: 8) ?? Data())
        try handle.close()
        guard CaptureArchiveContainer(header: header) != nil else {
            return try SavedCaptureStreamLoader(contentsOf: file).load()
        }
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-cli-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let expanded = try CaptureImporter.importCapture(from: file, intoDirectory: directory)
        return try SavedCaptureStreamLoader(contentsOf: expanded).load()
    }

    /// The same projection the window's Findings list uses, limited to `sessions`,
    /// worst severity first.
    private static func findings(of snapshot: InvestigationSnapshot, among sessions: [SessionSummary]) -> [Finding] {
        let hosts = Dictionary(sessions.map { ($0.id, $0.host) }, uniquingKeysWith: { first, _ in first })
        var result: [Finding] = []
        for finding in snapshot.connectionAnalysis.findings {
            if let host = hosts[SessionBuilder.sessionID(for: finding.tuple)] {
                result.append(Finding(finding, host: host))
            }
        }
        for finding in snapshot.datagramAnalysis.findings {
            if let host = hosts[finding.sessionID] {
                result.append(Finding(finding, host: host))
            }
        }
        for finding in snapshot.tlsAnalysis.findings {
            if let host = hosts[finding.sessionID] {
                result.append(Finding(finding, host: host))
            }
        }
        return result.enumerated()
            .sorted { lhs, rhs in
                lhs.element.severity.rawValue == rhs.element.severity.rawValue
                    ? lhs.offset < rhs.offset
                    : lhs.element.severity.rawValue < rhs.element.severity.rawValue
            }
            .map(\.element)
    }

    private static func exportInput(
        file: URL,
        total: Int,
        expression: String?,
        sessions: [SessionSummary],
        findings: [Finding]
    )
        -> InvestigationExportInput
    {
        let bySession = Dictionary(grouping: findings, by: \.sessionID)
        let hosts = Dictionary(sessions.map { ($0.id, $0.host) }, uniquingKeysWith: { first, _ in first })
        return InvestigationExportInput(
            captureName: file.deletingPathExtension().lastPathComponent,
            generatedAt: Date(),
            totalSessionCount: total,
            expression: expression,
            hasOtherFilters: false,
            sessions: sessions.map { session in
                InvestigationExportInput.SessionEntry(
                    session: session,
                    findingTitles: (bySession[session.id] ?? []).map(\.title),
                    notes: []
                )
            },
            findings: findings.map { finding in
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
    }

    private static func summaryText(file: URL, loaded: SavedCaptureLoadResult, findings: [Finding]) -> String {
        var lines = [
            "Capture: \(file.lastPathComponent)",
            "Frames: \(loaded.totalFrames)",
            "Sessions: \(loaded.sessions.count)",
            "Findings: \(findings.count)",
        ]
        let byTitle = Dictionary(grouping: findings, by: \.title)
        for (title, group) in byTitle.sorted(by: { ($0.value.count, $1.key) > ($1.value.count, $0.key) }) {
            lines.append("  \(group.count) × \(title) (\(group[0].severity.exportName))")
        }
        return lines.joined(separator: "\n") + "\n"
    }

    private static func summaryJSON(file: URL, loaded: SavedCaptureLoadResult, findings: [Finding]) throws -> String {
        let counts = Dictionary(grouping: findings, by: \.title).mapValues(\.count)
        let object: [String: Any] = [
            "capture": file.lastPathComponent,
            "frames": loaded.totalFrames,
            "sessions": loaded.sessions.count,
            "findings": findings.count,
            "findingsByTitle": counts,
        ]
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .prettyPrinted])
        return (String(bytes: data, encoding: .utf8) ?? "") + "\n"
    }
}

extension Finding.Severity {
    /// `note` or `warning` (an `error` finding does not exist yet but parses).
    init?(cliName: String) {
        switch cliName {
        case "note": self = .note
        case "warning": self = .warning
        case "error": self = .error
        default: return nil
        }
    }
}
