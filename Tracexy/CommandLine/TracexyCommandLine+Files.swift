import Foundation

// MARK: - TracexyCommandLine + info, select and merge

/// Wireshark's file tools, one capture per call: `info` is capinfos (the Get Info
/// report, with SHA-256 and SHA-1), `select` is editcap's frame selection and
/// duplicate removal, `merge` is mergecap's chronological merge. `select` and
/// `merge` write PCAPNG to standard output — still no file is written unless the
/// shell redirects there.
extension TracexyCommandLine {
    // MARK: Internal

    /// "1-100,250,300-310" as frame numbers; `nil` for an empty, reversed or
    /// unreadable list, or one naming more than ten million frames.
    static func frameList(_ text: String) -> Set<UInt64>? {
        var frames = Set<UInt64>()
        for part in text.split(separator: ",") {
            let bounds = part.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false)
            guard let low = UInt64(bounds[0].trimmingCharacters(in: .whitespaces)), low > 0 else {
                return nil
            }
            let high = bounds.count == 2 ? UInt64(bounds[1].trimmingCharacters(in: .whitespaces)) : low
            guard let high, high >= low, frames.count + Int(high - low) < 10_000_000 else {
                return nil
            }
            frames.formUnion(low ... high)
        }
        return frames.isEmpty ? nil : frames
    }

    static func runFileVerb(
        _ invocation: Invocation,
        file: URL,
        compiled: CompiledInvestigationQuery?,
        output: (String) -> Void,
        data: (Data) -> Void
    )
        throws -> Int32
    {
        switch invocation.command {
        case .info:
            try output(info(file, format: invocation.format))
        case .select:
            try select(invocation, file: file, compiled: compiled, data: data)
        case .merge:
            try merge([file] + invocation.moreFiles, data: data)
        default:
            break
        }
        return 0
    }

    // MARK: Private

    private static func info(_ file: URL, format: Format) throws -> String {
        let loaded = try withExpandedCapture(file) { try SavedCaptureStreamLoader(contentsOf: $0).load() }
        let digests = try CaptureHasher.digests(of: file)
        let size = (try? file.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        let snapshot = CaptureInfoSnapshot(
            title: file.lastPathComponent,
            source: .saved(SavedCapture(url: file, name: file.lastPathComponent, date: Date(), byteCount: size)),
            fileURL: file, properties: loaded.properties, activity: loaded.activity, metadata: loaded.metadata,
            sessionCount: loaded.sessions.count, visibleSessionCount: loaded.sessions.count, warning: nil,
            captureStartedAt: nil, hashState: .done(digests)
        )
        let text = CaptureInfoReport.text(for: snapshot)
        guard format == .json else {
            return text + "\n"
        }
        // One object per report line, in order, sections kept as their own keys.
        let pairs: [[String: String]] = text.split(separator: "\n").compactMap { line in
            guard let colon = line.firstIndex(of: ":") else {
                return nil
            }
            return [
                "key": line[..<colon].trimmingCharacters(in: .whitespaces),
                "value": line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces),
            ]
        }
        let json = try JSONSerialization.data(withJSONObject: pairs, options: [.prettyPrinted, .sortedKeys])
        return (String(bytes: json, encoding: .utf8) ?? "") + "\n"
    }

    private static func select(
        _ invocation: Invocation,
        file: URL,
        compiled: CompiledInvestigationQuery?,
        data: (Data) -> Void
    )
        throws
    {
        try withExpandedCapture(file) { url in
            let scope: FrameExportScope
            if let frames = invocation.frames {
                scope = .frames(frames)
            } else if let compiled {
                let loaded = try SavedCaptureStreamLoader(contentsOf: url).load()
                let snapshot = InvestigationSnapshot(
                    sessions: loaded.sessions, connections: loaded.connections,
                    datagramEvidence: loaded.datagramEvidence, tlsEvidence: loaded.tlsEvidence,
                    segmentSeries: loaded.segmentSeries, connectionAnalysis: loaded.connectionAnalysis,
                    datagramAnalysis: loaded.datagramAnalysis, tlsAnalysis: loaded.tlsAnalysis,
                    trafficTimeline: loaded.trafficTimeline
                )
                let matched = try InvestigationQueryEngine().evaluate(compiled, over: snapshot).matched
                scope = .sessions(Set(matched.map(\.id)))
            } else {
                scope = .wholeCapture
            }
            var options = FrameExportOptions()
            options.removesDuplicates = invocation.removesDuplicates
            options.truncatesTo = invocation.snapLength
            options.captureComments = invocation.comments
            options.shiftsTimeBy = invocation.timeShift
            try throughTemporaryFile { destination in
                _ = try CaptureFrameExporter.export(from: url, scope: scope, options: options, to: destination)
            } then: { data($0) }
        }
    }

    private static func merge(_ files: [URL], data: (Data) -> Void) throws {
        try throughTemporaryFile { destination in
            _ = try CaptureMerger.merge(sources: files, to: destination)
        } then: { data($0) }
    }

    /// Writes to a private temporary file, hands its bytes on, then removes it.
    private static func throughTemporaryFile(
        _ write: (URL) throws -> Void,
        then deliver: (Data) -> Void
    )
        throws
    {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-cli-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let destination = directory.appendingPathComponent("out.pcapng")
        try write(destination)
        try deliver(Data(contentsOf: destination))
    }

    /// Runs `body` over a readable capture: the file itself, or a gzip or LZ4
    /// container expanded into a temporary directory removed afterwards.
    static func withExpandedCapture<T>(_ file: URL, _ body: (URL) throws -> T) throws -> T {
        let handle = try FileHandle(forReadingFrom: file)
        let header = try [UInt8](handle.read(upToCount: 8) ?? Data())
        try handle.close()
        guard CaptureArchiveContainer(header: header) != nil else {
            return try body(file)
        }
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-cli-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        return try body(CaptureImporter.importCapture(from: file, intoDirectory: directory))
    }
}
