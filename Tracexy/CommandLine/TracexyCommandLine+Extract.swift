import Foundation

// MARK: - TracexyCommandLine + objects and follow

/// `objects` lists one kind of object in a capture — HTTP bodies, email messages, FTP
/// files or certificates (File ▸ Export Objects, tshark's `--export-objects`) — and
/// `--body` prints one to standard output;
/// `follow` prints one TCP stream (Follow Stream, tshark's `-z follow,tcp,…`). Still
/// read-only: bytes go to standard output, and a file exists only if the shell
/// redirects there.
extension TracexyCommandLine {
    // MARK: Internal

    /// The Follow Stream formats, by their command-line names.
    static let followFormats: [String: FollowStreamExport.Format] = [
        "ascii": .ascii, "hex": .hexDump, "raw": .raw, "c": .cArrays, "yaml": .yaml,
    ]

    static func runExtraction(
        _ invocation: Invocation,
        file: URL,
        compiled: CompiledInvestigationQuery?,
        output: (String) -> Void,
        data: (Data) -> Void
    )
        throws -> Int32
    {
        try withReadableCapture(file) { url in
            let loaded = try SavedCaptureStreamLoader(contentsOf: url).load()
            let snapshot = InvestigationSnapshot(
                sessions: loaded.sessions, connections: loaded.connections,
                datagramEvidence: loaded.datagramEvidence, tlsEvidence: loaded.tlsEvidence,
                segmentSeries: loaded.segmentSeries, connectionAnalysis: loaded.connectionAnalysis,
                datagramAnalysis: loaded.datagramAnalysis, tlsAnalysis: loaded.tlsAnalysis,
                trafficTimeline: loaded.trafficTimeline
            )
            let sessions = try compiled.map { try InvestigationQueryEngine().evaluate($0, over: snapshot).matched }
                ?? loaded.sessions
            let chosen = Set(sessions.map(\.id))
            let tuples = loaded.connections.summaries.map(\.tuple)
                .filter { $0.proto == .tcp && chosen.contains(SessionBuilder.sessionID(for: $0)) }
            if invocation.command == .follow {
                return try follow(
                    tuples,
                    url: url,
                    identity: loaded.identity,
                    invocation: invocation,
                    output: output,
                    data: data
                )
            }
            let kind = invocation.objectKind
            let (streams, connections) = CaptureObjectScanner.inputs(kind, in: sessions, from: loaded.sessions)
            let list = try CaptureObjectScanner.scan(
                kind, contentsOf: url, expectedIdentity: loaded.identity, streams: streams, connections: connections
            )
            if let number = invocation.objectNumber {
                guard number >= 1, number <= list.objects.count else {
                    throw UsageError(message: "--body takes an object number from 1 to \(list.objects.count).")
                }
                data(Data(list.objects[number - 1].body))
                return 0
            }
            try output(objectsTable(list).render(invocation.format))
            return 0
        }
    }

    // MARK: Private

    /// Runs `body` over a readable capture: the file itself, or a gzip or LZ4
    /// container expanded into a temporary directory removed afterwards.
    private static func withReadableCapture<T>(_ file: URL, _ body: (URL) throws -> T) throws -> T {
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

    private static func follow(
        _ tuples: [FiveTuple],
        url: URL,
        identity: PcapFileIdentity,
        invocation: Invocation,
        output: (String) -> Void,
        data: (Data) -> Void
    )
        throws -> Int32
    {
        guard tuples.count == 1, let tuple = tuples.first else {
            throw UsageError(message: tuples.isEmpty
                ? "No TCP session matches; follow needs --expression naming exactly one."
                : "\(tuples.count) TCP sessions match; follow needs --expression naming exactly one.")
        }
        let result = try FollowStreamReader(contentsOf: url, expectedIdentity: identity, tuple: tuple).read()
        let turns = FollowStreamExport.turns(of: result)
        let bytes = FollowStreamExport.data(turns, format: invocation.followFormat, side: .both, tuple: tuple)
        if invocation.followFormat == .raw {
            data(bytes)
        } else {
            output(String(bytes: bytes, encoding: .utf8) ?? "")
        }
        return 0
    }

    private static func objectsTable(_ list: CaptureObjectList) -> ObjectsTable {
        ObjectsTable(rows: list.objects.enumerated().map { index, object in
            [
                String(index + 1), object.frameOrdinal.map(String.init) ?? "", object.host, object.contentType,
                String(object.body.count), object.fileName,
            ]
        })
    }
}

// MARK: - ObjectsTable

/// The `objects` listing as text, CSV or JSON.
private struct ObjectsTable {
    // MARK: Internal

    static let columns = ["object", "frame", "host", "content_type", "bytes", "file_name"]

    let rows: [[String]]

    func render(_ format: TracexyCommandLine.Format) throws -> String {
        switch format {
        case .text:
            let widths = Self.columns.indices.map { column in
                ([Self.columns[column]] + rows.map { $0[column] }).map(\.count).max() ?? 0
            }
            return ([Self.columns] + rows).map { row in
                row.enumerated().map { $1.padding(toLength: widths[$0], withPad: " ", startingAt: 0) }
                    .joined(separator: "  ").trimmingCharacters(in: .whitespaces)
            }.joined(separator: "\n") + "\n"
        case .csv:
            return ([Self.columns] + rows).map { $0.map(Self.csvField).joined(separator: ",") }
                .joined(separator: "\r\n") + "\r\n"
        case .json:
            let objects = rows.map { Dictionary(uniqueKeysWithValues: zip(Self.columns, $0)) }
            let data = try JSONSerialization.data(withJSONObject: objects, options: [.prettyPrinted, .sortedKeys])
            return (String(bytes: data, encoding: .utf8) ?? "") + "\n"
        }
    }

    // MARK: Private

    private static func csvField(_ text: String) -> String {
        text.contains { [",", "\"", "\n", "\r"].contains($0) }
            ? "\"" + text.replacingOccurrences(of: "\"", with: "\"\"") + "\"" : text
    }
}
