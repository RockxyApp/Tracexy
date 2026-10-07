import Foundation

// MARK: - CaptureObjectKind

/// The kinds of File ▸ Export Objects Tracexy reads, named as Wireshark's menu and
/// tshark's `--export-objects` name them.
nonisolated enum CaptureObjectKind: String, CaseIterable, Identifiable, Sendable {
    case ftpData = "ftp-data"
    case http
    case imf
    case smb
    case tftp
    case x509 = "x509af"

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .ftpData: String(localized: "FTP Data")
        case .http: String(localized: "HTTP")
        case .imf: String(localized: "Email (IMF)")
        case .smb: String(localized: "SMB")
        case .tftp: String(localized: "TFTP")
        case .x509: String(localized: "X.509 Certificates")
        }
    }

    /// The application protocol a stream must carry to be read for this kind.
    var protocolKind: ProtocolKind {
        switch self {
        case .ftpData: .ftp
        case .http: .http
        case .imf: .smtp
        case .smb: .smb
        case .tftp: .tftp
        case .x509: .tls
        }
    }
}

// MARK: - CaptureObject

/// One object in a capture, as Wireshark's File ▸ Export Objects lists it: the frame
/// it was read in, the host it names, its content type, and the file name it saves
/// under.
nonisolated struct CaptureObject: Identifiable, Equatable, Sendable {
    let id: String
    let sessionID: UUID
    let frameOrdinal: UInt64?
    let host: String
    let contentType: String
    let fileName: String
    let body: [UInt8]
    /// Exact frames that contributed SMB protocol data or its name/extent witness.
    /// Other object readers leave this empty and retain their existing single-frame
    /// presentation.
    var contributingFrames: [SessionFrameProvenance] = []
}

// MARK: - CaptureObjectList

nonisolated struct CaptureObjectList: Equatable, Sendable {
    let objects: [CaptureObject]
    /// Streams read, and streams past ``CaptureObjectScanner/maximumStreams``.
    let scannedStreamCount: Int
    let skippedStreamCount: Int
    /// Objects left out past the object or byte bound.
    let omittedObjectCount: Int
}

// MARK: - CaptureObjectScanner

/// Reads the streams of a stable capture with the Follow Stream reader and lists the
/// objects of one kind in them, in frame order. Bounded in streams, objects and bytes;
/// cancellable between and within streams.
nonisolated enum CaptureObjectScanner {
    // MARK: Internal

    struct Stream: Sendable {
        let tuple: FiveTuple
        let sessionID: UUID
    }

    /// A connection FTP data (TCP) or a TFTP transfer (UDP) may have travelled on,
    /// and the frame it began in.
    struct Connection: Sendable {
        let tuple: FiveTuple
        let firstOrdinal: UInt64
    }

    static let maximumStreams = 200
    static let maximumObjects = 2_000
    static let maximumTotalBytes = 256 << 20

    /// The longest name written, in UTF-8 bytes: a file name holds 255, less room
    /// for the `(n)` a duplicate is given.
    static let maximumSavableNameBytes = 240

    /// Lists `kind`'s objects. `streams` are the flows carrying the kind's protocol;
    /// `connections` every TCP connection and UDP flow, where FTP data and TFTP
    /// transfers are looked for.
    static func scan(
        _ kind: CaptureObjectKind,
        contentsOf url: URL,
        expectedIdentity: PcapFileIdentity,
        streams: [Stream],
        connections: [Connection] = [],
        sourceToken: UUID? = nil,
        isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled },
        onProgress: (_ done: Int, _ total: Int) -> Void = { _, _ in }
    )
        throws -> CaptureObjectList
    {
        // Connections are read a group at a time, one file pass per group.
        let configuration = FollowStreamReader.Configuration(isCancelled: isCancelled)
        let followEach = { (tuples: [FiveTuple], body: (FollowStreamResult) throws -> Void) throws in
            try FollowStreamReader.readEach(
                contentsOf: url, expectedIdentity: expectedIdentity, tuples: tuples, sourceToken: sourceToken,
                configuration: configuration, body
            )
        }
        let read = Array(streams.prefix(maximumStreams))
        var found: [CaptureObject] = []
        // SMB files the bounds left out inside a stream's own read.
        var smbOmitted = 0
        switch kind {
        case .ftpData:
            var transfers: [FTPDataObjectReader.Transfer] = []
            var done = 0
            try followEach(read.map(\.tuple)) { result in
                transfers += FTPDataObjectReader.transfers(in: result)
                done += 1
                onProgress(done, read.count + transfers.count)
            }
            let matched = FTPDataObjectReader.match(transfers, to: connections)
            let pairsOn = Dictionary(grouping: matched.indices) { matched[$0].connection }
            var objects: [Int: CaptureObject] = [:]
            done = 0
            try followEach(matched.map(\.connection)) { result in
                for index in pairsOn[result.tuple] ?? [] {
                    let pair = matched[index]
                    objects[index] = try FTPDataObjectReader.object(
                        pair.transfer, in: result, sessionID: SessionBuilder.sessionID(for: pair.connection)
                    )
                    done += 1
                }
                onProgress(read.count + done, read.count + matched.count)
            }
            found = matched.indices.compactMap { objects[$0] }
        case .tftp:
            let datagramConfiguration = TFTPObjectReader.configuration(isCancelled: isCancelled)
            let datagramsEach = { (tuples: [FiveTuple], body: (FollowDatagramResult) throws -> Void) throws in
                try FollowDatagramReader.readEach(
                    contentsOf: url, expectedIdentity: expectedIdentity, tuples: tuples, sourceToken: sourceToken,
                    configuration: datagramConfiguration, body
                )
            }
            var requests: [FiveTuple: [TFTPObjectReader.Request]] = [:]
            try datagramsEach(read.map(\.tuple)) { result in
                requests[result.tuple] = TFTPObjectReader.requests(in: result)
                onProgress(requests.count, read.count + 1)
            }
            // Pairs keep the order a stream-by-stream reading would give them.
            var matched: [(request: TFTPObjectReader.Request, connection: FiveTuple)] = []
            for stream in read {
                matched += TFTPObjectReader.match(requests[stream.tuple] ?? [], on: stream.tuple, to: connections)
            }
            let pairsOn = Dictionary(grouping: matched.indices) { matched[$0].connection }
            var objects: [Int: CaptureObject] = [:]
            var done = 0
            try datagramsEach(matched.map(\.connection)) { result in
                for index in pairsOn[result.tuple] ?? [] {
                    let pair = matched[index]
                    objects[index] = try TFTPObjectReader.object(
                        pair.request, in: result, sessionID: SessionBuilder.sessionID(for: pair.connection)
                    )
                }
                done += 1
                onProgress(read.count + done, read.count + pairsOn.count)
            }
            found = matched.indices.compactMap { objects[$0] }
        case .smb:
            var totalSMBBytes = 0
            var done = 0
            let streamsOn = Dictionary(grouping: read) { $0.tuple }
            try followEach(read.map(\.tuple)) { result in
                if isCancelled() {
                    throw CancellationError()
                }
                for stream in streamsOn[result.tuple] ?? [] {
                    let remainingCount = max(0, maximumObjects - found.count)
                    let remainingBytes = max(0, maximumTotalBytes - totalSMBBytes)
                    let smbRead = SMBObjectReader.read(
                        result, sessionID: stream.sessionID,
                        maxObjects: remainingCount, maxAggregateBytes: remainingBytes,
                        isCancelled: isCancelled
                    )
                    smbOmitted += smbRead.omitted
                    for object in smbRead.objects {
                        guard found.count < maximumObjects,
                              object.body.count <= maximumTotalBytes - totalSMBBytes else
                        {
                            smbOmitted += 1
                            continue
                        }
                        totalSMBBytes += object.body.count
                        found.append(object)
                    }
                    done += 1
                }
                onProgress(done, read.count)
            }
        case .http,
             .imf,
             .x509:
            // Objects keep the stream order; a tuple two sessions share is read once.
            let streamsOn = Dictionary(grouping: read.indices) { read[$0].tuple }
            var objects: [Int: [CaptureObject]] = [:]
            var done = 0
            try followEach(read.map(\.tuple)) { result in
                for index in streamsOn[result.tuple] ?? [] {
                    let sessionID = read[index].sessionID
                    objects[index] = switch kind {
                    case .http: HTTPObjectReader.objects(of: result, sessionID: sessionID)
                    case .imf: MailObjectReader.objects(of: result, sessionID: sessionID)
                    case .smb: SMBObjectReader.objects(of: result, sessionID: sessionID)
                    default: CertificateObjectReader.objects(of: result, sessionID: sessionID)
                    }
                    done += 1
                }
                onProgress(done, read.count)
            }
            found = read.indices.flatMap { objects[$0] ?? [] }
        }
        var objects: [CaptureObject] = []
        var totalBytes = 0
        var omitted = smbOmitted
        for object in found {
            guard objects.count < maximumObjects, totalBytes + object.body.count <= maximumTotalBytes else {
                omitted += 1
                continue
            }
            totalBytes += object.body.count
            objects.append(object)
        }
        objects.sort { ($0.frameOrdinal ?? .max, $0.id) < ($1.frameOrdinal ?? .max, $1.id) }
        return CaptureObjectList(
            objects: objects, scannedStreamCount: read.count, skippedStreamCount: streams.count - read.count,
            omittedObjectCount: omitted
        )
    }

    /// What to scan for `kind`: the flows of `inView` carrying its protocol, and every
    /// flow of `all` as a connection its objects may have travelled on.
    static func inputs(
        _ kind: CaptureObjectKind,
        in inView: [SessionSummary],
        from all: [SessionSummary]
    )
        -> (streams: [Stream], connections: [Connection])
    {
        let streams = inView.filter { $0.protocolStack.contains(kind.protocolKind) }.compactMap { session in
            flow(of: session).map { Stream(tuple: $0, sessionID: session.id) }
        }
        let connections = all.compactMap { session in
            flow(of: session).map { Connection(tuple: $0, firstOrdinal: session.firstCaptureOrdinal ?? 0) }
        }
        return (streams, connections)
    }

    /// `name`, or `name(1)`, `name(2)`… — the first not in `taken`, as tshark
    /// names files that share a name.
    static func uniqueName(_ name: String, taken: Set<String>) -> String {
        // macOS volumes usually ignore case: `A.txt` and `a.txt` are one file.
        let folded = Set(taken.map { $0.lowercased() })
        guard folded.contains(name.lowercased()) else {
            return name
        }
        var counter = 1
        while folded.contains("\(name)(\(counter))".lowercased()) {
            counter += 1
        }
        return "\(name)(\(counter))"
    }

    /// A listed name made safe to save: the characters a file name cannot hold
    /// written as `%xx`, as tshark's `--export-objects` writes them.
    static func savableName(_ name: String) -> String {
        let escaped = name.unicodeScalars.map { scalar -> String in
            if "<>:\"/\\|?*".unicodeScalars.contains(scalar) || scalar.value < 0x20 {
                return String(format: "%%%02x", scalar.value)
            }
            return String(scalar)
        }.joined()
        guard !escaped.isEmpty, escaped != ".", escaped != ".." else {
            return "object"
        }
        guard escaped.utf8.count > maximumSavableNameBytes else {
            return escaped
        }
        // Too long for a file name: shorten the stem and keep a short extension.
        var stem = escaped
        var suffix = ""
        if let dot = escaped.lastIndex(of: "."), escaped[dot...].utf8.count <= 16 {
            stem = String(escaped[..<dot])
            suffix = String(escaped[dot...])
        }
        while !stem.isEmpty, stem.utf8.count + suffix.utf8.count > maximumSavableNameBytes {
            stem.removeLast()
        }
        return stem + suffix
    }

    // MARK: Private

    /// A session's TCP or UDP flow.
    private static func flow(of session: SessionSummary) -> FiveTuple? {
        guard let source = session.sourceEndpointValue, let destination = session.destinationEndpointValue else {
            return nil
        }
        let proto: ProtocolKind? = session.protocolStack.contains(.tcp) ? .tcp
            : session.protocolStack.contains(.udp) ? .udp : nil
        return proto.map { FiveTuple(proto: $0, source: source, destination: destination) }
    }
}

// MARK: - HTTPObjectReader

/// Every HTTP/1 response body of one followed stream, as Wireshark's File ▸ Export
/// Objects ▸ HTTP lists it. A gzip or deflate body is decoded, as Wireshark's export
/// is; any other content coding is kept.
nonisolated enum HTTPObjectReader {
    // MARK: Internal

    static func objects(of result: FollowStreamResult, sessionID: UUID) -> [CaptureObject] {
        guard let presentation = FollowHTTPPresentation(result: result) else {
            return []
        }
        return presentation.rows.compactMap { row in
            guard let response = row.savableResponse,
                  let raw = presentation.responseBody(of: row, in: result) else
            {
                return nil
            }
            let (body, coding) = decoded(raw, contentEncoding: response.contentEncoding)
            let target = String(row.request.drop { $0 != " " }.dropFirst())
            return CaptureObject(
                id: "\(sessionID.uuidString)-\(row.id)",
                sessionID: sessionID,
                frameOrdinal: row.responseFrame?.ordinal.rawValue,
                host: row.host ?? "",
                contentType: response.contentType ?? "",
                fileName: HTTPBodyFileName.suggested(
                    target: target, contentType: response.contentType, contentEncoding: coding
                ),
                body: body
            )
        }
    }

    // MARK: Private

    /// The body with a gzip or deflate coding removed, and the coding left on it.
    private static func decoded(_ body: [UInt8], contentEncoding: String?) -> ([UInt8], String?) {
        let coding = contentEncoding?.trimmingCharacters(in: .whitespaces).lowercased()
        let decoder: [PacketBytesDecoding] = switch coding {
        case "gzip",
             "x-gzip": [.gzip]
        case "deflate": [.zlib, .rawDeflate]
        default: []
        }
        for candidate in decoder {
            if let plain = try? candidate.decode(body) {
                return (plain, nil)
            }
        }
        return (body, contentEncoding)
    }
}
