import Foundation

// MARK: - MailObjectReader

/// File ▸ Export Objects ▸ IMF: every message an SMTP client sent after DATA, as
/// Wireshark's IMF export lists it — the bytes up to the line holding only ".", kept
/// as sent (dot-stuffing included), named by its Subject, with the From address as
/// the host. Reading stops at STARTTLS, after which the stream is encrypted.
nonisolated enum MailObjectReader {
    // MARK: Internal

    static func objects(of result: FollowStreamResult, sessionID: UUID) -> [CaptureObject] {
        guard let client = ObjectStreamSides.clientDirection(of: result) else {
            return []
        }
        let snapshot = client == .aToB ? result.aToB : result.bToA
        guard let run = snapshot.runs.first, run.sequenceAnchor == snapshot.anchorSequence else {
            return []
        }
        let bytes = run.bytes
        var objects: [CaptureObject] = []
        var offset = 0
        while let lineEnd = ObjectStreamSides.lineEnd(in: bytes, from: offset) {
            let verb = (String(bytes: bytes[offset ..< lineEnd], encoding: .isoLatin1) ?? "")
                .trimmingCharacters(in: .whitespaces).uppercased()
            let next = lineEnd + 2
            if verb == "STARTTLS" {
                break
            }
            guard verb == "DATA" else {
                offset = next
                continue
            }
            // The message ends at CRLF "." CRLF; the CRLF ending DATA counts, so an
            // empty message ends at once.
            guard let terminator = find([0x0D, 0x0A, 0x2E, 0x0D, 0x0A], in: bytes, from: lineEnd) else {
                break
            }
            let message = Array(bytes[next ..< max(next, terminator + 2)])
            let headers = headers(of: message)
            let sender = headers["from"] ?? ""
            objects.append(CaptureObject(
                id: "\(sessionID.uuidString)-\(String(format: "%05d", objects.count))",
                sessionID: sessionID,
                frameOrdinal: snapshot.firstFrame(ofByte: terminator + 4, in: run)?.ordinal.rawValue,
                host: address(in: sender),
                contentType: "EML file",
                fileName: "\(headers["subject"] ?? "").eml",
                body: message
            ))
            offset = terminator + 5
        }
        return objects
    }

    // MARK: Private

    private static func find(_ needle: [UInt8], in bytes: [UInt8], from start: Int) -> Int? {
        guard needle.count <= bytes.count else {
            return nil
        }
        var index = start
        while index + needle.count <= bytes.count {
            if bytes[index] == needle[0], Array(bytes[index ..< index + needle.count]) == needle {
                return index
            }
            index += 1
        }
        return nil
    }

    /// The From and Subject values as Wireshark's IMF dissector reads them: after the
    /// colon, leading white space skipped, folded lines kept, the last CRLF dropped,
    /// bytes past ASCII replaced. A later field of the same name wins.
    private static func headers(of message: [UInt8]) -> [String: String] {
        var fields: [String: String] = [:]
        var offset = 0
        while let lineEnd = ObjectStreamSides.lineEnd(in: message, from: offset), lineEnd > offset {
            var end = lineEnd + 2
            while end < message.count, message[end] == 0x20 || message[end] == 0x09,
                  let folded = ObjectStreamSides.lineEnd(in: message, from: end)
            {
                end = folded + 2
            }
            let field = Array(message[offset ..< end - 2])
            offset = end
            guard let colon = field.firstIndex(of: 0x3A) else {
                continue
            }
            let name = (String(bytes: field[..<colon], encoding: .isoLatin1) ?? "").lowercased()
            guard name == "from" || name == "subject" else {
                continue
            }
            var value = field[(colon + 1)...]
            let trimmed = value.drop { [0x20, 0x09, 0x0D, 0x0A, 0x0B, 0x0C].contains($0) }
            if !trimmed.isEmpty {
                value = trimmed
            }
            fields[name] = String(value.map { $0 < 0x80 ? Character(UnicodeScalar($0)) : "\u{FFFD}" })
        }
        return fields
    }

    /// The address inside the last `<…>` of a From value, else the whole value.
    private static func address(in sender: String) -> String {
        guard let open = sender.range(of: "<", options: .backwards),
              let close = sender.range(of: ">", options: .backwards),
              open.upperBound <= close.lowerBound else
        {
            return sender
        }
        return String(sender[open.upperBound ..< close.lowerBound])
    }
}

// MARK: - FTPDataObjectReader

/// File ▸ Export Objects ▸ FTP-DATA: the files an FTP control connection moved with
/// RETR, STOR, STOU or APPE, as Wireshark ties them together — the data connection a
/// PASV or EPSV reply, or a PORT or EPRT command, set up, named by the command's
/// argument, its bytes in capture order, and the frame and sender of its first byte.
nonisolated enum FTPDataObjectReader {
    // MARK: Internal

    /// A data connection the control connection set up, and the command it serves.
    struct Transfer: Sendable, Equatable {
        let setupOrdinal: UInt64
        /// The listening end, and where a NATed PASV reply leaves it.
        let endpoints: [IPEndpoint]
        let peerIP: String
        let command: String
    }

    /// The transfers of one control connection whose command sends a file.
    static func transfers(in result: FollowStreamResult) -> [Transfer] {
        guard let client = ObjectStreamSides.clientDirection(of: result) else {
            return []
        }
        let clientIP = client == .aToB ? result.tuple.a.ip : result.tuple.b.ip
        let serverIP = client == .aToB ? result.tuple.b.ip : result.tuple.a.ip
        var transfers: [Transfer] = []
        var current: (setup: UInt64, endpoints: [IPEndpoint], peer: String, command: String?)?
        func finish() {
            if let current, let command = current.command, isExported(command) {
                transfers.append(Transfer(
                    setupOrdinal: current.setup, endpoints: current.endpoints, peerIP: current.peer, command: command
                ))
            }
        }
        for turn in FollowStreamExport.turns(of: result) {
            for line in lines(turn.bytes) {
                if turn.direction == client {
                    // Wireshark gives the line to the current data connection first:
                    // the first command, or a data command after a non-data one.
                    if let command = current?.command {
                        if !isData(command), isData(line) {
                            current?.command = line
                        }
                    } else if current != nil {
                        current?.command = line
                    }
                    if let endpoint = activeEndpoint(line) {
                        finish()
                        current = (turn.firstOrdinal, [endpoint], serverIP, nil)
                    }
                } else if let port = passivePort(line) {
                    finish()
                    var endpoints = [IPEndpoint(ip: port.ip ?? serverIP, port: port.port)]
                    if let ip = port.ip, ip != serverIP {
                        endpoints.append(IPEndpoint(ip: serverIP, port: port.port))
                    }
                    current = (turn.firstOrdinal, endpoints, clientIP, nil)
                }
            }
        }
        finish()
        return transfers
    }

    /// Each transfer with the first connection after its setup between its listening
    /// end and its peer; a connection serves one transfer.
    static func match(
        _ transfers: [Transfer],
        to connections: [CaptureObjectScanner.Connection]
    )
        -> [(transfer: Transfer, connection: FiveTuple)]
    {
        var used = Set<FiveTuple>()
        let ordered = connections.sorted { $0.firstOrdinal < $1.firstOrdinal }
        return transfers.compactMap { transfer in
            let listening = Set(transfer.endpoints.map(normalized))
            guard let connection = ordered.first(where: { connection in
                guard connection.firstOrdinal > transfer.setupOrdinal, !used.contains(connection.tuple) else {
                    return false
                }
                let a = normalized(connection.tuple.a)
                let b = normalized(connection.tuple.b)
                let peer = normalized(IPEndpoint(ip: transfer.peerIP, port: 0)).ip
                return (listening.contains(a) && b.ip == peer) || (listening.contains(b) && a.ip == peer)
            }) else {
                return nil
            }
            used.insert(connection.tuple)
            return (transfer, connection.tuple)
        }
    }

    /// The transfer's object: every byte of the data connection in capture order.
    static func object(_ transfer: Transfer, in result: FollowStreamResult, sessionID: UUID) -> CaptureObject? {
        let turns = FollowStreamExport.turns(of: result)
        guard let first = turns.first else {
            return nil
        }
        return CaptureObject(
            id: "\(sessionID.uuidString)-\(transfer.setupOrdinal)",
            sessionID: sessionID,
            frameOrdinal: first.firstOrdinal,
            host: first.direction == .aToB ? result.tuple.a.ip : result.tuple.b.ip,
            contentType: "FTP file",
            fileName: transfer.command.count > 5 ? String(transfer.command.dropFirst(5)) : "(MISSING)",
            body: turns.flatMap(\.bytes)
        )
    }

    // MARK: Private

    private static func isData(_ command: String) -> Bool {
        ["RETR", "STOR", "STOU", "APPE", "LIST", "NLST", "MLSD"].contains { command.hasPrefix($0) }
    }

    private static func isExported(_ command: String) -> Bool {
        ["RETR", "STOR", "STOU", "APPE"].contains { command.hasPrefix($0) }
    }

    private static func lines(_ bytes: [UInt8]) -> [String] {
        (String(bytes: bytes, encoding: .utf8) ?? String(bytes: bytes, encoding: .isoLatin1) ?? "")
            .split(omittingEmptySubsequences: true) { $0 == "\r\n" || $0 == "\n" }
            .map(String.init)
    }

    /// PORT h1,h2,h3,h4,p1,p2 or EPRT |af|address|port|: where the client listens.
    private static func activeEndpoint(_ line: String) -> IPEndpoint? {
        let upper = line.uppercased()
        if upper.hasPrefix("PORT ") {
            return sixNumbers(in: line.dropFirst(5))
        }
        guard upper.hasPrefix("EPRT "), let delimiter = line.dropFirst(5).first else {
            return nil
        }
        let parts = line.dropFirst(5).split(separator: delimiter, omittingEmptySubsequences: false)
        guard parts.count >= 4, let port = UInt16(parts[3]) else {
            return nil
        }
        return IPEndpoint(ip: String(parts[2]), port: port)
    }

    /// A 227 reply's address and port, or a 229 reply's port on the server.
    private static func passivePort(_ line: String) -> (ip: String?, port: UInt16)? {
        if line.hasPrefix("227"), let open = line.firstIndex(where: \.isNumber).map({ line.index(after: $0) }) {
            let rest = line[open...].drop { $0.isNumber }
            return sixNumbers(in: rest).map { ($0.ip, $0.port) }
        }
        guard line.hasPrefix("229"), let open = line.firstIndex(of: "("),
              let delimiter = line[line.index(after: open)...].first else
        {
            return nil
        }
        let parts = line[line.index(after: open)...].split(separator: delimiter, omittingEmptySubsequences: false)
        guard parts.count >= 4, let port = UInt16(parts[3]) else {
            return nil
        }
        return (nil, port)
    }

    /// The first `h1,h2,h3,h4,p1,p2` in `text`.
    private static func sixNumbers(in text: Substring) -> IPEndpoint? {
        guard let match = text.firstMatch(of: #/(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3})/#),
              let values = Optional([match.1, match.2, match.3, match.4, match.5, match.6].compactMap { Int($0) }),
              values.count == 6, values.allSatisfy({ $0 <= 255 }) else
        {
            return nil
        }
        return IPEndpoint(
            ip: values[0 ..< 4].map(String.init).joined(separator: "."), port: UInt16(values[4] << 8 | values[5])
        )
    }

    private static func normalized(_ endpoint: IPEndpoint) -> IPEndpoint {
        IPEndpoint(ip: IPAddressValue(parsing: endpoint.ip)?.compressedText ?? endpoint.ip, port: endpoint.port)
    }
}

// MARK: - CertificateObjectReader

/// File ▸ Export Objects ▸ X509AF: every certificate a TLS handshake sent in the
/// clear, as Wireshark's export lists it — its DER, named by its serial number, with
/// the subject's common name as the host and the frame that completed its record.
nonisolated enum CertificateObjectReader {
    static func objects(of result: FollowStreamResult, sessionID: UUID) -> [CaptureObject] {
        [(ConnectionDirection.aToB, result.aToB), (.bToA, result.bToA)].flatMap { direction, snapshot in
            guard let run = snapshot.runs.first, run.sequenceAnchor == snapshot.anchorSequence else {
                return [CaptureObject]()
            }
            let (outcome, recordEnd) = TLSCertificateExtraction.walk(run.bytes)
            let frame = recordEnd.flatMap { snapshot.firstFrame(ofByte: $0 - 1, in: run) }?.ordinal.rawValue
            return outcome.certificates.enumerated().map { index, certificate in
                CaptureObject(
                    id: "\(sessionID.uuidString)-\(direction == .aToB ? "a" : "b")-\(String(format: "%02d", index))",
                    sessionID: sessionID,
                    frameOrdinal: frame,
                    host: certificate.subject.attributes.first { $0.label == "CN" }?.value ?? "",
                    contentType: "application/pkix-cert",
                    fileName: certificate.serialNumber.map { String(format: "%02x", $0) }.joined() + ".cer",
                    body: certificate.der
                )
            }
        }
    }
}

// MARK: - ObjectStreamSides

/// Which side of a text protocol's stream is the client: the server's side opens with
/// a three-digit reply (FTP and SMTP greet first), the client's with a command.
nonisolated enum ObjectStreamSides {
    // MARK: Internal

    static func clientDirection(of result: FollowStreamResult) -> ConnectionDirection? {
        let aReplies = startsWithReply(result.aToB)
        let bReplies = startsWithReply(result.bToA)
        switch (aReplies, bReplies) {
        case (true?, false?),
             (true?, nil): return .bToA
        case (false?, true?),
             (nil, true?): return .aToB
        case (false?, nil): return .aToB
        case (nil, false?): return .bToA
        default: return nil
        }
    }

    /// The index of the next CR LF at or after `start`.
    static func lineEnd(in bytes: [UInt8], from start: Int) -> Int? {
        var index = start
        while index + 1 < bytes.count {
            if bytes[index] == 0x0D, bytes[index + 1] == 0x0A {
                return index
            }
            index += 1
        }
        return nil
    }

    // MARK: Private

    /// Whether the direction's first bytes are a reply code; `nil` when it sent none.
    private static func startsWithReply(_ snapshot: FollowStreamDirectionSnapshot) -> Bool? {
        guard let bytes = snapshot.runs.first?.bytes, !bytes.isEmpty else {
            return nil
        }
        return bytes.count >= 4 && bytes[0 ..< 3].allSatisfy { (0x30 ... 0x39).contains($0) }
            && (bytes[3] == 0x20 || bytes[3] == 0x2D)
    }
}

// MARK: - TFTPObjectReader

/// File ▸ Export Objects ▸ TFTP: each file a read or write request moved, as
/// Wireshark rebuilds it — the transfer is every datagram between the requesting
/// client port and the server (any server port), blocks taken in order at the size an
/// option acknowledgement set (512 by default), a repeated block ignored, a missing one
/// dropping the file, and the short block that ends it naming the frame.
nonisolated enum TFTPObjectReader {
    // MARK: Internal

    struct Request: Sendable, Equatable {
        let ordinal: UInt64
        let client: IPEndpoint
        let serverIP: String
        let fileName: String
    }

    /// Reads a whole transfer: many datagrams, each up to the largest block.
    static func configuration(isCancelled: @escaping @Sendable () -> Bool) -> FollowDatagramReader.Configuration {
        FollowDatagramReader.Configuration(
            maxMessages: FollowDatagramReader.Configuration.ceilingMaxMessages,
            maxPayloadBytesPerMessage: FollowDatagramReader.Configuration.ceilingMaxPayloadBytesPerMessage,
            maxRetainedPayloadBytes: CaptureObjectScanner.maximumTotalBytes, isCancelled: isCancelled
        )
    }

    /// The read and write requests of one conversation with port 69.
    static func requests(in result: FollowDatagramResult) -> [Request] {
        result.messages.compactMap { message in
            let payload = message.payload
            guard payload.count > 4, payload[0] == 0, payload[1] == 1 || payload[1] == 2,
                  let end = payload[2...].firstIndex(of: 0) else
            {
                return nil
            }
            let client = message.direction == .aToB ? result.tuple.a : result.tuple.b
            let server = message.direction == .aToB ? result.tuple.b : result.tuple.a
            return Request(
                ordinal: message.provenance.ordinal.rawValue, client: client, serverIP: server.ip,
                fileName: String(payload[2 ..< end].map { Character(UnicodeScalar($0)) })
            )
        }
    }

    /// Each request with the first later UDP flow between its client port and its
    /// server, or the request's own flow when the server answered from port 69.
    static func match(
        _ requests: [Request],
        on requestFlow: FiveTuple,
        to connections: [CaptureObjectScanner.Connection]
    )
        -> [(request: Request, connection: FiveTuple)]
    {
        let ordered = connections.filter { $0.tuple.proto == .udp }.sorted { $0.firstOrdinal < $1.firstOrdinal }
        var used = Set<FiveTuple>()
        return requests.map { request in
            let flow = ordered.first { connection in
                let tuple = connection.tuple
                let other = tuple.a == request.client ? tuple.b : tuple.b == request.client ? tuple.a : nil
                return connection.firstOrdinal > request.ordinal && other?.ip == request.serverIP
                    && tuple != requestFlow && !used.contains(tuple)
            }?.tuple ?? requestFlow
            used.insert(flow)
            return (request, flow)
        }
    }

    static func object(_ request: Request, in result: FollowDatagramResult, sessionID: UUID) -> CaptureObject? {
        var blockSize = 512
        var next = 1
        var data: [UInt8] = []
        for message in result.messages {
            let payload = message.payload
            guard payload.count >= 4, payload[0] == 0 else {
                continue
            }
            if payload[1] == 6, let size = blockSizeOption(payload) {
                blockSize = size
            }
            guard payload[1] == 3 else {
                continue
            }
            let block = fullBlockNumber(Int(payload[2]) << 8 | Int(payload[3]), next: next)
            guard block <= next else {
                return nil // A block went missing; Wireshark exports nothing.
            }
            guard block == next else {
                continue // A repeated block.
            }
            guard message.boundOmittedByteCount == 0, !message.isCaptureTruncated else {
                return nil
            }
            data += payload.dropFirst(4)
            next += 1
            if payload.count - 4 < blockSize {
                return CaptureObject(
                    id: "\(sessionID.uuidString)-\(request.ordinal)",
                    sessionID: sessionID,
                    frameOrdinal: message.provenance.ordinal.rawValue,
                    host: "",
                    contentType: "",
                    fileName: request.fileName.split(separator: "/").last.map(String.init) ?? request.fileName,
                    body: data
                )
            }
        }
        return nil
    }

    // MARK: Private

    /// An option acknowledgement's `blksize`, when it is within 8…65464.
    private static func blockSizeOption(_ payload: [UInt8]) -> Int? {
        let strings = payload.dropFirst(2).split(separator: 0, omittingEmptySubsequences: false)
            .map { String($0.map { Character(UnicodeScalar($0)) }) }
        guard let index = strings.firstIndex(where: { $0.lowercased() == "blksize" }), index + 1 < strings.count,
              let size = Int(strings[index + 1]), (8 ... 65_464).contains(size) else
        {
            return nil
        }
        return size
    }

    /// The 16-bit block number widened past its wrap, nearest the expected block.
    private static func fullBlockNumber(_ block: Int, next: Int) -> Int {
        var full = (next & ~0xFFFF) | block
        if full + 0x8000 < next {
            full += 0x10000
        } else if full > next + 0x8000, full >= 0x10000 {
            full -= 0x10000
        }
        return full
    }
}
