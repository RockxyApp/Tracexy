import Foundation

// MARK: - PacketDecoder text services

/// SSH, FTP, SMTP, POP3 and IMAP over TCP, and SSDP over UDP: the line-based
/// services a Mac still speaks (git over SSH, mail clients, a TV or speaker
/// announcing itself). Each frame is read on its own: command and response lines are
/// named only when they have the service's exact shape, anything else is message
/// data. A user name or secret is never read out — Tracexy keeps only that a login
/// crossed the wire (see ``CleartextCredentialDetector``).
extension PacketDecoder {
    // MARK: Internal

    /// Lines read from one frame, at most.
    static let maximumServiceLines = 16

    /// After TLS, DNS and HTTP: SSH by its banner on any port, or on port 22; the
    /// mail and file-transfer services on their standard ports when the payload is text.
    static let textServiceTCPCandidates: [ApplicationCandidate] = [
        ApplicationCandidate(
            matches: { startsWith($0.payload, "SSH-") || $0.sourcePort == 22 || $0.destinationPort == 22 },
            decode: { context, packet in
                try ssh(context.payload, into: &packet)
                return nil
            }
        ),
        sipCandidate,
        smbCandidate,
    ] + directoryCandidates + TextService.allCases.map { service in
        ApplicationCandidate(
            matches: { context in
                !service.ports.isDisjoint(with: [context.sourcePort, context.destinationPort])
                    && isText(context.payload)
            },
            decode: { context, packet in
                try textService(service, context.payload, into: &packet)
                return nil
            }
        )
    }

    /// SIP on UDP or TCP 5060: a request line ending `SIP/2.0` or a status line.
    static let sipCandidate = ApplicationCandidate(
        matches: { ($0.sourcePort == 5_060 || $0.destinationPort == 5_060) && isSIP($0.payload) },
        decode: { context, packet in
            try sip(context.payload, into: &packet)
            return nil
        }
    )

    /// SSDP on UDP 1900: HTTP-shaped discovery messages (`M-SEARCH`, `NOTIFY`, `HTTP/1.1 200`).
    static let ssdpCandidate = ApplicationCandidate(
        matches: { ($0.sourcePort == 1_900 || $0.destinationPort == 1_900) && isSSDP($0.payload) },
        decode: { context, packet in
            try ssdp(context.payload, into: &packet)
            return nil
        }
    )

    /// SSH: the version banner (`SSH-2.0-OpenSSH_9.6`), or a binary packet — key
    /// exchange or encrypted — which is named, not read.
    static func ssh(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        packet.appProtocol = .ssh
        let head = try buf.bytes(0, min(buf.length, 255))
        guard head.starts(with: Array("SSH-".utf8)) else {
            packet.layers.append(DecodedLayer(
                proto: .ssh, title: "SSH Protocol",
                summary: "Binary packet, \(buf.length) bytes",
                fields: [], byteRange: span(buf, buf.length)
            ))
            return
        }
        let end = head.firstIndex { $0 == 0x0D || $0 == 0x0A } ?? head.count
        let banner = String(bytes: head[..<end], encoding: .isoLatin1) ?? ""
        packet.layers.append(DecodedLayer(
            proto: .ssh, title: "SSH Protocol", summary: banner,
            fields: [ranged("Protocol", banner, in: buf, at: 0, end)],
            byteRange: span(buf, buf.length)
        ))
    }

    static func textService(_ service: TextService, _ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        packet.appProtocol = service.kind
        let bytes = try buf.bytes(0, min(buf.length, CleartextCredentialDetector.scanLimit))
        var fields: [DecodedField] = []
        var summary: String?
        for line in serviceLines(bytes).prefix(maximumServiceLines) {
            guard let parsed = service.parse(line.text) else {
                continue
            }
            for (name, value, offset, length) in parsed.fields {
                fields.append(ranged(name, value, in: buf, at: line.offset + offset, length))
            }
            summary = summary ?? parsed.summary
        }
        packet.layers.append(DecodedLayer(
            proto: service.kind, title: service.title,
            summary: summary ?? "Message data, \(buf.length) bytes",
            fields: fields, byteRange: span(buf, buf.length)
        ))
    }

    /// SSDP: the start line, then the discovery headers that say what is offered
    /// and where (`ST`, `NT`, `NTS`, `USN`, `LOCATION`, `SERVER`, `MAN`, `MX`).
    static func ssdp(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        packet.appProtocol = .ssdp
        let bytes = try buf.bytes(0, min(buf.length, 2_048))
        let lines = serviceLines(bytes)
        guard let start = lines.first else {
            return
        }
        var fields: [DecodedField] = []
        var summary = start.text
        let words = start.text.split(separator: " ", maxSplits: 2).map(String.init)
        if start.text.hasPrefix("HTTP/"), words.count >= 2 {
            fields.append(ranged("Status", words[1], in: buf, at: start.offset + words[0].count + 1, words[1].count))
            summary = words.dropFirst().joined(separator: " ")
        } else if let method = words.first {
            fields.append(ranged("Method", method, in: buf, at: start.offset, method.count))
            summary = method
        }
        let named: Set = ["ST", "NT", "NTS", "USN", "LOCATION", "SERVER", "MAN", "MX"]
        for line in lines.dropFirst().prefix(maximumServiceLines) {
            guard let colon = line.text.firstIndex(of: ":") else {
                continue
            }
            let name = line.text[..<colon].trimmingCharacters(in: .whitespaces).uppercased()
            let value = line.text[line.text.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            guard named.contains(name), !value.isEmpty else {
                continue
            }
            fields.append(ranged(name, value, in: buf, at: line.offset, line.text.utf8.count))
            if ["ST", "NT"].contains(name) {
                summary += " " + value
            }
        }
        packet.layers.append(DecodedLayer(
            proto: .ssdp, title: "Simple Service Discovery Protocol", summary: summary,
            fields: fields, byteRange: span(buf, buf.length)
        ))
    }

    // MARK: Private

    private static func startsWith(_ buf: PacketBuffer, _ prefix: String) -> Bool {
        let expected = Array(prefix.utf8)
        return (try? buf.bytes(0, min(buf.length, expected.count))) == expected
    }

    /// Printable ASCII with tabs and line ends, over the first 512 bytes.
    private static func isText(_ buf: PacketBuffer) -> Bool {
        guard let head = try? buf.bytes(0, min(buf.length, 512)), !head.isEmpty else {
            return false
        }
        return head.allSatisfy { (0x20 ... 0x7E).contains($0) || $0 == 0x09 || $0 == 0x0A || $0 == 0x0D }
    }

    private static func isSSDP(_ buf: PacketBuffer) -> Bool {
        ["M-SEARCH * HTTP/1.", "NOTIFY * HTTP/1.", "HTTP/1.1 200", "HTTP/1.0 200"].contains { startsWith(buf, $0) }
    }

    /// CR/LF-separated printable lines with their byte offsets; stops at the first
    /// byte that is not text.
    private static func serviceLines(_ bytes: [UInt8]) -> [(text: String, offset: Int)] {
        var lines: [(String, Int)] = []
        var start = 0
        for (index, byte) in bytes.enumerated() {
            if byte == 0x0A || byte == 0x0D {
                if index > start {
                    lines.append((String(bytes: bytes[start ..< index], encoding: .ascii) ?? "", start))
                }
                start = index + 1
            } else if !(0x20 ... 0x7E).contains(byte), byte != 0x09 {
                return lines
            }
        }
        if start < bytes.count {
            lines.append((String(bytes: bytes[start...], encoding: .ascii) ?? "", start))
        }
        return lines
    }
}

// MARK: - TextService

/// The line-based services and how each names a line.
nonisolated enum TextService: CaseIterable, Sendable {
    case ftp
    case smtp
    case pop3
    case imap

    // MARK: Internal

    struct Line {
        /// (field name, value, offset in the line, length in bytes)
        var fields: [(String, String, Int, Int)]
        var summary: String
    }

    var kind: ProtocolKind {
        switch self {
        case .ftp: .ftp
        case .smtp: .smtp
        case .pop3: .pop3
        case .imap: .imap
        }
    }

    var title: String {
        switch self {
        case .ftp: "File Transfer Protocol"
        case .smtp: "Simple Mail Transfer Protocol"
        case .pop3: "Post Office Protocol"
        case .imap: "Internet Message Access Protocol"
        }
    }

    var ports: Set<UInt16> {
        switch self {
        case .ftp: [21]
        case .smtp: [25, 587]
        case .pop3: [110]
        case .imap: [143]
        }
    }

    /// The named parts of one line, or `nil` for message data.
    func parse(_ line: String) -> Line? {
        let words = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
        guard let first = words.first, !first.isEmpty else {
            return nil
        }
        let rest = words.count > 1 ? words[1] : ""
        switch self {
        case .ftp,
             .smtp:
            if let code = Self.replyCode(first) {
                let text = String(line.dropFirst(4))
                var fields = [("Response code", code, 0, 3)]
                if !text.isEmpty {
                    fields.append((self == .ftp ? "Response argument" : "Response parameter", text, 4, text.utf8.count))
                }
                return Line(fields: fields, summary: "Response: \(line)")
            }
            let command = first.uppercased()
            guard (self == .ftp ? Self.ftpCommands : Self.smtpCommands).contains(command) else {
                return nil
            }
            return request(command, rest, commandLength: first.utf8.count, name: "Request command")
        case .pop3:
            if first == "+OK" || first == "-ERR" {
                var fields = [("Response indicator", first, 0, first.utf8.count)]
                if !rest.isEmpty {
                    fields.append(("Response description", rest, first.utf8.count + 1, rest.utf8.count))
                }
                return Line(fields: fields, summary: "Response: \(line)")
            }
            let command = first.uppercased()
            guard Self.popCommands.contains(command) else {
                return nil
            }
            return request(command, rest, commandLength: first.utf8.count, name: "Request command")
        case .imap:
            return imap(first, rest)
        }
    }

    // MARK: Private

    private static let ftpCommands: Set = [
        "USER", "PASS", "ACCT", "CWD", "CDUP", "QUIT", "PORT", "PASV", "EPRT", "EPSV", "TYPE", "MODE", "STRU",
        "RETR", "STOR", "STOU", "APPE", "REST", "RNFR", "RNTO", "ABOR", "DELE", "RMD", "MKD", "PWD", "LIST",
        "NLST", "SITE", "SYST", "STAT", "HELP", "NOOP", "FEAT", "OPTS", "AUTH", "PBSZ", "PROT", "SIZE", "MDTM",
        "MLSD", "MLST", "XPWD", "XCWD", "XMKD", "XRMD",
    ]
    private static let smtpCommands: Set = [
        "HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "NOOP", "QUIT", "VRFY", "EXPN", "HELP", "AUTH", "STARTTLS",
        "BDAT", "TURN", "ETRN",
    ]
    private static let popCommands: Set = [
        "USER", "PASS", "APOP", "AUTH", "STAT", "LIST", "RETR", "DELE", "NOOP", "RSET", "QUIT", "TOP", "UIDL",
        "CAPA", "STLS",
    ]
    private static let imapCommands: Set = [
        "CAPABILITY", "NOOP", "LOGOUT", "STARTTLS", "AUTHENTICATE", "LOGIN", "SELECT", "EXAMINE", "CREATE",
        "DELETE", "RENAME", "SUBSCRIBE", "UNSUBSCRIBE", "LIST", "LSUB", "STATUS", "APPEND", "CHECK", "CLOSE",
        "EXPUNGE", "SEARCH", "FETCH", "STORE", "COPY", "MOVE", "UID", "IDLE", "DONE", "NAMESPACE", "ENABLE", "ID",
    ]
    /// Commands whose argument is a user name or a secret.
    private static let secretCommands: Set = ["USER", "PASS", "ACCT", "APOP", "AUTH", "LOGIN", "AUTHENTICATE"]
    private static let imapStatuses: Set = ["OK", "NO", "BAD", "PREAUTH", "BYE"]

    private static func replyCode(_ word: String) -> String? {
        let digits = word.prefix(3)
        guard digits.count == 3, digits.allSatisfy { $0.isASCII && $0.isNumber },
              word.count == 3 || word.dropFirst(3) == "-" else
        {
            return nil
        }
        return String(digits)
    }

    private func request(_ command: String, _ argument: String, commandLength: Int, name: String) -> Line {
        var fields = [(name, command, 0, commandLength)]
        guard !argument.isEmpty else {
            return Line(fields: fields, summary: "Request: \(command)")
        }
        if Self.secretCommands.contains(command) {
            fields.append(("Request argument", "Not shown", commandLength + 1, argument.utf8.count))
            return Line(fields: fields, summary: "Request: \(command)")
        }
        fields.append(("Request argument", argument, commandLength + 1, argument.utf8.count))
        return Line(fields: fields, summary: "Request: \(command) \(argument)")
    }

    /// `tag COMMAND …` from the client; `* …`, `+ …` or `tag OK|NO|BAD …` from the server.
    private func imap(_ first: String, _ rest: String) -> Line? {
        let restWords = rest.split(separator: " ", maxSplits: 1).map(String.init)
        guard let second = restWords.first else {
            return nil
        }
        let upper = second.uppercased()
        if first == "*" || first == "+" || Self.imapStatuses.contains(upper) {
            var fields = [("Response tag", first, 0, first.utf8.count)]
            if Self.imapStatuses.contains(upper) {
                fields.append(("Response status", upper, first.utf8.count + 1, second.utf8.count))
            }
            return Line(fields: fields, summary: "Response: \(first) \(rest)")
        }
        guard Self.imapCommands.contains(upper) else {
            return nil
        }
        var line = request(
            upper, restWords.count > 1 ? restWords[1] : "", commandLength: second.utf8.count, name: "Request command"
        )
        // Shift the command's fields past the tag, and name the tag first.
        line.fields = [("Request tag", first, 0, first.utf8.count)] + line.fields.map {
            ($0.0, $0.1, $0.2 + first.utf8.count + 1, $0.3)
        }
        return line
    }
}
