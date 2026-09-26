import Foundation

// MARK: - PacketDecoder HTTP/1

/// HTTP/1 over the first 512 bytes of a TCP payload: a request line and its Host, or
/// a status line and the headers that explain the response. Kept beside the decoder
/// so the request layer stays byte-identical to what replay goldens pin.
extension PacketDecoder {
    static func http(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        // Only the header block is text. A body — or, after the HTTP/2 preface,
        // binary frames — in the same segment would fail UTF-8 decoding and hide
        // the request line, so the text ends at the blank line when one is seen.
        let text = try asciiString(headerBlock(buf.bytes(0, min(buf.length, 512))))
        let firstLine = text.split(separator: "\r\n", maxSplits: 1, omittingEmptySubsequences: false).first
            .map(String.init) ?? ""
        packet.appProtocol = .http
        if firstLine == "PRI * HTTP/2.0" {
            // HTTP/2 with prior knowledge: the connection preface, "the Magic".
            packet.appProtocol = .http2
            packet.negotiatedApplication = .http2
            packet.layers.append(DecodedLayer(
                proto: .http2, title: "HyperText Transfer Protocol 2", summary: "Connection preface",
                fields: [ranged("Magic", firstLine, in: buf, at: 0, min(firstLine.utf8.count, buf.length))],
                byteRange: span(buf, buf.length)
            ))
            return
        }
        if Self.upgradesToWebSocket(text) {
            packet.negotiatedApplication = .websocket
        } else if firstLine.hasPrefix("HTTP/1.1 101"), Self.upgradeTokens(text).contains("h2c") {
            // The server agreed to continue this connection in HTTP/2 (RFC 7540 §3.2).
            packet.negotiatedApplication = .http2
        }
        if firstLine.hasPrefix("HTTP/") {
            httpResponse(firstLine: firstLine, text: text, buf: buf, into: &packet)
            return
        }
        var host = ""
        for line in text.split(separator: "\r\n") where line.lowercased().hasPrefix("host:") {
            host = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
            break
        }
        let requestLength = min(firstLine.utf8.count, buf.length)
        packet.layers.append(DecodedLayer(
            proto: .http, title: "Hypertext Transfer Protocol", summary: firstLine,
            fields: [
                ranged("Request", firstLine, in: buf, at: 0, requestLength),
                .init(name: "Host", value: host.isEmpty ? "—" : host)
            ],
            byteRange: span(buf, buf.length)
        ))
    }

    /// `bytes` up to and including the first blank line (`CRLF CRLF`), or all of
    /// them when the header block does not end inside the window.
    static func headerBlock(_ bytes: [UInt8]) -> [UInt8] {
        guard bytes.count >= 4 else {
            return bytes
        }
        for index in 0 ... bytes.count - 4
            where bytes[index] == 0x0D && bytes[index + 1] == 0x0A && bytes[index + 2] == 0x0D && bytes[index + 3] ==
            0x0A
        {
            return Array(bytes[..<(index + 4)])
        }
        return bytes
    }

    /// An `Upgrade: websocket` header in the message's header block — the request
    /// asking for the switch, or the 101 response agreeing to it.
    static func upgradesToWebSocket(_ text: String) -> Bool {
        text.components(separatedBy: "\r\n").dropFirst().prefix { !$0.isEmpty }.contains { line in
            guard let colon = line.firstIndex(of: ":") else {
                return false
            }
            return line[..<colon].trimmingCharacters(in: .whitespaces).lowercased() == "upgrade"
                && line[line.index(after: colon)...].lowercased().contains("websocket")
        }
    }

    /// The protocol tokens of the message's `Upgrade` headers, lower-cased
    /// (`Upgrade: h2c` → `["h2c"]`).
    static func upgradeTokens(_ text: String) -> [String] {
        text.components(separatedBy: "\r\n").dropFirst().prefix { !$0.isEmpty }.flatMap { line -> [String] in
            guard let colon = line.firstIndex(of: ":"),
                  line[..<colon].trimmingCharacters(in: .whitespaces).lowercased() == "upgrade" else
            {
                return []
            }
            return line[line.index(after: colon)...].split(separator: ",").map {
                $0.trimmingCharacters(in: .whitespaces).lowercased()
            }
        }
    }

    /// An HTTP/1 status line and the few headers that explain a response: what it
    /// is, how long, who served it, and where a redirect points. Read only from the
    /// first 512 bytes; a header cut by that window is not reported. Credentials are
    /// never surfaced — `Set-Cookie` and `WWW-Authenticate` are named only as present.
    private static func httpResponse(
        firstLine: String,
        text: String,
        buf: PacketBuffer,
        into packet: inout DecodedPacket
    ) {
        let parts = firstLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        let version = parts.first.map(String.init) ?? ""
        let code = parts.count > 1 ? String(parts[1]) : ""
        let reason = parts.count > 2 ? String(parts[2]) : ""
        let lineLength = min(firstLine.utf8.count, buf.length)
        var fields: [DecodedField] = [
            ranged("Status", reason.isEmpty ? code : "\(code) \(reason)", in: buf, at: 0, lineLength),
            .init(name: "Version", value: version),
        ]
        let named: [(header: String, label: String)] = [
            ("content-type", "Content-Type"), ("content-length", "Content-Length"),
            ("content-encoding", "Content-Encoding"), ("transfer-encoding", "Transfer-Encoding"),
            ("server", "Server"), ("location", "Location"), ("cache-control", "Cache-Control"),
        ]
        var presentOnly: [String] = []
        // The header block ends at the first empty line; a header past the window is
        // simply not seen.
        let headerLines = text.components(separatedBy: "\r\n").dropFirst().prefix { !$0.isEmpty }.prefix(32)
        for line in headerLines {
            guard let colon = line.firstIndex(of: ":") else {
                continue
            }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            if let match = named.first(where: { $0.header == name }), !value.isEmpty {
                fields.append(.init(name: match.label, value: String(value.prefix(200))))
            } else if name == "set-cookie" || name == "www-authenticate" {
                presentOnly.append(name == "set-cookie" ? "Set-Cookie" : "WWW-Authenticate")
            }
        }
        for header in Set(presentOnly).sorted() {
            fields.append(.init(name: header, value: "present (value not shown)"))
        }
        packet.layers.append(DecodedLayer(
            proto: .http, title: "Hypertext Transfer Protocol", summary: firstLine,
            fields: fields,
            byteRange: span(buf, buf.length)
        ))
    }
}
