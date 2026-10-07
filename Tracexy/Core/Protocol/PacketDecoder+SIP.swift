import Foundation

// MARK: - SIPMessageFacts

/// What Statistics ▸ SIP reads from one SIP message: the start line and the dialog
/// headers that tie messages into transactions.
nonisolated struct SIPMessageFacts: Hashable, Sendable {
    /// `INVITE`, `ACK`, … for a request; `nil` for a response.
    let method: String?
    /// The status code of a response; `nil` for a request.
    let statusCode: Int?
    let reason: String?
    let callID: String?
    let cseqNumber: UInt32?
    let cseqMethod: String?
    /// The From and To addresses (the URI, without display name or tags).
    var from: String?
    var to: String?

    /// `sip:alice@example.test` from `"Alice" <sip:alice@example.test>;tag=a1`.
    static func address(_ header: String?) -> String? {
        guard let header, !header.isEmpty else {
            return nil
        }
        if let open = header.firstIndex(of: "<"), let close = header[open...].firstIndex(of: ">") {
            return String(header[header.index(after: open) ..< close])
        }
        return header.split(separator: ";").first.map { $0.trimmingCharacters(in: .whitespaces) }
    }
}

// MARK: - PacketDecoder + SIP

/// SIP (RFC 3261): the start line and the Call-ID, From, To and CSeq headers
/// (compact forms `i`, `f`, `t` too). Credentials in Authorization headers are
/// never read.
extension PacketDecoder {
    // MARK: Internal

    static func isSIP(_ buf: PacketBuffer) -> Bool {
        guard let head = try? buf.bytes(0, min(buf.length, 256)),
              let end = head.firstIndex(where: { $0 == 0x0D || $0 == 0x0A }),
              let line = String(bytes: head[..<end], encoding: .ascii) else
        {
            return false
        }
        return line.hasPrefix("SIP/2.0 ") || line.hasSuffix(" SIP/2.0")
    }

    static func sip(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        packet.appProtocol = .sip
        let bytes = try buf.bytes(0, min(buf.length, 4_096))
        var lines: [(text: String, offset: Int)] = []
        var start = 0
        for (index, byte) in bytes.enumerated() where byte == 0x0A {
            let end = index > start && bytes[index - 1] == 0x0D ? index - 1 : index
            let text = String(bytes: bytes[start ..< end], encoding: .utf8) ?? ""
            if text.isEmpty {
                break
            }
            lines.append((text, start))
            start = index + 1
        }
        guard let first = lines.first else {
            return
        }
        var fields: [DecodedField] = []
        var method: String?
        var statusCode: Int?
        var reason: String?
        var summary: String
        let words = first.text.split(separator: " ", maxSplits: 2).map(String.init)
        if first.text.hasPrefix("SIP/2.0 "), words.count >= 2, let code = Int(words[1]) {
            statusCode = code
            reason = words.count > 2 ? words[2] : nil
            fields.append(ranged("Status-Code", words[1], in: buf, at: first.offset + 8, words[1].count))
            if let reason {
                fields.append(ranged(
                    "Reason Phrase",
                    reason,
                    in: buf,
                    at: first.offset + 9 + words[1].count,
                    reason.utf8.count
                ))
            }
            summary = "Status: \(words.dropFirst().joined(separator: " "))"
        } else {
            method = words.first
            fields.append(ranged("Method", words[0], in: buf, at: first.offset, words[0].utf8.count))
            if words.count > 1 {
                fields.append(ranged(
                    "Request-URI",
                    words[1],
                    in: buf,
                    at: first.offset + words[0].utf8.count + 1,
                    words[1].utf8.count
                ))
            }
            summary = "Request: \(words.prefix(2).joined(separator: " "))"
        }
        var headers: [String: String] = [:]
        let names = [
            "call-id": "Call-ID",
            "i": "Call-ID",
            "from": "From",
            "f": "From",
            "to": "To",
            "t": "To",
            "cseq": "CSeq"
        ]
        for line in lines.dropFirst() {
            guard let colon = line.text.firstIndex(of: ":") else {
                continue
            }
            let raw = line.text[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            guard let name = names[raw], headers[name] == nil else {
                continue
            }
            let value = line.text[line.text.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            headers[name] = value
            fields.append(ranged(name, value, in: buf, at: line.offset, line.text.utf8.count))
        }
        let cseq = headers["CSeq"]?.split(separator: " ").map(String.init)
        packet.sip = SIPMessageFacts(
            method: method, statusCode: statusCode, reason: reason, callID: headers["Call-ID"],
            cseqNumber: cseq?.first.flatMap { UInt32($0) }, cseqMethod: cseq.flatMap { $0.count > 1 ? $0[1] : nil },
            from: SIPMessageFacts.address(headers["From"]), to: SIPMessageFacts.address(headers["To"])
        )
        packet.layers.append(DecodedLayer(
            proto: .sip, title: "Session Initiation Protocol", summary: summary, fields: fields,
            byteRange: span(buf, buf.length)
        ))
    }
}
