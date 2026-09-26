import Foundation

// MARK: - PacketDecoder directory services

/// Kerberos (UDP/TCP 88) and LDAP (TCP 389, 3268): the sign-in and directory traffic
/// of a Mac bound to a domain. Read with a small BER walker to the message type, the
/// LDAP operation and message id, and the error or result code a reply carries —
/// never a principal name, a bind DN or a credential.
extension PacketDecoder {
    // MARK: Internal

    static let directoryCandidates: [ApplicationCandidate] = [
        ApplicationCandidate(
            matches: { $0.sourcePort == 88 || $0.destinationPort == 88 },
            decode: { context, packet in
                try kerberos(context.payload, into: &packet)
                return nil
            }
        ),
        ApplicationCandidate(
            matches: { [389, 3_268].contains($0.sourcePort) || [389, 3_268].contains($0.destinationPort) },
            decode: { context, packet in
                try ldap(context.payload, into: &packet)
                return nil
            }
        ),
    ]

    /// A Kerberos message: its application tag names the type; a KRB-ERROR also
    /// gives its error code and realm. Over TCP a 4-byte record mark comes first.
    static func kerberos(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        var offset = 0
        if try buf.u8(0) & 0xE0 != 0x60 {
            offset = 4
        }
        let outer = try ber(buf, offset)
        let type = Int(outer.tag & 0x1F)
        guard outer.tag & 0xE0 == 0x60, let name = kerberosTypeName(type) else {
            return
        }
        packet.appProtocol = .kerberos
        var fields = [ranged("msg-type", "\(name) (\(type))", in: buf, at: offset, outer.valueOffset - offset)]
        var summary = name
        if type == 30 {
            let sequence = try ber(buf, outer.valueOffset)
            var cursor = sequence.valueOffset
            while cursor < min(buf.length, sequence.valueOffset + sequence.length) {
                let element = try ber(buf, cursor)
                let inner = try ber(buf, element.valueOffset)
                switch element.tag {
                case 0xA6:
                    let code = try berInteger(buf, inner)
                    let text = kerberosErrorName(code).map { "\($0) (\(code))" } ?? "\(code)"
                    fields.append(ranged("error-code", text, in: buf, at: inner.valueOffset, inner.length))
                    summary += ": \(kerberosErrorName(code) ?? "\(code)")"
                case 0xA9:
                    let realm = try String(bytes: buf.bytes(inner.valueOffset, inner.length), encoding: .ascii) ?? ""
                    fields.append(ranged("realm", realm, in: buf, at: inner.valueOffset, inner.length))
                default:
                    break
                }
                cursor = element.valueOffset + element.length
            }
        }
        packet.layers.append(DecodedLayer(
            proto: .kerberos, title: "Kerberos", summary: summary, fields: fields, byteRange: span(buf, buf.length)
        ))
    }

    /// The first LDAP message of a segment: message id, operation and — for a reply —
    /// its result code. Bind names and credentials are not read.
    static func ldap(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        let message = try ber(buf, 0)
        guard message.tag == 0x30 else {
            return
        }
        let identifier = try ber(buf, message.valueOffset)
        guard identifier.tag == 0x02 else {
            return
        }
        let messageID = try berInteger(buf, identifier)
        let operation = try ber(buf, identifier.valueOffset + identifier.length)
        let choice = Int(operation.tag & 0x1F)
        guard operation.tag & 0xC0 == 0x40, let name = ldapOperationName(choice) else {
            return
        }
        packet.appProtocol = .ldap
        var fields = [
            ranged("messageID", "\(messageID)", in: buf, at: identifier.valueOffset, identifier.length),
            ranged("protocolOp", "\(name) (\(choice))", in: buf, at: operation.valueOffset - 2, 1),
        ]
        var summary = name
        if [1, 5, 7, 9, 11, 13, 15, 24].contains(choice), operation.tag & 0x20 != 0 {
            let result = try ber(buf, operation.valueOffset)
            if result.tag == 0x0A {
                let code = try berInteger(buf, result)
                let text = ldapResultName(code) ?? "\(code)"
                fields.append(ranged("resultCode", "\(text) (\(code))", in: buf, at: result.valueOffset, result.length))
                summary += " \(text)"
            }
        }
        packet.layers.append(DecodedLayer(
            proto: .ldap, title: "Lightweight Directory Access Protocol", summary: "\(summary) (message \(messageID))",
            fields: fields, byteRange: span(buf, buf.length)
        ))
    }

    // MARK: Private

    private struct BERElement {
        let tag: UInt8
        let length: Int
        let valueOffset: Int
    }

    /// One BER tag-length header (single-byte tags; short or long-form lengths up to 4 bytes).
    private static func ber(_ buf: PacketBuffer, _ offset: Int) throws -> BERElement {
        let tag = try buf.u8(offset)
        let first = try buf.u8(offset + 1)
        guard first & 0x80 != 0 else {
            return BERElement(tag: tag, length: Int(first), valueOffset: offset + 2)
        }
        let count = Int(first & 0x7F)
        guard (1 ... 4).contains(count) else {
            throw PacketError.malformed("BER length")
        }
        let length = try buf.bytes(offset + 2, count).reduce(0) { $0 << 8 | Int($1) }
        return BERElement(tag: tag, length: length, valueOffset: offset + 2 + count)
    }

    private static func berInteger(_ buf: PacketBuffer, _ element: BERElement) throws -> Int {
        guard (1 ... 8).contains(element.length) else {
            throw PacketError.malformed("BER integer")
        }
        let bytes = try buf.bytes(element.valueOffset, element.length)
        let magnitude = bytes.reduce(0) { $0 << 8 | Int($1) }
        return bytes[0] & 0x80 != 0 ? magnitude - (1 << (8 * element.length)) : magnitude
    }

    private static func kerberosTypeName(_ type: Int) -> String? {
        switch type {
        case 10: "AS-REQ"
        case 11: "AS-REP"
        case 12: "TGS-REQ"
        case 13: "TGS-REP"
        case 14: "AP-REQ"
        case 15: "AP-REP"
        case 30: "KRB-ERROR"
        default: nil
        }
    }

    private static func kerberosErrorName(_ code: Int) -> String? {
        switch code {
        case 6: "KDC_ERR_C_PRINCIPAL_UNKNOWN"
        case 7: "KDC_ERR_S_PRINCIPAL_UNKNOWN"
        case 18: "KDC_ERR_CLIENT_REVOKED"
        case 23: "KDC_ERR_KEY_EXPIRED"
        case 24: "KDC_ERR_PREAUTH_FAILED"
        case 25: "KDC_ERR_PREAUTH_REQUIRED"
        case 31: "KRB_AP_ERR_BAD_INTEGRITY"
        case 32: "KRB_AP_ERR_TKT_EXPIRED"
        case 37: "KRB_AP_ERR_SKEW"
        case 68: "KDC_ERR_WRONG_REALM"
        default: nil
        }
    }

    private static func ldapOperationName(_ choice: Int) -> String? {
        let names = [
            0: "bindRequest", 1: "bindResponse", 2: "unbindRequest", 3: "searchRequest", 4: "searchResEntry",
            5: "searchResDone", 6: "modifyRequest", 7: "modifyResponse", 8: "addRequest", 9: "addResponse",
            10: "delRequest", 11: "delResponse", 12: "modDNRequest", 13: "modDNResponse", 14: "compareRequest",
            15: "compareResponse", 16: "abandonRequest", 19: "searchResRef", 23: "extendedReq", 24: "extendedResp",
        ]
        return names[choice]
    }

    private static func ldapResultName(_ code: Int) -> String? {
        switch code {
        case 0: "success"
        case 1: "operationsError"
        case 8: "strongerAuthRequired"
        case 32: "noSuchObject"
        case 49: "invalidCredentials"
        case 50: "insufficientAccessRights"
        case 51: "busy"
        case 52: "unavailable"
        case 53: "unwillingToPerform"
        default: nil
        }
    }
}
