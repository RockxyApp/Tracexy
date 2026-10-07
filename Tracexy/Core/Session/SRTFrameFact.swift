import Foundation

// MARK: - SRTFrameFact

/// What Statistics ▸ Service Response Time reads from a frame: an SMB2 header, an
/// LDAP message or a Kerberos message type — enough to pair each reply with its
/// request inside the frame's session, as Wireshark's SRT taps do.
nonisolated enum SRTFrameFact: Hashable, Sendable {
    /// An SMB2 header. An asynchronous STATUS_PENDING reply is an interim answer.
    case smb2(messageID: UInt64, command: Int, isResponse: Bool, isInterim: Bool)
    /// An LDAP message and its protocolOp choice.
    case ldap(messageID: Int, operation: Int)
    /// A Kerberos message type (10 AS-REQ, 11 AS-REP, 12 TGS-REQ, 13 TGS-REP, 30 KRB-ERROR).
    case kerberos(type: Int)
    /// An ICMP or ICMPv6 echo request or reply, keyed as Wireshark pairs them: the
    /// identifier, the sequence number and the checksum the reply carries.
    case echo(isV6: Bool, isRequest: Bool, key: UInt64)

    // MARK: Lifecycle

    init?(_ packet: DecodedPacket, bytes: [UInt8] = []) {
        if let echo = Self.echo(packet, bytes: bytes) {
            self = echo
            return
        }
        guard let layer = packet.layers.last(where: { [.smb, .ldap, .kerberos].contains($0.proto) }) else {
            return nil
        }
        func field(_ name: String) -> String? {
            layer.fields.first { $0.name == name }?.value
        }
        switch layer.proto {
        case .smb:
            guard let command = field("Command").flatMap(Self.code), let flags = field("Flags"),
                  let messageID = field("Message ID").flatMap({ UInt64($0) }) else
            {
                return nil
            }
            let isResponse = flags == "Response"
            // An asynchronous header has no Tree ID.
            let isInterim = isResponse && field("Tree ID") == nil && field("NT Status") == "STATUS_PENDING"
            self = .smb2(messageID: messageID, command: command, isResponse: isResponse, isInterim: isInterim)
        case .ldap:
            guard let messageID = field("messageID").flatMap({ Int($0) }),
                  let operation = field("protocolOp").flatMap(Self.code) else
            {
                return nil
            }
            self = .ldap(messageID: messageID, operation: operation)
        default:
            guard let type = field("msg-type").flatMap(Self.code) else {
                return nil
            }
            self = .kerberos(type: type)
        }
    }

    // MARK: Private

    /// An echo request or reply, read from the ICMP header's bytes. A request's key
    /// holds the checksum its reply should carry — the type byte differs by 8 (IPv4)
    /// or 1 (IPv6) — so a reply that echoes the data pairs with it.
    private static func echo(_ packet: DecodedPacket, bytes: [UInt8]) -> Self? {
        guard let layer = packet.layers.last(where: { $0.proto == .icmp || $0.proto == .icmpv6 }),
              let start = layer.byteRange?.lowerBound, start + 8 <= bytes.count else
        {
            return nil
        }
        let isV6 = layer.proto == .icmpv6
        let type = bytes[start]
        let request: UInt8 = isV6 ? 128 : 8
        let reply: UInt8 = isV6 ? 129 : 0
        guard type == request || type == reply else {
            return nil
        }
        let checksum = UInt16(bytes[start + 2]) << 8 | UInt16(bytes[start + 3])
        let isRequest = type == request
        // IPv4 keys on the reply's checksum; IPv6 on the request's.
        let keyed: UInt16 = switch (isV6, isRequest) {
        case (false, true): onesComplementSum(checksum, 0x0800)
        case (true, false): onesComplementSum(checksum, 0x0100)
        default: checksum
        }
        let identifier = UInt64(bytes[start + 4]) << 8 | UInt64(bytes[start + 5])
        let sequence = UInt64(bytes[start + 6]) << 8 | UInt64(bytes[start + 7])
        let normalized = UInt64(keyed == 0xFFFF ? 0 : keyed)
        return .echo(isV6: isV6, isRequest: isRequest, key: identifier << 32 | sequence << 16 | normalized)
    }

    private static func onesComplementSum(_ lhs: UInt16, _ rhs: UInt16) -> UInt16 {
        let sum = UInt32(lhs) + UInt32(rhs)
        return UInt16(truncatingIfNeeded: (sum & 0xFFFF) + (sum >> 16))
    }

    /// The number in a trailing "(n)", as the decoders write codes.
    private static func code(_ text: String) -> Int? {
        guard text.hasSuffix(")"), let open = text.lastIndex(of: "(") else {
            return nil
        }
        return Int(text[text.index(after: open) ..< text.index(before: text.endIndex)])
    }
}
