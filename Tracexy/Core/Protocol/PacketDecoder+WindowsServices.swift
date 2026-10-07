import Foundation

// MARK: - PacketDecoder Windows-network services

/// SMB (file sharing, TCP 445/139), LLMNR (UDP 5355) and the NetBIOS Name Service
/// (UDP 137): the traffic behind "why can't this Mac reach the NAS or the Windows
/// share". SMB is read to its header only — command, status and ids — never the
/// file names or data it carries.
extension PacketDecoder {
    // MARK: Internal

    /// SMB over TCP 445 or 139, behind its NetBIOS session header.
    static let smbCandidate = ApplicationCandidate(
        matches: { [445, 139].contains($0.sourcePort) || [445, 139].contains($0.destinationPort) },
        decode: { context, packet in
            try smb(context.payload, into: &packet)
            return nil
        }
    )

    static let windowsUDPCandidates: [ApplicationCandidate] = directoryCandidates.prefix(1) + [
        ApplicationCandidate(
            matches: { $0.sourcePort == 5_355 || $0.destinationPort == 5_355 },
            decode: { context, packet in
                try dns(context.payload, into: &packet, tcp: false, kind: .llmnr)
                return nil
            }
        ),
        ApplicationCandidate(
            matches: { ($0.sourcePort == 137 || $0.destinationPort == 137) && $0.payload.length >= 12 },
            decode: { context, packet in
                try nbns(context.payload, into: &packet)
                return nil
            }
        ),
    ]

    /// The DNS-format decoder's layer title for each service that uses it.
    static func dnsTitle(_ kind: ProtocolKind) -> String {
        switch kind {
        case .mdns: "Multicast DNS"
        case .llmnr: "Link-local Multicast Name Resolution"
        default: "Domain Name System"
        }
    }

    /// SMB2/3 (`0xFE 'SMB'`) header: command, status, flags, message, tree and session
    /// ids. SMB1 (`0xFF 'SMB'`) is named with its command byte only.
    static func smb(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        packet.appProtocol = .smb
        // NetBIOS session message: type 0, then a 24-bit length.
        let base = try buf.u8(0) == 0 && buf.length >= 8 ? 4 : 0
        let magic = try buf.bytes(base, 4)
        if magic == [0xFF, 0x53, 0x4D, 0x42] {
            let command = try buf.u8(base + 4)
            packet.layers.append(DecodedLayer(
                proto: .smb, title: "SMB (Server Message Block Protocol)",
                summary: String(format: "SMB1 command 0x%02X", command),
                fields: [ranged("SMB Command", String(format: "0x%02X", command), in: buf, at: base + 4, 1)],
                byteRange: span(buf, buf.length)
            ))
            return
        }
        guard magic == [0xFE, 0x53, 0x4D, 0x42] else {
            packet.layers.append(DecodedLayer(
                proto: .smb, title: "SMB2 (Server Message Block Protocol version 2)",
                summary: "Continuation data, \(buf.length) bytes", fields: [], byteRange: span(buf, buf.length)
            ))
            return
        }
        let status = try buf.u32le(base + 8)
        let command = try buf.u16le(base + 12)
        let flags = try buf.u32le(base + 16)
        let messageID = try le64(buf, base + 24)
        let isResponse = flags & 1 != 0
        let isAsync = flags & 2 != 0
        let name = smbCommandName(command)
        // A request's status bytes are a channel sequence (SMB 3), so, as in Wireshark,
        // only a response names an NT status.
        var fields = isResponse ? [ranged("NT Status", smbStatusText(status), in: buf, at: base + 8, 4)] : []
        fields += [
            ranged("Command", "\(name) (\(command))", in: buf, at: base + 12, 2),
            ranged("Flags", isResponse ? "Response" : "Request", in: buf, at: base + 16, 4),
            ranged("Message ID", "\(messageID)", in: buf, at: base + 24, 8),
        ]
        if !isAsync {
            try fields.append(ranged(
                "Tree ID",
                String(format: "0x%08x", buf.u32le(base + 36)),
                in: buf,
                at: base + 36,
                4
            ))
        }
        try fields.append(ranged(
            "Session ID",
            String(format: "0x%016llx", le64(buf, base + 40)),
            in: buf,
            at: base + 40,
            8
        ))
        var summary = "\(name) \(isResponse ? "Response" : "Request")"
        if isResponse, status != 0 {
            summary += ", Error: \(smbStatusText(status))"
        }
        packet.layers.append(DecodedLayer(
            proto: .smb, title: "SMB2 (Server Message Block Protocol version 2)", summary: summary,
            fields: fields, byteRange: span(buf, buf.length)
        ))
    }

    /// NetBIOS Name Service (RFC 1002): a query or response for one encoded name,
    /// and the IPv4 address a positive response gives it.
    static func nbns(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        let flags = try buf.u16(2)
        let questions = try buf.u16(4)
        let answers = try buf.u16(6)
        let isResponse = flags & 0x8000 != 0
        let opcode = (flags >> 11) & 0x0F
        guard try buf.u8(12) == 32, let bare = try nbnsName(buf.bytes(13, 32)) else {
            return
        }
        // An answer record's name also says which service the suffix stands for.
        let service = try isResponse ? nbnsServiceName(buf.u8(13 + 30) &- 0x41, buf.u8(13 + 31) &- 0x41) : nil
        let name = service.map { "\(bare) (\($0))" } ?? bare
        packet.appProtocol = .nbns
        var fields = [
            ranged("Response", isResponse ? "Response" : "Query", in: buf, at: 2, 2),
            ranged("Opcode", nbnsOpcodeName(opcode), in: buf, at: 2, 2),
            ranged("Name", name, in: buf, at: 12, 34),
        ]
        var summary = "Name \(nbnsOpcodeName(opcode).lowercased()) \(isResponse ? "response" : "query") \(name)"
        // An answer record repeats the name, then type, class, TTL, length and NB flags + address.
        if isResponse, answers > 0, questions == 0, buf.length >= 12 + 34 + 10 + 6,
           try buf.u16(46) == 0x0020, try buf.u16(54) >= 6
        {
            let address = try ipv4Address(buf, 58)
            fields.append(ranged("Addr", address, in: buf, at: 58, 4))
            summary += " \(address)"
        }
        packet.layers.append(DecodedLayer(
            proto: .nbns, title: "NetBIOS Name Service", summary: summary, fields: fields,
            byteRange: span(buf, buf.length)
        ))
    }

    // MARK: Private

    private static func le64(_ buf: PacketBuffer, _ offset: Int) throws -> UInt64 {
        try buf.bytes(offset, 8).reversed().reduce(0) { $0 << 8 | UInt64($1) }
    }

    private static func smbCommandName(_ command: UInt16) -> String {
        let names = [
            "Negotiate Protocol", "Session Setup", "Session Logoff", "Tree Connect", "Tree Disconnect", "Create",
            "Close", "Flush", "Read", "Write", "Lock", "Ioctl", "Cancel", "KeepAlive", "Find", "Notify", "GetInfo",
            "SetInfo", "Break",
        ]
        return Int(command) < names.count ? names[Int(command)] : "Unknown (\(command))"
    }

    private static func smbStatusText(_ status: UInt32) -> String {
        switch status {
        case 0x00000000: "STATUS_SUCCESS"
        case 0x00000103: "STATUS_PENDING"
        case 0x80000006: "STATUS_NO_MORE_FILES"
        case 0xC0000011: "STATUS_END_OF_FILE"
        case 0xC0000016: "STATUS_MORE_PROCESSING_REQUIRED"
        case 0xC0000022: "STATUS_ACCESS_DENIED"
        case 0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND"
        case 0xC000006D: "STATUS_LOGON_FAILURE"
        case 0xC00000CC: "STATUS_BAD_NETWORK_NAME"
        default: String(format: "0x%08x", status)
        }
    }

    /// Wireshark's descriptions of the common NetBIOS name suffixes.
    private static func nbnsServiceName(_ high: UInt8, _ low: UInt8) -> String? {
        switch high << 4 | low {
        case 0x00: "Workstation/Redirector"
        case 0x03: "Messenger service/Main name"
        case 0x1B: "Domain Master Browser"
        case 0x1C: "Domain Controllers"
        case 0x1D: "Local Master Browser"
        case 0x1E: "Browser Election Service"
        case 0x20: "Server service"
        default: nil
        }
    }

    private static func nbnsOpcodeName(_ opcode: UInt16) -> String {
        switch opcode {
        case 0: "Query"
        case 5: "Registration"
        case 6: "Release"
        case 7: "Wait for acknowledgement"
        case 8: "Refresh"
        default: "Opcode \(opcode)"
        }
    }

    /// RFC 1001 first-level encoding: each byte as two letters `A`–`P`; 15 name
    /// characters then a suffix byte, shown as Wireshark shows it: `NAME<20>`.
    private static func nbnsName(_ encoded: [UInt8]) -> String? {
        guard encoded.count == 32, encoded.allSatisfy({ (0x41 ... 0x50).contains($0) }) else {
            return nil
        }
        let bytes = stride(from: 0, to: 32, by: 2).map { (encoded[$0] - 0x41) << 4 | (encoded[$0 + 1] - 0x41) }
        let name = String(bytes: bytes.prefix(15), encoding: .isoLatin1)?.trimmingCharacters(in: .whitespaces) ?? ""
        return name + String(format: "<%02x>", bytes[15])
    }
}
