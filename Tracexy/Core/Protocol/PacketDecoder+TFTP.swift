import Foundation

// MARK: - PacketDecoder TFTP

/// TFTP (RFC 1350, options RFC 2347–2349) on UDP 69: the opcode and what it carries —
/// a read or write request's file name, mode and options, a data or acknowledgement
/// block number, an error code and message, or an option acknowledgement. A transfer
/// continues on ports the two sides pick, which only Decode As names TFTP.
extension PacketDecoder {
    // MARK: Internal

    static let tftpCandidate = ApplicationCandidate(
        matches: { ($0.sourcePort == 69 || $0.destinationPort == 69) && isTFTP($0.payload) },
        decode: { context, packet in
            try tftp(context.payload, into: &packet)
            return nil
        }
    )

    static func tftp(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        let opcode = try buf.u16(0)
        var fields = [ranged("Opcode", "\(tftpOpcodeName(opcode)) (\(opcode))", in: buf, at: 0, 2)]
        var summary = tftpOpcodeName(opcode)
        switch opcode {
        case 1,
             2:
            let strings = nulTerminated(buf, from: 2)
            if let file = strings.first {
                fields.append(ranged(
                    opcode == 1 ? "Source File" : "Destination File", file.text, in: buf, at: file.offset, file.length
                ))
                summary += ", File: \(file.text)"
            }
            if strings.count > 1 {
                let mode = strings[1]
                fields.append(ranged("Type", mode.text, in: buf, at: mode.offset, mode.length))
                summary += ", Transfer type: \(mode.text)"
            }
            fields += options(strings.dropFirst(2), in: buf)
        case 3,
             4:
            let block = try buf.u16(2)
            fields.append(ranged("Block", "\(block)", in: buf, at: 2, 2))
            summary += ", Block: \(block)"
            if opcode == 3 {
                fields.append(ranged("Data", "\(buf.length - 4) bytes", in: buf, at: 4, buf.length - 4))
            }
        case 5:
            let code = try buf.u16(2)
            fields.append(ranged("Error code", "\(tftpErrorName(code)) (\(code))", in: buf, at: 2, 2))
            summary += ", Code: \(tftpErrorName(code))"
            if let message = nulTerminated(buf, from: 4).first {
                fields.append(ranged("Error message", message.text, in: buf, at: message.offset, message.length))
                summary += ", Message: \(message.text)"
            }
        case 6:
            fields += options(nulTerminated(buf, from: 2)[...], in: buf)
        default:
            break
        }
        packet.appProtocol = .tftp
        packet.layers.append(DecodedLayer(
            proto: .tftp, title: "Trivial File Transfer Protocol", summary: summary, fields: fields,
            byteRange: span(buf, buf.length)
        ))
    }

    /// Opcodes 1–6, with a request's file name ended by NUL.
    static func isTFTP(_ buf: PacketBuffer) -> Bool {
        guard buf.length >= 4, let opcode = try? buf.u16(0), (1 ... 6).contains(opcode) else {
            return false
        }
        if opcode == 1 || opcode == 2 {
            return (try? buf.bytes(2, buf.length - 2))?.contains(0) == true
        }
        return true
    }

    // MARK: Private

    /// The NUL-ended strings from `start`: each one's text, offset and length.
    private static func nulTerminated(
        _ buf: PacketBuffer,
        from start: Int
    )
        -> [(text: String, offset: Int, length: Int)]
    {
        guard start < buf.length, let bytes = try? buf.bytes(start, buf.length - start) else {
            return []
        }
        var strings: [(String, Int, Int)] = []
        var offset = 0
        while offset < bytes.count, let end = bytes[offset...].firstIndex(of: 0) {
            strings.append((asciiString(Array(bytes[offset ..< end])), start + offset, end - offset))
            offset = end + 1
        }
        return strings
    }

    /// Option name and value pairs, as `blksize: 1428`.
    private static func options(
        _ strings: ArraySlice<(text: String, offset: Int, length: Int)>,
        in buf: PacketBuffer
    )
        -> [DecodedField]
    {
        let list = Array(strings)
        return stride(from: 0, to: list.count - 1, by: 2).map { index in
            let name = list[index]
            let value = list[index + 1]
            return ranged(
                "Option", "\(name.text): \(value.text)", in: buf, at: name.offset,
                value.offset + value.length - name.offset
            )
        }
    }

    private static func tftpOpcodeName(_ opcode: UInt16) -> String {
        switch opcode {
        case 1: "Read Request"
        case 2: "Write Request"
        case 3: "Data Packet"
        case 4: "Acknowledgement"
        case 5: "Error Code"
        case 6: "Option Acknowledgement"
        default: "Unknown"
        }
    }

    private static func tftpErrorName(_ code: UInt16) -> String {
        switch code {
        case 0: "Not defined"
        case 1: "File not found"
        case 2: "Access violation"
        case 3: "Disk full or allocation exceeded"
        case 4: "Illegal TFTP Operation"
        case 5: "Unknown transfer ID"
        case 6: "File already exists"
        case 7: "No such user"
        case 8: "Option negotiation failed"
        default: "Unknown"
        }
    }
}
