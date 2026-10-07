import Foundation

// MARK: - PacketDecoder ServerHello ALPN

extension PacketDecoder {
    /// The protocol a ServerHello selected with the ALPN extension, reading its
    /// extensions after the cipher suite; `nil` when absent or unreadable. TLS 1.3
    /// moves this into the encrypted extensions, so only TLS 1.2 shows it.
    static func serverHelloALPN(_ buf: PacketBuffer, afterCipherAt start: Int, recordEnd: Int) -> String? {
        // compression_method(1), extensions length(2)
        guard let total = try? Int(buf.u16(start + 1)) else {
            return nil
        }
        var offset = start + 3
        let end = min(offset + total, recordEnd, buf.length)
        while offset + 4 <= end {
            guard let type = try? buf.u16(offset), let length = try? Int(buf.u16(offset + 2)) else {
                return nil
            }
            if type == 0x0010, offset + 4 + length <= end,
               // protocol_name_list: length(2), then one name: length(1) + name
               let nameLength = try? Int(buf.u8(offset + 6)), nameLength > 0, offset + 7 + nameLength <= end,
               let name = try? asciiString(buf.bytes(offset + 7, nameLength))
            {
                return name
            }
            offset += 4 + length
        }
        return nil
    }
}
