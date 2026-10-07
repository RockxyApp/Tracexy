import Foundation

// MARK: - Header field text

extension PacketDecoder {
    /// `0x0a1b` — a header value printed as Wireshark prints it.
    static func hex(_ value: some BinaryInteger, digits: Int) -> String {
        let text = String(value, radix: 16)
        return "0x" + String(repeating: "0", count: max(0, digits - text.count)) + text
    }

    /// IPv4's three flag bits: "Don't fragment", "More fragments", or "None".
    static func ipv4FlagsText(_ flagsFragment: UInt16) -> String {
        var names: [String] = []
        if flagsFragment & 0x4000 != 0 {
            names.append("Don't fragment")
        }
        if flagsFragment & 0x2000 != 0 {
            names.append("More fragments")
        }
        return names.isEmpty ? "None" : names.joined(separator: ", ")
    }

    static func tcpFlags(_ flags: UInt8) -> String {
        var parts: [String] = []
        if flags & 0x02 != 0 {
            parts.append("SYN")
        }
        if flags & 0x10 != 0 {
            parts.append("ACK")
        }
        if flags & 0x08 != 0 {
            parts.append("PSH")
        }
        if flags & 0x01 != 0 {
            parts.append("FIN")
        }
        if flags & 0x04 != 0 {
            parts.append("RST")
        }
        return parts.isEmpty ? "·" : parts.joined(separator: ", ")
    }
}
