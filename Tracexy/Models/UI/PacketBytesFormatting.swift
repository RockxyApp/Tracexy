import Foundation

// MARK: - PacketBytesFormat

/// The ways a frame's bytes (or the selected field's bytes) can be copied — the
/// same set Wireshark's Copy ▸ Bytes offers.
nonisolated enum PacketBytesFormat: String, CaseIterable, Identifiable, Sendable {
    case hexDump
    case hexStream
    case printableText
    case cArray
    case escapedString
    case base64

    // MARK: Internal

    var id: String {
        rawValue
    }

    var menuTitle: String {
        switch self {
        case .hexDump: "As Hex Dump"
        case .hexStream: "As Hex Stream"
        case .printableText: "As Printable Text"
        case .cArray: "As C Array"
        case .escapedString: "As Escaped String"
        case .base64: "As Base64"
        }
    }

    func text(for bytes: ArraySlice<UInt8>, startOffset: Int = 0) -> String {
        switch self {
        case .hexDump:
            return stride(from: bytes.startIndex, to: bytes.endIndex, by: 16).map { start in
                let row = bytes[start ..< min(start + 16, bytes.endIndex)]
                let hex = row.enumerated().map { index, byte in
                    (index == 8 ? " " : "") + String(format: "%02x", byte)
                }.joined(separator: " ")
                let padded = hex.padding(toLength: 16 * 3, withPad: " ", startingAt: 0)
                let ascii = String(row.map(Self.printable))
                return String(format: "%04x  ", start - bytes.startIndex + startOffset) + padded + "  " + ascii
            }.joined(separator: "\n")
        case .hexStream:
            return bytes.map { String(format: "%02x", $0) }.joined()
        case .printableText:
            return String(bytes.map(Self.printable))
        case .cArray:
            let rows = stride(from: bytes.startIndex, to: bytes.endIndex, by: 8).map { start in
                "    " + bytes[start ..< min(start + 8, bytes.endIndex)]
                    .map { String(format: "0x%02x", $0) }.joined(separator: ", ")
            }
            return "static const unsigned char bytes[\(bytes.count)] = {\n" + rows.joined(separator: ",\n") + "\n};"
        case .escapedString:
            return bytes.map { String(format: "\\x%02x", $0) }.joined()
        case .base64:
            return Data(bytes).base64EncodedString()
        }
    }

    // MARK: Private

    private static func printable(_ byte: UInt8) -> Character {
        byte >= 0x20 && byte < 0x7F ? Character(UnicodeScalar(byte)) : "."
    }
}

// MARK: - PacketBytesSearch

/// Find in a frame's bytes, as Wireshark's Find Packet by hex value or string: a
/// pattern made only of hex byte pairs (spaces, colons or dashes between them are
/// allowed) is a byte sequence; anything else is ASCII text, matched without case.
nonisolated enum PacketBytesSearch {
    // MARK: Internal

    /// At most this many matches are highlighted; the count says when there are more.
    static let maximumMatches = 256

    /// The byte pattern a query stands for, or `nil` for an empty query.
    static func pattern(for query: String) -> (bytes: [UInt8], isHex: Bool)? {
        let trimmed = query.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else {
            return nil
        }
        let compact = trimmed.filter { !" :-".contains($0) }
        if compact.count >= 2, compact.count.isMultiple(of: 2), compact.allSatisfy(\.isHexDigit) {
            var bytes: [UInt8] = []
            var index = compact.startIndex
            while index < compact.endIndex {
                let next = compact.index(index, offsetBy: 2)
                bytes.append(UInt8(compact[index ..< next], radix: 16) ?? 0)
                index = next
            }
            return (bytes, true)
        }
        return (Array(trimmed.utf8), false)
    }

    /// Non-overlapping matches, first-to-last, and whether more existed than kept.
    static func matches(_ query: String, in bytes: [UInt8]) -> (ranges: [Range<Int>], truncated: Bool) {
        guard let (pattern, isHex) = pattern(for: query), pattern.count <= bytes.count else {
            return ([], false)
        }
        let folded = isHex ? bytes : bytes.map(Self.lower)
        let needle = isHex ? pattern : pattern.map(Self.lower)
        var ranges: [Range<Int>] = []
        var index = 0
        while index + needle.count <= folded.count {
            if folded[index] == needle[0], Array(folded[index ..< index + needle.count]) == needle {
                guard ranges.count < maximumMatches else {
                    return (ranges, true)
                }
                ranges.append(index ..< index + needle.count)
                index += needle.count
            } else {
                index += 1
            }
        }
        return (ranges, false)
    }

    // MARK: Private

    private static func lower(_ byte: UInt8) -> UInt8 {
        (0x41 ... 0x5A).contains(byte) ? byte + 0x20 : byte
    }
}
