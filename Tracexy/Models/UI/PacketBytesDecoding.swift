import Foundation

// MARK: - PacketBytesDecoding

/// Show Packet Bytes: Wireshark's "Decode as" step over a run of captured bytes —
/// Base64, gzip, zlib or raw deflate, percent-encoding, quoted-printable, ROT-13 or
/// hex text. Pure and bounded: output is capped so a small compressed payload cannot
/// grow without limit, and a step that does not apply says why instead of guessing.
nonisolated enum PacketBytesDecoding: String, CaseIterable, Identifiable, Sendable {
    case none
    case base64
    case gzip
    case zlib
    case rawDeflate
    case percent
    case quotedPrintable
    case rot13
    case hexText

    // MARK: Internal

    enum Failure: Error, Equatable {
        case notApplicable(String)
        case outputTooLarge(limit: Int)
    }

    /// The most bytes one decode may produce (16 MiB).
    static let outputLimit = 16 * 1_024 * 1_024

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .none: String(localized: "None")
        case .base64: String(localized: "Base64")
        case .gzip: String(localized: "Gzip")
        case .zlib: String(localized: "Zlib (HTTP deflate)")
        case .rawDeflate: String(localized: "Raw Deflate")
        case .percent: String(localized: "Percent-Encoding")
        case .quotedPrintable: String(localized: "Quoted-Printable")
        case .rot13: String(localized: "ROT-13")
        case .hexText: String(localized: "Hex Digits")
        }
    }

    func decode(_ bytes: [UInt8], limit: Int = outputLimit) throws(Failure) -> [UInt8] {
        switch self {
        case .none:
            return bytes
        case .base64:
            let text = lossyUTF8(bytes).filter { !$0.isWhitespace }
            guard let data = Data(base64Encoded: text, options: .ignoreUnknownCharacters) ?? Self.unpadded(text) else {
                throw .notApplicable(String(localized: "These bytes are not Base64."))
            }
            return [UInt8](data)
        case .gzip:
            return try Self.inflate(bytes, mode: .gzip, limit: limit)
        case .zlib:
            return try Self.inflate(bytes, mode: .zlib, limit: limit)
        case .rawDeflate:
            return try Self.inflate(bytes, mode: .rawDeflate, limit: limit)
        case .percent:
            return try Self.percentDecoded(bytes)
        case .quotedPrintable:
            return Self.quotedPrintableDecoded(bytes)
        case .rot13:
            return bytes.map(Self.rot13)
        case .hexText:
            return try Self.hexDecoded(bytes)
        }
    }

    // MARK: Private

    /// Base64 without its trailing `=` padding, which HTTP headers often drop.
    private static func unpadded(_ text: String) -> Data? {
        let padding = (4 - text.count % 4) % 4
        guard padding < 3 else {
            return nil
        }
        return Data(base64Encoded: text + String(repeating: "=", count: padding))
    }

    private static func inflate(_ bytes: [UInt8], mode: ZlibInflateStream.Mode, limit: Int) throws(Failure) -> [UInt8] {
        let stream: ZlibInflateStream
        do {
            stream = try ZlibInflateStream(mode: mode)
        } catch {
            throw .notApplicable(String(localized: "The decompressor could not start."))
        }
        var output: [UInt8] = []
        var chunk = [UInt8](repeating: 0, count: 64 * 1_024)
        var offset = 0
        var stalled = 0
        while true {
            let outcome: ZlibInflateStream.Outcome
            do {
                outcome = try stream.step(input: bytes, offset: offset, available: bytes.count - offset, into: &chunk)
            } catch {
                throw .notApplicable(String(localized: "These bytes are not a complete \(mode.label) stream."))
            }
            offset += outcome.consumed
            output.append(contentsOf: chunk[0 ..< outcome.produced])
            guard output.count <= limit else {
                throw .outputTooLarge(limit: limit)
            }
            if outcome.finished {
                return output
            }
            stalled = outcome.madeProgress ? 0 : stalled + 1
            if stalled > 2 || (offset >= bytes.count && outcome.produced == 0) {
                // A truncated stream: show what inflated, which is what a partial capture holds.
                guard !output.isEmpty else {
                    throw .notApplicable(String(localized: "These bytes are not a complete \(mode.label) stream."))
                }
                return output
            }
        }
    }

    private static func percentDecoded(_ bytes: [UInt8]) throws(Failure) -> [UInt8] {
        var result: [UInt8] = []
        var index = 0
        while index < bytes.count {
            let byte = bytes[index]
            if byte == UInt8(ascii: "%") {
                guard index + 2 < bytes.count, let value = hexPair(bytes[index + 1], bytes[index + 2]) else {
                    throw .notApplicable(String(localized: "A % is not followed by two hex digits."))
                }
                result.append(value)
                index += 3
            } else {
                result.append(byte == UInt8(ascii: "+") ? UInt8(ascii: " ") : byte)
                index += 1
            }
        }
        return result
    }

    private static func quotedPrintableDecoded(_ bytes: [UInt8]) -> [UInt8] {
        var result: [UInt8] = []
        var index = 0
        while index < bytes.count {
            let byte = bytes[index]
            if byte == UInt8(ascii: "="), index + 1 < bytes.count {
                // A soft line break (=CRLF or =LF) joins lines; =XX is a byte.
                if bytes[index + 1] == 0x0A {
                    index += 2
                    continue
                }
                if bytes[index + 1] == 0x0D, index + 2 < bytes.count, bytes[index + 2] == 0x0A {
                    index += 3
                    continue
                }
                if index + 2 < bytes.count, let value = hexPair(bytes[index + 1], bytes[index + 2]) {
                    result.append(value)
                    index += 3
                    continue
                }
            }
            result.append(byte)
            index += 1
        }
        return result
    }

    private static func hexDecoded(_ bytes: [UInt8]) throws(Failure) -> [UInt8] {
        let digits = bytes.filter { !($0 == 0x20 || $0 == 0x0A || $0 == 0x0D || $0 == 0x09 || $0 == UInt8(ascii: ":")) }
        guard digits.count.isMultiple(of: 2) else {
            throw .notApplicable(String(localized: "An odd number of hex digits."))
        }
        var result: [UInt8] = []
        result.reserveCapacity(digits.count / 2)
        for index in stride(from: 0, to: digits.count, by: 2) {
            guard let value = hexPair(digits[index], digits[index + 1]) else {
                throw .notApplicable(String(localized: "These bytes are not hex digits."))
            }
            result.append(value)
        }
        return result
    }

    private static func hexPair(_ high: UInt8, _ low: UInt8) -> UInt8? {
        guard let high = hexValue(high), let low = hexValue(low) else {
            return nil
        }
        return high << 4 | low
    }

    private static func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case UInt8(ascii: "0") ... UInt8(ascii: "9"): byte - UInt8(ascii: "0")
        case UInt8(ascii: "a") ... UInt8(ascii: "f"): byte - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A") ... UInt8(ascii: "F"): byte - UInt8(ascii: "A") + 10
        default: nil
        }
    }

    private static func rot13(_ byte: UInt8) -> UInt8 {
        switch byte {
        case UInt8(ascii: "a") ... UInt8(ascii: "z"): (byte - UInt8(ascii: "a") + 13) % 26 + UInt8(ascii: "a")
        case UInt8(ascii: "A") ... UInt8(ascii: "Z"): (byte - UInt8(ascii: "A") + 13) % 26 + UInt8(ascii: "A")
        default: byte
        }
    }
}

private extension ZlibInflateStream.Mode {
    var label: String {
        switch self {
        case .gzip: "gzip"
        case .zlib: "zlib"
        case .rawDeflate: "deflate"
        }
    }
}

// MARK: - PacketBytesPresentation

/// Show Packet Bytes: Wireshark's "Show as" — how the decoded bytes are drawn.
nonisolated enum PacketBytesPresentation: String, CaseIterable, Identifiable, Sendable {
    case text
    case json
    case hexDump
    case cArray
    case image

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .text: String(localized: "Text (UTF-8)")
        case .json: String(localized: "JSON")
        case .hexDump: String(localized: "Hex Dump")
        case .cArray: String(localized: "C Array")
        case .image: String(localized: "Image")
        }
    }

    /// Whether these bytes parse as JSON, so the view can say when they do not.
    static func isJSON(_ bytes: [UInt8]) -> Bool {
        (try? JSONSerialization.jsonObject(with: Data(bytes), options: [.fragmentsAllowed])) != nil
    }

    /// The text rendering, or `nil` for the image presentation. JSON that does not
    /// parse is shown as text with a note rather than refused.
    func text(for bytes: [UInt8]) -> String? {
        switch self {
        case .text:
            return lossyUTF8(bytes)
        case .json:
            guard let object = try? JSONSerialization.jsonObject(with: Data(bytes), options: [.fragmentsAllowed]),
                  let pretty = try? JSONSerialization.data(
                      withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .fragmentsAllowed]
                  ) else
            {
                return lossyUTF8(bytes)
            }
            return lossyUTF8([UInt8](pretty))
        case .hexDump:
            return PacketBytesFormat.hexDump.text(for: bytes[...])
        case .cArray:
            return PacketBytesFormat.cArray.text(for: bytes[...])
        case .image:
            return nil
        }
    }
}

/// Captured bytes as text, invalid sequences shown as U+FFFD rather than refused —
/// a capture's text is whatever was sent, and hiding it would hide evidence.
private func lossyUTF8(_ bytes: [UInt8]) -> String {
    // swiftlint:disable:next optional_data_string_conversion
    String(decoding: bytes, as: UTF8.self)
}
