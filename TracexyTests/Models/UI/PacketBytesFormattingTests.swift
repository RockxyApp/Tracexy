import Foundation
import Testing
@testable import Tracexy

/// Find in a frame's bytes (hex or text) and Copy Bytes in Wireshark's
/// formats, for the whole frame or the selected field.
struct PacketBytesFormattingTests {
    // MARK: Internal

    @Test
    func hexAndTextPatterns() {
        #expect(PacketBytesSearch.pattern(for: "16 03 01")?.bytes == [0x16, 0x03, 0x01])
        #expect(PacketBytesSearch.pattern(for: "16:03:01")?.isHex == true)
        #expect(PacketBytesSearch.pattern(for: "host")?.isHex == false)
        #expect(PacketBytesSearch.pattern(for: "  ") == nil)
        // An odd number of hex digits is text, not a byte sequence.
        #expect(PacketBytesSearch.pattern(for: "abc")?.isHex == false)
        #expect(PacketBytesSearch.matches("16 03 01", in: bytes).ranges == [25 ..< 28])
        #expect(PacketBytesSearch.matches("HOST", in: bytes).ranges == [16 ..< 20])
        #expect(PacketBytesSearch.matches("zzz", in: bytes).ranges.isEmpty)
        let many = PacketBytesSearch.matches("00", in: [UInt8](repeating: 0, count: 1_000))
        #expect(many.ranges.count == PacketBytesSearch.maximumMatches)
        #expect(many.truncated)
    }

    @Test
    func copyFormats() {
        let slice = bytes[25 ..< 29]
        #expect(PacketBytesFormat.hexStream.text(for: slice) == "16030100")
        #expect(PacketBytesFormat.escapedString.text(for: slice) == "\\x16\\x03\\x01\\x00")
        #expect(PacketBytesFormat.base64.text(for: slice) == Data(slice).base64EncodedString())
        #expect(PacketBytesFormat.printableText.text(for: bytes[0 ..< 3]) == "GET")
        #expect(PacketBytesFormat.cArray.text(for: slice)
            == "static const unsigned char bytes[4] = {\n    0x16, 0x03, 0x01, 0x00\n};")
        let dump = PacketBytesFormat.hexDump.text(for: bytes[16 ..< 29], startOffset: 16)
        #expect(dump.hasPrefix("0010  48 6f 73 74"))
        #expect(dump.hasSuffix("Host: a......"))
    }

    // MARK: Private

    private let bytes: [UInt8] = Array("GET / HTTP/1.1\r\nHost: a\r\n".utf8) + [0x16, 0x03, 0x01, 0x00]
}
