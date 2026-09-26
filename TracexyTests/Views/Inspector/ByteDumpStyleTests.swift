import Foundation
import Testing
@testable import Tracexy

/// The bytes pane shows bytes as bits, 8 a row, as Wireshark's
/// "…as Bits"; pointing and clicking still land on the right byte.
@MainActor
struct ByteDumpStyleTests {
    @Test
    func bitsRowsMapCharactersToBytes() {
        // `0000   ` then eight 9-character cells, one space, eight ASCII characters.
        #expect(HexDumpView.column(atCharacter: 6, style: .bits) == nil)
        #expect(HexDumpView.column(atCharacter: 7, style: .bits) == 0)
        #expect(HexDumpView.column(atCharacter: 15, style: .bits) == 0)
        #expect(HexDumpView.column(atCharacter: 16, style: .bits) == 1)
        #expect(HexDumpView.column(atCharacter: 78, style: .bits) == 7)
        #expect(HexDumpView.column(atCharacter: 79, style: .bits) == nil)
        #expect(HexDumpView.column(atCharacter: 80, style: .bits) == 0)
        #expect(HexDumpView.column(atCharacter: 87, style: .bits) == 7)
        #expect(HexDumpView.column(atCharacter: 88, style: .bits) == nil)
        // Hexadecimal is unchanged.
        #expect(HexDumpView.column(atCharacter: 58) == 0)
        #expect(ByteDumpStyle.bits.bytesPerRow == 8)
    }

    @Test
    func bitsReadMostSignificantFirst() {
        #expect(HexDumpView.bits(0x45) == "01000101")
        #expect(HexDumpView.bits(0x00) == "00000000")
        #expect(HexDumpView.bits(0xFF) == "11111111")
        #expect(HexDumpView.bits(0x80) == "10000000")
    }

    @Test
    func theChoiceIsKeptPerProject() throws {
        let suite = "byte-dump-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let options = PacketDetailOptions()
        options.bind(to: defaults)
        #expect(options.byteDumpStyle == .hex)
        options.byteDumpStyle = .bits
        let reloaded = PacketDetailOptions()
        reloaded.bind(to: defaults)
        #expect(reloaded.byteDumpStyle == .bits)
    }
}
