import Foundation
import Testing
@testable import Tracexy

@Suite("Wireshark coloring rule import")
struct WiresharkColorRuleImporterTests {
    @Test
    func importsSupportedJSONCInOrderAndReportsUnsupportedFilters() throws {
        let source = #"""
        // Comments and trailing commas occur in JSONC profiles.
        [
          { "Reset // Web": { "filter": "tcp.flags.reset", "foreground": "#ffffff", "background": "7f1d1d", "enabled": true, }, },
          { "Disabled ACK": { "filter": "tcp.flags.ack", "foreground": "000000", "background": "fef08a", "enabled": false } },
          { "Unsupported DNS": { "filter": "dns.qry.name == example.test", "foreground": "ffffff", "background": "7f1d1d", "enabled": false } },
        ]
        """#
        let result = try WiresharkColorRuleImporter.parse(Data(source.utf8))
        #expect(result.sourceRuleCount == 3)
        #expect(result.rules.map(\.name) == ["Reset // Web", "Disabled ACK"])
        #expect(result.rules[0].expression == "tcp.flags.reset")
        #expect(result.rules[0].foregroundRGB == 0xFFFFFF)
        #expect(result.rules[0].backgroundRGB == 0x7F1D1D)
        #expect(result.rules[0].isEnabled)
        #expect(!result.rules[1].isEnabled)
        #expect(result.skipped.count == 1)
        #expect(result.skipped[0].contains("Unsupported DNS"))
        #expect(result.skipped[0].contains("position"))
    }

    @Test
    func importsLegacyColorFiltersAndKeepsRuleOrder() throws {
        let source = """
        # Wireshark legacy colorfilters
        @SYN@tcp.flags.syn@[32768,0,0][65535,65535,65535]
        @RST@tcp.flags.reset@[32768,0,0][65535,65535,65535]
        """
        let result = try WiresharkColorRuleImporter.parse(Data(source.utf8))
        #expect(result.sourceRuleCount == 2)
        #expect(result.rules.map(\.name) == ["SYN", "RST"])
        #expect(result.rules.map(\.expression) == ["tcp.flags.syn", "tcp.flags.reset"])
        #expect(result.rules[0].backgroundRGB == 0x800000)
        #expect(result.rules[0].foregroundRGB == 0xFFFFFF)
        #expect(result.skipped.isEmpty)
    }

    @Test
    func boundsFileAndRuleCountsAndRejectsMalformedRoots() throws {
        #expect(throws: WiresharkColorRuleImportError.fileTooLarge) {
            try WiresharkColorRuleImporter.parse(Data(
                repeating: 32,
                count: WiresharkColorRuleImporter.maximumFileBytes + 1
            ))
        }
        for malformedRoot in [
            "{\"not\":\"an array\"}",
            "{}",
            "\u{FEFF}  {\"not\":\"an array\"}",
            "/* JSONC comment */ {\"not\":\"an array\"}",
            "{broken JSON",
        ] {
            #expect(throws: WiresharkColorRuleImportError.malformedFile) {
                try WiresharkColorRuleImporter.parse(Data(malformedRoot.utf8))
            }
        }
        let tooMany = "[" + Array(repeating: "{}", count: WiresharkColorRuleImporter.maximumSourceRules + 1)
            .joined(separator: ",") + "]"
        #expect(throws: WiresharkColorRuleImportError.tooManyRules) {
            try WiresharkColorRuleImporter.parse(Data(tooMany.utf8))
        }
        #expect(throws: WiresharkColorRuleImportError.malformedFile) {
            try WiresharkColorRuleImporter.parse(Data("# only a comment".utf8))
        }
    }

    @Test
    func reportsMalformedLegacyLinesAlongsideRecognizedRules() throws {
        let source = """
        # Wireshark legacy colorfilters
        invalid legacy line
        @SYN@tcp.flags.syn@[32768,0,0][65535,65535,65535]
        """
        let result = try WiresharkColorRuleImporter.parse(Data(source.utf8))
        #expect(result.sourceRuleCount == 2)
        #expect(result.rules.map(\.name) == ["SYN"])
        #expect(result.skipped == ["Line 2: invalid legacy rule syntax."])
    }

    @Test
    func skipsMalformedColorsAndContrastFailuresWithoutDiscardingGoodRules() throws {
        let source = #"""
        [
          { "Good": { "filter": "tcp.flags.syn", "foreground": "ffffff", "background": "7f1d1d", "enabled": true } },
          { "Bad color": { "filter": "tcp.flags.syn", "foreground": "white", "background": "7f1d1d", "enabled": true } },
          { "Low contrast": { "filter": "tcp.flags.syn", "foreground": "aaaaaa", "background": "bbbbbb", "enabled": true } },
        ]
        """#
        let result = try WiresharkColorRuleImporter.parse(Data(source.utf8))
        #expect(result.rules.map(\.name) == ["Good"])
        #expect(result.skipped.count == 2)
        #expect(result.skipped[0].contains("Bad color"))
        #expect(result.skipped[0].contains("foreground color"))
        #expect(result.skipped[1].contains("Low contrast"))
        #expect(result.skipped[1].contains("4.5:1"))
    }
}
