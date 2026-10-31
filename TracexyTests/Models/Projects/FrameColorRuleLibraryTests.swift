import Foundation
import Testing
@testable import Tracexy

@Suite("Project packet coloring rules")
@MainActor
struct FrameColorRuleLibraryTests {
    // MARK: Internal

    @Test
    func evaluationUsesFirstMatchAndUnknownBlocksLowerPriority() {
        let first = FrameColorRule(
            name: "First",
            expression: "tcp.flags.syn",
            foregroundRGB: 0xFFFFFF,
            backgroundRGB: 0x7F1D1D
        )
        let second = FrameColorRule(
            name: "Second",
            expression: "frame.len >= 0",
            foregroundRGB: 0x000000,
            backgroundRGB: 0xFEF08A
        )
        var packet = DecodedPacket(timestamp: nil, originalLength: 54)
        packet.tcpFacts = TCPSegmentFacts(
            sequenceNumber: 1, acknowledgementNumber: 0, flags: [.syn], windowSize: 4_096,
            headerLength: 20, payloadSequence: 2, payloadLength: 0, options: TCPOptionFacts()
        )
        let matching = row(1, facts: FrameFilterFacts(packet: packet))
        let matched = FrameColorRuleEvaluation.evaluate([first, second], rows: [matching])
        #expect(matched.ruleByOrdinal[1] == first.id)

        packet.tcpFacts = nil
        packet.decodeStop = .cutShort
        let undecidable = row(2, facts: FrameFilterFacts(packet: packet))
        let unknown = FrameColorRuleEvaluation.evaluate([first, second], rows: [undecidable])
        #expect(unknown.ruleByOrdinal[2] == nil)
        #expect(unknown.unknownOrdinals == [2])
    }

    @Test
    func rejectsInvalidExpressionAndInsufficientColorContrast() {
        #expect(!FrameColorRuleLibrary.isValid(FrameColorRule(
            name: "Bad expression", expression: "tcp.flags.syn = 1",
            foregroundRGB: 0xFFFFFF, backgroundRGB: 0x000000
        )))
        #expect(!FrameColorRuleLibrary.isValid(FrameColorRule(
            name: "Low contrast", expression: "tcp.flags.syn",
            foregroundRGB: 0xAAAAAA, backgroundRGB: 0xBBBBBB
        )))
    }

    @Test
    func duplicateCreatesIndependentRuleWithBoundedUniqueNameAndCopiedSettings() throws {
        let original = FrameColorRule(
            name: "SYN", expression: "tcp.flags.syn", foregroundRGB: 0xFFFFFF,
            backgroundRGB: 0x7F1D1D, isEnabled: false
        )
        let existingCopy = FrameColorRule(
            name: "syn copy", expression: "tcp.flags.reset", foregroundRGB: 0xFFFFFF,
            backgroundRGB: 0x000000
        )
        let copy = try #require(FrameColorRuleLibrary.duplicate(original, among: [original, existingCopy]))
        #expect(copy.id != original.id)
        #expect(copy.name == "SYN Copy 2")
        #expect(copy.expression == original.expression)
        #expect(copy.foregroundRGB == original.foregroundRGB)
        #expect(copy.backgroundRGB == original.backgroundRGB)
        #expect(copy.isEnabled == original.isEnabled)

        let longName = String(repeating: "n", count: FrameColorRuleLibrary.maximumNameCharacters)
        let longOriginal = FrameColorRule(
            name: longName, expression: "tcp.flags.syn", foregroundRGB: 0xFFFFFF,
            backgroundRGB: 0x7F1D1D
        )
        let longCopy = try #require(FrameColorRuleLibrary.duplicate(longOriginal, among: [longOriginal]))
        #expect(longCopy.name.count == FrameColorRuleLibrary.maximumNameCharacters)
        #expect(FrameColorRuleLibrary.isValid(longCopy))
        #expect(FrameColorRuleLibrary.duplicate(original, among: Array(repeating: original, count: 32)) == nil)
        #expect(FrameColorRuleLibrary.duplicate(original, among: []) == nil)
    }

    @Test
    func projectBindingAndReplacementAreIsolatedAndBounded() throws {
        let projectA = UUID()
        let projectB = UUID()
        let suiteA = "FrameColorRuleLibraryTests.\(UUID())"
        let suiteB = "FrameColorRuleLibraryTests.\(UUID())"
        let defaultsA = try #require(UserDefaults(suiteName: suiteA))
        let defaultsB = try #require(UserDefaults(suiteName: suiteB))
        defer {
            defaultsA.removePersistentDomain(forName: suiteA)
            defaultsB.removePersistentDomain(forName: suiteB)
        }
        let library = FrameColorRuleLibrary()
        library.bind(projectID: projectA, defaults: defaultsA)
        let rule = FrameColorRule(
            name: "SYN",
            expression: "tcp.flags.syn",
            foregroundRGB: 0xFFFFFF,
            backgroundRGB: 0x7F1D1D
        )
        #expect(library.replaceAll([rule], expectedProjectID: projectB) == false)
        #expect(library.replaceAll([rule], expectedProjectID: projectA))
        let other = FrameColorRuleLibrary()
        other.bind(projectID: projectB, defaults: defaultsB)
        #expect(other.rules.isEmpty)
        let reopened = FrameColorRuleLibrary()
        reopened.bind(projectID: projectA, defaults: defaultsA)
        #expect(reopened.rules == [rule])
    }

    // MARK: Private

    private func row(_ ordinal: UInt64, facts: FrameFilterFacts) -> CaptureFrameRow {
        let provenance = SessionFrameProvenance(
            ordinal: FrameOrdinal(ordinal), timestamp: nil,
            capturedLength: 54, originalLength: 54, linkType: 1
        )
        return CaptureFrameRow(
            provenance: provenance, source: "", destination: "", protocolName: "TCP", info: "",
            sessionID: nil, interfaceID: 0, hasComment: false, filterFacts: facts
        )
    }
}
