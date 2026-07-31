import Foundation
import Testing
@testable import Tracexy

@Suite("Bundled helper version metadata parsing")
struct HelperVersionMetadataTests {
    @Test("Valid xcconfig-style string values parse verbatim")
    func validValues() {
        let metadata = BundledHelperMetadata(infoDictionary: [
            BundledHelperMetadata.Key.version: "1.2.3",
            BundledHelperMetadata.Key.build: "42",
            BundledHelperMetadata.Key.protocolVersion: "3",
        ])

        #expect(metadata == BundledHelperMetadata(version: "1.2.3", build: 42, protocolVersion: 3))
    }

    @Test("A nil or empty dictionary fails closed")
    func missingValues() {
        let fromNil = BundledHelperMetadata(infoDictionary: nil)
        let fromEmpty = BundledHelperMetadata(infoDictionary: [:])
        let expected = BundledHelperMetadata(version: "0.0.0", build: 0, protocolVersion: 0)

        #expect(fromNil == expected)
        #expect(fromEmpty == expected)
    }

    @Test("Malformed numeric strings fail closed to zero")
    func malformedNumericValues() {
        let metadata = BundledHelperMetadata(infoDictionary: [
            BundledHelperMetadata.Key.version: "9.9.9",
            BundledHelperMetadata.Key.build: "not-a-number",
            BundledHelperMetadata.Key.protocolVersion: "1.5",
        ])

        #expect(metadata.version == "9.9.9")
        #expect(metadata.build == 0)
        #expect(metadata.protocolVersion == 0)
    }

    @Test("Numeric Int and NSNumber values are accepted")
    func numericObjectValues() {
        let metadata = BundledHelperMetadata(infoDictionary: [
            BundledHelperMetadata.Key.version: "2.0.0",
            BundledHelperMetadata.Key.build: 7,
            BundledHelperMetadata.Key.protocolVersion: NSNumber(value: 4),
        ])

        #expect(metadata == BundledHelperMetadata(version: "2.0.0", build: 7, protocolVersion: 4))
    }

    @Test("A blank or non-string version fails closed to 0.0.0")
    func blankVersion() {
        let blank = BundledHelperMetadata(infoDictionary: [
            BundledHelperMetadata.Key.version: "   ",
            BundledHelperMetadata.Key.build: "1",
            BundledHelperMetadata.Key.protocolVersion: "1",
        ])
        let nonString = BundledHelperMetadata(infoDictionary: [
            BundledHelperMetadata.Key.version: 3,
            BundledHelperMetadata.Key.build: "1",
            BundledHelperMetadata.Key.protocolVersion: "1",
        ])

        #expect(blank.version == "0.0.0")
        #expect(nonString.version == "0.0.0")
    }

    @Test(
        "Non-positive protocol and build values fail closed to zero",
        arguments: [
            ["0", "0"],
            ["-1", "-4"],
        ]
    )
    func nonPositiveValues(pair: [String]) {
        let metadata = BundledHelperMetadata(infoDictionary: [
            BundledHelperMetadata.Key.version: "1.0.0",
            BundledHelperMetadata.Key.build: pair[0],
            BundledHelperMetadata.Key.protocolVersion: pair[1],
        ])

        #expect(metadata.build == 0)
        #expect(metadata.protocolVersion == 0)
    }

    @Test("Non-positive Int and NSNumber values also fail closed")
    func nonPositiveObjectValues() {
        let metadata = BundledHelperMetadata(infoDictionary: [
            BundledHelperMetadata.Key.version: "1.0.0",
            BundledHelperMetadata.Key.build: 0,
            BundledHelperMetadata.Key.protocolVersion: NSNumber(value: -2),
        ])

        #expect(metadata.build == 0)
        #expect(metadata.protocolVersion == 0)
    }

    @Test("The shared helper protocol parser reads the same bundle key")
    func sharedProtocolParser() {
        #expect(HelperProtocolVersion.value(in: [
            HelperProtocolVersion.infoDictionaryKey: "5",
        ]) == 5)
        #expect(HelperProtocolVersion.value(in: [
            HelperProtocolVersion.infoDictionaryKey: "invalid",
        ]) == 0)
        #expect(HelperProtocolVersion.value(in: nil) == 0)
    }
}
