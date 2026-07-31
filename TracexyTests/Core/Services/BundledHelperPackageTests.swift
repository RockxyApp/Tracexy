import Foundation
import Testing
@testable import Tracexy

@Suite("Bundled helper package preflight (launchd plist)")
struct BundledHelperPackageTests {
    // MARK: Internal

    @Test("A well-formed plist validates")
    func valid() {
        #expect(BundledHelperPackage.validateLaunchdPlist(Self.plist(), requirements: Self.requirements) == .ok)
    }

    @Test("A missing or mismatched Label is incomplete")
    func label() {
        var missing = Self.plist()
        missing["Label"] = nil
        var wrong = Self.plist()
        wrong["Label"] = "com.other.helper"

        expectIncomplete(BundledHelperPackage.validateLaunchdPlist(missing, requirements: Self.requirements))
        expectIncomplete(BundledHelperPackage.validateLaunchdPlist(wrong, requirements: Self.requirements))
    }

    @Test("A missing or mismatched BundleProgram is incomplete")
    func bundleProgram() {
        var missing = Self.plist()
        missing["BundleProgram"] = nil
        var wrong = Self.plist()
        wrong["BundleProgram"] = "Contents/Library/HelperTools/SomethingElse"

        expectIncomplete(BundledHelperPackage.validateLaunchdPlist(missing, requirements: Self.requirements))
        expectIncomplete(BundledHelperPackage.validateLaunchdPlist(wrong, requirements: Self.requirements))
    }

    @Test("A missing, absent, or disabled Mach service is incomplete")
    func machServices() {
        var noDict = Self.plist()
        noDict["MachServices"] = nil
        var wrongName = Self.plist()
        wrongName["MachServices"] = ["com.other.helper": true]
        var disabled = Self.plist()
        disabled["MachServices"] = [Self.machServiceName: false]

        expectIncomplete(BundledHelperPackage.validateLaunchdPlist(noDict, requirements: Self.requirements))
        expectIncomplete(BundledHelperPackage.validateLaunchdPlist(wrongName, requirements: Self.requirements))
        expectIncomplete(BundledHelperPackage.validateLaunchdPlist(disabled, requirements: Self.requirements))
    }

    @Test("Missing, empty, or non-matching AssociatedBundleIdentifiers is incomplete")
    func associatedBundleIdentifiers() {
        var missing = Self.plist()
        missing["AssociatedBundleIdentifiers"] = nil
        var empty = Self.plist()
        empty["AssociatedBundleIdentifiers"] = [String]()
        var unrelated = Self.plist()
        unrelated["AssociatedBundleIdentifiers"] = ["com.other.app"]

        expectIncomplete(BundledHelperPackage.validateLaunchdPlist(missing, requirements: Self.requirements))
        expectIncomplete(BundledHelperPackage.validateLaunchdPlist(empty, requirements: Self.requirements))
        expectIncomplete(BundledHelperPackage.validateLaunchdPlist(unrelated, requirements: Self.requirements))
    }

    @Test("Unexpected AssociatedBundleIdentifiers are rejected even when this app is included")
    func associatedSupersetIsRejected() {
        var superset = Self.plist()
        superset["AssociatedBundleIdentifiers"] = [Self.appIdentifier, "\(Self.appIdentifier).pro"]
        expectIncomplete(BundledHelperPackage.validateLaunchdPlist(superset, requirements: Self.requirements))
    }

    @Test("AssociatedBundleIdentifiers compare as a normalized set")
    func associatedSetNormalization() {
        var reordered = Self.plist()
        reordered["AssociatedBundleIdentifiers"] = [
            Self.communityAppIdentifier,
            Self.appIdentifier,
            Self.appIdentifier,
        ]
        #expect(BundledHelperPackage.validateLaunchdPlist(reordered, requirements: Self.requirements) == .ok)
    }

    // MARK: Private

    private static let machServiceName = "com.example.tracexy.helper"
    private static let bundleProgram = "Contents/Library/HelperTools/TracexyCaptureHelper"
    private static let appIdentifier = "com.example.tracexy"
    private static let communityAppIdentifier = "com.example.tracexy.community"

    private static let requirements = BundledHelperPackage.Requirements(
        expectedLabel: machServiceName,
        expectedBundleProgram: bundleProgram,
        expectedMachServiceName: machServiceName,
        expectedAssociatedBundleIdentifiers: [appIdentifier, communityAppIdentifier]
    )

    private static func plist() -> [String: Any] {
        [
            "Label": machServiceName,
            "BundleProgram": bundleProgram,
            "MachServices": [machServiceName: true],
            "AssociatedBundleIdentifiers": [appIdentifier, communityAppIdentifier],
        ]
    }

    private func expectIncomplete(_ validation: BundledHelperPackage.Validation) {
        guard case .incomplete = validation else {
            Issue.record("expected .incomplete, got \(validation)")
            return
        }
    }
}
