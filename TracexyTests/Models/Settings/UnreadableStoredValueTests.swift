import Foundation
import Testing
@testable import Tracexy

// MARK: - UnreadableStoredValueTests

/// Saved Focus Sets and Session Expressions a build cannot read (a newer
/// version's, or damaged) are set aside before the list starts empty, so the
/// next save cannot destroy them.
@Suite("Unreadable saved lists are kept")
@MainActor
struct UnreadableStoredValueTests {
    @Test("Saved Session Expressions that can't be read are set aside, once")
    func savedExpressionsAreSetAside() throws {
        let suite = "unreadable-expressions-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let key = ProjectScopedSettingsKeys.savedSessionExpressions
        let newer = Data(#"{"version": 2, "items": []}"#.utf8)
        defaults.set(newer, forKey: key)

        let library = SessionExpressionLibrary()
        library.bind(to: defaults)
        #expect(library.saved.isEmpty)
        #expect(defaults.data(forKey: UnreadableStoredValue.backupKey(for: key)) == newer)

        #expect(library.save("tcp", named: "TCP"))
        defaults.set(Data("{".utf8), forKey: key)
        library.bind(to: defaults)
        #expect(defaults.data(forKey: UnreadableStoredValue.backupKey(for: key)) == newer)
    }

    @Test("A readable list leaves nothing aside")
    func readableListLeavesNoBackup() throws {
        let suite = "readable-expressions-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let library = SessionExpressionLibrary()
        library.bind(to: defaults)
        #expect(library.save("dns", named: "DNS"))
        library.bind(to: defaults)
        #expect(library.saved.map(\.name) == ["DNS"])
        let key = ProjectScopedSettingsKeys.savedSessionExpressions
        #expect(defaults.object(forKey: UnreadableStoredValue.backupKey(for: key)) == nil)
    }
}
