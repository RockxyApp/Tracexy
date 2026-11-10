import Foundation
import Testing
@testable import Tracexy

// MARK: - FrameFilterPresetLibraryTests

@Suite("Saved Frame Filter presets")
@MainActor
struct FrameFilterPresetLibraryTests {
    @Test("Presets save, replace without changing identity, reload and remove")
    func saveReloadReplaceRemove() throws {
        let suite = "frame-filter-presets-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let projectID = UUID()
        let library = FrameFilterPresetLibrary()
        library.bind(projectID: projectID, defaults: defaults)

        #expect(library.save(name: "Reset", expression: "tcp.rst", expectedProjectID: projectID))
        let firstID = try #require(library.filters.first?.id)
        #expect(library.save(name: "reset", expression: "tcp.syn", expectedProjectID: projectID))
        #expect(library.filters.count == 1)
        #expect(library.filters[0].id == firstID)
        #expect(library.filters[0].expression == "tcp.syn")

        let reloaded = FrameFilterPresetLibrary()
        reloaded.bind(projectID: projectID, defaults: defaults)
        #expect(reloaded.filters == library.filters)
        #expect(reloaded.remove(firstID, expectedProjectID: projectID))
        #expect(reloaded.filters.isEmpty)
    }

    @Test("A preset remains Project-local and stale saves are rejected")
    func projectIsolationAndStaleSave() throws {
        let suiteA = "frame-filter-project-a-\(UUID().uuidString)"
        let suiteB = "frame-filter-project-b-\(UUID().uuidString)"
        let defaultsA = try #require(UserDefaults(suiteName: suiteA))
        let defaultsB = try #require(UserDefaults(suiteName: suiteB))
        defer {
            TestPreferences.remove(suiteA)
            TestPreferences.remove(suiteB)
        }
        let projectA = UUID()
        let projectB = UUID()
        let library = FrameFilterPresetLibrary()
        library.bind(projectID: projectA, defaults: defaultsA)
        #expect(library.save(name: "DNS", expression: "udp.port == 53", expectedProjectID: projectA))

        library.bind(projectID: projectB, defaults: defaultsB)
        #expect(library.filters.isEmpty)
        #expect(!library.save(name: "Stale", expression: "tcp.rst", expectedProjectID: projectA))
        #expect(library.save(name: "SYN", expression: "tcp.syn", expectedProjectID: projectB))

        library.bind(projectID: projectA, defaults: defaultsA)
        #expect(library.filters.map(\.name) == ["DNS"])
    }

    @Test("Unknown grammar is preserved and the library stays read-only")
    func unknownGrammarIsPreserved() throws {
        let suite = "frame-filter-future-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let key = ProjectScopedSettingsKeys.savedFrameFilters
        let future = Data(
            #"{"formatVersion":1,"grammarID":"tracexy.frame-expression","grammarVersion":2,"filters":[]}"#.utf8
        )
        defaults.set(future, forKey: key)

        let projectID = UUID()
        let library = FrameFilterPresetLibrary()
        library.bind(projectID: projectID, defaults: defaults)
        #expect(!library.storageAvailable)
        #expect(library.filters.isEmpty)
        #expect(defaults.data(forKey: key) == future)
        #expect(defaults.data(forKey: UnreadableStoredValue.backupKey(for: key)) == future)
        #expect(!library.save(name: "Changed", expression: "tcp.rst", expectedProjectID: projectID))
        #expect(defaults.data(forKey: key) == future)
    }

    @Test("Project seeding materializes a fresh empty envelope")
    func projectSeedHasEmptyEnvelope() throws {
        let values = ProjectSettingsSeeding.safeDefaultValues()
        let data = try #require(values[ProjectScopedSettingsKeys.savedFrameFilters] as? Data)
        let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(object["formatVersion"] as? Int == 1)
        #expect(object["grammarID"] as? String == "tracexy.frame-expression")
        #expect(object["grammarVersion"] as? Int == 1)
        #expect((object["filters"] as? [Any])?.isEmpty == true)
    }

    @Test("Invalid expressions and duplicate IDs cannot be written")
    func rejectsInvalidAndDuplicateValues() throws {
        let suite = "frame-filter-invalid-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let projectID = UUID()
        let library = FrameFilterPresetLibrary()
        library.bind(projectID: projectID, defaults: defaults)

        #expect(!library.save(name: "Broken", expression: "tcp.rst and and", expectedProjectID: projectID))
        #expect(!library.save(name: "Bad\nName", expression: "tcp.rst", expectedProjectID: projectID))
        let duplicateID = UUID()
        let duplicates = [
            SavedFrameFilter(id: duplicateID, name: "One", expression: "tcp.rst"),
            SavedFrameFilter(id: duplicateID, name: "Two", expression: "tcp.syn"),
        ]
        #expect(!library.replaceAll(duplicates, expectedProjectID: projectID))
        let duplicateNames = [
            SavedFrameFilter(name: "Same", expression: "tcp.rst"),
            SavedFrameFilter(name: "same", expression: "tcp.syn"),
        ]
        #expect(!library.replaceAll(duplicateNames, expectedProjectID: projectID))
        #expect(library.filters.isEmpty)
        #expect(defaults.data(forKey: ProjectScopedSettingsKeys.savedFrameFilters) == nil)
    }
}
