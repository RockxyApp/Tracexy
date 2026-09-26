import CoreFoundation
import Foundation
import os

// MARK: - TestPreferences

/// Removes a test's preferences domain completely.
///
/// `removePersistentDomain(forName:)` empties a domain but leaves its property
/// list on disk: the preferences daemon writes the empty file back after the call
/// returns, and again when the test process disconnects. Every run then leaves
/// thousands of files, and a preferences folder with a hundred thousand of them
/// stops the daemon from reading or saving settings for any app on the Mac.
///
/// So the file is deleted now if it is already empty, the names removed are
/// listed in a temporary file when the process exits, and the next test process
/// deletes those files once the daemon has written them back empty. A file that
/// holds anything is never deleted.
enum TestPreferences {
    // MARK: Internal

    static func remove(_ suiteName: String) {
        precondition(!suiteName.isEmpty && suiteName != Bundle.main.bundleIdentifier)
        UserDefaults.standard.removePersistentDomain(forName: suiteName)
        CFPreferencesAppSynchronize(suiteName as CFString)
        deleteIfEmpty(suiteName)
        let first = removed.withLock { state in
            state.names.insert(suiteName)
            defer { state.started = true }
            return !state.started
        }
        if first {
            deleteListedByEarlierRuns()
            atexit {
                TestPreferences.listRemovedNames()
            }
        }
    }

    // MARK: Private

    private struct State {
        var names: Set<String> = []
        var started = false
    }

    private static let removed = OSAllocatedUnfairLock(initialState: State())

    private static var listDirectory: URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("tracexy-test-preferences", isDirectory: true)
    }

    private static func listRemovedNames() {
        let names = removed.withLock { $0.names }
        guard !names.isEmpty else {
            return
        }
        try? FileManager.default.createDirectory(at: listDirectory, withIntermediateDirectories: true)
        let file = listDirectory.appendingPathComponent("\(UUID().uuidString).txt")
        try? Data(names.sorted().joined(separator: "\n").utf8).write(to: file, options: .atomic)
    }

    /// Deletes the files earlier test processes listed, when they are empty. A
    /// list stays until every file on it is gone, so one written moments ago by a
    /// process that has not quite finished is tried again next time; a list older
    /// than a day is dropped.
    private static func deleteListedByEarlierRuns() {
        let lists = (try? FileManager.default.contentsOfDirectory(
            at: listDirectory,
            includingPropertiesForKeys: [.contentModificationDateKey]
        )) ?? []
        let dayAgo = Date(timeIntervalSinceNow: -86_400)
        for list in lists where list.pathExtension == "txt" {
            let modified = try? list.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate
            guard let text = try? String(contentsOf: list, encoding: .utf8), (modified ?? .distantPast) > dayAgo else {
                try? FileManager.default.removeItem(at: list)
                continue
            }
            let names = text.split(separator: "\n").map(String.init)
            let remaining = names.filter { !deleteIfEmpty($0) }
            if remaining.isEmpty {
                try? FileManager.default.removeItem(at: list)
            } else if remaining.count < names.count {
                try? Data(remaining.joined(separator: "\n").utf8).write(to: list, options: .atomic)
            }
        }
    }

    /// Deletes the domain's file when it holds nothing, so a domain some other
    /// code wrote to again is never lost. Returns whether no file is left.
    @discardableResult
    private static func deleteIfEmpty(_ suiteName: String) -> Bool {
        guard !suiteName.isEmpty, !suiteName.contains("/") else {
            return true
        }
        let file = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Preferences", isDirectory: true)
            .appendingPathComponent("\(suiteName).plist")
        guard let data = try? Data(contentsOf: file) else {
            return true
        }
        let contents = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        guard contents?.isEmpty == true else {
            return false
        }
        return (try? FileManager.default.removeItem(at: file)) != nil
    }
}
