import Foundation
import Testing
@testable import Tracexy

// MARK: - HistoryStoreFactoryTests

@Suite("HistoryStoreFactory path resolution and failure isolation")
struct HistoryStoreFactoryTests {
    // MARK: Internal

    @Test("A writable database is composed, usable and reopened at the same path")
    func composesUsableStore() async throws {
        let directory = Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("History/history.sqlite")

        guard case let .ready(store) = HistoryStoreFactory.make(databaseURL: url) else {
            Issue.record("Expected a ready store")
            return
        }
        let capture = HistoryCaptureRecord(
            captureID: UUID(),
            startedAt: 1_000,
            endedAt: 1_010,
            sourceKind: .live,
            completeness: .complete
        )
        try await store.replaceCapture(capture, sessions: [])
        #expect(try await store.capture(id: capture.captureID)?.sessionCount == 0)

        // The database file was created under the resolved subdirectory.
        #expect(FileManager.default.fileExists(atPath: url.path))
    }

    @Test("A directory that cannot be created isolates as unavailable, never a throw")
    func directoryFailureIsIsolated() throws {
        let directory = Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        // Place a regular file where the History directory's parent must be, so
        // creating the enclosing directory is impossible.
        let blocker = directory.appendingPathComponent("blocker")
        try Data([0x00]).write(to: blocker)
        let url = blocker.appendingPathComponent("History/history.sqlite")

        guard case let .unavailable(reason) = HistoryStoreFactory.make(databaseURL: url) else {
            Issue.record("Expected unavailable")
            return
        }
        #expect(!reason.isEmpty)
    }

    @Test("An unmigratable existing file isolates as unavailable")
    func openFailureIsIsolated() throws {
        let directory = Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let historyDirectory = directory.appendingPathComponent("History")
        try FileManager.default.createDirectory(at: historyDirectory, withIntermediateDirectories: true)
        let url = historyDirectory.appendingPathComponent("history.sqlite")
        // A future schema version can never be migrated, so opening fails typed and
        // the factory isolates it rather than throwing.
        let raw = try SQLiteDatabase(path: url.path, readOnly: false)
        try raw.execute("PRAGMA user_version = 99;")
        raw.close()

        guard case .unavailable = HistoryStoreFactory.make(databaseURL: url) else {
            Issue.record("Expected unavailable")
            return
        }
    }

    @Test("The production path resolves under the identity-derived app-support directory")
    func productionPathIsIdentityDerived() {
        let url = HistoryStoreFactory.productionDatabaseURL()
        #expect(url.pathComponents.contains("History"))
        #expect(url.lastPathComponent == "history.sqlite")
        // In tests, ``TracexyIdentity`` resolves under a per-run temporary directory,
        // so a production database is never shared with a test run.
        #expect(url.path.contains("tracexy-tests-"))
    }

    // MARK: Private

    private static func temporaryDirectory() -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("history-factory-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }
}
