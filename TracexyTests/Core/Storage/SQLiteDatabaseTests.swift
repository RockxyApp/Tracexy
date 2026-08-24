import Foundation
import Testing
@testable import Tracexy

// MARK: - SQLiteDatabaseTests

@Suite("SQLite wrapper primitives and error mapping")
struct SQLiteDatabaseTests {
    // MARK: Internal

    @Test("Result codes map to distinct typed failures using the primary code")
    func mapsResultCodesToTypedFailures() {
        #expect(HistoryStoreError.map(5, message: "busy") == .busy)
        #expect(HistoryStoreError.map(6, message: "locked") == .locked)
        #expect(HistoryStoreError.map(8, message: "ro") == .readOnly)
        #expect(HistoryStoreError.map(13, message: "full") == .diskFull)
        #expect(HistoryStoreError.map(11, message: "corrupt") == .corruption("corrupt"))
        #expect(HistoryStoreError.map(26, message: "notadb") == .corruption("notadb"))
        // Extended read-only code (SQLITE_READONLY_DBMOVED = 8 | (5<<8)) still maps
        // to .readOnly via the primary low byte.
        #expect(HistoryStoreError.map(8 | (5 << 8), message: "moved") == .readOnly)
        // An unmapped code preserves the raw value.
        #expect(HistoryStoreError.map(1, message: "generic") == .sqlite(code: 1, message: "generic"))
    }

    @Test("An in-memory database executes, prepares and reads a value round-trip")
    func inMemoryRoundTrip() throws {
        let database = try SQLiteDatabase(path: ":memory:", readOnly: false)
        defer { database.close() }
        try database.execute("CREATE TABLE t (k INTEGER, v TEXT);")
        try database.execute("INSERT INTO t (k, v) VALUES (1, 'hello');")

        let statement = try database.prepare("SELECT k, v FROM t WHERE k = ?;")
        defer { statement.finalizeStatement() }
        try statement.bindInt(1, 1)
        #expect(try statement.step())
        #expect(statement.columnInt64(0) == 1)
        #expect(statement.columnText(1) == "hello")
        #expect(try !statement.step())
    }

    @Test("A prepared statement reuses across reset with rebinding")
    func statementResetReuse() throws {
        let database = try SQLiteDatabase(path: ":memory:", readOnly: false)
        defer { database.close() }
        try database.execute("CREATE TABLE t (v TEXT);")

        let insert = try database.prepare("INSERT INTO t (v) VALUES (?);")
        defer { insert.finalizeStatement() }
        for value in ["a", "b", "c"] {
            insert.reset()
            try insert.bindText(1, value)
            #expect(try !insert.step())
        }

        let count = try database.prepare("SELECT COUNT(*) FROM t;")
        defer { count.finalizeStatement() }
        #expect(try count.step())
        #expect(count.columnInt64(0) == 3)
    }

    @Test("NULL columns are reported and text is copied safely")
    func nullColumnsAndSafeTextCopy() throws {
        let database = try SQLiteDatabase(path: ":memory:", readOnly: false)
        defer { database.close() }
        try database.execute("CREATE TABLE t (a TEXT, b TEXT);")

        let insert = try database.prepare("INSERT INTO t (a, b) VALUES (?, ?);")
        defer { insert.finalizeStatement() }
        // Bind a transient string, then let it go out of scope before reading back:
        // SQLITE_TRANSIENT must already have copied it.
        try insert.bindText(1, String("kept".reversed()))
        try insert.bindNull(2)
        #expect(try !insert.step())

        let read = try database.prepare("SELECT a, b FROM t;")
        defer { read.finalizeStatement() }
        #expect(try read.step())
        #expect(read.columnText(0) == "tpek")
        #expect(read.columnIsNull(1))
        #expect(read.columnText(1) == nil)
    }

    @Test("A malformed statement throws a typed error, not a trap")
    func malformedStatementThrows() throws {
        let database = try SQLiteDatabase(path: ":memory:", readOnly: false)
        defer { database.close() }
        #expect(throws: HistoryStoreError.self) {
            _ = try database.prepare("SELECT FROM nowhere bogus;")
        }
    }

    @Test("Opening a missing file read-only fails typed instead of creating it")
    func readOnlyOpenOfMissingFileThrows() throws {
        let url = Self.temporaryURL()
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(throws: HistoryStoreError.self) {
            _ = try SQLiteDatabase(path: url.path, readOnly: true)
        }
        #expect(!FileManager.default.fileExists(atPath: url.path))
    }

    @Test("A busy timeout can be set without error")
    func busyTimeoutIsSettable() throws {
        let database = try SQLiteDatabase(path: ":memory:", readOnly: false)
        defer { database.close() }
        database.setBusyTimeout(2_500)
        #expect(try database.readIntegerPragma("busy_timeout") == 2_500)
    }

    @Test("close is idempotent")
    func closeIsIdempotent() throws {
        let database = try SQLiteDatabase(path: ":memory:", readOnly: false)
        database.close()
        database.close()
    }

    // MARK: Private

    private static func temporaryURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("sqlite-\(UUID().uuidString).db")
    }
}
