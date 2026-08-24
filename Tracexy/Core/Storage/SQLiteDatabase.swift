import Foundation
import SQLite3

// MARK: - SQLiteTransient

/// SQLite's `SQLITE_TRANSIENT` sentinel: it instructs SQLite to copy a bound blob
/// or text immediately during the bind call, so no Swift-owned pointer must outlive
/// the call. Every text binding in this package uses it, so a transient Swift
/// string is always safely copied.
nonisolated(unsafe) private let sqliteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

// MARK: - SQLiteDatabase

/// A thin, non-`Sendable` wrapper over exactly one system SQLite connection. It is
/// owned by a single ``SessionStore`` actor and therefore never touched
/// concurrently. It exposes only the primitives the store needs — open, exec,
/// prepare, typed pragma reads, busy timeout — and maps SQLite result codes onto
/// the typed ``HistoryStoreError`` domain. It performs no policy: transactions,
/// schema and validation live in the store.
nonisolated final class SQLiteDatabase {
    // MARK: Lifecycle

    /// Open one connection at `path`, read-only or read-write/create.
    ///
    /// - Throws: ``HistoryStoreError`` mapped from the SQLite open result. A
    ///   read-only open of a missing file fails here rather than creating one.
    init(path: String, readOnly: Bool) throws {
        var flags = readOnly
            ? SQLITE_OPEN_READONLY
            : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE)
        flags |= SQLITE_OPEN_FULLMUTEX
        var handle: OpaquePointer?
        let code = sqlite3_open_v2(path, &handle, flags, nil)
        guard code == SQLITE_OK, let handle else {
            let message = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "unable to open database"
            if let handle {
                sqlite3_close_v2(handle)
            }
            throw HistoryStoreError.map(code, message: message)
        }
        self.handle = handle
    }

    deinit {
        close()
    }

    // MARK: Internal

    /// Install SQLite's own busy timeout so a contended lock retries up to
    /// `milliseconds` before returning `SQLITE_BUSY`.
    func setBusyTimeout(_ milliseconds: Int32) {
        sqlite3_busy_timeout(handle, milliseconds)
    }

    /// Execute one or more statements that return no rows.
    func execute(_ sql: String) throws {
        let code = sqlite3_exec(handle, sql, nil, nil, nil)
        guard code == SQLITE_OK else {
            throw HistoryStoreError.map(code, message: lastMessage())
        }
    }

    /// Prepare a single statement; the caller owns finalizing it.
    func prepare(_ sql: String) throws -> SQLiteStatement {
        guard let handle else {
            throw HistoryStoreError.sqlite(code: SQLITE_MISUSE, message: "database is closed")
        }
        return try SQLiteStatement(database: handle, sql: sql)
    }

    /// Read a single-integer pragma (for example `user_version` or `foreign_keys`).
    func readIntegerPragma(_ name: String) throws -> Int64 {
        let statement = try prepare("PRAGMA \(name);")
        defer { statement.finalizeStatement() }
        guard try statement.step() else {
            return 0
        }
        return statement.columnInt64(0)
    }

    /// Set the journal mode to WAL and return the mode SQLite actually adopted. A
    /// file database adopts `"wal"`; an in-memory or temporary database cannot and
    /// reports its own mode, which the caller must not require to be WAL.
    func setJournalModeWAL() throws -> String {
        let statement = try prepare("PRAGMA journal_mode = WAL;")
        defer { statement.finalizeStatement() }
        guard try statement.step() else {
            return ""
        }
        return statement.columnText(0) ?? ""
    }

    /// Return `true` if `PRAGMA foreign_key_check` reports any violation.
    func hasForeignKeyViolations() throws -> Bool {
        let statement = try prepare("PRAGMA foreign_key_check;")
        defer { statement.finalizeStatement() }
        return try statement.step()
    }

    /// Close the connection with `sqlite3_close_v2`, which is safe even if a
    /// statement outlived its finalize; idempotent.
    func close() {
        if let handle {
            sqlite3_close_v2(handle)
        }
        handle = nil
    }

    // MARK: Private

    private var handle: OpaquePointer?

    private func lastMessage() -> String {
        guard let handle else {
            return "database is closed"
        }
        return String(cString: sqlite3_errmsg(handle))
    }
}

// MARK: - SQLiteStatement

/// A single prepared statement. It copies every text binding, maps step/bind
/// failures onto the typed error domain, and finalizes exactly once — from an
/// explicit ``finalizeStatement()`` (the store always does this in `defer`) or, as
/// a backstop, from `deinit`.
nonisolated final class SQLiteStatement {
    // MARK: Lifecycle

    init(database: OpaquePointer, sql: String) throws {
        self.database = database
        var statement: OpaquePointer?
        let code = sqlite3_prepare_v2(database, sql, -1, &statement, nil)
        guard code == SQLITE_OK, let statement else {
            let message = String(cString: sqlite3_errmsg(database))
            if let statement {
                sqlite3_finalize(statement)
            }
            throw HistoryStoreError.map(code, message: message)
        }
        self.statement = statement
    }

    deinit {
        finalizeStatement()
    }

    // MARK: Internal

    /// Bind text at a 1-based index, copied immediately (`SQLITE_TRANSIENT`).
    func bindText(_ index: Int32, _ value: String) throws {
        let code = sqlite3_bind_text(statement, index, value, -1, sqliteTransient)
        try check(code)
    }

    /// Bind a 64-bit integer at a 1-based index.
    func bindInt(_ index: Int32, _ value: Int64) throws {
        try check(sqlite3_bind_int64(statement, index, value))
    }

    /// Bind a double at a 1-based index.
    func bindDouble(_ index: Int32, _ value: Double) throws {
        try check(sqlite3_bind_double(statement, index, value))
    }

    /// Bind SQL NULL at a 1-based index.
    func bindNull(_ index: Int32) throws {
        try check(sqlite3_bind_null(statement, index))
    }

    /// Advance one row.
    ///
    /// - Returns: `true` when a row is available, `false` at completion.
    /// - Throws: ``HistoryStoreError`` mapped from any other result code.
    func step() throws -> Bool {
        let code = sqlite3_step(statement)
        switch code {
        case SQLITE_ROW:
            return true
        case SQLITE_DONE:
            return false
        default:
            throw HistoryStoreError.map(code, message: String(cString: sqlite3_errmsg(database)))
        }
    }

    /// Reset the statement so its next execution can rebind and re-step.
    func reset() {
        sqlite3_reset(statement)
    }

    func columnIsNull(_ index: Int32) -> Bool {
        sqlite3_column_type(statement, index) == SQLITE_NULL
    }

    func columnInt64(_ index: Int32) -> Int64 {
        sqlite3_column_int64(statement, index)
    }

    func columnDouble(_ index: Int32) -> Double {
        sqlite3_column_double(statement, index)
    }

    func columnText(_ index: Int32) -> String? {
        guard let pointer = sqlite3_column_text(statement, index) else {
            return nil
        }
        return String(cString: pointer)
    }

    /// Finalize exactly once; idempotent.
    func finalizeStatement() {
        if let statement {
            sqlite3_finalize(statement)
        }
        statement = nil
    }

    // MARK: Private

    private let database: OpaquePointer
    private var statement: OpaquePointer?

    private func check(_ code: Int32) throws {
        guard code == SQLITE_OK else {
            throw HistoryStoreError.map(code, message: String(cString: sqlite3_errmsg(database)))
        }
    }
}

// MARK: - HistoryStoreError + SQLite mapping

extension HistoryStoreError {
    /// Map a SQLite result code onto the typed failure domain. The primary code
    /// (low byte) is used so an extended code such as `SQLITE_READONLY_DBMOVED`
    /// still maps to `.readOnly`.
    static func map(_ code: Int32, message: String) -> HistoryStoreError {
        switch code & 0xFF {
        case SQLITE_BUSY:
            .busy
        case SQLITE_LOCKED:
            .locked
        case SQLITE_READONLY:
            .readOnly
        case SQLITE_FULL:
            .diskFull
        case SQLITE_CORRUPT,
             SQLITE_NOTADB:
            .corruption(message)
        default:
            .sqlite(code: code, message: message)
        }
    }
}
