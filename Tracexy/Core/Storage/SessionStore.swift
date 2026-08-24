import Foundation
import SQLite3

// MARK: - SessionStore

/// A pure, actor-isolated SQLite substrate for terminal capture history. It owns
/// exactly one connection, enables and verifies foreign keys (and, for a writable
/// file, WAL) before migrating schema v1 in one immediate transaction, and exposes
/// only atomic whole-capture replacement, bounded keyset reads and whole-group
/// retention. It never reads settings, touches `@MainActor`, converts a
/// `SessionSummary`/`Finding`, retains raw bytes, or schedules anything — it is a
/// terminal write/read primitive, not a live integration.
///
/// Every failure is a typed ``HistoryStoreError`` (or Swift's `CancellationError`);
/// no failure ever mutates capture state. All prepared statements are finalized,
/// all text bindings are copied, integers are overflow-checked and persisted enum
/// integers decode fail-closed.
actor SessionStore {
    // MARK: Lifecycle

    /// Open and migrate the store described by `configuration`. On any
    /// initialization/migration failure the handle is closed and the error is
    /// rethrown, so a partially migrated actor is never returned.
    init(configuration: Configuration = Configuration()) throws {
        self.configuration = configuration
        let database = try SQLiteDatabase(
            path: configuration.location.path,
            readOnly: configuration.readOnly
        )
        do {
            try Self.migrate(database, configuration: configuration)
        } catch {
            database.close()
            throw error
        }
        self.database = database
    }

    deinit {
        database.close()
    }

    // MARK: Internal

    let configuration: Configuration

    // MARK: Private

    private let database: SQLiteDatabase

    private var faultHook: FaultHook? {
        configuration.faultInjection
    }
}

// MARK: SessionStore.Configuration

extension SessionStore {
    /// Where and how one store opens its connection. Tests inject `.memory` or a
    /// temporary file, optional read-only opening, a bounded busy timeout, a
    /// deterministic cancellation closure and an internal fault-injection hook.
    struct Configuration: Sendable {
        // MARK: Lifecycle

        init(
            location: Location = .memory,
            readOnly: Bool = false,
            busyTimeout: TimeInterval = 2.5,
            isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled },
            faultInjection: FaultHook? = nil
        ) {
            self.location = location
            self.readOnly = readOnly
            self.busyTimeout = max(0, busyTimeout)
            self.isCancelled = isCancelled
            self.faultInjection = faultInjection
        }

        // MARK: Internal

        /// The connection target: a private in-memory database or a file URL.
        enum Location: Sendable, Equatable {
            case memory
            case file(URL)

            // MARK: Internal

            var isFile: Bool {
                if case .file = self {
                    return true
                }
                return false
            }

            var path: String {
                switch self {
                case .memory:
                    ":memory:"
                case let .file(url):
                    url.path
                }
            }
        }

        let location: Location
        let readOnly: Bool
        let busyTimeout: TimeInterval
        let isCancelled: @Sendable () -> Bool
        let faultInjection: FaultHook?

        /// The busy timeout clamped to a valid millisecond count.
        var busyTimeoutMilliseconds: Int32 {
            guard !busyTimeout.isNaN else {
                return 0
            }
            guard busyTimeout.isFinite else {
                return busyTimeout > 0 ? Int32.max : 0
            }
            let millis = (busyTimeout * 1_000).rounded()
            guard millis > 0 else {
                return 0
            }
            return Int32(min(millis, Double(Int32.max)))
        }
    }
}

// MARK: - SessionStore.FaultStage

extension SessionStore {
    /// A named point inside a real transaction where a test may force a SQLite
    /// result code. Because the fault fires mid-transaction, it proves the store
    /// rolls back and preserves the prior committed record — it is not merely a
    /// standalone code-to-error mapping.
    enum FaultStage: Sendable, Equatable {
        case migrationBegin
        case migrationCreateSchema
        case migrationCommit
        case replaceBeforeBegin
        case replaceAfterDelete
        case replaceCaptureInsert
        case replaceBatchBoundary(ordinal: Int)
        case replaceSessionInsert(ordinal: Int)
        case replaceProtocolInsert(ordinal: Int)
        case replaceCommit
        case retentionBegin
        case retentionDelete(index: Int)
        case retentionCommit
    }

    /// A deterministic fault hook: return a nonzero SQLite result code to force a
    /// failure at `stage`, or `SQLITE_OK` to allow it.
    typealias FaultHook = @Sendable (FaultStage) -> Int32
}

// MARK: - SessionStore migration

private extension SessionStore {
    /// The exact schema v1 DDL. Installed atomically; `user_version` is bumped in
    /// the same transaction.
    static let schemaSQL = """
    CREATE TABLE captures (
        id TEXT PRIMARY KEY,
        started_at REAL NOT NULL,
        ended_at REAL NOT NULL,
        source_kind INTEGER NOT NULL,
        completeness INTEGER NOT NULL,
        session_count INTEGER NOT NULL
    );
    CREATE TABLE sessions (
        capture_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL,
        start_time REAL NOT NULL,
        duration REAL NOT NULL,
        process_name TEXT NULL,
        host TEXT NOT NULL,
        source_endpoint TEXT NOT NULL,
        destination_endpoint TEXT NOT NULL,
        status INTEGER NOT NULL,
        latency_ms REAL NULL,
        bytes_up INTEGER NOT NULL,
        bytes_down INTEGER NOT NULL,
        PRIMARY KEY(capture_id, session_id),
        UNIQUE(capture_id, ordinal),
        FOREIGN KEY(capture_id) REFERENCES captures(id) ON DELETE CASCADE
    );
    CREATE TABLE session_protocols (
        capture_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        protocol_ordinal INTEGER NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY(capture_id, session_id, protocol_ordinal),
        FOREIGN KEY(capture_id, session_id) REFERENCES sessions(capture_id, session_id) ON DELETE CASCADE
    );
    CREATE INDEX idx_captures_ended ON captures(ended_at, id);
    PRAGMA user_version = 1;
    """

    /// Configure the connection and migrate to schema v1.
    ///
    /// Every handle sets and verifies `foreign_keys = ON` before any transaction —
    /// setting it inside a transaction is silently ignored, so it must precede one.
    /// A writable file additionally sets and verifies WAL; a read-only or in-memory
    /// database preserves its journal mode. Version 0 migrates to 1; a future
    /// version is a typed unsupported-schema error; a read-only version-0 database
    /// cannot migrate and fails typed.
    static func migrate(_ database: SQLiteDatabase, configuration: Configuration) throws {
        database.setBusyTimeout(configuration.busyTimeoutMilliseconds)

        try database.execute("PRAGMA foreign_keys = ON;")
        guard try database.readIntegerPragma("foreign_keys") == 1 else {
            throw HistoryStoreError.configurationFailed("foreign_keys could not be enabled")
        }

        if configuration.location.isFile, !configuration.readOnly {
            let mode = try database.setJournalModeWAL()
            guard mode.lowercased() == "wal" else {
                throw HistoryStoreError.configurationFailed("WAL journal mode was not adopted (got \(mode))")
            }
        }

        let version = try database.readIntegerPragma("user_version")
        switch version {
        case 1:
            return
        case 0:
            guard !configuration.readOnly else {
                throw HistoryStoreError.cannotMigrateReadOnly
            }
            try installSchema(database, faultHook: configuration.faultInjection)
        default:
            throw HistoryStoreError.unsupportedSchema(version: Int(clamping: version))
        }
    }

    /// Install schema v1 in one immediate transaction, verifying integrity, and
    /// roll back on any error so a failed migration leaves version 0 intact.
    static func installSchema(_ database: SQLiteDatabase, faultHook: FaultHook?) throws {
        try checkFault(faultHook, .migrationBegin)
        try database.execute("BEGIN IMMEDIATE;")
        do {
            try checkFault(faultHook, .migrationCreateSchema)
            try database.execute(schemaSQL)
            guard try !database.hasForeignKeyViolations() else {
                throw HistoryStoreError.corruption("schema failed foreign_key_check")
            }
            try checkFault(faultHook, .migrationCommit)
            try database.execute("COMMIT;")
        } catch {
            try? database.execute("ROLLBACK;")
            throw error
        }
    }
}

// MARK: - SessionStore replacement

extension SessionStore {
    /// Atomically replace the capture with `capture.captureID`: delete any prior
    /// rows for that ID, then insert the capture and its sessions/protocols in
    /// input order.
    ///
    /// The whole input is validated before `BEGIN IMMEDIATE`: numeric finiteness,
    /// non-negativity, string/protocol/session bounds and duplicate session IDs.
    /// Cancellation is honored before begin and at each 256-row batch boundary, and
    /// any failure rolls the transaction back so the prior committed record
    /// survives untouched.
    func replaceCapture(_ capture: HistoryCaptureRecord, sessions: [HistorySessionRecord]) throws {
        guard !configuration.readOnly else {
            throw HistoryStoreError.readOnly
        }

        try capture.validate()
        guard sessions.count <= HistoryLimits.maxSessionsPerCapture else {
            throw HistoryStoreError.tooManySessions(count: sessions.count)
        }
        var seen = Set<UUID>(minimumCapacity: sessions.count)
        for session in sessions {
            try session.validate()
            guard seen.insert(session.sessionID).inserted else {
                throw HistoryStoreError.duplicateSessionID(session.sessionID.uuidString)
            }
        }

        try checkCancellation()
        try Self.checkFault(faultHook, .replaceBeforeBegin)

        try database.execute("BEGIN IMMEDIATE;")
        do {
            try writeCapture(capture, sessions: sessions)
            try Self.checkFault(faultHook, .replaceCommit)
            try database.execute("COMMIT;")
        } catch {
            try? database.execute("ROLLBACK;")
            throw error
        }
    }

    // MARK: Private

    private func writeCapture(_ capture: HistoryCaptureRecord, sessions: [HistorySessionRecord]) throws {
        let captureID = capture.captureID.uuidString

        let delete = try database.prepare("DELETE FROM captures WHERE id = ?;")
        defer { delete.finalizeStatement() }
        try delete.bindText(1, captureID)
        _ = try delete.step()
        try Self.checkFault(faultHook, .replaceAfterDelete)

        let insertCapture = try database.prepare("""
        INSERT INTO captures (id, started_at, ended_at, source_kind, completeness, session_count)
        VALUES (?, ?, ?, ?, ?, ?);
        """)
        defer { insertCapture.finalizeStatement() }
        try insertCapture.bindText(1, captureID)
        try insertCapture.bindDouble(2, capture.startedAt)
        try insertCapture.bindDouble(3, capture.endedAt)
        try insertCapture.bindInt(4, Int64(capture.sourceKind.rawValue))
        try insertCapture.bindInt(5, Int64(capture.completeness.rawValue))
        try insertCapture.bindInt(6, Int64(sessions.count))
        _ = try insertCapture.step()
        try Self.checkFault(faultHook, .replaceCaptureInsert)

        try insertSessions(sessions, captureID: captureID)
    }

    private func insertSessions(_ sessions: [HistorySessionRecord], captureID: String) throws {
        let insertSession = try database.prepare("""
        INSERT INTO sessions (
            capture_id, session_id, ordinal, start_time, duration, process_name, host,
            source_endpoint, destination_endpoint, status, latency_ms, bytes_up, bytes_down
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """)
        defer { insertSession.finalizeStatement() }
        let insertProtocol = try database.prepare("""
        INSERT INTO session_protocols (capture_id, session_id, protocol_ordinal, value)
        VALUES (?, ?, ?, ?);
        """)
        defer { insertProtocol.finalizeStatement() }

        for (ordinal, session) in sessions.enumerated() {
            if ordinal % HistoryLimits.cancellationBatchSize == 0 {
                try checkCancellation()
                try Self.checkFault(faultHook, .replaceBatchBoundary(ordinal: ordinal))
            }
            insertSession.reset()
            try bindSession(insertSession, captureID: captureID, ordinal: ordinal, session: session)
            _ = try insertSession.step()
            try Self.checkFault(faultHook, .replaceSessionInsert(ordinal: ordinal))

            let sessionID = session.sessionID.uuidString
            for (protocolOrdinal, value) in session.protocols.enumerated() {
                insertProtocol.reset()
                try insertProtocol.bindText(1, captureID)
                try insertProtocol.bindText(2, sessionID)
                try insertProtocol.bindInt(3, Int64(protocolOrdinal))
                try insertProtocol.bindText(4, boundedText(value, field: "protocol"))
                _ = try insertProtocol.step()
            }
            try Self.checkFault(faultHook, .replaceProtocolInsert(ordinal: ordinal))
        }
    }

    private func bindSession(
        _ statement: SQLiteStatement,
        captureID: String,
        ordinal: Int,
        session: HistorySessionRecord
    )
        throws
    {
        try statement.bindText(1, captureID)
        try statement.bindText(2, session.sessionID.uuidString)
        try statement.bindInt(3, Int64(ordinal))
        try statement.bindDouble(4, session.startTime)
        try statement.bindDouble(5, session.duration)
        if let processName = session.processName {
            try statement.bindText(6, boundedText(processName, field: "processName"))
        } else {
            try statement.bindNull(6)
        }
        try statement.bindText(7, boundedText(session.host, field: "host"))
        try statement.bindText(8, boundedText(session.sourceEndpoint, field: "sourceEndpoint"))
        try statement.bindText(9, boundedText(session.destinationEndpoint, field: "destinationEndpoint"))
        try statement.bindInt(10, Int64(session.status.rawValue))
        if let latency = session.latencyMilliseconds {
            try statement.bindDouble(11, latency)
        } else {
            try statement.bindNull(11)
        }
        try statement.bindInt(12, session.bytesUp)
        try statement.bindInt(13, session.bytesDown)
    }
}

// MARK: - SessionStore reads

extension SessionStore {
    /// Fetch one capture by ID, with its database-derived session count, or `nil`.
    func capture(id: UUID) throws -> HistoryStoredCapture? {
        let statement = try database.prepare("""
        SELECT started_at, ended_at, source_kind, completeness, session_count
        FROM captures WHERE id = ?;
        """)
        defer { statement.finalizeStatement() }
        try statement.bindText(1, id.uuidString)
        guard try statement.step() else {
            return nil
        }
        let record = try Self.decodeCapture(
            captureID: id,
            startedAt: statement.columnDouble(0),
            endedAt: statement.columnDouble(1),
            rawSourceKind: statement.columnInt64(2),
            rawCompleteness: statement.columnInt64(3)
        )
        let count = try Self.decodeCount(statement.columnInt64(4), field: "session_count")
        return HistoryStoredCapture(record: record, sessionCount: count)
    }

    /// Read one newest-first page of captures ordered by keyset `(ended_at, id)`
    /// descending. `limit` must be in `1...500`; no OFFSET is used.
    func captures(after cursor: HistoryCaptureCursor?, limit: Int) throws -> HistoryCapturePage {
        let pageLimit = try Self.validatedPageLimit(limit)
        let statement = try capturePageStatement(after: cursor, limit: pageLimit)
        defer { statement.finalizeStatement() }

        var rows: [HistoryStoredCapture] = []
        while try statement.step() {
            guard let identifier = UUID(uuidString: statement.columnText(0) ?? "") else {
                throw HistoryStoreError.corruption("captures.id was not a UUID")
            }
            let record = try Self.decodeCapture(
                captureID: identifier,
                startedAt: statement.columnDouble(1),
                endedAt: statement.columnDouble(2),
                rawSourceKind: statement.columnInt64(3),
                rawCompleteness: statement.columnInt64(4)
            )
            let count = try Self.decodeCount(statement.columnInt64(5), field: "session_count")
            rows.append(HistoryStoredCapture(record: record, sessionCount: count))
        }

        let next = rows.count == pageLimit
            ? rows.last.map { HistoryCaptureCursor(endedAt: $0.record.endedAt, captureID: $0.record.captureID) }
            : nil
        return HistoryCapturePage(captures: rows, nextCursor: next)
    }

    /// Read one ordinal-ascending page of a capture's sessions. `limit` must be in
    /// `1...500`; no OFFSET is used.
    func sessions(
        captureID: UUID,
        after cursor: HistorySessionCursor?,
        limit: Int
    )
        throws -> HistorySessionPage
    {
        let pageLimit = try Self.validatedPageLimit(limit)
        // Ordinals are zero-based and non-negative; -1 selects everything.
        let afterOrdinal = cursor.map { Int64($0.ordinal) } ?? -1

        let statement = try database.prepare("""
        SELECT session_id, ordinal, start_time, duration, process_name, host,
               source_endpoint, destination_endpoint, status, latency_ms, bytes_up, bytes_down
        FROM sessions WHERE capture_id = ? AND ordinal > ?
        ORDER BY ordinal ASC LIMIT ?;
        """)
        defer { statement.finalizeStatement() }
        try statement.bindText(1, captureID.uuidString)
        try statement.bindInt(2, afterOrdinal)
        try statement.bindInt(3, Int64(pageLimit))

        var rows: [HistorySessionRecord] = []
        var lastOrdinal = 0
        while try statement.step() {
            let (record, ordinal) = try decodeSession(statement, captureID: captureID)
            rows.append(record)
            lastOrdinal = ordinal
        }

        let next = rows.count == pageLimit ? HistorySessionCursor(ordinal: lastOrdinal) : nil
        return HistorySessionPage(sessions: rows, nextCursor: next)
    }

    // MARK: Private

    private func capturePageStatement(after cursor: HistoryCaptureCursor?, limit: Int) throws -> SQLiteStatement {
        guard let cursor else {
            let statement = try database.prepare("""
            SELECT id, started_at, ended_at, source_kind, completeness, session_count
            FROM captures ORDER BY ended_at DESC, id DESC LIMIT ?;
            """)
            try statement.bindInt(1, Int64(limit))
            return statement
        }
        let statement = try database.prepare("""
        SELECT id, started_at, ended_at, source_kind, completeness, session_count
        FROM captures WHERE ended_at < ? OR (ended_at = ? AND id < ?)
        ORDER BY ended_at DESC, id DESC LIMIT ?;
        """)
        try statement.bindDouble(1, cursor.endedAt)
        try statement.bindDouble(2, cursor.endedAt)
        try statement.bindText(3, cursor.captureID.uuidString)
        try statement.bindInt(4, Int64(limit))
        return statement
    }

    private func decodeSession(
        _ statement: SQLiteStatement,
        captureID: UUID
    )
        throws -> (record: HistorySessionRecord, ordinal: Int)
    {
        guard let sessionID = UUID(uuidString: statement.columnText(0) ?? "") else {
            throw HistoryStoreError.corruption("sessions.session_id was not a UUID")
        }
        let ordinal = try Self.decodeCount(statement.columnInt64(1), field: "ordinal")
        guard let status = HistorySessionStatus(rawValue: Int(clamping: statement.columnInt64(8))) else {
            throw HistoryStoreError.corruption("sessions.status was not a known value")
        }
        let protocols = try loadProtocols(captureID: captureID, sessionID: sessionID)
        let record = HistorySessionRecord(
            sessionID: sessionID,
            startTime: statement.columnDouble(2),
            duration: statement.columnDouble(3),
            processName: statement.columnIsNull(4) ? nil : statement.columnText(4),
            host: statement.columnText(5) ?? "",
            sourceEndpoint: statement.columnText(6) ?? "",
            destinationEndpoint: statement.columnText(7) ?? "",
            protocols: protocols,
            status: status,
            latencyMilliseconds: statement.columnIsNull(9) ? nil : statement.columnDouble(9),
            bytesUp: statement.columnInt64(10),
            bytesDown: statement.columnInt64(11)
        )
        return (record, ordinal)
    }

    private func loadProtocols(captureID: UUID, sessionID: UUID) throws -> [String] {
        let statement = try database.prepare("""
        SELECT value FROM session_protocols
        WHERE capture_id = ? AND session_id = ? ORDER BY protocol_ordinal ASC;
        """)
        defer { statement.finalizeStatement() }
        try statement.bindText(1, captureID.uuidString)
        try statement.bindText(2, sessionID.uuidString)
        var values: [String] = []
        while try statement.step() {
            values.append(statement.columnText(0) ?? "")
        }
        return values
    }
}

// MARK: - SessionStore retention

extension SessionStore {
    /// Delete whole capture groups oldest-first by keyset `(ended_at, id)` until
    /// every supplied bound holds, atomically. Returns the deleted IDs in
    /// deterministic oldest-first order and the exact deleted session count summed
    /// from each selected capture's stored `session_count` — never from
    /// `sqlite3_changes()`, which omits foreign-key cascade deletes.
    func applyRetention(_ policy: HistoryRetentionPolicy) throws -> HistoryRetentionOutcome {
        guard !configuration.readOnly else {
            throw HistoryStoreError.readOnly
        }
        try policy.validate()
        try checkCancellation()

        try Self.checkFault(faultHook, .retentionBegin)
        try database.execute("BEGIN IMMEDIATE;")
        do {
            let outcome = try performRetention(policy)
            try Self.checkFault(faultHook, .retentionCommit)
            try database.execute("COMMIT;")
            return outcome
        } catch {
            try? database.execute("ROLLBACK;")
            throw error
        }
    }

    // MARK: Private

    /// A capture as loaded for retention: its ID, ordering key and validated
    /// stored session count.
    private struct RetentionCandidate {
        let captureID: UUID
        let endedAt: Double
        let sessionCount: Int
    }

    private func performRetention(_ policy: HistoryRetentionPolicy) throws -> HistoryRetentionOutcome {
        let candidates = try loadRetentionCandidates()
        let prefix = try Self.retentionPrefix(candidates, policy: policy)
        guard prefix > 0 else {
            return HistoryRetentionOutcome(deletedCaptureIDs: [], deletedSessionCount: 0)
        }

        let delete = try database.prepare("DELETE FROM captures WHERE id = ?;")
        defer { delete.finalizeStatement() }

        var deletedIDs: [UUID] = []
        var deletedSessions = 0
        for index in 0 ..< prefix {
            try Self.checkFault(faultHook, .retentionDelete(index: index))
            let candidate = candidates[index]
            delete.reset()
            try delete.bindText(1, candidate.captureID.uuidString)
            _ = try delete.step()
            deletedIDs.append(candidate.captureID)
            let (sum, overflow) = deletedSessions.addingReportingOverflow(candidate.sessionCount)
            guard !overflow else {
                throw HistoryStoreError.integerOverflow(field: "deletedSessionCount")
            }
            deletedSessions = sum
        }
        return HistoryRetentionOutcome(deletedCaptureIDs: deletedIDs, deletedSessionCount: deletedSessions)
    }

    private func loadRetentionCandidates() throws -> [RetentionCandidate] {
        let statement = try database.prepare("""
        SELECT id, ended_at, session_count FROM captures ORDER BY ended_at ASC, id ASC;
        """)
        defer { statement.finalizeStatement() }
        var candidates: [RetentionCandidate] = []
        while try statement.step() {
            guard let identifier = UUID(uuidString: statement.columnText(0) ?? "") else {
                throw HistoryStoreError.corruption("captures.id was not a UUID")
            }
            let count = try Self.decodeCount(statement.columnInt64(2), field: "session_count")
            candidates.append(RetentionCandidate(
                captureID: identifier,
                endedAt: statement.columnDouble(1),
                sessionCount: count
            ))
        }
        return candidates
    }

    /// Compute how many leading (oldest) captures must be deleted so every supplied
    /// bound holds. Each bound deletes an oldest-first prefix, so the union is the
    /// longest single prefix; deleting more only reduces remaining count/sessions,
    /// so the maximum satisfies all bounds simultaneously.
    private static func retentionPrefix(
        _ candidates: [RetentionCandidate],
        policy: HistoryRetentionPolicy
    )
        throws -> Int
    {
        let total = candidates.count
        var prefix = 0

        if let cutoff = policy.oldestAllowedEndDate {
            var count = 0
            while count < total, candidates[count].endedAt < cutoff {
                count += 1
            }
            prefix = max(prefix, count)
        }

        if let maxCaptures = policy.maxCaptureCount {
            prefix = max(prefix, max(0, total - maxCaptures))
        }

        if let maxSessions = policy.maxTotalSessionCount {
            var totalSessions = 0
            for candidate in candidates {
                let (sum, overflow) = totalSessions.addingReportingOverflow(candidate.sessionCount)
                guard !overflow else {
                    throw HistoryStoreError.integerOverflow(field: "totalSessionCount")
                }
                totalSessions = sum
            }
            var remaining = totalSessions
            var count = 0
            while count < total, remaining > maxSessions {
                remaining -= candidates[count].sessionCount
                count += 1
            }
            prefix = max(prefix, count)
        }

        return prefix
    }
}

// MARK: - SessionStore helpers

private extension SessionStore {
    /// Throw a mapped typed error if the fault hook forces a nonzero code at
    /// `stage`; otherwise proceed.
    static func checkFault(_ hook: FaultHook?, _ stage: FaultStage) throws {
        guard let hook else {
            return
        }
        let code = hook(stage)
        guard code == SQLITE_OK else {
            throw HistoryStoreError.map(code, message: "injected fault at \(stage)")
        }
    }

    /// Rebuild a capture record from its columns, decoding both persisted enums
    /// fail-closed.
    static func decodeCapture(
        captureID: UUID,
        startedAt: Double,
        endedAt: Double,
        rawSourceKind: Int64,
        rawCompleteness: Int64
    )
        throws -> HistoryCaptureRecord
    {
        guard let sourceKind = HistorySourceKind(rawValue: Int(clamping: rawSourceKind)) else {
            throw HistoryStoreError.corruption("captures.source_kind was not a known value")
        }
        guard let completeness = HistoryCompleteness(rawValue: Int(clamping: rawCompleteness)) else {
            throw HistoryStoreError.corruption("captures.completeness was not a known value")
        }
        return HistoryCaptureRecord(
            captureID: captureID,
            startedAt: startedAt,
            endedAt: endedAt,
            sourceKind: sourceKind,
            completeness: completeness
        )
    }

    /// Decode a non-negative count/ordinal, overflow- and range-checked.
    static func decodeCount(_ value: Int64, field: String) throws -> Int {
        guard let count = Int(exactly: value) else {
            throw HistoryStoreError.integerOverflow(field: field)
        }
        guard count >= 0 else {
            throw HistoryStoreError.corruption("\(field) was negative")
        }
        return count
    }

    static func validatedPageLimit(_ limit: Int) throws -> Int {
        guard (1 ... HistoryLimits.maxReadPageSize).contains(limit) else {
            throw HistoryStoreError.invalidPageLimit(limit)
        }
        return limit
    }

    /// Re-check a string's UTF-8 byte bound while binding, so an oversized value
    /// can never reach SQLite even if it changed after prevalidation.
    func boundedText(_ value: String, field: String) throws -> String {
        let byteCount = value.utf8.count
        guard byteCount <= HistoryLimits.maxStringUTF8Bytes else {
            throw HistoryStoreError.stringTooLong(field: field, byteCount: byteCount)
        }
        return value
    }

    /// Throw `CancellationError` if the injected cancellation predicate is set.
    func checkCancellation() throws {
        if configuration.isCancelled() {
            throw CancellationError()
        }
    }
}
