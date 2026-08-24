import Foundation
import Testing
@testable import Tracexy

// MARK: - SessionStoreTests

@Suite("SessionStore schema, atomic replacement, paging and retention")
struct SessionStoreTests {
    // MARK: Internal

    // MARK: Internal — schema and migration

    @Test("A fresh in-memory store migrates and reads empty")
    func freshStoreIsEmpty() async throws {
        let store = try SessionStore()
        #expect(try await store.capture(id: UUID()) == nil)
        let page = try await store.captures(after: nil, limit: 500)
        #expect(page.captures.isEmpty)
        #expect(page.nextCursor == nil)
    }

    @Test("A writable file database adopts WAL journal mode")
    func writableFileAdoptsWAL() throws {
        let url = Self.temporaryURL()
        defer { Self.removeDatabaseFiles(url) }
        let store = try SessionStore(configuration: .init(location: .file(url)))

        let probe = try SQLiteDatabase(path: url.path, readOnly: false)
        defer { probe.close() }
        let statement = try probe.prepare("PRAGMA journal_mode;")
        defer { statement.finalizeStatement() }
        #expect(try statement.step())
        #expect(statement.columnText(0)?.lowercased() == "wal")
        // Keep the store's WAL connection open across the probe's read.
        withExtendedLifetime(store) {}
    }

    @Test("Schema v1 capture values are non-null")
    func captureSchemaRequiresValues() throws {
        let url = Self.temporaryURL()
        defer { Self.removeDatabaseFiles(url) }
        let store = try SessionStore(configuration: .init(location: .file(url)))

        let probe = try SQLiteDatabase(path: url.path, readOnly: true)
        defer { probe.close() }
        let statement = try probe.prepare("PRAGMA table_info(captures);")
        defer { statement.finalizeStatement() }

        var requiredColumns: Set<String> = []
        while try statement.step() {
            if statement.columnInt64(3) == 1, let name = statement.columnText(1) {
                requiredColumns.insert(name)
            }
        }
        #expect(requiredColumns == [
            "started_at", "ended_at", "source_kind", "completeness", "session_count",
        ])
        withExtendedLifetime(store) {}
    }

    @Test("A failed migration rolls back and leaves version 0 for a clean retry")
    func migrationRollsBackOnFault() async throws {
        let url = Self.temporaryURL()
        defer { Self.removeDatabaseFiles(url) }

        #expect(throws: HistoryStoreError.diskFull) {
            _ = try SessionStore(configuration: .init(
                location: .file(url),
                faultInjection: Self.fault(at: .migrationCommit, code: 13)
            ))
        }

        // A second attempt without the fault migrates cleanly, proving the failed
        // migration left version 0 and created no tables.
        let store = try SessionStore(configuration: .init(location: .file(url)))
        let capture = Self.capture()
        try await store.replaceCapture(capture, sessions: [Self.session()])
        #expect(try await store.capture(id: capture.captureID)?.sessionCount == 1)
    }

    @Test("A future schema version fails closed and is never recreated")
    func futureSchemaVersionFailsClosed() throws {
        let url = Self.temporaryURL()
        defer { Self.removeDatabaseFiles(url) }
        let raw = try SQLiteDatabase(path: url.path, readOnly: false)
        try raw.execute("PRAGMA user_version = 2;")
        raw.close()

        #expect(throws: HistoryStoreError.unsupportedSchema(version: 2)) {
            _ = try SessionStore(configuration: .init(location: .file(url)))
        }
    }

    @Test("A read-only version-0 database cannot migrate")
    func readOnlyVersionZeroCannotMigrate() throws {
        let url = Self.temporaryURL()
        defer { Self.removeDatabaseFiles(url) }
        #expect(FileManager.default.createFile(atPath: url.path, contents: Data()))

        #expect(throws: HistoryStoreError.cannotMigrateReadOnly) {
            _ = try SessionStore(configuration: .init(location: .file(url), readOnly: true))
        }
    }

    @Test("A non-database file maps to typed corruption")
    func nonDatabaseFileMapsToCorruption() throws {
        let url = Self.temporaryURL()
        defer { Self.removeDatabaseFiles(url) }
        let garbage = Data("this is definitely not a sqlite database header".utf8)
        try garbage.write(to: url)

        #expect(throws: HistoryStoreError.self) {
            _ = try SessionStore(configuration: .init(location: .file(url)))
        }
    }

    // MARK: Internal — round-trip and separation

    @Test("A capture and its sessions round-trip with protocols and derived count")
    func captureRoundTrip() async throws {
        let store = try SessionStore()
        let capture = Self.capture(sourceKind: .saved, completeness: .incomplete)
        let sessions = [
            Self.session(protocols: ["tcp", "tls", "http"], status: .ok),
            Self.session(processName: nil, status: .warning, latencyMilliseconds: nil),
            Self.session(protocols: [], status: .error, bytesUp: 0, bytesDown: 9_000),
        ]
        try await store.replaceCapture(capture, sessions: sessions)

        let stored = try #require(try await store.capture(id: capture.captureID))
        #expect(stored.record == capture)
        #expect(stored.sessionCount == 3)

        let page = try await store.sessions(captureID: capture.captureID, after: nil, limit: 500)
        #expect(page.sessions == sessions)
        #expect(page.nextCursor == nil)
    }

    @Test("Sessions are separated by capture ID")
    func capturesAreSeparated() async throws {
        let store = try SessionStore()
        let first = Self.capture(endedAt: 2_000)
        let second = Self.capture(endedAt: 3_000)
        let firstSessions = [Self.session(), Self.session()]
        let secondSessions = [Self.session()]
        try await store.replaceCapture(first, sessions: firstSessions)
        try await store.replaceCapture(second, sessions: secondSessions)

        let firstPage = try await store.sessions(captureID: first.captureID, after: nil, limit: 500)
        let secondPage = try await store.sessions(captureID: second.captureID, after: nil, limit: 500)
        #expect(firstPage.sessions == firstSessions)
        #expect(secondPage.sessions == secondSessions)
        #expect(try await store.capture(id: first.captureID)?.sessionCount == 2)
        #expect(try await store.capture(id: second.captureID)?.sessionCount == 1)
    }

    @Test("Replacing the same capture ID fully swaps its sessions")
    func sameIDReplacementIsAtomic() async throws {
        let store = try SessionStore()
        let capture = Self.capture()
        let original = [Self.session(), Self.session(), Self.session()]
        try await store.replaceCapture(capture, sessions: original)

        let replacement = [Self.session(host: "new.example"), Self.session(host: "new2.example")]
        try await store.replaceCapture(capture, sessions: replacement)

        let page = try await store.sessions(captureID: capture.captureID, after: nil, limit: 500)
        #expect(page.sessions == replacement)
        #expect(try await store.capture(id: capture.captureID)?.sessionCount == 2)
    }

    // MARK: Internal — invalid inputs

    @Test("Duplicate session IDs are rejected and nothing is written")
    func duplicateSessionIDsRejected() async throws {
        let store = try SessionStore()
        let capture = Self.capture()
        let shared = UUID()
        let sessions = [Self.session(sessionID: shared), Self.session(sessionID: shared)]

        await #expect(throws: HistoryStoreError.duplicateSessionID(shared.uuidString)) {
            try await store.replaceCapture(capture, sessions: sessions)
        }
        #expect(try await store.capture(id: capture.captureID) == nil)
    }

    @Test("An oversized string is rejected before any SQL")
    func oversizedStringRejected() async throws {
        let store = try SessionStore()
        let capture = Self.capture()
        let overBound = String(repeating: "a", count: HistoryLimits.maxStringUTF8Bytes + 1)

        await #expect(throws: HistoryStoreError.self) {
            try await store.replaceCapture(capture, sessions: [Self.session(host: overBound)])
        }
        #expect(try await store.capture(id: capture.captureID) == nil)
    }

    @Test("Too many protocols are rejected before any SQL")
    func tooManyProtocolsRejected() async throws {
        let store = try SessionStore()
        let capture = Self.capture()
        let tooMany = (0 ... HistoryLimits.maxProtocolsPerSession).map { "p\($0)" }

        await #expect(throws: HistoryStoreError.tooManyProtocols(count: tooMany.count)) {
            try await store.replaceCapture(capture, sessions: [Self.session(protocols: tooMany)])
        }
    }

    @Test("A page limit outside 1...500 is rejected")
    func pageLimitBoundsEnforced() async throws {
        let store = try SessionStore()
        await #expect(throws: HistoryStoreError.invalidPageLimit(0)) {
            _ = try await store.captures(after: nil, limit: 0)
        }
        await #expect(throws: HistoryStoreError.invalidPageLimit(501)) {
            _ = try await store.captures(after: nil, limit: 501)
        }
        await #expect(throws: HistoryStoreError.invalidPageLimit(501)) {
            _ = try await store.sessions(captureID: UUID(), after: nil, limit: 501)
        }
    }

    @Test("A write against a read-only database is rejected")
    func readOnlyWriteRejected() async throws {
        let url = Self.temporaryURL()
        defer { Self.removeDatabaseFiles(url) }
        // Keep the writer's connection alive for the whole read-only exercise so the
        // migrated schema (and its WAL) stays available to the reader.
        let writer = try SessionStore(configuration: .init(location: .file(url)))

        let reader = try SessionStore(configuration: .init(location: .file(url), readOnly: true))
        await #expect(throws: HistoryStoreError.readOnly) {
            try await reader.replaceCapture(Self.capture(), sessions: [])
        }
        await #expect(throws: HistoryStoreError.readOnly) {
            _ = try await reader.applyRetention(HistoryRetentionPolicy(maxCaptureCount: 0))
        }
        #expect(try await reader.capture(id: UUID()) == nil)
        _ = try await writer.capture(id: UUID())
    }

    // MARK: Internal — cancellation

    @Test("Cancellation before begin preserves the prior record")
    func cancellationBeforeBeginRollsBack() async throws {
        let url = Self.temporaryURL()
        defer { Self.removeDatabaseFiles(url) }
        let gate = CancellationGate(cancelOnCall: 1)
        let store = try SessionStore(configuration: .init(
            location: .file(url),
            isCancelled: { gate.shouldCancel() }
        ))

        let capture = Self.capture()
        try await store.replaceCapture(capture, sessions: [Self.session(), Self.session()])
        gate.arm()

        await #expect(throws: CancellationError.self) {
            try await store.replaceCapture(capture, sessions: [Self.session()])
        }
        #expect(try await store.capture(id: capture.captureID)?.sessionCount == 2)
    }

    @Test("Cancellation at a mid-transaction batch boundary rolls back")
    func cancellationDuringBatchesRollsBack() async throws {
        let url = Self.temporaryURL()
        defer { Self.removeDatabaseFiles(url) }
        // Fire at the third armed gate call: before-begin, ordinal-0 boundary,
        // then the ordinal-256 boundary after 256 rows were already inserted.
        let gate = CancellationGate(cancelOnCall: 3)
        let store = try SessionStore(configuration: .init(
            location: .file(url),
            isCancelled: { gate.shouldCancel() }
        ))

        let capture = Self.capture()
        try await store.replaceCapture(capture, sessions: [Self.session()])
        gate.arm()

        let many = (0 ..< 300).map { _ in Self.session() }
        await #expect(throws: CancellationError.self) {
            try await store.replaceCapture(capture, sessions: many)
        }
        // The prior single-session record survived the rolled-back replacement.
        let page = try await store.sessions(captureID: capture.captureID, after: nil, limit: 500)
        #expect(page.sessions.count == 1)
        #expect(try await store.capture(id: capture.captureID)?.sessionCount == 1)
    }

    // MARK: Internal — fault-injected rollback

    @Test("A disk-full fault mid-insert rolls back and preserves the prior record")
    func diskFullFaultPreservesPriorRecord() async throws {
        let url = Self.temporaryURL()
        defer { Self.removeDatabaseFiles(url) }
        let faulting = FaultBox()
        let store = try SessionStore(configuration: .init(
            location: .file(url),
            faultInjection: { faulting.code(for: $0) }
        ))

        let capture = Self.capture()
        let original = [
            Self.session(host: "a.example"),
            Self.session(host: "b.example"),
            Self.session(host: "c.example")
        ]
        try await store.replaceCapture(capture, sessions: original)

        faulting.arm(stage: .replaceSessionInsert(ordinal: 1), code: 13)
        await #expect(throws: HistoryStoreError.diskFull) {
            try await store.replaceCapture(
                capture,
                sessions: [Self.session(host: "z.example"), Self.session(host: "y.example")]
            )
        }

        let page = try await store.sessions(captureID: capture.captureID, after: nil, limit: 500)
        #expect(page.sessions == original)
        #expect(try await store.capture(id: capture.captureID)?.sessionCount == 3)
    }

    @Test("A busy fault before commit maps to the busy failure and rolls back")
    func busyFaultRollsBack() async throws {
        let url = Self.temporaryURL()
        defer { Self.removeDatabaseFiles(url) }
        let faulting = FaultBox()
        let store = try SessionStore(configuration: .init(
            location: .file(url),
            faultInjection: { faulting.code(for: $0) }
        ))

        let capture = Self.capture()
        try await store.replaceCapture(capture, sessions: [Self.session()])

        faulting.arm(stage: .replaceCommit, code: 5)
        await #expect(throws: HistoryStoreError.busy) {
            try await store.replaceCapture(capture, sessions: [Self.session(), Self.session()])
        }
        #expect(try await store.capture(id: capture.captureID)?.sessionCount == 1)
    }

    @Test("A real competing writer maps SQLite contention to busy")
    func competingWriterMapsToBusy() async throws {
        let url = Self.temporaryURL()
        defer { Self.removeDatabaseFiles(url) }
        let store = try SessionStore(configuration: .init(
            location: .file(url),
            busyTimeout: 0
        ))
        let locker = try SQLiteDatabase(path: url.path, readOnly: false)
        defer {
            try? locker.execute("ROLLBACK;")
            locker.close()
        }
        try locker.execute("BEGIN IMMEDIATE;")

        let capture = Self.capture()
        await #expect(throws: HistoryStoreError.busy) {
            try await store.replaceCapture(capture, sessions: [Self.session()])
        }
        #expect(try await store.capture(id: capture.captureID) == nil)
    }

    // MARK: Internal — deterministic paging

    @Test("Capture paging is newest-first, complete and duplicate-free")
    func capturePagingIsDeterministic() async throws {
        let store = try SessionStore()
        var expected: [UUID] = []
        for index in 0 ..< 12 {
            let capture = Self.capture(endedAt: Double(1_000 + index))
            try await store.replaceCapture(capture, sessions: [Self.session()])
            expected.append(capture.captureID)
        }
        // Newest-first is descending ended_at.
        expected.reverse()

        var collected: [UUID] = []
        var cursor: HistoryCaptureCursor?
        while true {
            let page = try await store.captures(after: cursor, limit: 5)
            collected.append(contentsOf: page.captures.map(\.record.captureID))
            guard let next = page.nextCursor else {
                break
            }
            cursor = next
        }
        #expect(collected == expected)
    }

    @Test("Session paging is ordinal-ascending, complete and duplicate-free")
    func sessionPagingIsDeterministic() async throws {
        let store = try SessionStore()
        let capture = Self.capture()
        let sessions = (0 ..< 23).map { _ in Self.session() }
        try await store.replaceCapture(capture, sessions: sessions)

        var collected: [HistorySessionRecord] = []
        var cursor: HistorySessionCursor?
        while true {
            let page = try await store.sessions(captureID: capture.captureID, after: cursor, limit: 10)
            collected.append(contentsOf: page.sessions)
            guard let next = page.nextCursor else {
                break
            }
            cursor = next
        }
        #expect(collected == sessions)
    }

    // MARK: Internal — retention

    @Test("Retention by capture count deletes whole oldest groups first")
    func retentionByCaptureCount() async throws {
        let store = try SessionStore()
        let captures = try await Self.seedCaptures(store, endedAtSessionCounts: [
            (1_000, 2), (1_001, 3), (1_002, 1), (1_003, 4), (1_004, 2),
        ])

        let outcome = try await store.applyRetention(HistoryRetentionPolicy(maxCaptureCount: 3))
        #expect(outcome.deletedCaptureIDs == [captures[0], captures[1]])
        #expect(outcome.deletedSessionCount == 5)

        let remaining = try await store.captures(after: nil, limit: 500)
        #expect(remaining.captures.count == 3)
    }

    @Test("Retention by total session count deletes oldest until the bound holds")
    func retentionByTotalSessionCount() async throws {
        let store = try SessionStore()
        let captures = try await Self.seedCaptures(store, endedAtSessionCounts: [
            (1_000, 5), (1_001, 5), (1_002, 5),
        ])

        // Total is 15; keep at most 7 → delete the two oldest (10 sessions).
        let outcome = try await store.applyRetention(HistoryRetentionPolicy(maxTotalSessionCount: 7))
        #expect(outcome.deletedCaptureIDs == [captures[0], captures[1]])
        #expect(outcome.deletedSessionCount == 10)
    }

    @Test("Retention by age deletes captures strictly older than the cutoff")
    func retentionByAge() async throws {
        let store = try SessionStore()
        let captures = try await Self.seedCaptures(store, endedAtSessionCounts: [
            (1_000, 1), (1_001, 1), (1_002, 1), (1_003, 1),
        ])

        let outcome = try await store.applyRetention(HistoryRetentionPolicy(oldestAllowedEndDate: 1_002))
        // Strictly older than 1_002 → the first two.
        #expect(outcome.deletedCaptureIDs == [captures[0], captures[1]])
        #expect(outcome.deletedSessionCount == 2)
    }

    @Test("Retention satisfies every supplied bound simultaneously")
    func retentionCombinedBounds() async throws {
        let store = try SessionStore()
        let captures = try await Self.seedCaptures(store, endedAtSessionCounts: [
            (1_000, 10), (1_001, 1), (1_002, 1), (1_003, 1), (1_004, 1),
        ])

        // Count bound alone would delete 1; session bound (keep <= 3) forces the
        // large oldest capture out; the union is the longer prefix.
        let outcome = try await store.applyRetention(HistoryRetentionPolicy(
            maxCaptureCount: 4,
            maxTotalSessionCount: 3,
            oldestAllowedEndDate: 1_001
        ))
        #expect(outcome.deletedCaptureIDs == [captures[0], captures[1]])
        #expect(outcome.deletedSessionCount == 11)

        let remaining = try await store.captures(after: nil, limit: 500)
        #expect(remaining.captures.count == 3)
    }

    @Test("Zero-capture retention clears the whole history (the History clear primitive)")
    func zeroRetentionClearsEverything() async throws {
        let store = try SessionStore()
        let captures = try await Self.seedCaptures(store, endedAtSessionCounts: [
            (1_000, 2), (1_001, 3), (1_002, 1),
        ])

        let outcome = try await store.applyRetention(HistoryRetentionPolicy(maxCaptureCount: 0))
        #expect(Set(outcome.deletedCaptureIDs) == Set(captures))
        #expect(outcome.deletedSessionCount == 6)
        #expect(try await store.captures(after: nil, limit: 500).captures.isEmpty)
    }

    @Test("An empty retention policy deletes nothing")
    func emptyRetentionDeletesNothing() async throws {
        let store = try SessionStore()
        _ = try await Self.seedCaptures(store, endedAtSessionCounts: [(1_000, 1), (1_001, 1)])
        let outcome = try await store.applyRetention(HistoryRetentionPolicy())
        #expect(outcome.deletedCaptureIDs.isEmpty)
        #expect(outcome.deletedSessionCount == 0)
        #expect(try await store.captures(after: nil, limit: 500).captures.count == 2)
    }

    // MARK: Internal — handle cleanup

    @Test("Data persists across store instances, proving the handle is released")
    func dataPersistsAcrossInstances() async throws {
        let url = Self.temporaryURL()
        defer { Self.removeDatabaseFiles(url) }
        let capture = Self.capture()

        do {
            let writer = try SessionStore(configuration: .init(location: .file(url)))
            try await writer.replaceCapture(capture, sessions: [Self.session(), Self.session()])
        }

        let reader = try SessionStore(configuration: .init(location: .file(url)))
        #expect(try await reader.capture(id: capture.captureID)?.sessionCount == 2)
    }

    // MARK: Private

    private static func capture(
        captureID: UUID = UUID(),
        startedAt: Double = 1_000,
        endedAt: Double = 2_000,
        sourceKind: HistorySourceKind = .live,
        completeness: HistoryCompleteness = .complete
    )
        -> HistoryCaptureRecord
    {
        HistoryCaptureRecord(
            captureID: captureID,
            startedAt: startedAt,
            endedAt: endedAt,
            sourceKind: sourceKind,
            completeness: completeness
        )
    }

    private static func session(
        sessionID: UUID = UUID(),
        startTime: Double = 1_000,
        duration: Double = 5,
        processName: String? = "curl",
        host: String = "example.com",
        sourceEndpoint: String = "10.0.0.1:5000",
        destinationEndpoint: String = "93.184.216.34:443",
        protocols: [String] = ["tcp", "tls"],
        status: HistorySessionStatus = .ok,
        latencyMilliseconds: Double? = 12.5,
        bytesUp: Int64 = 100,
        bytesDown: Int64 = 200
    )
        -> HistorySessionRecord
    {
        HistorySessionRecord(
            sessionID: sessionID,
            startTime: startTime,
            duration: duration,
            processName: processName,
            host: host,
            sourceEndpoint: sourceEndpoint,
            destinationEndpoint: destinationEndpoint,
            protocols: protocols,
            status: status,
            latencyMilliseconds: latencyMilliseconds,
            bytesUp: bytesUp,
            bytesDown: bytesDown
        )
    }

    /// Insert captures with the given `(endedAt, sessionCount)` pairs in order and
    /// return their IDs in that (oldest-first) order.
    private static func seedCaptures(
        _ store: SessionStore,
        endedAtSessionCounts: [(Double, Int)]
    )
        async throws -> [UUID]
    {
        var ids: [UUID] = []
        for (endedAt, count) in endedAtSessionCounts {
            let record = capture(endedAt: endedAt)
            let sessions = (0 ..< count).map { _ in session() }
            try await store.replaceCapture(record, sessions: sessions)
            ids.append(record.captureID)
        }
        return ids
    }

    private static func fault(
        at target: SessionStore.FaultStage,
        code: Int32
    )
        -> SessionStore.FaultHook
    {
        { stage in stage == target ? code : 0 }
    }

    private static func temporaryURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("session-store-\(UUID().uuidString).sqlite")
    }

    private static func removeDatabaseFiles(_ url: URL) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            try? FileManager.default.removeItem(at: URL(fileURLWithPath: url.path + suffix))
        }
    }
}

// MARK: - CancellationGate

/// A thread-safe, armable cancellation predicate. Before `arm()` it never cancels,
/// so setup writes complete; after arming it cancels on the `cancelOnCall`-th call,
/// making mid-transaction cancellation deterministic.
private final class CancellationGate: @unchecked Sendable {
    // MARK: Lifecycle

    init(cancelOnCall: Int) {
        self.cancelOnCall = cancelOnCall
    }

    // MARK: Internal

    func arm() {
        lock.lock()
        defer { lock.unlock() }
        armed = true
        count = 0
    }

    func shouldCancel() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard armed else {
            return false
        }
        count += 1
        return count >= cancelOnCall
    }

    // MARK: Private

    private let cancelOnCall: Int
    private let lock = NSLock()
    private var armed = false
    private var count = 0
}

// MARK: - FaultBox

/// A thread-safe, armable fault hook targeting one named transaction stage. Setup
/// writes run fault-free; once armed it forces the given SQLite code exactly at the
/// matching stage.
private final class FaultBox: @unchecked Sendable {
    // MARK: Internal

    func arm(stage: SessionStore.FaultStage, code: Int32) {
        lock.lock()
        defer { lock.unlock() }
        target = stage
        forced = code
    }

    func code(for stage: SessionStore.FaultStage) -> Int32 {
        lock.lock()
        defer { lock.unlock() }
        return stage == target ? forced : 0
    }

    // MARK: Private

    private let lock = NSLock()
    private var target: SessionStore.FaultStage?
    private var forced: Int32 = 0
}
