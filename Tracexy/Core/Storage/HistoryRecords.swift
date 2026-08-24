import Foundation

// MARK: - HistoryLimits

/// The frozen N4a hard bounds. Every limit is checked before any SQL runs and,
/// where a per-row string binding could still exceed a bound, checked again while
/// binding. These are storage invariants, not tunables — they never widen at
/// runtime.
nonisolated enum HistoryLimits {
    /// Maximum sessions accepted in one capture replacement.
    static let maxSessionsPerCapture = 100_000
    /// Maximum ordered protocol raw values retained per session.
    static let maxProtocolsPerSession = 16
    /// Maximum UTF-8 byte length of any single stored string.
    static let maxStringUTF8Bytes = 4_096
    /// Sessions are inserted in bounded batches; cancellation is honored at each
    /// batch boundary.
    static let cancellationBatchSize = 256
    /// Maximum records returned by any single keyset read page.
    static let maxReadPageSize = 500
}

// MARK: - HistorySourceKind

/// How a capture was obtained. Persisted as a stable `INTEGER`; an unknown value
/// read back is fail-closed corruption, never a silent default.
nonisolated enum HistorySourceKind: Int, Sendable, Equatable, CaseIterable {
    case live = 0
    case saved = 1
}

// MARK: - HistoryCompleteness

/// Whether a capture is a complete record or a recoverable prefix. Persisted as a
/// stable `INTEGER`.
nonisolated enum HistoryCompleteness: Int, Sendable, Equatable, CaseIterable {
    case complete = 0
    case incomplete = 1
}

// MARK: - HistorySessionStatus

/// The storage-owned session status. It is deliberately its own small vocabulary,
/// never a persisted copy of a transitional UI value. Persisted as a stable
/// `INTEGER`.
nonisolated enum HistorySessionStatus: Int, Sendable, Equatable, CaseIterable {
    case ok = 0
    case warning = 1
    case error = 2
}

// MARK: - HistoryCaptureRecord

/// The neutral, storage-owned identity and lifetime of one persisted capture. It
/// carries a durable minted `captureID` — never a per-launch runtime epoch — and
/// finite start/end timestamps. The database derives the session count from the
/// rows inserted alongside it; the record never supplies or trusts one.
nonisolated struct HistoryCaptureRecord: Sendable, Equatable {
    /// Durable capture identity, stable across launches.
    let captureID: UUID
    /// Finite capture start (seconds since 1970).
    let startedAt: Double
    /// Finite capture end (seconds since 1970); must be `>= startedAt`.
    let endedAt: Double
    let sourceKind: HistorySourceKind
    let completeness: HistoryCompleteness

    /// Validate every finite/ordering invariant before any SQL touches this record.
    func validate() throws {
        guard startedAt.isFinite else {
            throw HistoryStoreError.nonFiniteValue(field: "startedAt")
        }
        guard endedAt.isFinite else {
            throw HistoryStoreError.nonFiniteValue(field: "endedAt")
        }
        guard endedAt >= startedAt else {
            throw HistoryStoreError.endBeforeStart
        }
    }
}

// MARK: - HistorySessionRecord

/// The neutral, storage-owned summary of one session inside a capture. It keys by
/// `(captureID, sessionID)` — the `captureID` is supplied by the enclosing
/// ``SessionStore/replaceCapture(_:sessions:)`` call, so the record itself carries
/// only its own `sessionID`. It holds bounded rendered/neutral fields only: it has
/// no raw bytes, decoded layer trees, dedicated SNI/DNS evidence fields, typed
/// evidence, locator, finding or file identity. The normalized display `host` can
/// still be derived from SNI or DNS, exactly like the live Sessions table.
nonisolated struct HistorySessionRecord: Sendable, Equatable, Identifiable {
    /// The deterministic, tuple-derived session identity within its capture.
    let sessionID: UUID
    /// Finite session start (seconds since 1970).
    let startTime: Double
    /// Finite, non-negative session duration in seconds.
    let duration: Double
    /// Optional attributed process name.
    let processName: String?
    /// Rendered neutral host label.
    let host: String
    /// Rendered source endpoint string.
    let sourceEndpoint: String
    /// Rendered destination endpoint string.
    let destinationEndpoint: String
    /// Ordered protocol raw values (for example `["tcp", "tls", "http"]`).
    let protocols: [String]
    let status: HistorySessionStatus
    /// Optional finite, non-negative latency in milliseconds.
    let latencyMilliseconds: Double?
    /// Non-negative bytes sent in the canonical `a → b` direction.
    let bytesUp: Int64
    /// Non-negative bytes sent in the canonical `b → a` direction.
    let bytesDown: Int64

    var id: UUID {
        sessionID
    }

    /// Validate every bound and finite/non-negative invariant before any SQL. The
    /// string byte bounds are re-checked while binding, so an oversized string can
    /// never reach SQLite even if a caller mutated it after validation.
    func validate() throws {
        guard startTime.isFinite else {
            throw HistoryStoreError.nonFiniteValue(field: "startTime")
        }
        guard duration.isFinite else {
            throw HistoryStoreError.nonFiniteValue(field: "duration")
        }
        guard duration >= 0 else {
            throw HistoryStoreError.negativeValue(field: "duration")
        }
        if let latencyMilliseconds {
            guard latencyMilliseconds.isFinite else {
                throw HistoryStoreError.nonFiniteValue(field: "latencyMilliseconds")
            }
            guard latencyMilliseconds >= 0 else {
                throw HistoryStoreError.negativeValue(field: "latencyMilliseconds")
            }
        }
        guard bytesUp >= 0 else {
            throw HistoryStoreError.negativeValue(field: "bytesUp")
        }
        guard bytesDown >= 0 else {
            throw HistoryStoreError.negativeValue(field: "bytesDown")
        }
        guard protocols.count <= HistoryLimits.maxProtocolsPerSession else {
            throw HistoryStoreError.tooManyProtocols(count: protocols.count)
        }
        try HistoryStoreError.requireStringBound(processName, field: "processName")
        try HistoryStoreError.requireStringBound(host, field: "host")
        try HistoryStoreError.requireStringBound(sourceEndpoint, field: "sourceEndpoint")
        try HistoryStoreError.requireStringBound(destinationEndpoint, field: "destinationEndpoint")
        for value in protocols {
            try HistoryStoreError.requireStringBound(value, field: "protocol")
        }
    }
}

// MARK: - HistoryStoredCapture

/// A capture read back from storage: the neutral input record plus the
/// database-derived session count. The input ``HistoryCaptureRecord`` never
/// carries a count, so this read wrapper is the only place the derived value is
/// exposed.
nonisolated struct HistoryStoredCapture: Sendable, Equatable, Identifiable {
    let record: HistoryCaptureRecord
    /// The database-derived count of sessions stored under this capture.
    let sessionCount: Int

    var id: UUID {
        record.captureID
    }
}

// MARK: - HistoryCaptureCursor

/// A storage-owned keyset cursor for newest-first capture paging. It carries the
/// exact `(endedAt, captureID)` boundary of the last returned row so the next page
/// resumes deterministically without OFFSET.
nonisolated struct HistoryCaptureCursor: Sendable, Equatable {
    let endedAt: Double
    let captureID: UUID
}

// MARK: - HistorySessionCursor

/// A storage-owned keyset cursor for ordinal-ascending session paging.
nonisolated struct HistorySessionCursor: Sendable, Equatable {
    /// The zero-based ordinal of the last returned session; the next page reads
    /// strictly greater ordinals.
    let ordinal: Int
}

// MARK: - HistoryCapturePage

/// One newest-first page of captures plus the cursor to resume after it, or `nil`
/// when the page was not full and no further rows remain.
nonisolated struct HistoryCapturePage: Sendable, Equatable {
    let captures: [HistoryStoredCapture]
    let nextCursor: HistoryCaptureCursor?
}

// MARK: - HistorySessionPage

/// One ordinal-ascending page of sessions plus the cursor to resume after it.
nonisolated struct HistorySessionPage: Sendable, Equatable {
    let sessions: [HistorySessionRecord]
    let nextCursor: HistorySessionCursor?
}

// MARK: - HistoryRetentionPolicy

/// The explicit, caller-supplied retention bounds. Every field is optional; a
/// `nil` field imposes no condition. N4a never reads settings, starts a timer or
/// schedules retention itself — the caller decides when to apply this.
nonisolated struct HistoryRetentionPolicy: Sendable, Equatable {
    // MARK: Lifecycle

    init(
        maxCaptureCount: Int? = nil,
        maxTotalSessionCount: Int? = nil,
        oldestAllowedEndDate: Double? = nil
    ) {
        self.maxCaptureCount = maxCaptureCount
        self.maxTotalSessionCount = maxTotalSessionCount
        self.oldestAllowedEndDate = oldestAllowedEndDate
    }

    // MARK: Internal

    /// Maximum captures to keep; older whole captures beyond this are deleted.
    let maxCaptureCount: Int?
    /// Maximum total sessions to keep across all captures.
    let maxTotalSessionCount: Int?
    /// Captures whose `endedAt` is strictly older than this (seconds since 1970)
    /// are deleted.
    let oldestAllowedEndDate: Double?

    /// Validate the bounds before any SQL: counts must be non-negative and a
    /// supplied cutoff date must be finite.
    func validate() throws {
        if let maxCaptureCount, maxCaptureCount < 0 {
            throw HistoryStoreError.negativeValue(field: "maxCaptureCount")
        }
        if let maxTotalSessionCount, maxTotalSessionCount < 0 {
            throw HistoryStoreError.negativeValue(field: "maxTotalSessionCount")
        }
        if let oldestAllowedEndDate, !oldestAllowedEndDate.isFinite {
            throw HistoryStoreError.nonFiniteValue(field: "oldestAllowedEndDate")
        }
    }
}

// MARK: - HistoryRetentionOutcome

/// The deterministic result of one retention pass: exactly which captures were
/// deleted, oldest-first, and the exact number of sessions removed — summed from
/// each deleted capture's validated `session_count`, never from a cascade change
/// count.
nonisolated struct HistoryRetentionOutcome: Sendable, Equatable {
    /// Deleted capture IDs in deterministic oldest-first `(endedAt, id)` order.
    let deletedCaptureIDs: [UUID]
    /// Exact sessions removed, summed from each deleted capture's stored count.
    let deletedSessionCount: Int
}

// MARK: - HistoryStoreError

/// The single typed failure domain for the history store. Validation failures are
/// raised before any SQL; SQLite result codes map to distinct cases; a corrupt
/// persisted enum or unsupported schema is fail-closed. Cancellation is reported
/// separately as Swift's `CancellationError`.
nonisolated enum HistoryStoreError: Error, Equatable {
    /// A numeric field was NaN or infinite.
    case nonFiniteValue(field: String)
    /// A field that must be non-negative was negative.
    case negativeValue(field: String)
    /// A capture's `endedAt` preceded its `startedAt`.
    case endBeforeStart
    /// A string exceeded the UTF-8 byte bound.
    case stringTooLong(field: String, byteCount: Int)
    /// More protocol values than the per-session bound.
    case tooManyProtocols(count: Int)
    /// More sessions than the per-capture bound.
    case tooManySessions(count: Int)
    /// The same session ID appeared twice in one replacement.
    case duplicateSessionID(String)
    /// A read page limit outside `1...500`.
    case invalidPageLimit(Int)
    /// A stored integer did not fit its expected Swift range.
    case integerOverflow(field: String)
    /// A stored enum/UUID value could not be decoded (fail-closed corruption).
    case corruption(String)
    /// The database reported `SQLITE_BUSY`.
    case busy
    /// The database reported `SQLITE_LOCKED`.
    case locked
    /// A write was attempted against a read-only database.
    case readOnly
    /// The database reported `SQLITE_FULL`.
    case diskFull
    /// A schema newer than this build's version was found; it is never downgraded
    /// or silently recreated.
    case unsupportedSchema(version: Int)
    /// A read-only database still at schema version 0 cannot be migrated.
    case cannotMigrateReadOnly
    /// A required pragma could not be set/verified before migration.
    case configurationFailed(String)
    /// Any other SQLite result code, preserved for diagnosis.
    case sqlite(code: Int32, message: String)

    // MARK: Internal

    /// Enforce the UTF-8 byte bound for one optional string; a `nil` value passes.
    static func requireStringBound(_ value: String?, field: String) throws {
        guard let value else {
            return
        }
        let byteCount = value.utf8.count
        guard byteCount <= HistoryLimits.maxStringUTF8Bytes else {
            throw HistoryStoreError.stringTooLong(field: field, byteCount: byteCount)
        }
    }
}
