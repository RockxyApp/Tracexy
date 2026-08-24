import Foundation

// MARK: - AutomationSourceKind

/// Transport-neutral spelling of a stored capture's origin. It is a *separate*
/// vocabulary from the storage-owned ``HistorySourceKind`` (which is deliberately
/// not `Codable`); N5A never leaks a persisted integer enum into JSON/CSV.
nonisolated enum AutomationSourceKind: String, Codable, Sendable, Equatable {
    case live
    case saved

    // MARK: Lifecycle

    init(_ storage: HistorySourceKind) {
        switch storage {
        case .live: self = .live
        case .saved: self = .saved
        }
    }
}

// MARK: - AutomationCompleteness

/// Transport-neutral spelling of whether a capture is complete or a recoverable
/// prefix. Independent of the persisted ``HistoryCompleteness`` integer enum.
nonisolated enum AutomationCompleteness: String, Codable, Sendable, Equatable {
    case complete
    case incomplete

    // MARK: Lifecycle

    init(_ storage: HistoryCompleteness) {
        switch storage {
        case .complete: self = .complete
        case .incomplete: self = .incomplete
        }
    }
}

// MARK: - AutomationSessionStatus

/// Transport-neutral spelling of the storage-owned session status. It mirrors the
/// storage vocabulary exhaustively so a new persisted case forces a decision here
/// rather than defaulting silently.
nonisolated enum AutomationSessionStatus: String, Codable, Sendable, Equatable {
    case ok
    case warning
    case error

    // MARK: Lifecycle

    init(_ storage: HistorySessionStatus) {
        switch storage {
        case .ok: self = .ok
        case .warning: self = .warning
        case .error: self = .error
        }
    }
}

// MARK: - AutomationFilterField

/// Which filter field a validation error refers to. Kept small and stable so a
/// caller can localize/branch on it without parsing a message.
nonisolated enum AutomationFilterField: String, Sendable, Equatable {
    case process
    case host
    case `protocol`
    case status
    case startTime
    case totalBytes
}

// MARK: - AutomationError

/// The single typed failure domain for N5A request validation and lookup. Store
/// and corruption failures are *not* remapped here — they propagate as the
/// underlying ``HistoryStoreError``/`CancellationError` for the in-process caller.
nonisolated enum AutomationError: Error, Sendable, Equatable {
    /// A caller page size outside the exact `1...500` bound.
    case invalidPageSize(Int)
    /// The explicit capture ID does not exist in the store.
    case captureNotFound(UUID)
    /// A text operand was empty after trimming.
    case emptyFilterOperand(field: AutomationFilterField)
    /// A text operand exceeded the 256 UTF-8 byte bound.
    case filterOperandTooLong(field: AutomationFilterField, byteCount: Int)
    /// A text operand contained a control character.
    case filterOperandContainsControlCharacter(field: AutomationFilterField)
    /// A numeric bound pair was supplied out of order (`atLeast > atMost`).
    case filterBoundsOutOfOrder(field: AutomationFilterField)
    /// A start-time bound was NaN or infinite.
    case nonFiniteFilterBound(field: AutomationFilterField)
    /// A byte bound was negative.
    case negativeByteBound(field: AutomationFilterField)
    /// A text filter was requested without the matching disclosure opt-in — the
    /// disclosure-oracle guard that stops filtering from leaking an undisclosed
    /// value.
    case filterRequiresDisclosure(field: AutomationFilterField)
    /// A cursor carried a non-finite timestamp or negative ordinal.
    case invalidCursor(field: String)
}

// MARK: - AutomationText

/// Deterministic, locale-fixed operand normalization shared by validation and
/// matching. All folding uses `en_US_POSIX` so case-insensitive substring
/// matching never depends on the host locale.
nonisolated enum AutomationText {
    // MARK: Internal

    /// Maximum UTF-8 byte length of any single filter operand.
    static let maxOperandUTF8Bytes = 256

    /// Case-fold `value` under the fixed POSIX locale.
    static func fold(_ value: String) -> String {
        value.folding(options: .caseInsensitive, locale: locale)
    }

    /// Whether the (already folded) `needle` occurs literally in the (already
    /// folded) `haystack`. `.literal` avoids locale-sensitive canonicalization, so
    /// the comparison is byte-stable after folding.
    static func contains(_ haystack: String, _ needle: String) -> Bool {
        haystack.range(of: needle, options: [.literal]) != nil
    }

    /// Trim, reject empty/oversized/control-containing operands, then fold. The
    /// returned value is the normalized form used for matching.
    static func normalizeOperand(_ raw: String, field: AutomationFilterField) throws -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw AutomationError.emptyFilterOperand(field: field)
        }
        let byteCount = trimmed.utf8.count
        guard byteCount <= maxOperandUTF8Bytes else {
            throw AutomationError.filterOperandTooLong(field: field, byteCount: byteCount)
        }
        guard !trimmed.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw AutomationError.filterOperandContainsControlCharacter(field: field)
        }
        return fold(trimmed)
    }

    // MARK: Private

    private static let locale = Locale(identifier: "en_US_POSIX")
}

// MARK: - AutomationDisclosure

/// The independent, opt-in sensitive-field switches. ``minimum`` is the default
/// and omits process, host and both endpoints; each family is enabled separately.
/// Host disclosure is documented as potentially SNI/DNS-derived (see
/// ``AutomationSessionValue/host``).
nonisolated struct AutomationDisclosure: Codable, Sendable, Equatable {
    // MARK: Lifecycle

    init(includesProcess: Bool = false, includesHost: Bool = false, includesEndpoints: Bool = false) {
        self.includesProcess = includesProcess
        self.includesHost = includesHost
        self.includesEndpoints = includesEndpoints
    }

    // MARK: Internal

    /// The privacy-preserving default: no process, host or endpoints projected.
    static let minimum = AutomationDisclosure()

    /// Expose the stored process name family.
    var includesProcess: Bool
    /// Expose the stored, possibly SNI/DNS-derived host family.
    var includesHost: Bool
    /// Expose the stored source/destination endpoint family (one switch for both).
    var includesEndpoints: Bool
}

// MARK: - AutomationCaptureValue

/// The transport-neutral projection of one stored capture. It carries only the
/// durable ID, finite lifetime instants, stable enum spellings and the
/// database-derived session count — no path/file identity or rich evidence.
nonisolated struct AutomationCaptureValue: Codable, Sendable, Equatable {
    // MARK: Lifecycle

    init(_ stored: HistoryStoredCapture) {
        captureID = stored.record.captureID
        startedAt = stored.record.startedAt
        endedAt = stored.record.endedAt
        sourceKind = AutomationSourceKind(stored.record.sourceKind)
        completeness = AutomationCompleteness(stored.record.completeness)
        sessionCount = stored.sessionCount
    }

    // MARK: Internal

    let captureID: UUID
    let startedAt: Double
    let endedAt: Double
    let sourceKind: AutomationSourceKind
    let completeness: AutomationCompleteness
    let sessionCount: Int
}

// MARK: - AutomationSessionValue

/// The transport-neutral projection of one stored session, gated by an
/// ``AutomationDisclosure``. The non-sensitive fields (IDs, timing/duration,
/// ordered protocol strings, status, optional latency, non-negative byte totals)
/// are always present; process/host/endpoints appear only when their family is
/// disclosed, so a minimum projection has them absent *by construction*.
nonisolated struct AutomationSessionValue: Codable, Sendable, Equatable {
    // MARK: Lifecycle

    init(_ record: HistorySessionRecord, disclosure: AutomationDisclosure) {
        sessionID = record.sessionID
        startTime = record.startTime
        duration = record.duration
        protocols = record.protocols
        status = AutomationSessionStatus(record.status)
        latencyMilliseconds = record.latencyMilliseconds
        bytesUp = record.bytesUp
        bytesDown = record.bytesDown
        processName = disclosure.includesProcess ? record.processName : nil
        host = disclosure.includesHost ? record.host : nil
        sourceEndpoint = disclosure.includesEndpoints ? record.sourceEndpoint : nil
        destinationEndpoint = disclosure.includesEndpoints ? record.destinationEndpoint : nil
    }

    // MARK: Internal

    let sessionID: UUID
    let startTime: Double
    let duration: Double
    /// Ordered, storage-bounded protocol raw values (for example `["tcp", "tls"]`).
    let protocols: [String]
    let status: AutomationSessionStatus
    let latencyMilliseconds: Double?
    let bytesUp: Int64
    let bytesDown: Int64
    /// Process name — present only when process disclosure is opted in *and* the
    /// stored value is non-nil.
    let processName: String?
    /// Rendered host label — present only when host disclosure is opted in. This
    /// value can be **SNI- or DNS-derived** exactly like the live Sessions table,
    /// so it is treated as sensitive; stored masking cannot be assumed when the
    /// write-time privacy flag was off.
    let host: String?
    /// Rendered source endpoint — present only when the endpoint family is opted in.
    let sourceEndpoint: String?
    /// Rendered destination endpoint — present only when the endpoint family is
    /// opted in.
    let destinationEndpoint: String?
}

// MARK: - AutomationCaptureCursor

/// An opaque, typed, `Codable` capture cursor. It wraps the storage keyset
/// boundary; converting back to a store cursor validates a finite timestamp.
nonisolated struct AutomationCaptureCursor: Codable, Sendable, Equatable {
    // MARK: Lifecycle

    init(endedAt: Double, captureID: UUID) {
        self.endedAt = endedAt
        self.captureID = captureID
    }

    init(_ storage: HistoryCaptureCursor) {
        endedAt = storage.endedAt
        captureID = storage.captureID
    }

    // MARK: Internal

    let endedAt: Double
    let captureID: UUID

    /// Validate the finite timestamp before it can drive a store read.
    func storageCursor() throws -> HistoryCaptureCursor {
        guard endedAt.isFinite else {
            throw AutomationError.invalidCursor(field: "endedAt")
        }
        return HistoryCaptureCursor(endedAt: endedAt, captureID: captureID)
    }
}

// MARK: - AutomationSessionCursor

/// An opaque, typed, `Codable` session cursor keyed on the store's zero-based
/// ordinal; converting back validates a non-negative ordinal.
nonisolated struct AutomationSessionCursor: Codable, Sendable, Equatable {
    // MARK: Lifecycle

    init(ordinal: Int) {
        self.ordinal = ordinal
    }

    init(_ storage: HistorySessionCursor) {
        ordinal = storage.ordinal
    }

    // MARK: Internal

    let ordinal: Int

    /// Validate the non-negative ordinal before it can drive a store read.
    func storageCursor() throws -> HistorySessionCursor {
        guard ordinal >= 0 else {
            throw AutomationError.invalidCursor(field: "ordinal")
        }
        return HistorySessionCursor(ordinal: ordinal)
    }
}

// MARK: - AutomationSessionFilter

/// A conjunctive (AND) session filter. Every field is optional; a `nil` field
/// imposes no condition. Text operands are substring (process/host) or exact
/// (protocol) matches; there is deliberately **no endpoint predicate**. Numeric
/// bounds are inclusive.
nonisolated struct AutomationSessionFilter: Codable, Sendable, Equatable {
    // MARK: Lifecycle

    init(
        processSubstring: String? = nil,
        hostSubstring: String? = nil,
        protocolEquals: String? = nil,
        status: AutomationSessionStatus? = nil,
        startTimeAtLeast: Double? = nil,
        startTimeAtMost: Double? = nil,
        totalBytesAtLeast: Int64? = nil,
        totalBytesAtMost: Int64? = nil
    ) {
        self.processSubstring = processSubstring
        self.hostSubstring = hostSubstring
        self.protocolEquals = protocolEquals
        self.status = status
        self.startTimeAtLeast = startTimeAtLeast
        self.startTimeAtMost = startTimeAtMost
        self.totalBytesAtLeast = totalBytesAtLeast
        self.totalBytesAtMost = totalBytesAtMost
    }

    // MARK: Internal

    /// The no-op filter: matches every examined row.
    static let none = AutomationSessionFilter()

    var processSubstring: String?
    var hostSubstring: String?
    var protocolEquals: String?
    var status: AutomationSessionStatus?
    var startTimeAtLeast: Double?
    var startTimeAtMost: Double?
    var totalBytesAtLeast: Int64?
    var totalBytesAtMost: Int64?

    /// Validate operands/bounds and produce the folded matcher, or throw a typed
    /// ``AutomationError``. Never touches the store.
    func normalized() throws -> NormalizedSessionFilter {
        let process = try processSubstring.map { try AutomationText.normalizeOperand($0, field: .process) }
        let host = try hostSubstring.map { try AutomationText.normalizeOperand($0, field: .host) }
        let proto = try protocolEquals.map { try AutomationText.normalizeOperand($0, field: .protocol) }

        try Self.validateFiniteBound(startTimeAtLeast, field: .startTime)
        try Self.validateFiniteBound(startTimeAtMost, field: .startTime)
        if let low = startTimeAtLeast, let high = startTimeAtMost, low > high {
            throw AutomationError.filterBoundsOutOfOrder(field: .startTime)
        }

        try Self.validateNonNegativeBound(totalBytesAtLeast, field: .totalBytes)
        try Self.validateNonNegativeBound(totalBytesAtMost, field: .totalBytes)
        if let low = totalBytesAtLeast, let high = totalBytesAtMost, low > high {
            throw AutomationError.filterBoundsOutOfOrder(field: .totalBytes)
        }

        return NormalizedSessionFilter(
            process: process,
            host: host,
            proto: proto,
            status: status,
            startAtLeast: startTimeAtLeast,
            startAtMost: startTimeAtMost,
            bytesAtLeast: totalBytesAtLeast,
            bytesAtMost: totalBytesAtMost
        )
    }

    // MARK: Private

    private static func validateFiniteBound(_ value: Double?, field: AutomationFilterField) throws {
        if let value, !value.isFinite {
            throw AutomationError.nonFiniteFilterBound(field: field)
        }
    }

    private static func validateNonNegativeBound(_ value: Int64?, field: AutomationFilterField) throws {
        if let value, value < 0 {
            throw AutomationError.negativeByteBound(field: field)
        }
    }
}

// MARK: - NormalizedSessionFilter

/// The validated, folded matcher derived from an ``AutomationSessionFilter``. It
/// is an internal evaluation value, never exported, and matching is pure.
nonisolated struct NormalizedSessionFilter: Sendable, Equatable {
    // MARK: Internal

    let process: String?
    let host: String?
    let proto: String?
    let status: AutomationSessionStatus?
    let startAtLeast: Double?
    let startAtMost: Double?
    let bytesAtLeast: Int64?
    let bytesAtMost: Int64?

    /// Whether this matcher reads the process field (drives the disclosure oracle).
    var hasProcessPredicate: Bool {
        process != nil
    }

    /// Whether this matcher reads the host field (drives the disclosure oracle).
    var hasHostPredicate: Bool {
        host != nil
    }

    /// Total bytes with overflow-safe addition: an overflow saturates to
    /// `Int64.max` so a comparison never traps.
    static func totalBytes(_ record: HistorySessionRecord) -> Int64 {
        let (sum, overflow) = record.bytesUp.addingReportingOverflow(record.bytesDown)
        return overflow ? Int64.max : sum
    }

    /// Evaluate the AND of every active predicate against one stored row. Each
    /// field is a small pure helper so this stays flat and easy to reason about.
    func matches(_ record: HistorySessionRecord) -> Bool {
        matchesProcess(record)
            && matchesHost(record)
            && matchesProtocol(record)
            && matchesStatus(record)
            && matchesStartTime(record)
            && matchesBytes(record)
    }

    // MARK: Private

    private func matchesProcess(_ record: HistorySessionRecord) -> Bool {
        guard let process else {
            return true
        }
        guard let name = record.processName else {
            return false
        }
        return AutomationText.contains(AutomationText.fold(name), process)
    }

    private func matchesHost(_ record: HistorySessionRecord) -> Bool {
        guard let host else {
            return true
        }
        return AutomationText.contains(AutomationText.fold(record.host), host)
    }

    private func matchesProtocol(_ record: HistorySessionRecord) -> Bool {
        guard let proto else {
            return true
        }
        return record.protocols.contains { AutomationText.fold($0) == proto }
    }

    private func matchesStatus(_ record: HistorySessionRecord) -> Bool {
        guard let status else {
            return true
        }
        return AutomationSessionStatus(record.status) == status
    }

    private func matchesStartTime(_ record: HistorySessionRecord) -> Bool {
        if let startAtLeast, record.startTime < startAtLeast {
            return false
        }
        if let startAtMost, record.startTime > startAtMost {
            return false
        }
        return true
    }

    private func matchesBytes(_ record: HistorySessionRecord) -> Bool {
        let total = Self.totalBytes(record)
        if let bytesAtLeast, total < bytesAtLeast {
            return false
        }
        if let bytesAtMost, total > bytesAtMost {
            return false
        }
        return true
    }
}

// MARK: - AutomationCapturePage

/// One newest-first page of projected captures plus the opaque cursor to resume
/// after it (or `nil` when no further rows remain) and the caller's page size.
nonisolated struct AutomationCapturePage: Codable, Sendable, Equatable {
    let captures: [AutomationCaptureValue]
    let nextCursor: AutomationCaptureCursor?
    let pageSize: Int
}

// MARK: - AutomationSessionPage

/// One ordinal-ascending page of *matched* sessions for one capture. `examinedCount`
/// is the number of stored rows read on this single page *before* filtering, and
/// `nextCursor` is present whenever the examined page was full — so zero matches
/// never imply end-of-capture.
nonisolated struct AutomationSessionPage: Codable, Sendable, Equatable {
    let captureID: UUID
    let sessions: [AutomationSessionValue]
    /// Rows examined on this page before the filter (0...pageSize).
    let examinedCount: Int
    let nextCursor: AutomationSessionCursor?
    let pageSize: Int
    let disclosure: AutomationDisclosure
}

// MARK: - AutomationCapturePageRequest

/// A validated request for one page of captures.
nonisolated struct AutomationCapturePageRequest: Sendable, Equatable {
    // MARK: Lifecycle

    init(pageSize: Int, cursor: AutomationCaptureCursor? = nil) {
        self.pageSize = pageSize
        self.cursor = cursor
    }

    // MARK: Internal

    let pageSize: Int
    let cursor: AutomationCaptureCursor?

    /// Validate the exact `1...500` page bound.
    func validatePageSize() throws {
        guard (1 ... HistoryLimits.maxReadPageSize).contains(pageSize) else {
            throw AutomationError.invalidPageSize(pageSize)
        }
    }
}

// MARK: - AutomationSessionPageRequest

/// A validated request for one page of a capture's sessions, with its AND filter
/// and disclosure opt-ins.
nonisolated struct AutomationSessionPageRequest: Sendable, Equatable {
    // MARK: Lifecycle

    init(
        captureID: UUID,
        pageSize: Int,
        cursor: AutomationSessionCursor? = nil,
        filter: AutomationSessionFilter = .none,
        disclosure: AutomationDisclosure = .minimum
    ) {
        self.captureID = captureID
        self.pageSize = pageSize
        self.cursor = cursor
        self.filter = filter
        self.disclosure = disclosure
    }

    // MARK: Internal

    let captureID: UUID
    let pageSize: Int
    let cursor: AutomationSessionCursor?
    let filter: AutomationSessionFilter
    let disclosure: AutomationDisclosure

    /// Validate the page bound and filter, and enforce the disclosure oracle:
    /// a process/host predicate requires the matching disclosure opt-in. Returns
    /// the folded matcher for the one page.
    func validated() throws -> NormalizedSessionFilter {
        guard (1 ... HistoryLimits.maxReadPageSize).contains(pageSize) else {
            throw AutomationError.invalidPageSize(pageSize)
        }
        let normalized = try filter.normalized()
        if normalized.hasProcessPredicate, !disclosure.includesProcess {
            throw AutomationError.filterRequiresDisclosure(field: .process)
        }
        if normalized.hasHostPredicate, !disclosure.includesHost {
            throw AutomationError.filterRequiresDisclosure(field: .host)
        }
        return normalized
    }
}
