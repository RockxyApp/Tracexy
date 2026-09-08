import Foundation

// MARK: - InvestigationQueryDraft

/// Capture-local structured input for the Investigation editor. This is deliberately
/// separate from persisted `SessionFilterRule`/`FocusSet` values: it compiles native
/// controls to the typed Core query and has no Codable or persistence surface.
///
/// The draft carries *both* editable representations at once. Switching mode never
/// discards the other one, and only the active `mode` is compiled, so a user can move
/// between the row builder and the session-expression text without losing work.
nonisolated struct InvestigationQueryDraft: Hashable, Sendable {
    enum Combination: String, CaseIterable, Identifiable, Hashable, Sendable {
        case all
        case any

        // MARK: Internal

        var id: String {
            rawValue
        }

        var label: String {
            switch self {
            case .all: "All"
            case .any: "Any"
            }
        }
    }

    /// Which editable representation Apply compiles. `rows` stays the default so an
    /// untouched draft behaves exactly as before.
    enum Mode: String, CaseIterable, Identifiable, Hashable, Sendable {
        case rows
        case expression

        // MARK: Internal

        var id: String {
            rawValue
        }

        var label: String {
            switch self {
            case .rows: "Rows"
            case .expression: "Expression"
            }
        }
    }

    var combination: Combination = .all
    var rows: [InvestigationQueryDraftRow] = [InvestigationQueryDraftRow()]
    /// Declared after `rows` so the existing memberwise initializations keep working.
    var mode: Mode = .rows
    /// The retained session-expression text, kept verbatim across mode switches.
    var expression: String = ""
}

// MARK: - InvestigationQueryDraftRow

nonisolated struct InvestigationQueryDraftRow: Identifiable, Hashable, Sendable {
    // MARK: Lifecycle

    init(
        id: UUID = UUID(),
        isNegated: Bool = false,
        predicate: InvestigationPredicateDraft = .hostContains("")
    ) {
        self.id = id
        self.isNegated = isNegated
        self.predicate = predicate
    }

    // MARK: Internal

    let id: UUID
    var isNegated: Bool
    var predicate: InvestigationPredicateDraft
}

// MARK: - InvestigationDraftField

nonisolated enum InvestigationDraftField: String, CaseIterable, Identifiable, Hashable, Sendable {
    case process
    case host
    case ip
    case cidr
    case port
    case `protocol`
    case status
    case finding
    case startTime
    case totalBytes
    case evidence

    // MARK: Internal

    var id: String {
        rawValue
    }

    var label: String {
        switch self {
        case .process: "Process"
        case .host: "Host"
        case .ip: "IP Address"
        case .cidr: "CIDR"
        case .port: "Port"
        case .protocol: "Protocol"
        case .status: "Status"
        case .finding: "Finding"
        case .startTime: "Start Time"
        case .totalBytes: "Total Bytes"
        case .evidence: "Has Evidence"
        }
    }
}

// MARK: - InvestigationPredicateDraft

/// Editable values for one structured row. Numeric values remain strings until Apply
/// so a partially typed field never mutates the last accepted query.
nonisolated enum InvestigationPredicateDraft: Hashable, Sendable {
    case processContains(String)
    case hostContains(String)
    case ipEquals(String, scope: EndpointScope)
    case cidrContains(String, scope: EndpointScope)
    case portInRange(lower: String, upper: String, scope: EndpointScope)
    case protocolStackContains(ProtocolKind)
    case statusEquals(SessionStatus)
    case findingKind(QueryFindingKind)
    case startDateInRange(lower: Date, upper: Date)
    case totalBytesInRange(lower: String, upper: String)
    case hasEvidence(QueryEvidenceField)

    // MARK: Internal

    var field: InvestigationDraftField {
        switch self {
        case .processContains: .process
        case .hostContains: .host
        case .ipEquals: .ip
        case .cidrContains: .cidr
        case .portInRange: .port
        case .protocolStackContains: .protocol
        case .statusEquals: .status
        case .findingKind: .finding
        case .startDateInRange: .startTime
        case .totalBytesInRange: .totalBytes
        case .hasEvidence: .evidence
        }
    }

    static func initialValue(for field: InvestigationDraftField, now: Date = Date())
        -> InvestigationPredicateDraft
    {
        switch field {
        case .process: .processContains("")
        case .host: .hostContains("")
        case .ip: .ipEquals("", scope: .either)
        case .cidr: .cidrContains("", scope: .either)
        case .port: .portInRange(lower: "", upper: "", scope: .either)
        case .protocol: .protocolStackContains(.tcp)
        case .status: .statusEquals(.warning)
        case .finding: .findingKind(.reset)
        case .startTime: .startDateInRange(lower: now, upper: now)
        case .totalBytes: .totalBytesInRange(lower: "", upper: "")
        case .evidence: .hasEvidence(.anyFinding)
        }
    }
}

// MARK: - InvestigationQueryDraftError

nonisolated struct InvestigationQueryDraftError: Error, Hashable, Sendable {
    enum Reason: Hashable, Sendable {
        case emptyDraft
        case tooManyRows(limit: Int)
        case invalidIPAddress
        case invalidCIDR
        case invalidPort
        case invalidByteCount
        /// The session-expression text could not be parsed. Always draft-level: the
        /// typed position inside the error locates the offending characters.
        case expression(SessionQueryParseError)
        case core(QueryValidationError)
    }

    /// `nil` identifies a draft-level failure; otherwise the exact editable row owns
    /// the error and remains visible for correction.
    let rowID: UUID?
    let reason: Reason
}

// MARK: - CompiledInvestigationQueryDraft

nonisolated struct CompiledInvestigationQueryDraft: Hashable, Sendable {
    let query: InvestigationQuery
    let compiled: CompiledInvestigationQuery
}

// MARK: - InvestigationQueryDraftCompiler

nonisolated struct InvestigationQueryDraftCompiler: Hashable, Sendable {
    // MARK: Lifecycle

    init(
        engine: InvestigationQueryEngine = InvestigationQueryEngine(),
        parser: SessionQueryParser = SessionQueryParser()
    ) {
        self.engine = engine
        self.parser = parser
    }

    // MARK: Internal

    static let maximumRows = InvestigationQueryEngine.Configuration.productionMaxChildrenPerGroup
    static let maximumExpressionUTF8Bytes = SessionQueryParser.Configuration.productionMaxUTF8Bytes

    let engine: InvestigationQueryEngine
    let parser: SessionQueryParser

    /// Compile whichever representation the draft's `mode` selects. Both paths end in
    /// the same ``InvestigationQueryEngine/compile(_:)`` validation, so bounds and
    /// three-valued semantics are identical however the query was written.
    func compile(_ draft: InvestigationQueryDraft) throws -> CompiledInvestigationQueryDraft {
        switch draft.mode {
        case .rows: try compileRows(draft)
        case .expression: try compileExpression(draft)
        }
    }

    // MARK: Private

    private func compileExpression(
        _ draft: InvestigationQueryDraft
    )
        throws -> CompiledInvestigationQueryDraft
    {
        let query: InvestigationQuery
        do {
            query = try parser.parse(draft.expression)
        } catch let error as SessionQueryParseError {
            throw InvestigationQueryDraftError(rowID: nil, reason: .expression(error))
        }
        do {
            return try CompiledInvestigationQueryDraft(query: query, compiled: engine.compile(query))
        } catch let error as QueryValidationError {
            throw InvestigationQueryDraftError(rowID: nil, reason: .core(error))
        }
    }

    private func compileRows(
        _ draft: InvestigationQueryDraft
    )
        throws -> CompiledInvestigationQueryDraft
    {
        guard !draft.rows.isEmpty else {
            throw InvestigationQueryDraftError(rowID: nil, reason: .emptyDraft)
        }
        guard draft.rows.count <= Self.maximumRows else {
            throw InvestigationQueryDraftError(
                rowID: nil,
                reason: .tooManyRows(limit: Self.maximumRows)
            )
        }

        let children = try draft.rows.map { row in
            let leaf = try InvestigationQuery.leaf(predicate(for: row))
            let node = row.isNegated ? InvestigationQuery.not(leaf) : leaf
            do {
                _ = try engine.compile(node)
            } catch let error as QueryValidationError {
                throw InvestigationQueryDraftError(rowID: row.id, reason: .core(error))
            }
            return node
        }
        let query: InvestigationQuery = switch draft.combination {
        case .all: .all(children)
        case .any: .any(children)
        }
        do {
            return try CompiledInvestigationQueryDraft(query: query, compiled: engine.compile(query))
        } catch let error as QueryValidationError {
            throw InvestigationQueryDraftError(rowID: nil, reason: .core(error))
        }
    }

    private func predicate(for row: InvestigationQueryDraftRow) throws -> QueryPredicate {
        switch row.predicate {
        case let .processContains(value):
            return .processContains(value)
        case let .hostContains(value):
            return .hostContains(value)
        case let .ipEquals(value, scope):
            guard let address = IPAddressValue(parsing: normalizedScalar(value)) else {
                throw InvestigationQueryDraftError(rowID: row.id, reason: .invalidIPAddress)
            }
            return .ipEquals(address, scope: scope)
        case let .cidrContains(value, scope):
            guard let cidr = CIDRValue(parsing: normalizedScalar(value)) else {
                throw InvestigationQueryDraftError(rowID: row.id, reason: .invalidCIDR)
            }
            return .cidrContains(cidr, scope: scope)
        case let .portInRange(lower, upper, scope):
            guard let lower = parseUInt16(lower), let upper = parseUInt16(upper) else {
                throw InvestigationQueryDraftError(rowID: row.id, reason: .invalidPort)
            }
            return .portInRange(lower: lower, upper: upper, scope: scope)
        case let .protocolStackContains(value):
            return .protocolStackContains(value)
        case let .statusEquals(value):
            return .statusEquals(value)
        case let .findingKind(value):
            return .findingKind(value)
        case let .startDateInRange(lower, upper):
            return .startDateInRange(lower: lower, upper: upper)
        case let .totalBytesInRange(lower, upper):
            guard let lower = parseNonNegativeInt(lower), let upper = parseNonNegativeInt(upper) else {
                throw InvestigationQueryDraftError(rowID: row.id, reason: .invalidByteCount)
            }
            return .totalBytesInRange(lower: lower, upper: upper)
        case let .hasEvidence(value):
            return .hasEvidence(value)
        }
    }

    private func normalizedScalar(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func parseUInt16(_ value: String) -> UInt16? {
        let value = normalizedScalar(value)
        guard isASCIIDecimal(value) else {
            return nil
        }
        return UInt16(value)
    }

    private func parseNonNegativeInt(_ value: String) -> Int? {
        let value = normalizedScalar(value)
        guard isASCIIDecimal(value) else {
            return nil
        }
        return Int(value)
    }

    private func isASCIIDecimal(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }
    }
}
