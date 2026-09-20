import Foundation

// This file declares the bounded local audit trail for the read-only MCP
// boundary. It is deliberately a *minimization* type, not a log: it can only
// express an instant, a tool name, a coarse result class, the authorized Project
// id, and the **names** of the filter fields a request used. There is no field
// for an operand, host, process name, endpoint, path, payload, cursor value or
// returned row, so an oversharing record cannot be written by mistake.

// MARK: - MCPAuditResult

/// The coarse outcome of one call. It records *that* a call was refused, never
/// what it asked for.
nonisolated enum MCPAuditResult: String, Codable, Sendable, Equatable {
    /// The call was authorized and answered.
    case ok
    /// The grant was absent, stale, superseded, or named another Project.
    case denied
    /// The request was malformed, out of bounds, or named an unknown tool.
    case invalid
    /// The authorized database could not be read.
    case unavailable
}

// MARK: - MCPAuditTool

/// The closed set of tool names the trail can carry: the three advertised names,
/// or `unknown` for anything else. A client-supplied name never reaches the
/// file — a refused call is recorded as *unknown*, not as whatever was asked.
nonisolated enum MCPAuditTool: String, Codable, Sendable, Equatable, CaseIterable {
    case describeScope = "describe_scope"
    case listCaptures = "list_captures"
    case listSessions = "list_sessions"
    case unknown

    // MARK: Lifecycle

    /// Canonicalize a dispatched name. Anything that is not exactly one of the
    /// advertised names is `unknown`.
    init(name: String) {
        switch MCPToolName(rawValue: name) {
        case .describeScope: self = .describeScope
        case .listCaptures: self = .listCaptures
        case .listSessions: self = .listSessions
        case nil: self = .unknown
        }
    }
}

// MARK: - MCPAuditRecord

/// One bounded audit entry.
///
/// Both names it carries are drawn from closed sets at construction *and* at
/// decode: the tool is one of ``MCPAuditTool`` and every filter field is one of
/// ``MCPFilterFieldName``. A request cannot persist an arbitrary string, and a
/// tampered trail cannot replay one back into the Settings surface.
nonisolated struct MCPAuditRecord: Codable, Sendable, Equatable {
    // MARK: Lifecycle

    init(
        at time: Double,
        tool: String,
        result: MCPAuditResult,
        projectID: UUID?,
        filterFields: [String] = []
    ) {
        self.time = time
        self.tool = MCPAuditTool(name: tool).rawValue
        self.result = result
        self.projectID = projectID
        // Allowlisted, sorted and de-duplicated so the record is deterministic,
        // and bounded so a hostile request cannot grow the trail through its
        // field list.
        let known = filterFields.compactMap { MCPFilterFieldName(rawValue: $0)?.rawValue }
        self.filterFields = Array(Set(known)).sorted().prefix(Self.maxFilterFields).map { $0 }
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            at: container.decode(Double.self, forKey: .time),
            tool: container.decode(String.self, forKey: .tool),
            result: container.decode(MCPAuditResult.self, forKey: .result),
            projectID: container.decodeIfPresent(UUID.self, forKey: .projectID),
            filterFields: container.decodeIfPresent([String].self, forKey: .filterFields) ?? []
        )
    }

    // MARK: Internal

    /// The longest tool name the trail can carry; every ``MCPAuditTool`` fits.
    static let maxToolNameLength = 64
    static let maxFilterFields = 16

    /// Seconds since the reference date.
    let time: Double
    /// The canonical tool name — one of ``MCPAuditTool``'s raw values.
    let tool: String
    let result: MCPAuditResult
    /// The authorized Project, or `nil` when no valid grant existed.
    let projectID: UUID?
    /// Allowlisted filter **field names** only, sorted. Never an operand.
    let filterFields: [String]

    // MARK: Private

    private enum CodingKeys: String, CodingKey {
        case time
        case tool
        case result
        case projectID
        case filterFields
    }
}

// MARK: - MCPAuditTrail

/// A bounded, owner-only, newline-delimited JSON trail. Appending trims the file
/// to the newest ``MCPGrantLimits/maxAuditRecords`` records, so the trail can
/// never grow without limit and never needs a retention job.
///
/// Every failure is swallowed deliberately: an unwritable audit file must not
/// turn an authorized read into an error, and must not become a channel that
/// reports filesystem state back to a client.
nonisolated struct MCPAuditTrail: Sendable {
    // MARK: Lifecycle

    init(url: URL, limit: Int = MCPGrantLimits.maxAuditRecords) {
        self.url = url
        self.limit = max(1, limit)
    }

    // MARK: Internal

    let url: URL

    /// Append one record, trimming to the newest `limit` records. Best effort.
    func append(_ record: MCPAuditRecord) {
        var records = recent(limit: limit)
        records.append(record)
        if records.count > limit {
            records.removeFirst(records.count - limit)
        }
        write(records)
    }

    /// The newest records, oldest-first, bounded by `limit`. An unreadable or
    /// partially corrupt trail yields the records that did decode.
    func recent(limit: Int) -> [MCPAuditRecord] {
        guard let data = FileManager.default.contents(atPath: url.path) else {
            return []
        }
        guard let text = String(data: data, encoding: .utf8) else {
            return []
        }
        let decoder = JSONDecoder()
        var records: [MCPAuditRecord] = []
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            guard let record = try? decoder.decode(MCPAuditRecord.self, from: Data(line.utf8)) else {
                continue
            }
            records.append(record)
        }
        let bound = max(0, limit)
        if records.count > bound {
            records.removeFirst(records.count - bound)
        }
        return records
    }

    /// Remove the trail entirely. Used by an explicit revoke, so revoking leaves
    /// nothing behind to read.
    func clear() {
        try? FileManager.default.removeItem(at: url)
    }

    // MARK: Private

    private let limit: Int

    private func write(_ records: [MCPAuditRecord]) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var payload = Data()
        for record in records {
            guard let line = try? encoder.encode(record) else {
                continue
            }
            payload.append(line)
            payload.append(0x0A)
        }
        let manager = FileManager.default
        try? manager.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        // Owner-only from the moment it exists: the trail names the Project a
        // grant authorized, so it is never group- or world-readable.
        if manager.fileExists(atPath: url.path) {
            try? payload.write(to: url, options: [.atomic])
            try? manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } else {
            manager.createFile(atPath: url.path, contents: payload, attributes: [.posixPermissions: 0o600])
        }
    }
}
