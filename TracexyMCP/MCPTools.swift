import Foundation

// This file declares the three read-only tools the bundled MCP executable
// advertises, their exact input schemas, and the bounded decoding from a client's
// `arguments` object onto the existing N5A automation request values.
//
// The surface is deliberately closed. There is no endpoint predicate, no CSV or
// file output, no path argument, no arbitrary SQL, no write, no capture control,
// and no raw-frame access — a request can only ask for one bounded page of the
// one Project a grant already authorized.

// MARK: - MCPToolName

/// The complete advertised tool set.
nonisolated enum MCPToolName: String, CaseIterable, Sendable {
    case describeScope = "describe_scope"
    case listCaptures = "list_captures"
    case listSessions = "list_sessions"
}

// MARK: - MCPFilterFieldName

/// The closed set of `list_sessions` filter keys. It is the single source for
/// the advertised schema, the argument decoder and the audit allowlist, so the
/// three cannot drift apart.
nonisolated enum MCPFilterFieldName: String, CaseIterable, Sendable, Equatable {
    case processSubstring
    case hostSubstring
    case protocolEquals
    case status
    case startTimeAtLeast
    case startTimeAtMost
    case totalBytesAtLeast
    case totalBytesAtMost
}

// MARK: - MCPToolFailure

/// Why a tool call was refused before it reached the store. Each maps to a
/// JSON-RPC error and carries no operand, host, path or row.
nonisolated enum MCPToolFailure: Error, Sendable, Equatable {
    case unknownTool(String)
    case missingArgument(String)
    case invalidArgument(String)
    /// An object carried a key its advertised schema does not declare. The
    /// offending key is deliberately not echoed; `object` names the schema
    /// location (`arguments`, `cursor` or `filter`) in the server's own words.
    case unexpectedArgument(in: String)
    case argumentsNotAnObject

    // MARK: Internal

    /// The longest unknown tool name echoed back to a client.
    static let maxEchoedToolNameLength = 64

    var message: String {
        switch self {
        case let .unknownTool(name): "Unknown tool “\(name.prefix(Self.maxEchoedToolNameLength))”."
        case let .missingArgument(name): "Missing required argument “\(name)”."
        case let .invalidArgument(name): "Invalid value for argument “\(name)”."
        case let .unexpectedArgument(object):
            "“\(object)” carries a key this tool does not accept. Only the advertised properties are allowed."
        case .argumentsNotAnObject: "Tool arguments must be an object."
        }
    }
}

// MARK: - MCPToolCatalog

/// The `tools/list` payload. Schemas are literal, stable JSON objects rather than
/// something derived at runtime, so what is advertised and what is accepted can be
/// compared directly in a test.
nonisolated enum MCPToolCatalog {
    // MARK: Internal

    /// The advertised descriptors, in the fixed order above.
    static func descriptors(maxPageSize: Int) -> [[String: Any]] {
        MCPToolName.allCases.map { descriptor(for: $0, maxPageSize: maxPageSize) }
    }

    static func descriptor(for tool: MCPToolName, maxPageSize: Int) -> [String: Any] {
        switch tool {
        case .describeScope:
            [
                "name": tool.rawValue,
                "description": """
                Describe the single authorized scope: the Project, the disclosed field families, the row ceiling \
                and the read-only guarantees. Takes no arguments.
                """,
                "inputSchema": ["type": "object", "properties": [String: Any](), "additionalProperties": false],
            ]
        case .listCaptures:
            [
                "name": tool.rawValue,
                "description": """
                List one newest-first page of stored captures for the authorized Project. Returns an opaque cursor \
                to resume after the page.
                """,
                "inputSchema": [
                    "type": "object",
                    "additionalProperties": false,
                    "properties": [
                        "pageSize": [
                            "type": "integer",
                            "minimum": 1,
                            "maximum": maxPageSize,
                            "description": "Rows to read on this one page.",
                        ],
                        "cursor": captureCursorSchema,
                    ],
                ],
            ]
        case .listSessions:
            [
                "name": tool.rawValue,
                "description": """
                List one ordinal-ascending page of a capture's session summaries, filtered on that single examined \
                page. Sensitive fields appear only when the grant discloses them.
                """,
                "inputSchema": [
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["captureID"],
                    "properties": [
                        "captureID": ["type": "string", "description": "The capture to read, as a UUID string."],
                        "pageSize": [
                            "type": "integer",
                            "minimum": 1,
                            "maximum": maxPageSize,
                            "description": "Rows to examine on this one page, before filtering.",
                        ],
                        "cursor": sessionCursorSchema,
                        "filter": filterSchema,
                    ],
                ],
            ]
        }
    }

    // MARK: Private

    private static var captureCursorSchema: [String: Any] {
        [
            "type": "object",
            "additionalProperties": false,
            "required": ["endedAt", "captureID"],
            "description": "The opaque cursor returned by a previous page.",
            "properties": [
                "endedAt": ["type": "number"],
                "captureID": ["type": "string"],
            ],
        ]
    }

    private static var sessionCursorSchema: [String: Any] {
        [
            "type": "object",
            "additionalProperties": false,
            "required": ["ordinal"],
            "description": "The opaque cursor returned by a previous page.",
            "properties": ["ordinal": ["type": "integer", "minimum": 0]],
        ]
    }

    private static var filterSchema: [String: Any] {
        [
            "type": "object",
            "additionalProperties": false,
            "description": """
            A conjunctive filter applied to the one examined page. Process and host predicates require the matching \
            disclosure; there is deliberately no endpoint predicate.
            """,
            "properties": [
                MCPFilterFieldName.processSubstring.rawValue:
                    ["type": "string", "maxLength": AutomationText.maxOperandUTF8Bytes],
                MCPFilterFieldName.hostSubstring.rawValue:
                    ["type": "string", "maxLength": AutomationText.maxOperandUTF8Bytes],
                MCPFilterFieldName.protocolEquals.rawValue:
                    ["type": "string", "maxLength": AutomationText.maxOperandUTF8Bytes],
                MCPFilterFieldName.status.rawValue: ["type": "string", "enum": ["ok", "warning", "error"]],
                MCPFilterFieldName.startTimeAtLeast.rawValue: ["type": "number"],
                MCPFilterFieldName.startTimeAtMost.rawValue: ["type": "number"],
                MCPFilterFieldName.totalBytesAtLeast.rawValue: ["type": "integer", "minimum": 0],
                MCPFilterFieldName.totalBytesAtMost.rawValue: ["type": "integer", "minimum": 0],
            ],
        ]
    }
}

// MARK: - MCPToolArguments

/// Bounded decoding from a client `arguments` object onto the existing typed
/// automation requests. Every numeric is range-checked here so an out-of-range
/// value is an `invalid` tool call rather than something the store has to defend
/// against.
nonisolated enum MCPToolArguments {
    // MARK: Internal

    /// The *advertised* filter field names present in a request, for the audit
    /// trail. Names only, and only names the schema declares — an operand, or a
    /// key the client invented, is never returned from here.
    static func filterFieldNames(in arguments: [String: Any]) -> [String] {
        guard let filter = arguments["filter"] as? [String: Any] else {
            return []
        }
        return filter.keys.compactMap { MCPFilterFieldName(rawValue: $0)?.rawValue }.sorted()
    }

    /// `describe_scope` advertises an empty object; any key at all is refused.
    static func requireNoArguments(_ arguments: [String: Any]) throws {
        try rejectUnknownKeys(in: arguments, allowed: [], object: "arguments")
    }

    /// Decode a `list_captures` request under the grant's page ceiling.
    static func capturePageRequest(
        _ arguments: [String: Any],
        maxPageSize: Int
    )
        throws -> AutomationCapturePageRequest
    {
        try rejectUnknownKeys(in: arguments, allowed: ["pageSize", "cursor"], object: "arguments")
        let pageSize = try pageSize(arguments, maxPageSize: maxPageSize)
        var cursor: AutomationCaptureCursor?
        if let raw = arguments["cursor"] {
            guard let object = raw as? [String: Any] else {
                throw MCPToolFailure.invalidArgument("cursor")
            }
            try rejectUnknownKeys(in: object, allowed: ["endedAt", "captureID"], object: "cursor")
            guard let endedAt = finiteNumber(object["endedAt"]) else {
                throw MCPToolFailure.invalidArgument("cursor.endedAt")
            }
            guard let text = object["captureID"] as? String, let captureID = UUID(uuidString: text) else {
                throw MCPToolFailure.invalidArgument("cursor.captureID")
            }
            cursor = AutomationCaptureCursor(endedAt: endedAt, captureID: captureID)
        }
        return AutomationCapturePageRequest(pageSize: pageSize, cursor: cursor)
    }

    /// Decode a `list_sessions` request under the grant's page ceiling and its
    /// disclosure policy. The disclosure is taken from the grant, never from the
    /// request: a client cannot ask for a field the user did not authorize.
    static func sessionPageRequest(
        _ arguments: [String: Any],
        maxPageSize: Int,
        disclosure: AutomationDisclosure
    )
        throws -> AutomationSessionPageRequest
    {
        try rejectUnknownKeys(
            in: arguments,
            allowed: ["captureID", "pageSize", "cursor", "filter"],
            object: "arguments"
        )
        guard let rawCapture = arguments["captureID"] else {
            throw MCPToolFailure.missingArgument("captureID")
        }
        guard let text = rawCapture as? String, let captureID = UUID(uuidString: text) else {
            throw MCPToolFailure.invalidArgument("captureID")
        }
        let pageSize = try pageSize(arguments, maxPageSize: maxPageSize)

        var cursor: AutomationSessionCursor?
        if let raw = arguments["cursor"] {
            guard let object = raw as? [String: Any] else {
                throw MCPToolFailure.invalidArgument("cursor")
            }
            try rejectUnknownKeys(in: object, allowed: ["ordinal"], object: "cursor")
            guard let ordinal = integer(object["ordinal"]),
                  ordinal >= 0,
                  ordinal <= Int(Int32.max) else
            {
                throw MCPToolFailure.invalidArgument("cursor.ordinal")
            }
            cursor = AutomationSessionCursor(ordinal: ordinal)
        }

        return try AutomationSessionPageRequest(
            captureID: captureID,
            pageSize: pageSize,
            cursor: cursor,
            filter: filter(arguments),
            disclosure: disclosure
        )
    }

    // MARK: Private

    /// Enforce the advertised `additionalProperties: false`. The schema says a
    /// client may send only the declared keys; this is where that becomes true
    /// at runtime, before any page is read.
    private static func rejectUnknownKeys(
        in object: [String: Any],
        allowed: Set<String>,
        object name: String
    )
        throws
    {
        guard object.keys.allSatisfy(allowed.contains) else {
            throw MCPToolFailure.unexpectedArgument(in: name)
        }
    }

    /// An absent page size defaults to the grant's ceiling; a present one must be
    /// an integer inside `1...ceiling`.
    private static func pageSize(_ arguments: [String: Any], maxPageSize: Int) throws -> Int {
        let ceiling = min(max(1, maxPageSize), MCPGrantLimits.maxPageSize)
        guard let raw = arguments["pageSize"] else {
            return ceiling
        }
        guard let value = integer(raw), (1 ... ceiling).contains(value) else {
            throw MCPToolFailure.invalidArgument("pageSize")
        }
        return value
    }

    private static func filter(_ arguments: [String: Any]) throws -> AutomationSessionFilter {
        guard let raw = arguments["filter"] else {
            return .none
        }
        guard let object = raw as? [String: Any] else {
            throw MCPToolFailure.invalidArgument("filter")
        }
        try rejectUnknownKeys(
            in: object,
            allowed: Set(MCPFilterFieldName.allCases.map(\.rawValue)),
            object: "filter"
        )
        var filter = AutomationSessionFilter()
        filter.processSubstring = try text(object, .processSubstring)
        filter.hostSubstring = try text(object, .hostSubstring)
        filter.protocolEquals = try text(object, .protocolEquals)
        if let rawStatus = object[MCPFilterFieldName.status.rawValue] {
            guard let name = rawStatus as? String, let status = AutomationSessionStatus(rawValue: name) else {
                throw MCPToolFailure.invalidArgument("filter.\(MCPFilterFieldName.status.rawValue)")
            }
            filter.status = status
        }
        filter.startTimeAtLeast = try number(object, .startTimeAtLeast)
        filter.startTimeAtMost = try number(object, .startTimeAtMost)
        filter.totalBytesAtLeast = try byteBound(object, .totalBytesAtLeast)
        filter.totalBytesAtMost = try byteBound(object, .totalBytesAtMost)
        return filter
    }

    private static func text(_ object: [String: Any], _ key: MCPFilterFieldName) throws -> String? {
        guard let raw = object[key.rawValue] else {
            return nil
        }
        guard let value = raw as? String else {
            throw MCPToolFailure.invalidArgument("filter.\(key.rawValue)")
        }
        return value
    }

    private static func number(_ object: [String: Any], _ key: MCPFilterFieldName) throws -> Double? {
        guard let raw = object[key.rawValue] else {
            return nil
        }
        guard let value = finiteNumber(raw) else {
            throw MCPToolFailure.invalidArgument("filter.\(key.rawValue)")
        }
        return value
    }

    private static func byteBound(_ object: [String: Any], _ key: MCPFilterFieldName) throws -> Int64? {
        guard let raw = object[key.rawValue] else {
            return nil
        }
        guard let number = raw as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue.rounded() == number.doubleValue,
              number.int64Value >= 0 else
        {
            throw MCPToolFailure.invalidArgument("filter.\(key.rawValue)")
        }
        return number.int64Value
    }

    private static func integer(_ raw: Any?) -> Int? {
        guard let number = raw as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else {
            return nil
        }
        let value = number.doubleValue
        guard value.isFinite, value.rounded() == value, value.magnitude <= Double(Int.max) else {
            return nil
        }
        return number.intValue
    }

    private static func finiteNumber(_ raw: Any?) -> Double? {
        guard let number = raw as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else {
            return nil
        }
        return number.doubleValue.isFinite ? number.doubleValue : nil
    }
}
