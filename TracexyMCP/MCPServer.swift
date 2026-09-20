import Foundation

// This file declares the read-only MCP request handler. It owns the whole policy
// of the boundary: initialize pins exactly one grant, every later call re-reads
// and re-validates it, and every answered call reads exactly one bounded page
// through the existing ``HistoryAutomationService``.
//
// It never opens a port, never writes to the database, never migrates a schema,
// never accepts a path, and never emits anything on stdout itself — it returns
// response bytes and the transport decides where they go.

// MARK: - MCPServerInfo

/// The immutable identity this server advertises during `initialize`.
nonisolated struct MCPServerInfo: Sendable, Equatable {
    // MARK: Lifecycle

    init(name: String = "tracexy-history", version: String = "0") {
        self.name = name
        self.version = version
    }

    // MARK: Internal

    /// The MCP protocol revision this server implements.
    static let protocolVersion = "2025-06-18"

    let name: String
    let version: String
}

// MARK: - MCPServer

/// The single request handler. It is an actor because reading a page is `async`
/// through the store actor, and because the pinned scope must not be observed
/// mid-update.
actor MCPServer {
    // MARK: Lifecycle

    /// - Parameters:
    ///   - grantReader: the identity-derived grant reader. There is no other way
    ///     to name a database.
    ///   - audit: the bounded local trail.
    ///   - info: the advertised server identity.
    ///   - now: seconds since the reference date, injectable for tests.
    ///   - openStore: how a read-only store is opened, injectable so a test can
    ///     assert the exact configuration without a bundled binary.
    init(
        grantReader: MCPGrantReader,
        audit: MCPAuditTrail,
        info: MCPServerInfo = MCPServerInfo(),
        now: @escaping @Sendable () -> Double = { Date().timeIntervalSinceReferenceDate },
        openStore: @escaping @Sendable (URL) throws -> SessionStore = MCPServer.openReadOnlyStore
    ) {
        self.grantReader = grantReader
        self.audit = audit
        self.info = info
        self.now = now
        self.openStore = openStore
    }

    // MARK: Internal

    /// Open one read-only connection to an already-existing History database.
    /// `readOnly: true` is what makes an old-schema database a controlled failure
    /// rather than an in-place migration of a file the user did not authorize us
    /// to change.
    static func openReadOnlyStore(at url: URL) throws -> SessionStore {
        try SessionStore(configuration: .init(location: .file(url), readOnly: true))
    }

    /// Handle one framed line. Returns the response bytes, or `nil` for a
    /// notification (which JSON-RPC answers with nothing).
    func handle(line: Data) async -> Data? {
        let request: MCPRequest
        do {
            request = try MCPMessage.parse(line: line)
        } catch let failure as MCPParseFailure {
            return MCPMessage.encodeError(id: .null, code: failure.code, message: failure.message)
        } catch {
            return MCPMessage.encodeError(
                id: .null,
                code: .parseError,
                message: MCPParseFailure.notJSONObject.message
            )
        }

        guard let id = request.id else {
            // A notification is answered with nothing at all, including
            // `notifications/initialized`, which is expected and ignored.
            return nil
        }
        return await respond(to: request, id: id)
    }

    /// Answer a line that exceeded the wire bound. The id is unknowable because
    /// the bytes were never parsed, so JSON-RPC's null id is used.
    func respondToOversizeLine(byteCount: Int) -> Data? {
        MCPMessage.encodeError(
            id: .null,
            code: .parseError,
            message: MCPParseFailure.lineTooLong(byteCount: byteCount).message
        )
    }

    // MARK: Private

    /// Neutral copy for every closed-grant outcome. It never says *why* in a way
    /// that would report the host's filesystem or Project state to a client.
    private static let unauthorizedMessage =
        "This request is not authorized. Grant MCP access to a Project in Tracexy Settings, then reconnect."

    private let grantReader: MCPGrantReader
    private let audit: MCPAuditTrail
    private let info: MCPServerInfo
    private let now: @Sendable () -> Double
    private let openStore: @Sendable (URL) throws -> SessionStore

    /// The scope pinned at `initialize`. Nothing may be read before it exists.
    private var pinnedGrant: MCPGrantPin?
    /// The one read-only store, opened lazily for the pinned scope only.
    private var store: SessionStore?

    /// The scope description. Everything here is already known to the user who
    /// issued the grant; nothing is derived from capture contents.
    private static func describeScopeJSON(_ grant: MCPGrantDocument) throws -> String {
        let payload: [String: Any] = [
            "projectID": grant.projectID.uuidString,
            "grantRevision": grant.revision,
            "grantSchemaVersion": grant.schemaVersion,
            "issuedAt": grant.issuedAt,
            "maxPageSize": grant.maxPageSize,
            "disclosure": [
                "includesProcess": grant.disclosure.includesProcess,
                "includesHost": grant.disclosure.includesHost,
                "includesEndpoints": grant.disclosure.includesEndpoints,
            ],
            "transport": "stdio",
            "opensNetworkPort": false,
            "readOnly": true,
            "exposes": [
                "captures": true,
                "sessions": true,
                "capturePackets": false,
                "captureControls": false,
                "filePaths": false,
                "rawFrames": false,
            ],
        ]
        let data = try JSONSerialization.data(
            withJSONObject: payload,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        return try text(data)
    }

    private static func text(_ data: Data) throws -> String {
        guard let text = String(data: data, encoding: .utf8) else {
            throw MCPToolFailure.invalidArgument("result")
        }
        return text
    }

    /// Neutral copy for a typed automation failure. It names the *field*, never
    /// the operand the client supplied.
    private static func message(for error: AutomationError) -> String {
        switch error {
        case let .invalidPageSize(value):
            "Page size \(value) is outside the supported range."
        case .captureNotFound:
            "No capture with that identifier exists in the authorized Project."
        case let .emptyFilterOperand(field):
            "Filter field “\(field.rawValue)” was empty."
        case let .filterOperandTooLong(field, _):
            "Filter field “\(field.rawValue)” exceeds the supported length."
        case let .filterOperandContainsControlCharacter(field):
            "Filter field “\(field.rawValue)” contains a control character."
        case let .filterBoundsOutOfOrder(field):
            "Filter field “\(field.rawValue)” has bounds in the wrong order."
        case let .nonFiniteFilterBound(field):
            "Filter field “\(field.rawValue)” is not a finite number."
        case let .negativeByteBound(field):
            "Filter field “\(field.rawValue)” must not be negative."
        case let .filterRequiresDisclosure(field):
            "Filtering on “\(field.rawValue)” requires that field to be disclosed by the grant."
        case let .invalidCursor(field):
            "Cursor field “\(field)” is not valid."
        }
    }

    private func respond(to request: MCPRequest, id: MCPRequestID) async -> Data? {
        switch request.method {
        case "initialize":
            initialize(id: id)
        case "ping":
            MCPMessage.encodeResult(id: id, result: [:])
        case "tools/list":
            toolsList(id: id)
        case "tools/call":
            await toolsCall(request, id: id)
        default:
            MCPMessage.encodeError(
                id: id,
                code: .methodNotFound,
                message: "Unsupported method “\(request.method)”."
            )
        }
    }

    /// Pin exactly one grant. A missing or invalid grant fails the handshake, so a
    /// client is never told a scope exists before one does.
    private func initialize(id: MCPRequestID) -> Data? {
        guard let grant = try? grantReader.load() else {
            return MCPMessage.encodeError(id: id, code: .invalidRequest, message: Self.unauthorizedMessage)
        }
        // Re-pinning discards any store opened for a previous scope.
        if pinnedGrant != grant.pin {
            store = nil
        }
        pinnedGrant = grant.pin

        return encode(id: id, result: [
            "protocolVersion": MCPServerInfo.protocolVersion,
            // Exactly one capability. No resources, prompts, sampling, logging or
            // completion is advertised, because none exists.
            "capabilities": ["tools": ["listChanged": false]],
            "serverInfo": ["name": info.name, "version": info.version],
            "instructions": """
            Tracexy exposes one user-authorized Project's stored capture history, read-only, over stdio. \
            No network port is opened. Packet bytes, capture files, file paths and capture controls are not \
            available. Start with describe_scope to see which fields the grant discloses.
            """,
        ])
    }

    private func toolsList(id: MCPRequestID) -> Data? {
        guard let pinned = pinnedGrant, let grant = try? grantReader.load(matching: pinned) else {
            return MCPMessage.encodeError(id: id, code: .invalidRequest, message: Self.unauthorizedMessage)
        }
        return encode(id: id, result: ["tools": MCPToolCatalog.descriptors(maxPageSize: grant.maxPageSize)])
    }

    private func toolsCall(_ request: MCPRequest, id: MCPRequestID) async -> Data? {
        let name = (request.params["name"] as? String) ?? ""
        var arguments: [String: Any] = [:]
        if let raw = request.params["arguments"], !(raw is NSNull) {
            guard let object = raw as? [String: Any] else {
                record(tool: name, result: .invalid, projectID: nil)
                return MCPMessage.encodeError(
                    id: id,
                    code: .invalidParams,
                    message: MCPToolFailure.argumentsNotAnObject.message
                )
            }
            arguments = object
        }

        guard let pinned = pinnedGrant, let grant = try? grantReader.load(matching: pinned) else {
            record(tool: name, result: .denied, projectID: pinnedGrant?.projectID)
            return MCPMessage.encodeError(id: id, code: .invalidRequest, message: Self.unauthorizedMessage)
        }

        guard let tool = MCPToolName(rawValue: name) else {
            record(tool: name, result: .invalid, projectID: grant.projectID)
            return MCPMessage.encodeError(
                id: id,
                code: .invalidParams,
                message: MCPToolFailure.unknownTool(name).message
            )
        }

        let fields = MCPToolArguments.filterFieldNames(in: arguments)
        do {
            let payload = try await run(tool, arguments: arguments, grant: grant)
            record(tool: name, result: .ok, projectID: grant.projectID, filterFields: fields)
            return encode(id: id, result: [
                "content": [["type": "text", "text": payload]],
                "isError": false,
            ])
        } catch let failure as MCPToolFailure {
            record(tool: name, result: .invalid, projectID: grant.projectID, filterFields: fields)
            return MCPMessage.encodeError(id: id, code: .invalidParams, message: failure.message)
        } catch let failure as AutomationError {
            record(tool: name, result: .invalid, projectID: grant.projectID, filterFields: fields)
            return MCPMessage.encodeError(id: id, code: .invalidParams, message: Self.message(for: failure))
        } catch {
            record(tool: name, result: .unavailable, projectID: grant.projectID, filterFields: fields)
            return MCPMessage.encodeError(
                id: id,
                code: .internalError,
                message: "The authorized History database could not be read."
            )
        }
    }

    /// Execute one tool and return its deterministic JSON payload as text.
    private func run(
        _ tool: MCPToolName,
        arguments: [String: Any],
        grant: MCPGrantDocument
    )
        async throws -> String
    {
        switch tool {
        case .describeScope:
            try MCPToolArguments.requireNoArguments(arguments)
            return try Self.describeScopeJSON(grant)
        case .listCaptures:
            let request = try MCPToolArguments.capturePageRequest(arguments, maxPageSize: grant.maxPageSize)
            let page = try await service(for: grant).capturePage(request)
            return try Self.text(AutomationExport.json(capturePage: page))
        case .listSessions:
            let request = try MCPToolArguments.sessionPageRequest(
                arguments,
                maxPageSize: grant.maxPageSize,
                disclosure: grant.disclosure
            )
            let page = try await service(for: grant).sessionPage(request)
            return try Self.text(AutomationExport.json(sessionPage: page))
        }
    }

    /// The read-only automation boundary for the pinned scope. The store is opened
    /// once and reused; it is discarded whenever the pinned scope changes.
    private func service(for grant: MCPGrantDocument) throws -> HistoryAutomationService {
        if let store {
            return HistoryAutomationService(store: store)
        }
        let opened = try openStore(grant.historyDatabaseURL)
        store = opened
        return HistoryAutomationService(store: opened)
    }

    private func record(
        tool: String,
        result: MCPAuditResult,
        projectID: UUID?,
        filterFields: [String] = []
    ) {
        audit.append(MCPAuditRecord(
            at: now(),
            tool: tool,
            result: result,
            projectID: projectID,
            filterFields: filterFields
        ))
    }

    private func encode(id: MCPRequestID, result: [String: Any]) -> Data? {
        guard let data = MCPMessage.encodeResult(id: id, result: result) else {
            return MCPMessage.encodeError(
                id: id,
                code: .internalError,
                message: "The response exceeded the supported size."
            )
        }
        return data
    }
}
