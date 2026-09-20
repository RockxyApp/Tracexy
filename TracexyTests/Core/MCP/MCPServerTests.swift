import Foundation
import Testing
@testable import Tracexy

// MARK: - MCPServerTests

@Suite("MCP server: handshake, tool schemas, bounds, read-only reads and fail-closed grants")
struct MCPServerTests {
    // MARK: Internal

    @Test("Every call fails closed while no grant exists, and ping still answers")
    func failsClosedWithoutGrant() async throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        let server = environment.makeServer()

        let initialize = try await response(server, "initialize", id: 1)
        #expect(errorCode(initialize) == MCPErrorCode.invalidRequest.rawValue)

        let list = try await response(server, "tools/list", id: 2)
        #expect(errorCode(list) == MCPErrorCode.invalidRequest.rawValue)

        // `ping` is a liveness check, not a read, so it answers regardless.
        let ping = try await response(server, "ping", id: 3)
        #expect(ping["result"] != nil)
    }

    @Test("Initialize advertises tools only — no resources, prompts or writes")
    func initializeAdvertisesToolsOnly() async throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        try await environment.seedHistory()
        _ = try environment.issuer.issue(scope: environment.scope, disclosure: .minimum, maxPageSize: 10)
        let server = environment.makeServer()

        let result = try #require(try await response(server, "initialize", id: 1)["result"] as? [String: Any])
        #expect(result["protocolVersion"] as? String == MCPServerInfo.protocolVersion)
        let capabilities = try #require(result["capabilities"] as? [String: Any])
        #expect(Set(capabilities.keys) == ["tools"])
        #expect(result["serverInfo"] != nil)
    }

    @Test("tools/list advertises exactly the three read-only tools with bounded schemas")
    func toolsListIsClosed() async throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        try await environment.seedHistory()
        _ = try environment.issuer.issue(scope: environment.scope, disclosure: .minimum, maxPageSize: 37)
        let server = environment.makeServer()
        _ = try await response(server, "initialize", id: 1)

        let result = try #require(try await response(server, "tools/list", id: 2)["result"] as? [String: Any])
        let tools = try #require(result["tools"] as? [[String: Any]])
        #expect(tools.compactMap { $0["name"] as? String } == [
            "describe_scope",
            "list_captures",
            "list_sessions",
        ])

        // The advertised ceiling is the grant's, not the service's hard bound.
        let sessions = try #require(tools.last)
        let schema = try #require(sessions["inputSchema"] as? [String: Any])
        let properties = try #require(schema["properties"] as? [String: Any])
        let pageSize = try #require(properties["pageSize"] as? [String: Any])
        #expect(pageSize["maximum"] as? Int == 37)
        #expect(schema["additionalProperties"] as? Bool == false)

        // There is no endpoint predicate, path, SQL or output-format argument.
        let filter = try #require(properties["filter"] as? [String: Any])
        let filterProperties = try #require(filter["properties"] as? [String: Any])
        #expect(Set(filterProperties.keys) == [
            "hostSubstring",
            "processSubstring",
            "protocolEquals",
            "startTimeAtLeast",
            "startTimeAtMost",
            "status",
            "totalBytesAtLeast",
            "totalBytesAtMost",
        ])
    }

    @Test("describe_scope states the boundary without touching the database")
    func describeScopeIsTruthful() async throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        try await environment.seedHistory()
        _ = try environment.issuer.issue(
            scope: environment.scope,
            disclosure: .init(includesHost: true),
            maxPageSize: 20
        )
        let server = environment.makeServer()
        _ = try await response(server, "initialize", id: 1)

        let payload = try await toolText(server, name: "describe_scope", id: 2)
        let object = try #require(try JSONSerialization.jsonObject(with: Data(payload.utf8)) as? [String: Any])
        #expect(object["opensNetworkPort"] as? Bool == false)
        #expect(object["readOnly"] as? Bool == true)
        #expect(object["transport"] as? String == "stdio")
        #expect(object["projectID"] as? String == environment.projectID.uuidString)
        #expect(object["maxPageSize"] as? Int == 20)
        let exposes = try #require(object["exposes"] as? [String: Any])
        #expect(exposes["rawFrames"] as? Bool == false)
        #expect(exposes["captureControls"] as? Bool == false)
        #expect(exposes["filePaths"] as? Bool == false)
    }

    @Test("list_captures and list_sessions read one bounded page of the granted database")
    func readsAreBoundedAndDisclosureGated() async throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        let captureID = try await environment.seedHistory(sessionCount: 4)
        _ = try environment.issuer.issue(scope: environment.scope, disclosure: .minimum, maxPageSize: 2)
        let server = environment.makeServer()
        _ = try await response(server, "initialize", id: 1)

        let captures = try await toolObject(server, name: "list_captures", id: 2)
        let captureList = try #require(captures["captures"] as? [[String: Any]])
        #expect(captureList.count == 1)
        #expect(captureList[0]["captureID"] as? String == captureID.uuidString)
        #expect(captures["pageSize"] as? Int == 2)

        let sessions = try await toolObject(
            server,
            name: "list_sessions",
            id: 3,
            arguments: ["captureID": captureID.uuidString]
        )
        let sessionList = try #require(sessions["sessions"] as? [[String: Any]])
        // The grant's ceiling bounds the page even though the capture has four rows.
        #expect(sessionList.count == 2)
        #expect(sessions["nextCursor"] != nil)
        // Minimum disclosure omits every sensitive family by construction.
        for session in sessionList {
            #expect(session["host"] == nil)
            #expect(session["processName"] == nil)
            #expect(session["sourceEndpoint"] == nil)
            #expect(session["destinationEndpoint"] == nil)
        }
    }

    @Test("A host filter without host disclosure is refused, and disclosed reads project the field")
    func disclosureOracleIsEnforced() async throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        let captureID = try await environment.seedHistory(sessionCount: 2)
        _ = try environment.issuer.issue(scope: environment.scope, disclosure: .minimum, maxPageSize: 10)
        let server = environment.makeServer()
        _ = try await response(server, "initialize", id: 1)

        let refused = try await response(server, "tools/call", id: 2, params: [
            "name": "list_sessions",
            "arguments": [
                "captureID": captureID.uuidString,
                "filter": ["hostSubstring": "example"],
            ],
        ])
        #expect(errorCode(refused) == MCPErrorCode.invalidParams.rawValue)

        // The audit records the field name that was refused — never the operand.
        let audit = environment.issuer.recentAudit()
        let record = try #require(audit.last)
        #expect(record.result == .invalid)
        #expect(record.filterFields == ["hostSubstring"])

        _ = try environment.issuer.issue(
            scope: environment.scope,
            disclosure: .init(includesHost: true),
            maxPageSize: 10
        )
        let reinitialized = environment.makeServer()
        _ = try await response(reinitialized, "initialize", id: 1)
        let allowed = try await toolObject(
            reinitialized,
            name: "list_sessions",
            id: 2,
            arguments: [
                "captureID": captureID.uuidString,
                "filter": ["hostSubstring": "example"],
            ]
        )
        let list = try #require(allowed["sessions"] as? [[String: Any]])
        #expect(list.count == 2)
        #expect(list[0]["host"] != nil)
        #expect(list[0]["processName"] == nil)
    }

    @Test("Out-of-bound arguments and unknown tools are invalid params")
    func invalidArgumentsAreRefused() async throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        let captureID = try await environment.seedHistory()
        _ = try environment.issuer.issue(scope: environment.scope, disclosure: .minimum, maxPageSize: 10)
        let server = environment.makeServer()
        _ = try await response(server, "initialize", id: 1)

        let tooBig = try await response(server, "tools/call", id: 2, params: [
            "name": "list_captures",
            "arguments": ["pageSize": 11],
        ])
        #expect(errorCode(tooBig) == MCPErrorCode.invalidParams.rawValue)

        let unknown = try await response(server, "tools/call", id: 3, params: [
            "name": "delete_everything",
            "arguments": [:],
        ])
        #expect(errorCode(unknown) == MCPErrorCode.invalidParams.rawValue)

        let badCapture = try await response(server, "tools/call", id: 4, params: [
            "name": "list_sessions",
            "arguments": ["captureID": "not-a-uuid"],
        ])
        #expect(errorCode(badCapture) == MCPErrorCode.invalidParams.rawValue)

        let missingCapture = try await response(server, "tools/call", id: 5, params: [
            "name": "list_sessions",
            "arguments": ["captureID": UUID().uuidString],
        ])
        #expect(errorCode(missingCapture) == MCPErrorCode.invalidParams.rawValue)

        // A valid call still works afterwards: a refusal is not a fatal state.
        let ok = try await toolObject(
            server,
            name: "list_sessions",
            id: 6,
            arguments: ["captureID": captureID.uuidString]
        )
        #expect(ok["captureID"] as? String == captureID.uuidString)
    }

    @Test("Unknown top-level, cursor and filter keys are refused before any page is read")
    func additionalPropertiesAreRefused() async throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        let captureID = try await environment.seedHistory(sessionCount: 2)
        _ = try environment.issuer.issue(
            scope: environment.scope,
            disclosure: .init(includesHost: true),
            maxPageSize: 10
        )
        let server = MCPServer(
            grantReader: MCPGrantReader(url: environment.grantURL),
            audit: MCPAuditTrail(url: environment.auditURL),
            openStore: { _ in throw HistoryStoreError.corruption("must not be opened") }
        )
        _ = try await response(server, "initialize", id: 1)

        let refused: [(String, [String: Any])] = [
            ("describe_scope", ["path": "/tmp/x"]),
            ("list_captures", ["pageSize": 2, "sql": "select 1"]),
            ("list_captures", ["cursor": ["endedAt": 1.0, "captureID": captureID.uuidString, "path": "/"]]),
            ("list_sessions", ["captureID": captureID.uuidString, "format": "csv"]),
            ("list_sessions", ["captureID": captureID.uuidString, "cursor": ["ordinal": 0, "offset": 5]]),
            ("list_sessions", ["captureID": captureID.uuidString, "filter": ["endpointSubstring": "10.0"]]),
            ("list_sessions", ["captureID": captureID.uuidString, "filter": ["HostSubstring": "example"]]),
        ]
        for (index, (name, arguments)) in refused.enumerated() {
            let object = try await response(server, "tools/call", id: 10 + index, params: [
                "name": name,
                "arguments": arguments,
            ])
            #expect(errorCode(object) == MCPErrorCode.invalidParams.rawValue, "\(name) \(arguments)")
            let message = try #require((object["error"] as? [String: Any])?["message"] as? String)
            // The refusal names the schema location, never the client's key.
            #expect(!message.contains("sql"))
            #expect(!message.contains("path"))
            #expect(!message.contains("endpointSubstring"))
        }
        // Nothing reached the store, and the audit carries only advertised names.
        for record in environment.issuer.recentAudit() {
            #expect(record.result == .invalid)
            #expect(MCPAuditTool(rawValue: record.tool) != nil)
            #expect(record.filterFields.allSatisfy { MCPFilterFieldName(rawValue: $0) != nil })
        }
    }

    @Test("Every advertised argument shape is still accepted after the schema is enforced")
    func advertisedArgumentsStillWork() async throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        let captureID = try await environment.seedHistory(sessionCount: 3)
        _ = try environment.issuer.issue(
            scope: environment.scope,
            disclosure: .init(includesProcess: true, includesHost: true),
            maxPageSize: 10
        )
        let server = environment.makeServer()
        _ = try await response(server, "initialize", id: 1)

        _ = try await toolObject(server, name: "describe_scope", id: 2)
        let captures = try await toolObject(server, name: "list_captures", id: 3, arguments: ["pageSize": 1])
        let cursor = try #require(captures["nextCursor"] as? [String: Any])
        let next = try await toolObject(server, name: "list_captures", id: 4, arguments: ["cursor": cursor])
        #expect((next["captures"] as? [[String: Any]])?.isEmpty == true)

        let filtered = try await toolObject(server, name: "list_sessions", id: 5, arguments: [
            "captureID": captureID.uuidString,
            "pageSize": 2,
            "cursor": ["ordinal": 0],
            "filter": [
                "hostSubstring": "example",
                "protocolEquals": "TCP",
                "status": "ok",
                "startTimeAtLeast": 0,
                "startTimeAtMost": 2_000_000_000,
                "totalBytesAtLeast": 0,
                "totalBytesAtMost": 1_000_000,
            ],
        ])
        #expect(filtered["captureID"] as? String == captureID.uuidString)
        let record = try #require(environment.issuer.recentAudit().last)
        #expect(record.result == .ok)
        #expect(record.filterFields == [
            "hostSubstring",
            "protocolEquals",
            "startTimeAtLeast",
            "startTimeAtMost",
            "status",
            "totalBytesAtLeast",
            "totalBytesAtMost",
        ])
    }

    @Test("A refused unknown tool is audited as “unknown”, never by the name the client sent")
    func unknownToolIsAuditedAsUnknown() async throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        try await environment.seedHistory()
        _ = try environment.issuer.issue(scope: environment.scope, disclosure: .minimum, maxPageSize: 10)
        let server = environment.makeServer()
        _ = try await response(server, "initialize", id: 1)

        let hostile = "read_file /example/secrets " + String(repeating: "x", count: 2_000)
        let refused = try await response(server, "tools/call", id: 2, params: ["name": hostile, "arguments": [:]])
        #expect(errorCode(refused) == MCPErrorCode.invalidParams.rawValue)
        let record = try #require(environment.issuer.recentAudit().last)
        #expect(record.tool == MCPAuditTool.unknown.rawValue)
        #expect(record.result == .invalid)
        let trail = try String(contentsOf: environment.auditURL, encoding: .utf8)
        #expect(!trail.contains("secrets"))
    }

    @Test("An unknown method is method-not-found; an oversize line is a parse error")
    func unknownMethodAndOversizeLine() async throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        let server = environment.makeServer()

        let unknown = try await response(server, "resources/list", id: 1)
        #expect(errorCode(unknown) == MCPErrorCode.methodNotFound.rawValue)

        let oversize = try #require(await server.respondToOversizeLine(byteCount: 9_999_999))
        let object = try #require(try JSONSerialization.jsonObject(with: oversize) as? [String: Any])
        #expect(errorCode(object) == MCPErrorCode.parseError.rawValue)
        #expect(object["id"] is NSNull)
    }

    @Test("A notification produces no output at all")
    func notificationsAreSilent() async {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        let server = environment.makeServer()
        let line = Data("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}".utf8)
        #expect(await server.handle(line: line) == nil)
    }

    @Test("A Project switch and a revoke both invalidate a pinned session")
    func projectSwitchAndRevokeInvalidate() async throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        let captureID = try await environment.seedHistory()
        _ = try environment.issuer.issue(scope: environment.scope, disclosure: .minimum, maxPageSize: 10)
        let server = environment.makeServer()
        _ = try await response(server, "initialize", id: 1)
        _ = try await toolObject(
            server,
            name: "list_sessions",
            id: 2,
            arguments: ["captureID": captureID.uuidString]
        )

        // A Project switch re-points the grant at another Project.
        _ = try environment.issuer.issue(
            scope: MCPGrantScope(
                projectID: UUID(),
                projectName: "Other",
                historyDatabaseURL: environment.databaseURL
            ),
            disclosure: .minimum,
            maxPageSize: 10
        )
        let afterSwitch = try await response(server, "tools/call", id: 3, params: [
            "name": "list_captures",
            "arguments": [:],
        ])
        #expect(errorCode(afterSwitch) == MCPErrorCode.invalidRequest.rawValue)

        try environment.issuer.revoke()
        let afterRevoke = try await response(server, "tools/call", id: 4, params: [
            "name": "list_captures",
            "arguments": [:],
        ])
        #expect(errorCode(afterRevoke) == MCPErrorCode.invalidRequest.rawValue)
    }

    @Test("The store is opened read-only, so a v1 database is refused, never migrated")
    func readOnlyDatabaseIsNeverMigrated() async throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        try await environment.seedHistory()

        // The production opener must refuse to migrate. Prove it on a fresh,
        // unmigrated file: a read-only open of a version-0 database cannot install
        // a schema.
        let empty = environment.root.appendingPathComponent("empty.sqlite")
        FileManager.default.createFile(atPath: empty.path, contents: Data())
        await #expect(throws: HistoryStoreError.cannotMigrateReadOnly) {
            _ = try MCPServer.openReadOnlyStore(at: empty)
        }

        // And the migrated fixture opens read-only and answers reads.
        let store = try MCPServer.openReadOnlyStore(at: environment.databaseURL)
        #expect(await store.configuration.readOnly)
        let page = try await store.captures(after: nil, limit: 10)
        #expect(page.captures.count == 1)
    }

    @Test("A database that cannot be read is an internal error, and is audited as unavailable")
    func unreadableDatabaseIsControlled() async throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        try await environment.seedHistory()
        _ = try environment.issuer.issue(scope: environment.scope, disclosure: .minimum, maxPageSize: 10)
        let server = MCPServer(
            grantReader: MCPGrantReader(url: environment.grantURL),
            audit: MCPAuditTrail(url: environment.auditURL),
            openStore: { _ in throw HistoryStoreError.corruption("fixture") }
        )
        _ = try await response(server, "initialize", id: 1)
        let failed = try await response(server, "tools/call", id: 2, params: [
            "name": "list_captures",
            "arguments": [:],
        ])
        #expect(errorCode(failed) == MCPErrorCode.internalError.rawValue)
        #expect(environment.issuer.recentAudit().last?.result == .unavailable)
    }

    // MARK: Private

    private func response(
        _ server: MCPServer,
        _ method: String,
        id: Int,
        params: [String: Any] = [:]
    )
        async throws -> [String: Any]
    {
        var request: [String: Any] = ["jsonrpc": "2.0", "id": id, "method": method]
        if !params.isEmpty {
            request["params"] = params
        }
        let line = try JSONSerialization.data(withJSONObject: request)
        let data = try #require(await server.handle(line: line))
        return try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func toolText(
        _ server: MCPServer,
        name: String,
        id: Int,
        arguments: [String: Any] = [:]
    )
        async throws -> String
    {
        let object = try await response(server, "tools/call", id: id, params: [
            "name": name,
            "arguments": arguments,
        ])
        let result = try #require(object["result"] as? [String: Any])
        #expect(result["isError"] as? Bool == false)
        let content = try #require(result["content"] as? [[String: Any]])
        return try #require(content.first?["text"] as? String)
    }

    private func toolObject(
        _ server: MCPServer,
        name: String,
        id: Int,
        arguments: [String: Any] = [:]
    )
        async throws -> [String: Any]
    {
        let text = try await toolText(server, name: name, id: id, arguments: arguments)
        return try #require(try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
    }

    private func errorCode(_ object: [String: Any]) -> Int? {
        (object["error"] as? [String: Any])?["code"] as? Int
    }
}

// MARK: - Server composition

private extension MCPTestEnvironment {
    func makeServer() -> MCPServer {
        MCPServer(
            grantReader: MCPGrantReader(url: grantURL),
            audit: MCPAuditTrail(url: auditURL)
        )
    }
}
