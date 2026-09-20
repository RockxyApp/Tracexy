import Foundation
import Testing
@testable import Tracexy

// MARK: - MCPSubprocessIntegrationTests

/// End-to-end coverage of the **real bundled executable**, launched as a
/// subprocess and driven over its actual stdin/stdout pipes.
///
/// It exercises the shipped binary rather than the in-process handler, so it is
/// the test that can catch an embedding, identity-resolution or transport
/// regression that unit tests structurally cannot.
///
/// The child inherits this test run's environment, so ``TracexyIdentity``
/// resolves the same per-run temporary Application Support location in both
/// processes. Nothing here can reach the developer's real grant or History.
@Suite("MCP executable: real stdio subprocess against a real History database", .serialized)
struct MCPSubprocessIntegrationTests {
    // MARK: Internal

    /// Ask the executable where it reads authorization from, by starting it with
    /// an empty stdin and reading its one startup diagnostic. Probing beats
    /// re-deriving the path in the test: it proves the two processes agree.
    static func resolveGrantURL() throws -> URL {
        let process = try makeProcess()
        let error = Pipe()
        process.standardInput = Pipe()
        process.standardOutput = Pipe()
        process.standardError = error
        try process.run()
        (process.standardInput as? Pipe)?.fileHandleForWriting.closeFile()
        let data = error.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        let text = String(data: data, encoding: .utf8) ?? ""
        let line = try #require(text
            .split(separator: "\n")
            .first { $0.contains(MCPGrantLocation.diagnosticPrefix) })
        let path = try #require(line.components(separatedBy: MCPGrantLocation.diagnosticPrefix).last)
        return URL(fileURLWithPath: String(path))
    }

    @Test("The bundled executable ships inside the app bundle")
    func executableIsBundled() throws {
        let url = try #require(Self.executableURL)
        #expect(FileManager.default.isExecutableFile(atPath: url.path))
    }

    @Test("A real client handshake lists exactly the three read-only tools and reads one page")
    func handshakeAndReads() async throws {
        let fixture = try await ProductionGrantFixture(sessionCount: 4)
        defer { fixture.tearDown() }
        _ = try fixture.issue(maxPageSize: 2)

        let responses = try Self.run(lines: [
            Self.request(id: 1, method: "initialize"),
            Self.notification(method: "notifications/initialized"),
            Self.request(id: 2, method: "ping"),
            Self.request(id: 3, method: "tools/list"),
            Self.request(id: 4, method: "tools/call", params: [
                "name": "describe_scope",
                "arguments": [:],
            ]),
            Self.request(id: 5, method: "tools/call", params: [
                "name": "list_captures",
                "arguments": [:],
            ]),
            Self.request(id: 6, method: "tools/call", params: [
                "name": "list_sessions",
                "arguments": ["captureID": fixture.captureID.uuidString],
            ]),
        ])

        // Exactly one response per request, and nothing for the notification.
        #expect(responses.count == 6)
        #expect(responses.compactMap { $0["id"] as? Int } == [1, 2, 3, 4, 5, 6])

        let initialize = try #require(responses[0]["result"] as? [String: Any])
        #expect(initialize["protocolVersion"] as? String == MCPServerInfo.protocolVersion)

        let tools = try #require((responses[3 - 1]["result"] as? [String: Any])?["tools"] as? [[String: Any]])
        #expect(tools.compactMap { $0["name"] as? String } == [
            "describe_scope",
            "list_captures",
            "list_sessions",
        ])

        let scope = try Self.toolObject(responses[3])
        #expect(scope["opensNetworkPort"] as? Bool == false)
        #expect(scope["projectID"] as? String == fixture.projectID.uuidString)

        let captures = try Self.toolObject(responses[4])
        let captureList = try #require(captures["captures"] as? [[String: Any]])
        #expect(captureList.count == 1)
        #expect(captureList[0]["captureID"] as? String == fixture.captureID.uuidString)

        let sessions = try Self.toolObject(responses[5])
        let sessionList = try #require(sessions["sessions"] as? [[String: Any]])
        #expect(sessionList.count == 2)
        // Minimum disclosure: no sensitive family crosses the process boundary.
        for session in sessionList {
            #expect(session["host"] == nil)
            #expect(session["processName"] == nil)
        }
    }

    @Test("Without a grant, the real executable refuses everything and writes nothing to stdout but JSON-RPC")
    func failsClosedWithoutGrant() async throws {
        let fixture = try await ProductionGrantFixture(sessionCount: 1)
        defer { fixture.tearDown() }
        fixture.revoke()

        let (responses, stdout) = try Self.runCapturingStdout(lines: [
            Self.request(id: 1, method: "initialize"),
            Self.request(id: 2, method: "tools/call", params: [
                "name": "list_captures",
                "arguments": [:],
            ]),
            Data("this is not json at all".utf8),
        ])
        #expect(responses.count == 3)
        for response in responses {
            #expect(response["error"] != nil)
            #expect(response["result"] == nil)
        }
        // Every stdout line is a JSON-RPC object: no banner, no log, no stray text.
        for line in stdout.split(separator: "\n", omittingEmptySubsequences: true) {
            let object = try JSONSerialization.jsonObject(with: Data(line.utf8))
            let dictionary = try #require(object as? [String: Any])
            #expect(dictionary["jsonrpc"] as? String == "2.0")
        }
    }

    @Test("A Project switch invalidates the pinned session mid-conversation")
    func projectSwitchInvalidatesMidSession() async throws {
        let fixture = try await ProductionGrantFixture(sessionCount: 2)
        defer { fixture.tearDown() }
        _ = try fixture.issue(maxPageSize: 10)

        // The child is driven with a pause between writes so the grant can be
        // re-pointed while the same process is still connected.
        let responses = try Self.runInteractive { write, read in
            write(Self.request(id: 1, method: "initialize"))
            _ = read()
            write(Self.request(id: 2, method: "tools/call", params: [
                "name": "list_captures",
                "arguments": [:],
            ]))
            let before = read()

            _ = try fixture.issueForAnotherProject()

            write(Self.request(id: 3, method: "tools/call", params: [
                "name": "list_captures",
                "arguments": [:],
            ]))
            let after = read()
            return [before, after].compactMap { $0 }
        }

        #expect(responses.count == 2)
        #expect(responses[0]["result"] != nil)
        #expect((responses[1]["error"] as? [String: Any])?["code"] as? Int
            == MCPErrorCode.invalidRequest.rawValue)
    }

    @Test("A revoke invalidates the pinned session, and the audit trail stays minimal")
    func revokeInvalidatesAndAuditsMinimally() async throws {
        let fixture = try await ProductionGrantFixture(sessionCount: 2)
        defer { fixture.tearDown() }
        _ = try fixture.issue(maxPageSize: 10)

        let responses = try Self.run(lines: [
            Self.request(id: 1, method: "initialize"),
            Self.request(id: 2, method: "tools/call", params: [
                "name": "list_sessions",
                "arguments": [
                    "captureID": fixture.captureID.uuidString,
                    "filter": ["status": "ok"],
                ],
            ]),
        ])
        #expect(responses.count == 2)
        #expect(responses[1]["result"] != nil)

        // The trail names the filter *field* and nothing about its operand.
        let records = fixture.issuer.recentAudit()
        let record = try #require(records.last)
        #expect(record.tool == "list_sessions")
        #expect(record.result == .ok)
        #expect(record.filterFields == ["status"])
        #expect(record.projectID == fixture.projectID)

        fixture.revoke()
        let afterRevoke = try Self.run(lines: [
            Self.request(id: 1, method: "initialize"),
        ])
        #expect(afterRevoke.count == 1)
        #expect(afterRevoke[0]["error"] != nil)
    }

    // MARK: Private

    /// The embedded executable inside the built app bundle.
    private static var executableURL: URL? {
        let url = Bundle.main.bundleURL
            .appendingPathComponent("Contents/MacOS/TracexyMCP")
        return FileManager.default.fileExists(atPath: url.path) ? url : nil
    }

    /// The child's environment.
    ///
    /// `XCTestConfigurationFilePath` is set to one fixed, test-owned value so
    /// ``TracexyIdentity`` puts every child of this suite under the *same*
    /// throwaway Application Support root — the standard isolation this repo
    /// already relies on, and the reason no test can reach real user data. It is
    /// not a scope override: the executable still accepts no path, no database
    /// and no Project from its arguments, environment or requests.
    private static var childEnvironment: [String: String] {
        var environment = ProcessInfo.processInfo.environment
        // Keyed on this host process so two parallel test workers never share a
        // grant directory, while every child of *this* worker agrees on one.
        environment["XCTestConfigurationFilePath"] =
            "/tracexy-mcp-subprocess-\(ProcessInfo.processInfo.processIdentifier).xctestconfiguration"
        return environment
    }

    private static func request(id: Int, method: String, params: [String: Any] = [:]) -> Data {
        var object: [String: Any] = ["jsonrpc": "2.0", "id": id, "method": method]
        if !params.isEmpty {
            object["params"] = params
        }
        // swiftlint:disable:next force_try
        return try! JSONSerialization.data(withJSONObject: object)
    }

    private static func notification(method: String) -> Data {
        // swiftlint:disable:next force_try
        try! JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "method": method])
    }

    private static func toolObject(_ response: [String: Any]) throws -> [String: Any] {
        let result = try #require(response["result"] as? [String: Any])
        let content = try #require(result["content"] as? [[String: Any]])
        let text = try #require(content.first?["text"] as? String)
        return try #require(try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
    }

    private static func run(lines: [Data]) throws -> [[String: Any]] {
        try runCapturingStdout(lines: lines).responses
    }

    /// Write every line, close stdin, and read the whole answer.
    private static func runCapturingStdout(
        lines: [Data]
    )
        throws -> (responses: [[String: Any]], stdout: String)
    {
        let process = try makeProcess()
        let input = Pipe()
        let output = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = Pipe()
        try process.run()

        var payload = Data()
        for line in lines {
            payload.append(line)
            payload.append(0x0A)
        }
        input.fileHandleForWriting.write(payload)
        input.fileHandleForWriting.closeFile()

        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        let text = String(data: data, encoding: .utf8) ?? ""
        let responses = text
            .split(separator: "\n", omittingEmptySubsequences: true)
            .compactMap { try? JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: Any] }
        return (responses, text)
    }

    /// Drive the child turn by turn so state can change between requests.
    private static func runInteractive(
        _ body: (_ write: (Data) -> Void, _ read: () -> [String: Any]?) throws -> [[String: Any]]
    )
        throws -> [[String: Any]]
    {
        let process = try makeProcess()
        let input = Pipe()
        let output = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = Pipe()
        try process.run()

        var buffer = Data()
        let write: (Data) -> Void = { line in
            var payload = line
            payload.append(0x0A)
            input.fileHandleForWriting.write(payload)
        }
        let read: () -> [String: Any]? = {
            while true {
                if let index = buffer.firstIndex(of: 0x0A) {
                    let line = buffer[buffer.startIndex ..< index]
                    buffer.removeSubrange(buffer.startIndex ... index)
                    guard !line.isEmpty else {
                        continue
                    }
                    return try? JSONSerialization.jsonObject(with: Data(line)) as? [String: Any]
                }
                let chunk = output.fileHandleForReading.availableData
                if chunk.isEmpty {
                    return nil
                }
                buffer.append(chunk)
            }
        }

        defer {
            input.fileHandleForWriting.closeFile()
            process.terminate()
            process.waitUntilExit()
        }
        return try body(write, read)
    }

    private static func makeProcess() throws -> Process {
        let url = try #require(executableURL)
        let process = Process()
        process.executableURL = url
        process.environment = childEnvironment
        process.arguments = []
        return process
    }
}

// MARK: - ProductionGrantFixture

/// Writes a grant and a History database at the *identity-derived* locations —
/// which, under a test run, are this run's throwaway temporary directory — so the
/// subprocess finds them without any override.
private struct ProductionGrantFixture {
    // MARK: Lifecycle

    init(sessionCount: Int) async throws {
        // The grant must land exactly where the *executable* looks, so the
        // location is taken from the executable rather than re-derived here.
        grantURL = try MCPSubprocessIntegrationTests.resolveGrantURL()
        let directory = grantURL.deletingLastPathComponent()
        auditURL = directory.appendingPathComponent(MCPGrantLocation.auditFileName)
        databaseURL = directory
            .deletingLastPathComponent()
            .appendingPathComponent("MCPFixture/history.sqlite")
        projectID = UUID()
        captureID = UUID()

        // A previous run of this suite may have left a grant behind; every test
        // starts from the closed default state.
        try? FileManager.default.removeItem(at: grantURL)
        try? FileManager.default.removeItem(at: auditURL)

        try FileManager.default.createDirectory(
            at: databaseURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try? FileManager.default.removeItem(at: databaseURL)
        let store = try SessionStore(configuration: .init(location: .file(databaseURL)))
        var sessions: [HistorySessionRecord] = []
        for index in 0 ..< sessionCount {
            let start: Double = 1_760_000_000 + Double(index)
            sessions.append(HistorySessionRecord(
                sessionID: UUID(),
                startTime: start,
                duration: 1.5,
                processName: "ExampleClient",
                host: "service\(index).example.com",
                sourceEndpoint: "192.0.2.10:51310",
                destinationEndpoint: "203.0.113.42:443",
                protocols: ["tcp", "tls"],
                status: .ok,
                latencyMilliseconds: 42,
                bytesUp: 1_024,
                bytesDown: 4_096
            ))
        }
        try await store.replaceCapture(
            HistoryCaptureRecord(
                captureID: captureID,
                startedAt: 1_760_000_000,
                endedAt: 1_760_000_600,
                sourceKind: .live,
                completeness: .complete
            ),
            sessions: sessions
        )
    }

    // MARK: Internal

    let grantURL: URL
    let auditURL: URL
    let databaseURL: URL
    let projectID: UUID
    let captureID: UUID

    var issuer: MCPGrantIssuer {
        MCPGrantIssuer(grantURL: grantURL, auditURL: auditURL)
    }

    @discardableResult
    func issue(maxPageSize: Int) throws -> MCPGrantDocument {
        try issuer.issue(
            scope: MCPGrantScope(
                projectID: projectID,
                projectName: "Fixture",
                historyDatabaseURL: databaseURL
            ),
            disclosure: .minimum,
            maxPageSize: maxPageSize
        )
    }

    @discardableResult
    func issueForAnotherProject() throws -> MCPGrantDocument {
        try issuer.issue(
            scope: MCPGrantScope(
                projectID: UUID(),
                projectName: "Other",
                historyDatabaseURL: databaseURL
            ),
            disclosure: .minimum,
            maxPageSize: 10
        )
    }

    func revoke() {
        try? issuer.revoke()
    }

    func tearDown() {
        revoke()
        try? FileManager.default.removeItem(at: databaseURL.deletingLastPathComponent())
    }
}
