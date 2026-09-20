import Foundation
@testable import Tracexy

// MARK: - MCPTestEnvironment

/// A throwaway Application-Support-shaped directory holding one grant, one audit
/// trail and one History database, so no MCP test ever touches the real
/// identity-derived location.
///
/// Every record it writes is documentation-range data (RFC 5737 / RFC 1918 and
/// `example.com`), so a fixture database can be inspected or attached without
/// redaction.
struct MCPTestEnvironment {
    // MARK: Lifecycle

    init() {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-mcp-tests-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }

    // MARK: Internal

    let root: URL

    var grantURL: URL {
        root.appendingPathComponent("MCP/grant.json")
    }

    var auditURL: URL {
        root.appendingPathComponent("MCP/audit.jsonl")
    }

    var databaseURL: URL {
        root.appendingPathComponent("History/history.sqlite")
    }

    var issuer: MCPGrantIssuer {
        MCPGrantIssuer(grantURL: grantURL, auditURL: auditURL)
    }

    var projectID: UUID {
        AssistantDemoFixture.projectID
    }

    var scope: MCPGrantScope {
        MCPGrantScope(projectID: projectID, projectName: "Fixture", historyDatabaseURL: databaseURL)
    }

    func remove() {
        try? FileManager.default.removeItem(at: root)
    }

    /// Create a migrated, writable History database with one capture and
    /// `sessionCount` documentation-range sessions, then close it so the MCP path
    /// can open it read-only.
    @discardableResult
    func seedHistory(captureID: UUID = UUID(), sessionCount: Int = 3) async throws -> UUID {
        try FileManager.default.createDirectory(
            at: databaseURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let store = try SessionStore(configuration: .init(location: .file(databaseURL)))
        let capture = HistoryCaptureRecord(
            captureID: captureID,
            startedAt: 1_760_000_000,
            endedAt: 1_760_000_600,
            sourceKind: .live,
            completeness: .complete
        )
        var sessions: [HistorySessionRecord] = []
        for index in 0 ..< sessionCount {
            let start: Double = 1_760_000_000 + Double(index)
            let status: HistorySessionStatus = index == 0 ? .warning : .ok
            let bytesUp = Int64(1_024 * (index + 1))
            let bytesDown = Int64(4_096 * (index + 1))
            sessions.append(HistorySessionRecord(
                sessionID: UUID(),
                startTime: start,
                duration: 1.5,
                processName: "ExampleClient",
                host: "service\(index).example.com",
                sourceEndpoint: "192.0.2.10:5131\(index)",
                destinationEndpoint: "203.0.113.42:443",
                protocols: ["tcp", "tls"],
                status: status,
                latencyMilliseconds: 42,
                bytesUp: bytesUp,
                bytesDown: bytesDown
            ))
        }
        try await store.replaceCapture(capture, sessions: sessions)
        return captureID
    }
}
