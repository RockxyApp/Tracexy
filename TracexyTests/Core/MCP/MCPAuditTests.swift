import Foundation
import Testing
@testable import Tracexy

// MARK: - MCPAuditTests

@Suite("MCP audit trail: minimization, bounds and durability")
struct MCPAuditTests {
    @Test("A record can only express time, tool, result, Project and filter field names")
    func recordIsMinimal() throws {
        let record = MCPAuditRecord(
            at: 1_000,
            tool: "list_sessions",
            result: .ok,
            projectID: AssistantDemoFixture.projectID,
            filterFields: ["hostSubstring", "status"]
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(record)
        let object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(Set(object.keys) == ["filterFields", "projectID", "result", "time", "tool"])

        // The field list is names only — no operand can reach the trail.
        let fields = try #require(object["filterFields"] as? [String])
        #expect(fields == ["hostSubstring", "status"])
    }

    @Test("Filter field names are allowlisted, sorted, de-duplicated and bounded")
    func filterFieldsAreBounded() {
        let known = MCPFilterFieldName.allCases.map(\.rawValue)
        let invented = (0 ..< (MCPAuditRecord.maxFilterFields + 8)).map { "field\($0)" }
        let record = MCPAuditRecord(
            at: 0,
            tool: "list_sessions",
            result: .ok,
            projectID: nil,
            filterFields: invented + known + known + invented
        )
        #expect(record.filterFields == known.sorted())
        #expect(record.filterFields.count <= MCPAuditRecord.maxFilterFields)
        #expect(Set(record.filterFields).count == record.filterFields.count)
        #expect(MCPFilterFieldName.allCases.count <= MCPAuditRecord.maxFilterFields)
    }

    @Test("Only advertised tool names are recorded; anything else is “unknown”", arguments: [
        "delete_everything",
        "list_sessions ",
        "LIST_SESSIONS",
        "",
        "../../etc/passwd",
        "10.0.0.5:11434",
        String(repeating: "x", count: 4_096),
        "list_sessions\u{0}",
    ])
    func toolNameIsCanonical(_ name: String) {
        let record = MCPAuditRecord(at: 0, tool: name, result: .invalid, projectID: nil)
        #expect(record.tool == MCPAuditTool.unknown.rawValue)
        #expect(record.tool.count <= MCPAuditRecord.maxToolNameLength)
    }

    @Test("Every advertised tool name is recorded verbatim")
    func advertisedToolNamesAreRecorded() {
        for tool in MCPToolName.allCases {
            let record = MCPAuditRecord(at: 0, tool: tool.rawValue, result: .ok, projectID: nil)
            #expect(record.tool == tool.rawValue)
        }
        for tool in MCPAuditTool.allCases {
            #expect(tool.rawValue.count <= MCPAuditRecord.maxToolNameLength)
        }
    }

    @Test("Adversarial filter names never reach the trail", arguments: [
        ["hostSubstring=evil.example.com"],
        ["/example/Library/History.sqlite"],
        ["hostsubstring", "HostSubstring"],
        [String(repeating: "h", count: 65_536)],
        ["status\n{\"injected\":true}"],
    ])
    func adversarialFilterNamesAreDropped(_ names: [String]) {
        let record = MCPAuditRecord(at: 0, tool: "list_sessions", result: .ok, projectID: nil, filterFields: names)
        #expect(record.filterFields.isEmpty)
    }

    @Test("A tampered trail line is canonicalized on read, never replayed verbatim")
    func tamperedTrailIsCanonicalizedOnRead() throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        let trail = MCPAuditTrail(url: environment.auditURL)
        let tampered = """
        {"filterFields":["hostSubstring","host=10.0.0.5"],"projectID":null,"result":"ok",\
        "time":1,"tool":"curl http://evil.example.com"}

        """
        try FileManager.default.createDirectory(
            at: environment.auditURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data(tampered.utf8).write(to: environment.auditURL)

        let records = trail.recent(limit: 10)
        #expect(records.count == 1)
        #expect(records.first?.tool == MCPAuditTool.unknown.rawValue)
        #expect(records.first?.filterFields == ["hostSubstring"])
    }

    @Test("The trail keeps only the newest records and stays owner-only")
    func trailIsBoundedAndOwnerOnly() throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        let trail = MCPAuditTrail(url: environment.auditURL, limit: 5)

        for index in 0 ..< 20 {
            trail.append(MCPAuditRecord(
                at: Double(index),
                tool: "list_captures",
                result: .ok,
                projectID: environment.projectID
            ))
        }
        let records = trail.recent(limit: 100)
        #expect(records.count == 5)
        #expect(records.map(\.time) == [15, 16, 17, 18, 19])

        let attributes = try FileManager.default.attributesOfItem(atPath: environment.auditURL.path)
        let mode = try #require((attributes[.posixPermissions] as? NSNumber)?.uint16Value)
        #expect(mode & 0o077 == 0)
    }

    @Test("A partially corrupt trail yields the records that decode, never a crash")
    func corruptLinesAreSkipped() throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        let trail = MCPAuditTrail(url: environment.auditURL)
        trail.append(MCPAuditRecord(at: 1, tool: "ping", result: .ok, projectID: nil))

        var contents = try #require(FileManager.default.contents(atPath: environment.auditURL.path))
        contents.append(Data("{ broken\n".utf8))
        try contents.write(to: environment.auditURL)

        #expect(trail.recent(limit: 10).count == 1)
    }

    @Test("An unwritable trail is silently tolerated and never becomes a channel")
    func unwritableTrailIsTolerated() {
        // A directory where the file should be: every write fails, every read is empty.
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        try? FileManager.default.createDirectory(at: environment.auditURL, withIntermediateDirectories: true)

        let trail = MCPAuditTrail(url: environment.auditURL)
        trail.append(MCPAuditRecord(at: 1, tool: "ping", result: .ok, projectID: nil))
        #expect(trail.recent(limit: 10).isEmpty)
    }
}
