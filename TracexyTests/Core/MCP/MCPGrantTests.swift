import Foundation
import Testing
@testable import Tracexy

// MARK: - MCPGrantTests

@Suite("MCP grant: lifecycle, permissions, staleness, revision and Project scope")
struct MCPGrantTests {
    @Test("Client configuration escapes a Mac installation path and contains only the command")
    @MainActor
    func clientConfigurationUsesLocalCommand() throws {
        let command = "/Users/example/Apps/Research \"Tools\"/Tracexy.app/Contents/MacOS/TracexyMCP"
        let snippet = MCPAccessModel.clientConfigurationSnippet(commandPath: command)
        let root = try #require(JSONSerialization.jsonObject(with: Data(snippet.utf8)) as? [String: Any])
        let servers = try #require(root["mcpServers"] as? [String: Any])
        let tracexy = try #require(servers["tracexy"] as? [String: Any])

        #expect(Set(root.keys) == ["mcpServers"])
        #expect(Set(tracexy.keys) == ["command", "args"])
        #expect(tracexy["command"] as? String == command)
        #expect(tracexy["args"] as? [String] == [])
    }

    @Test("No grant is the default state, and it is refused rather than tolerated")
    func absentGrantFailsClosed() throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }

        #expect(environment.issuer.status() == .notGranted)
        #expect(throws: MCPGrantError.absent) {
            try MCPGrantReader(url: environment.grantURL).load()
        }
    }

    @Test("An issued grant is owner-only, atomic, and names exactly one Project")
    func issuedGrantIsOwnerOnly() throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        try environment.makeDatabaseFile()

        let document = try environment.issuer.issue(
            scope: environment.scope,
            disclosure: .init(includesHost: true),
            maxPageSize: 25
        )
        #expect(document.projectID == environment.projectID)
        #expect(document.revision == 1)
        #expect(document.maxPageSize == 25)
        #expect(document.disclosure.includesHost)
        #expect(!document.disclosure.includesProcess)

        let attributes = try FileManager.default.attributesOfItem(atPath: environment.grantURL.path)
        let mode = try #require((attributes[.posixPermissions] as? NSNumber)?.uint16Value)
        #expect(mode & 0o077 == 0)

        let loaded = try MCPGrantReader(url: environment.grantURL).load()
        #expect(loaded == document)
    }

    @Test("A group- or world-readable grant is refused")
    func looseModeIsRefused() throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        try environment.makeDatabaseFile()
        _ = try environment.issuer.issue(scope: environment.scope, disclosure: .minimum, maxPageSize: 10)

        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644],
            ofItemAtPath: environment.grantURL.path
        )
        #expect(throws: MCPGrantError.notOwnerOnly(mode: 0o644)) {
            try MCPGrantReader(url: environment.grantURL).load()
        }
    }

    @Test("A grant larger than the bound is refused before it is parsed")
    func oversizedGrantIsRefused() throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        try environment.makeDirectory()

        let payload = Data(repeating: 0x20, count: MCPGrantLimits.maxFileBytes + 1)
        FileManager.default.createFile(
            atPath: environment.grantURL.path,
            contents: payload,
            attributes: [.posixPermissions: 0o600]
        )
        #expect(throws: MCPGrantError.tooLarge(byteCount: MCPGrantLimits.maxFileBytes + 1)) {
            try MCPGrantReader(url: environment.grantURL).load()
        }
    }

    @Test("Malformed bytes are a controlled refusal, never a partial grant")
    func malformedGrantIsRefused() throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        try environment.makeDirectory()
        FileManager.default.createFile(
            atPath: environment.grantURL.path,
            contents: Data("{ not json".utf8),
            attributes: [.posixPermissions: 0o600]
        )
        #expect(throws: MCPGrantError.malformed) {
            try MCPGrantReader(url: environment.grantURL).load()
        }
    }

    @Test("A grant older than the maximum age is stale")
    func staleGrantIsRefused() throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        try environment.makeDatabaseFile()
        let now: Double = 1_000_000
        let issuer = MCPGrantIssuer(
            grantURL: environment.grantURL,
            auditURL: environment.auditURL,
            now: { now }
        )
        _ = try issuer.issue(scope: environment.scope, disclosure: .minimum, maxPageSize: 10)

        let later = now + MCPGrantLimits.maxAge + 1
        #expect(throws: MCPGrantError.stale) {
            try MCPGrantReader(url: environment.grantURL, now: { later }).load()
        }
        // Exactly at the boundary it is still usable.
        #expect(throws: Never.self) {
            try MCPGrantReader(url: environment.grantURL, now: { now + MCPGrantLimits.maxAge }).load()
        }
    }

    @Test("An implausible future issuance instant is refused")
    func futureGrantIsRefused() throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        try environment.makeDatabaseFile()
        let now: Double = 1_000_000
        let issuer = MCPGrantIssuer(
            grantURL: environment.grantURL,
            auditURL: environment.auditURL,
            now: { now + MCPGrantLimits.maxIssuanceSkew + 60 }
        )
        _ = try issuer.issue(scope: environment.scope, disclosure: .minimum, maxPageSize: 10)
        #expect(throws: MCPGrantError.invalidIssuanceTime) {
            try MCPGrantReader(url: environment.grantURL, now: { now }).load()
        }
    }

    @Test("An unknown schema version is refused rather than guessed")
    func unsupportedSchemaIsRefused() throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        try environment.makeDatabaseFile()
        try environment.write(MCPGrantDocument(
            schemaVersion: MCPGrantDocument.currentSchemaVersion + 1,
            revision: 1,
            projectID: environment.projectID,
            historyDatabasePath: environment.databaseURL.path,
            disclosure: .minimum,
            maxPageSize: 10,
            issuedAt: Date().timeIntervalSinceReferenceDate
        ))
        #expect(throws: MCPGrantError.unsupportedSchema(MCPGrantDocument.currentSchemaVersion + 1)) {
            try MCPGrantReader(url: environment.grantURL).load()
        }
    }

    @Test("A page size outside 1...500 is refused, and a non-positive revision too")
    func boundsAreEnforced() throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        try environment.makeDatabaseFile()

        try environment.write(environment.document(maxPageSize: MCPGrantLimits.maxPageSize + 1))
        #expect(throws: MCPGrantError.invalidPageSize(MCPGrantLimits.maxPageSize + 1)) {
            try MCPGrantReader(url: environment.grantURL).load()
        }

        try environment.write(environment.document(revision: 0))
        #expect(throws: MCPGrantError.invalidRevision(0)) {
            try MCPGrantReader(url: environment.grantURL).load()
        }
    }

    @Test("A grant naming a missing database is refused, and never creates one")
    func missingDatabaseIsRefused() throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        try environment.makeDirectory()
        try environment.write(environment.document())

        #expect(throws: MCPGrantError.databaseUnavailable) {
            try MCPGrantReader(url: environment.grantURL).load()
        }
        #expect(!FileManager.default.fileExists(atPath: environment.databaseURL.path))
    }

    @Test("A re-issued grant supersedes a pinned one, and a Project change is a mismatch")
    func pinnedScopeInvalidation() throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        try environment.makeDatabaseFile()

        let first = try environment.issuer.issue(
            scope: environment.scope,
            disclosure: .minimum,
            maxPageSize: 10
        )
        let reader = MCPGrantReader(url: environment.grantURL)
        #expect(throws: Never.self) {
            try reader.load(matching: first.pin)
        }

        // Re-issuing for the same Project advances the revision: superseded.
        let second = try environment.issuer.issue(
            scope: environment.scope,
            disclosure: .minimum,
            maxPageSize: 10
        )
        #expect(second.revision == first.revision + 1)
        #expect(throws: MCPGrantError.superseded) {
            try reader.load(matching: first.pin)
        }

        // Switching Projects re-points the grant: mismatch, not merely superseded.
        let otherScope = MCPGrantScope(
            projectID: UUID(),
            projectName: "Other",
            historyDatabaseURL: environment.databaseURL
        )
        _ = try environment.issuer.issue(scope: otherScope, disclosure: .minimum, maxPageSize: 10)
        #expect(throws: MCPGrantError.projectMismatch) {
            try reader.load(matching: second.pin)
        }
    }

    @Test("Revoking removes the grant and the audit trail, and restores the default state")
    func revokeRestoresDefault() throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        try environment.makeDatabaseFile()
        _ = try environment.issuer.issue(scope: environment.scope, disclosure: .minimum, maxPageSize: 10)
        MCPAuditTrail(url: environment.auditURL).append(
            MCPAuditRecord(at: 1, tool: "list_captures", result: .ok, projectID: environment.projectID)
        )

        try environment.issuer.revoke()
        #expect(environment.issuer.status() == .notGranted)
        #expect(environment.issuer.recentAudit().isEmpty)
        #expect(throws: MCPGrantError.absent) {
            try MCPGrantReader(url: environment.grantURL).load()
        }
    }

    @Test("A Project boundary revokes access but preserves the audit trail")
    @MainActor
    func projectBoundaryRevokesAccess() throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        try environment.makeDatabaseFile()
        let access = MCPAccessModel(issuer: environment.issuer)
        access.grant(scope: environment.scope, disclosure: .minimum, maxPageSize: 10)
        MCPAuditTrail(url: environment.auditURL).append(
            MCPAuditRecord(at: 1, tool: "describe_scope", result: .ok, projectID: environment.projectID)
        )

        let coordinator = MainContentCoordinator(mcpAccess: access)
        coordinator.invalidateOutgoingProjectWork()

        #expect(access.status == .notGranted)
        #expect(access.recentAudit.count == 1)
        #expect(throws: MCPGrantError.absent) {
            try MCPGrantReader(url: environment.grantURL).load()
        }
    }

    @Test("The grant document carries no token, credential, capture path or locator")
    func grantCarriesNoSecrets() throws {
        let environment = MCPTestEnvironment()
        defer { environment.remove() }
        try environment.makeDatabaseFile()
        _ = try environment.issuer.issue(
            scope: environment.scope,
            disclosure: .init(includesProcess: true, includesHost: true, includesEndpoints: true),
            maxPageSize: 50
        )
        let data = try #require(FileManager.default.contents(atPath: environment.grantURL.path))
        let object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(Set(object.keys) == [
            "disclosure",
            "historyDatabasePath",
            "issuedAt",
            "maxPageSize",
            "projectID",
            "revision",
            "schemaVersion",
        ])
    }
}

// MARK: - Fixture helpers

private extension MCPTestEnvironment {
    func makeDirectory() throws {
        try FileManager.default.createDirectory(
            at: grantURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
    }

    /// A plain regular file standing in for a History database. The grant reader
    /// only checks that the named database exists; opening it is the server's job.
    func makeDatabaseFile() throws {
        try FileManager.default.createDirectory(
            at: databaseURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        FileManager.default.createFile(atPath: databaseURL.path, contents: Data())
    }

    func document(
        revision: Int = 1,
        maxPageSize: Int = 10,
        issuedAt: Double = Date().timeIntervalSinceReferenceDate
    )
        -> MCPGrantDocument
    {
        MCPGrantDocument(
            revision: revision,
            projectID: projectID,
            historyDatabasePath: databaseURL.path,
            disclosure: .minimum,
            maxPageSize: maxPageSize,
            issuedAt: issuedAt
        )
    }

    func write(_ document: MCPGrantDocument) throws {
        try makeDirectory()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try? FileManager.default.removeItem(at: grantURL)
        try FileManager.default.createFile(
            atPath: grantURL.path,
            contents: encoder.encode(document),
            attributes: [.posixPermissions: 0o600]
        )
    }
}
