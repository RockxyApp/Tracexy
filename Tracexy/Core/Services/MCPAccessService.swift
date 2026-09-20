import Foundation
import Observation

// This file declares the app side of the MCP authorization boundary: issuing,
// inspecting and revoking the single grant, and reading back the bounded audit
// trail the bundled executable writes.
//
// It is the only writer. It never starts a process, never opens a socket, never
// reads the History database, and never puts a token, credential, capture path,
// locator or packet byte into a grant.

// MARK: - MCPGrantScope

/// The exact scope a grant may be issued for: one Project and the one History
/// database that Project owns. Resolved by the coordinator, never typed by a user
/// and never supplied by a client.
nonisolated struct MCPGrantScope: Sendable, Equatable {
    let projectID: UUID
    let projectName: String
    let historyDatabaseURL: URL
}

// MARK: - MCPAccessStatus

/// What the grant file says right now.
nonisolated enum MCPAccessStatus: Sendable, Equatable {
    /// No grant exists. This is the default state and what a revoke restores.
    case notGranted
    /// A structurally valid, unexpired grant.
    case granted(MCPGrantDocument)
    /// A grant exists but would be refused. Surfaced so the user can re-issue
    /// rather than wonder why a client is failing.
    case invalid(MCPGrantError)

    // MARK: Internal

    var document: MCPGrantDocument? {
        guard case let .granted(document) = self else {
            return nil
        }
        return document
    }
}

// MARK: - MCPGrantIssuer

/// The pure file-level grant writer/reader. Injectable URLs keep every test off
/// the production Application Support location.
nonisolated struct MCPGrantIssuer: Sendable {
    // MARK: Lifecycle

    init(
        grantURL: URL,
        auditURL: URL,
        now: @escaping @Sendable () -> Double = { Date().timeIntervalSinceReferenceDate }
    ) {
        self.grantURL = grantURL
        self.auditURL = auditURL
        self.now = now
    }

    // MARK: Internal

    let grantURL: URL
    let auditURL: URL

    /// The current status, validated exactly the way the executable validates it.
    func status() -> MCPAccessStatus {
        do {
            return try .granted(MCPGrantReader(url: grantURL, now: now).load())
        } catch let error as MCPGrantError {
            return error == .absent ? .notGranted : .invalid(error)
        } catch {
            return .invalid(.malformed)
        }
    }

    /// Issue (or re-issue) the single grant for one Project.
    ///
    /// The revision always advances, so any client holding the previous scope is
    /// superseded on its next call — which is exactly what a Project switch, a
    /// disclosure change or a re-grant must mean.
    @discardableResult
    func issue(
        scope: MCPGrantScope,
        disclosure: AutomationDisclosure,
        maxPageSize: Int
    )
        throws -> MCPGrantDocument
    {
        let document = MCPGrantDocument(
            revision: nextRevision(),
            projectID: scope.projectID,
            historyDatabasePath: scope.historyDatabaseURL.path,
            disclosure: disclosure,
            maxPageSize: min(max(1, maxPageSize), MCPGrantLimits.maxPageSize),
            issuedAt: now()
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        try writeOwnerOnly(encoder.encode(document), to: grantURL)
        return document
    }

    /// Remove the grant. Every subsequent call from any client fails closed.
    /// Explicit user revocation also clears the local audit trail; an automatic
    /// Project-boundary revocation preserves it so the user can still inspect
    /// which tools ran before the switch.
    func revoke(clearAudit: Bool = true) throws {
        let manager = FileManager.default
        if manager.fileExists(atPath: grantURL.path) {
            try manager.removeItem(at: grantURL)
        }
        if clearAudit {
            MCPAuditTrail(url: auditURL).clear()
        }
    }

    /// The newest audit records, oldest-first.
    func recentAudit(limit: Int = 20) -> [MCPAuditRecord] {
        MCPAuditTrail(url: auditURL).recent(limit: limit)
    }

    // MARK: Private

    private let now: @Sendable () -> Double

    /// One past whatever is on disk, so a revision never repeats even if a grant
    /// file is restored from a backup.
    private func nextRevision() -> Int {
        guard let data = FileManager.default.contents(atPath: grantURL.path),
              data.count <= MCPGrantLimits.maxFileBytes,
              let existing = try? JSONDecoder().decode(MCPGrantDocument.self, from: data) else
        {
            return 1
        }
        return existing.revision >= Int.max ? 1 : existing.revision + 1
    }

    /// Write owner-only, replacing atomically. The directory is created owner-only
    /// too, so the grant is never briefly world-readable.
    private func writeOwnerOnly(_ data: Data, to url: URL) throws {
        let manager = FileManager.default
        let directory = url.deletingLastPathComponent()
        try manager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        let temporary = directory.appendingPathComponent(".grant-\(UUID().uuidString).tmp")
        guard manager.createFile(
            atPath: temporary.path,
            contents: data,
            attributes: [.posixPermissions: 0o600]
        ) else {
            throw CocoaError(.fileWriteUnknown)
        }
        do {
            if manager.fileExists(atPath: url.path) {
                _ = try manager.replaceItemAt(url, withItemAt: temporary)
            } else {
                try manager.moveItem(at: temporary, to: url)
            }
        } catch {
            try? manager.removeItem(at: temporary)
            throw error
        }
        // `replaceItemAt` can preserve the destination's metadata, so the mode is
        // reasserted on whatever file now occupies the path.
        try? manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}

// MARK: - MCPAccessModel

/// The observable Settings-facing state for the MCP boundary. It holds no
/// capture data, starts nothing, and exposes exactly the three actions the pane
/// offers: refresh, grant, revoke.
@MainActor
@Observable
final class MCPAccessModel {
    // MARK: Lifecycle

    init(issuer: MCPGrantIssuer) {
        self.issuer = issuer
        status = issuer.status()
        recentAudit = issuer.recentAudit()
    }

    /// The production composition: the identity-derived Application Support
    /// location, and nothing overridable.
    ///
    /// `identity` is optional rather than defaulted to `.current` so the default is
    /// resolved *inside* this main-actor initializer; a default argument is
    /// evaluated in a nonisolated context, where reading `.current` is a
    /// concurrency violation.
    convenience init(identity: TracexyIdentity? = nil) {
        let resolved = identity ?? .current
        self.init(issuer: MCPGrantIssuer(
            grantURL: MCPGrantLocation.grantURL(identity: resolved),
            auditURL: MCPGrantLocation.auditURL(identity: resolved)
        ))
    }

    // MARK: Internal

    /// The default row ceiling offered when no grant exists yet. Deliberately far
    /// below the 500 bound: a smaller default is the honest one.
    static let defaultMaxPageSize = 100

    private(set) var status: MCPAccessStatus
    private(set) var recentAudit: [MCPAuditRecord]
    /// The last grant/revoke failure, in copy suitable for the pane.
    private(set) var errorMessage: String?

    /// The bundled client command a user pastes into an MCP client config.
    var bundledCommandPath: String {
        Bundle.main.bundleURL
            .appendingPathComponent("Contents/MacOS/TracexyMCP")
            .path
    }

    /// A ready-to-paste client configuration fragment. It names the bundled
    /// command and nothing else — no port, host, token or database path.
    var clientConfigurationSnippet: String {
        Self.clientConfigurationSnippet(commandPath: bundledCommandPath)
    }

    /// Encode the local app path as JSON: installation folders can contain
    /// quotes, backslashes or other characters that need escaping.
    static func clientConfigurationSnippet(commandPath: String) -> String {
        struct Server: Encodable {
            let command: String
            let args: [String]
        }
        struct Configuration: Encodable {
            let mcpServers: [String: Server]
        }

        let configuration = Configuration(mcpServers: [
            "tracexy": Server(command: commandPath, args: []),
        ])
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(configuration),
              let text = String(data: data, encoding: .utf8) else
        {
            return ""
        }
        return text
    }

    func refresh() {
        status = issuer.status()
        recentAudit = issuer.recentAudit()
    }

    func grant(scope: MCPGrantScope, disclosure: AutomationDisclosure, maxPageSize: Int) {
        do {
            _ = try issuer.issue(scope: scope, disclosure: disclosure, maxPageSize: maxPageSize)
            errorMessage = nil
        } catch {
            errorMessage = "Couldn’t write the MCP grant — \(error.localizedDescription)"
        }
        refresh()
    }

    func revoke() {
        do {
            try issuer.revoke()
            errorMessage = nil
        } catch {
            errorMessage = "Couldn’t remove the MCP grant — \(error.localizedDescription)"
        }
        refresh()
    }

    /// Revoke the active grant before the coordinator swaps Project-owned
    /// storage. The audit remains available in Settings, while the error is
    /// surfaced if the fail-closed removal itself could not be completed.
    func invalidateForProjectBoundary() {
        do {
            try issuer.revoke(clearAudit: false)
            errorMessage = nil
        } catch {
            errorMessage = "Couldn’t revoke MCP access while switching Projects — \(error.localizedDescription)"
        }
        refresh()
    }

    // MARK: Private

    private let issuer: MCPGrantIssuer
}
