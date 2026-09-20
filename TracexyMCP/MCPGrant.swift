import Foundation

// This file declares the frozen authorization boundary shared by the app (which
// issues a grant) and the bundled `TracexyMCP` executable (which only ever reads
// one). It is deliberately transport-free and process-free: it decides what a
// grant *is*, where it lives, and why a candidate grant must be refused. It
// opens no database, reads no settings, starts no listener, and never widens a
// scope it was handed.

// MARK: - MCPGrantLimits

/// The fixed bounds every grant is validated against. They are constants rather
/// than settings so a hostile or corrupted grant file cannot raise its own
/// ceiling.
nonisolated enum MCPGrantLimits {
    /// The largest grant document that will be read at all. A grant is a handful
    /// of scalars; anything larger is refused before it is parsed.
    static let maxFileBytes = 16_384

    /// The largest audit trail retained locally, in records.
    static let maxAuditRecords = 200

    /// How long an issued grant stays usable. A grant is a deliberate,
    /// re-issuable user action, so it expires rather than lingering forever.
    static let maxAge: Double = 30 * 24 * 60 * 60

    /// How far into the future an issuance instant may sit before it is treated
    /// as invalid rather than merely early. Absorbs ordinary clock skew only.
    static let maxIssuanceSkew: Double = 300

    /// The hard ceiling on a grant's declared page size, identical to the bound
    /// ``HistoryAutomationService`` already enforces.
    static let maxPageSize = HistoryLimits.maxReadPageSize
}

// MARK: - MCPGrantLocation

/// Where the single app-written grant and its local audit trail live. The path is
/// identity-derived and owner-only; nothing here accepts an override from an
/// argument, an environment variable, or a request.
enum MCPGrantLocation {
    /// The stable prefix of the executable's one stderr diagnostic naming where
    /// authorization is read from. It exists so a misconfigured client is
    /// debuggable; it is a diagnostic, never an input.
    nonisolated static let diagnosticPrefix = "Authorization grant: "

    nonisolated static let relativeDirectory = "MCP"
    nonisolated static let grantFileName = "grant.json"
    nonisolated static let auditFileName = "audit.jsonl"

    static func directoryURL(identity: TracexyIdentity) -> URL {
        identity.appSupportPath(relativeDirectory)
    }

    static func grantURL(identity: TracexyIdentity) -> URL {
        directoryURL(identity: identity).appendingPathComponent(grantFileName)
    }

    static func auditURL(identity: TracexyIdentity) -> URL {
        directoryURL(identity: identity).appendingPathComponent(auditFileName)
    }
}

// MARK: - MCPGrantError

/// Every reason a grant is refused. Each case is a *closed* outcome: the caller
/// answers with a protocol error and reads nothing. No case carries a path, a
/// token, a host, or any capture-derived value.
nonisolated enum MCPGrantError: Error, Sendable, Equatable {
    /// No grant exists — the default state, and what a revoke restores.
    case absent
    /// The grant path is not a regular file (a directory, symlink target, socket…).
    case notRegularFile
    /// The grant file is readable by group or other. A grant that anyone can
    /// rewrite is not an authorization.
    case notOwnerOnly(mode: UInt16)
    /// The file exceeded ``MCPGrantLimits/maxFileBytes`` and was not parsed.
    case tooLarge(byteCount: Int)
    /// The bytes were unreadable or were not a decodable grant document.
    case malformed
    /// The document declares a schema this build does not implement.
    case unsupportedSchema(Int)
    /// The revision was not a positive integer.
    case invalidRevision(Int)
    /// The declared page size was outside `1...500`.
    case invalidPageSize(Int)
    /// The issuance instant was non-finite, or sat implausibly in the future.
    case invalidIssuanceTime
    /// The grant is older than ``MCPGrantLimits/maxAge``.
    case stale
    /// The named History database is missing or is not a regular file.
    case databaseUnavailable
    /// A grant was re-issued (or revoked and re-issued) after this process pinned
    /// one. The pinned scope is never silently replaced mid-session.
    case superseded
    /// The grant now names a different Project than the pinned one — the exact
    /// state a Project switch produces.
    case projectMismatch
}

// MARK: - MCPGrantDocument

/// The complete on-disk grant. It names exactly one Project, one History
/// database, one disclosure policy and one page ceiling, plus the schema,
/// revision and issuance instant needed to detect a stale or superseded grant.
///
/// It deliberately carries no token, credential, capture-source path, evidence
/// locator, packet byte, host, process name or endpoint.
nonisolated struct MCPGrantDocument: Codable, Sendable, Equatable {
    // MARK: Lifecycle

    init(
        schemaVersion: Int = MCPGrantDocument.currentSchemaVersion,
        revision: Int,
        projectID: UUID,
        historyDatabasePath: String,
        disclosure: AutomationDisclosure,
        maxPageSize: Int,
        issuedAt: Double
    ) {
        self.schemaVersion = schemaVersion
        self.revision = revision
        self.projectID = projectID
        self.historyDatabasePath = historyDatabasePath
        self.disclosure = disclosure
        self.maxPageSize = maxPageSize
        self.issuedAt = issuedAt
    }

    // MARK: Internal

    /// The grant document schema this build issues and accepts.
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    /// A positive, app-incremented issuance revision. Any change to it supersedes
    /// a pinned grant.
    let revision: Int
    /// The one authorized Project.
    let projectID: UUID
    /// The one authorized History database. It is the only path the executable
    /// will ever open, and it is opened read-only.
    let historyDatabasePath: String
    /// The one disclosure policy applied to every projected session.
    let disclosure: AutomationDisclosure
    /// The page ceiling applied on top of the automation service's own bound.
    let maxPageSize: Int
    /// Seconds since the reference date at issuance.
    let issuedAt: Double

    /// The database URL, resolved without consulting any caller-supplied value.
    var historyDatabaseURL: URL {
        URL(fileURLWithPath: historyDatabasePath)
    }

    /// The identity a pinned scope is compared against. A change to either field
    /// invalidates every subsequent call.
    var pin: MCPGrantPin {
        MCPGrantPin(projectID: projectID, revision: revision)
    }

    /// Validate everything that can be decided from the document alone. Ordering
    /// is deliberate: cheap structural checks precede the filesystem probe.
    func validateStructure(now: Double) throws {
        guard schemaVersion == Self.currentSchemaVersion else {
            throw MCPGrantError.unsupportedSchema(schemaVersion)
        }
        guard revision > 0 else {
            throw MCPGrantError.invalidRevision(revision)
        }
        guard (1 ... MCPGrantLimits.maxPageSize).contains(maxPageSize) else {
            throw MCPGrantError.invalidPageSize(maxPageSize)
        }
        guard issuedAt.isFinite, issuedAt <= now + MCPGrantLimits.maxIssuanceSkew else {
            throw MCPGrantError.invalidIssuanceTime
        }
        guard now - issuedAt <= MCPGrantLimits.maxAge else {
            throw MCPGrantError.stale
        }
        guard !historyDatabasePath.isEmpty, historyDatabasePath.hasPrefix("/") else {
            throw MCPGrantError.malformed
        }
    }
}

// MARK: - MCPGrantPin

/// The scope one process pinned at `initialize`. Every later call re-reads the
/// grant and must match this exactly, so a Project switch or a revoke-and-reissue
/// fails closed instead of quietly serving a different Project.
nonisolated struct MCPGrantPin: Hashable, Sendable {
    let projectID: UUID
    let revision: Int
}

// MARK: - MCPGrantReader

/// The read side of the boundary. It re-reads and re-validates the grant file for
/// every call — it caches nothing — and never writes, creates, migrates or
/// deletes anything.
nonisolated struct MCPGrantReader: Sendable {
    // MARK: Lifecycle

    /// - Parameters:
    ///   - url: the identity-derived grant path, resolved by the composition root.
    ///   - now: seconds since the reference date, injectable for deterministic tests.
    init(url: URL, now: @escaping @Sendable () -> Double = { Date().timeIntervalSinceReferenceDate }) {
        self.url = url
        self.now = now
    }

    // MARK: Internal

    let url: URL

    /// Read and fully validate the current grant.
    func load() throws -> MCPGrantDocument {
        let document = try decode()
        try document.validateStructure(now: now())
        try validateDatabase(document)
        return document
    }

    /// Read and validate the current grant, then require it to be the exact scope
    /// `pinned` describes.
    func load(matching pinned: MCPGrantPin) throws -> MCPGrantDocument {
        let document = try load()
        guard document.projectID == pinned.projectID else {
            throw MCPGrantError.projectMismatch
        }
        guard document.revision == pinned.revision else {
            throw MCPGrantError.superseded
        }
        return document
    }

    // MARK: Private

    private let now: @Sendable () -> Double

    /// Read the bytes under the file-shape and permission rules, then decode.
    private func decode() throws -> MCPGrantDocument {
        let manager = FileManager.default
        var isDirectory: ObjCBool = false
        guard manager.fileExists(atPath: url.path, isDirectory: &isDirectory) else {
            throw MCPGrantError.absent
        }
        guard !isDirectory.boolValue else {
            throw MCPGrantError.notRegularFile
        }

        let attributes: [FileAttributeKey: Any]
        do {
            attributes = try manager.attributesOfItem(atPath: url.path)
        } catch {
            throw MCPGrantError.absent
        }
        guard (attributes[.type] as? FileAttributeType) == .typeRegular else {
            throw MCPGrantError.notRegularFile
        }
        // A grant anyone else can read or rewrite is not an authorization.
        let mode = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
        guard mode & 0o077 == 0 else {
            throw MCPGrantError.notOwnerOnly(mode: mode)
        }
        let byteCount = (attributes[.size] as? NSNumber)?.intValue ?? 0
        guard byteCount <= MCPGrantLimits.maxFileBytes else {
            throw MCPGrantError.tooLarge(byteCount: byteCount)
        }

        guard let data = manager.contents(atPath: url.path) else {
            throw MCPGrantError.malformed
        }
        // Re-check after the read: the size attribute is a hint, the bytes are the fact.
        guard data.count <= MCPGrantLimits.maxFileBytes else {
            throw MCPGrantError.tooLarge(byteCount: data.count)
        }
        do {
            return try JSONDecoder().decode(MCPGrantDocument.self, from: data)
        } catch {
            throw MCPGrantError.malformed
        }
    }

    /// The named database must exist as a regular file. It is never created,
    /// migrated or repaired from here.
    private func validateDatabase(_ document: MCPGrantDocument) throws {
        let manager = FileManager.default
        guard manager.fileExists(atPath: document.historyDatabasePath),
              let attributes = try? manager.attributesOfItem(atPath: document.historyDatabasePath),
              (attributes[.type] as? FileAttributeType) == .typeRegular else
        {
            throw MCPGrantError.databaseUnavailable
        }
    }
}
