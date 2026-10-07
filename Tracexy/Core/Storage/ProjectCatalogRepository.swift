import Darwin
import Foundation

// MARK: - ProjectCatalogPersisting

nonisolated protocol ProjectCatalogPersisting: Sendable {
    func load(seed: ProjectCatalog) async throws -> ProjectCatalog
    func save(_ catalog: ProjectCatalog, expectedRevision: UInt64) async throws
    func reset(to catalog: ProjectCatalog) async throws -> ProjectCatalog
}

// MARK: - ProjectCatalogRepositoryError

nonisolated enum ProjectCatalogRepositoryError: Error, Equatable, Sendable {
    case directoryIsSymbolicLink
    case directoryIsNotDirectory
    case catalogIsSymbolicLink
    case catalogIsNotRegularFile
    case catalogTooLarge(limit: Int)
    case encodedCatalogTooLarge(limit: Int)
    case malformedCatalog
    case invalidCatalog(ProjectCatalogValidationError)
    case staleRevision(expected: UInt64, actual: UInt64)
    case invalidNextRevision(expected: UInt64, actual: UInt64)
    case fileSystem(String)
}

// MARK: - ProjectCatalogCoding

/// The catalog's one JSON form, shared by the file and the size check made before
/// a change is accepted.
nonisolated enum ProjectCatalogCoding {
    static func makeEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }

    /// Bytes the catalog takes on disk; `Int.max` when it cannot be encoded.
    static func encodedByteCount(of catalog: ProjectCatalog) -> Int {
        (try? makeEncoder().encode(catalog).count) ?? Int.max
    }

    /// Bytes one Project takes inside the catalog (and inside a `.tracexyproject`).
    static func encodedByteCount(of project: Project) -> Int {
        (try? makeEncoder().encode(project).count) ?? Int.max
    }

    /// Bytes the catalog takes on disk, given each of its Projects' own encoded
    /// size in order. The encoding has no whitespace, so the file is the catalog
    /// without Projects plus each Project and the commas between them.
    static func encodedByteCount(of catalog: ProjectCatalog, projectBytes: [Int]) -> Int {
        var envelope = catalog
        envelope.projects = []
        guard let base = try? makeEncoder().encode(envelope).count else {
            return Int.max
        }
        var total = base + max(0, projectBytes.count - 1)
        for bytes in projectBytes {
            let (sum, overflow) = total.addingReportingOverflow(bytes)
            if overflow {
                return Int.max
            }
            total = sum
        }
        return total
    }
}

// MARK: - JSONProjectCatalogRepository

/// Actor-isolated JSON v1 catalog persistence rooted at an injected directory.
///
/// The store never persists capture data: its schema accepts only the bounded
/// project/workspace configuration DTOs. Writes use a same-directory replacement,
/// and every existing target must be a regular non-symlink file.
actor JSONProjectCatalogRepository: ProjectCatalogPersisting {
    // MARK: Lifecycle

    init(
        directoryURL: URL,
        fileName: String = "projects.json",
        fileManager: FileManager = .default
    ) {
        self.directoryURL = directoryURL.standardizedFileURL
        self.fileURL = directoryURL.appendingPathComponent(fileName, isDirectory: false)
            .standardizedFileURL
        self.fileManager = fileManager
    }

    // MARK: Internal

    let directoryURL: URL
    let fileURL: URL

    func load(seed: ProjectCatalog) async throws -> ProjectCatalog {
        try prepareDirectory()
        let identityBeforeRead = try existingFileStatus()?.identity
        if let data = try readExistingData() {
            let catalog = try decode(data)
            remember(catalog, in: identityBeforeRead)
            return catalog
        }

        let normalizedSeed = try validate(seed)
        let data = try encode(normalizedSeed)
        do {
            try remember(normalizedSeed, in: writeAtomically(data))
        } catch {
            // Another writer may have won the missing-file race. Adopt that
            // complete catalog instead of overwriting it.
            if let existing = try? readExistingData() {
                return try decode(existing)
            }
            throw error
        }
        return normalizedSeed
    }

    func save(_ catalog: ProjectCatalog, expectedRevision: UInt64) async throws {
        try prepareDirectory()
        let normalized = try validate(catalog)
        guard expectedRevision < UInt64.max,
              normalized.revision == expectedRevision + 1 else
        {
            throw ProjectCatalogRepositoryError.invalidNextRevision(
                expected: expectedRevision == UInt64.max ? UInt64.max : expectedRevision + 1,
                actual: normalized.revision
            )
        }

        let actualRevision: UInt64 = if let written = lastWritten,
                                        let status = try existingFileStatus(),
                                        status.identity == written.identity
        {
            // The file is still the one this repository wrote; reading back a
            // large catalog on every save only to learn its revision is wasted.
            written.revision
        } else if let existing = try readExistingData() {
            try decode(existing).revision
        } else {
            0
        }
        guard actualRevision == expectedRevision else {
            throw ProjectCatalogRepositoryError.staleRevision(
                expected: expectedRevision,
                actual: actualRevision
            )
        }
        let identity = try writeAtomically(encode(normalized))
        remember(normalized, in: identity)
    }

    @discardableResult
    func reset(to catalog: ProjectCatalog) async throws -> ProjectCatalog {
        try prepareDirectory()
        let normalized = try validate(catalog)
        let encoded = try encode(normalized)

        var recoveryURL: URL?
        if try existingFileStatus() != nil {
            let backup = directoryURL.appendingPathComponent(
                "projects.recovery-\(UUID().uuidString).json",
                isDirectory: false
            )
            do {
                try fileManager.moveItem(at: fileURL, to: backup)
                setRestrictiveFilePermissions(backup)
                recoveryURL = backup
            } catch {
                throw fileSystemError(error)
            }
        }

        do {
            try remember(normalized, in: writeAtomically(encoded))
        } catch {
            if let recoveryURL, !fileManager.fileExists(atPath: fileURL.path) {
                try? fileManager.moveItem(at: recoveryURL, to: fileURL)
            }
            throw error
        }
        return normalized
    }

    // MARK: Private

    private struct FileStatus {
        let fileType: mode_t
        let size: Int
        let identity: FileIdentity
    }

    /// What identifies one written version of the file: replacing it (another
    /// writer, a restore) changes the inode, and editing it in place changes the
    /// size or modification time.
    private struct FileIdentity: Equatable {
        let device: dev_t
        let inode: ino_t
        let size: off_t
        let modifiedSeconds: Int
        let modifiedNanoseconds: Int
    }

    private struct WrittenCatalog {
        let revision: UInt64
        let identity: FileIdentity
    }

    private static let encoder = ProjectCatalogCoding.makeEncoder()

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return decoder
    }()

    private let fileManager: FileManager

    private var lastWritten: WrittenCatalog?

    /// Notes that the file identified by `identity` holds `catalog`. An identity
    /// taken before a read, or from the written file before it replaced the old
    /// one, can only ever be stale — never wrongly current — so a later save
    /// falls back to reading the file instead of trusting it.
    private func remember(_ catalog: ProjectCatalog, in identity: FileIdentity?) {
        lastWritten = identity.map { WrittenCatalog(revision: catalog.revision, identity: $0) }
    }

    private func prepareDirectory() throws {
        if let status = try fileStatus(at: directoryURL) {
            guard status.fileType != S_IFLNK else {
                throw ProjectCatalogRepositoryError.directoryIsSymbolicLink
            }
            guard status.fileType == S_IFDIR else {
                throw ProjectCatalogRepositoryError.directoryIsNotDirectory
            }
        } else {
            do {
                try fileManager.createDirectory(
                    at: directoryURL,
                    withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o700]
                )
            } catch {
                throw fileSystemError(error)
            }
        }
        _ = chmod(directoryURL.path, 0o700)
    }

    private func existingFileStatus() throws -> FileStatus? {
        guard let status = try fileStatus(at: fileURL) else {
            return nil
        }
        guard status.fileType != S_IFLNK else {
            throw ProjectCatalogRepositoryError.catalogIsSymbolicLink
        }
        guard status.fileType == S_IFREG else {
            throw ProjectCatalogRepositoryError.catalogIsNotRegularFile
        }
        return status
    }

    private func readExistingData() throws -> Data? {
        guard let status = try existingFileStatus() else {
            return nil
        }
        guard status.size <= ProjectLimits.maximumCatalogBytes else {
            throw ProjectCatalogRepositoryError.catalogTooLarge(limit: ProjectLimits.maximumCatalogBytes)
        }
        do {
            let data = try Data(contentsOf: fileURL, options: .mappedIfSafe)
            guard data.count <= ProjectLimits.maximumCatalogBytes else {
                throw ProjectCatalogRepositoryError.catalogTooLarge(limit: ProjectLimits.maximumCatalogBytes)
            }
            return data
        } catch let error as ProjectCatalogRepositoryError {
            throw error
        } catch {
            throw fileSystemError(error)
        }
    }

    private func decode(_ data: Data) throws -> ProjectCatalog {
        do {
            let catalog = try Self.decoder.decode(ProjectCatalog.self, from: data)
            return try validate(catalog)
        } catch let error as ProjectCatalogValidationError {
            throw ProjectCatalogRepositoryError.invalidCatalog(error)
        } catch let error as ProjectCatalogRepositoryError {
            throw error
        } catch {
            throw ProjectCatalogRepositoryError.malformedCatalog
        }
    }

    private func encode(_ catalog: ProjectCatalog) throws -> Data {
        do {
            let data = try Self.encoder.encode(catalog)
            guard data.count <= ProjectLimits.maximumCatalogBytes else {
                throw ProjectCatalogRepositoryError.encodedCatalogTooLarge(
                    limit: ProjectLimits.maximumCatalogBytes
                )
            }
            return data
        } catch let error as ProjectCatalogRepositoryError {
            throw error
        } catch {
            throw fileSystemError(error)
        }
    }

    private func validate(_ catalog: ProjectCatalog) throws -> ProjectCatalog {
        do {
            return try catalog.normalizedValidated()
        } catch let error as ProjectCatalogValidationError {
            throw ProjectCatalogRepositoryError.invalidCatalog(error)
        }
    }

    /// Writes `data` beside the catalog and moves it into place. Returns the
    /// written file's identity, taken before the move so it can never describe a
    /// file another writer put there afterwards.
    @discardableResult
    private func writeAtomically(_ data: Data) throws -> FileIdentity? {
        let temporaryURL = directoryURL.appendingPathComponent(
            ".projects-\(UUID().uuidString).tmp",
            isDirectory: false
        )
        do {
            try data.write(to: temporaryURL, options: .withoutOverwriting)
            setRestrictiveFilePermissions(temporaryURL)
            let identity = try fileStatus(at: temporaryURL)?.identity
            if try existingFileStatus() != nil {
                _ = try fileManager.replaceItemAt(fileURL, withItemAt: temporaryURL)
            } else {
                try fileManager.moveItem(at: temporaryURL, to: fileURL)
            }
            setRestrictiveFilePermissions(fileURL)
            return identity
        } catch let error as ProjectCatalogRepositoryError {
            try? fileManager.removeItem(at: temporaryURL)
            throw error
        } catch {
            try? fileManager.removeItem(at: temporaryURL)
            throw fileSystemError(error)
        }
    }

    private func setRestrictiveFilePermissions(_ url: URL) {
        _ = chmod(url.path, 0o600)
    }

    private func fileStatus(at url: URL) throws -> FileStatus? {
        var value = stat()
        let result = url.path.withCString { lstat($0, &value) }
        if result == 0 {
            return FileStatus(
                fileType: value.st_mode & S_IFMT,
                size: Int(clamping: value.st_size),
                identity: FileIdentity(
                    device: value.st_dev,
                    inode: value.st_ino,
                    size: value.st_size,
                    modifiedSeconds: value.st_mtimespec.tv_sec,
                    modifiedNanoseconds: value.st_mtimespec.tv_nsec
                )
            )
        }
        if errno == ENOENT {
            return nil
        }
        throw ProjectCatalogRepositoryError.fileSystem(String(cString: strerror(errno)))
    }

    private func fileSystemError(_ error: Error) -> ProjectCatalogRepositoryError {
        ProjectCatalogRepositoryError.fileSystem(error.localizedDescription)
    }
}
