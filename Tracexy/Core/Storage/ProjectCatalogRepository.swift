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
        if let data = try readExistingData() {
            return try decode(data)
        }

        let normalizedSeed = try validate(seed)
        let data = try encode(normalizedSeed)
        do {
            try writeAtomically(data)
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

        let actualRevision: UInt64 = if let existing = try readExistingData() {
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
        try writeAtomically(encode(normalized))
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
            try writeAtomically(encoded)
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
    }

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }()

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return decoder
    }()

    private let fileManager: FileManager

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

    private func writeAtomically(_ data: Data) throws {
        let temporaryURL = directoryURL.appendingPathComponent(
            ".projects-\(UUID().uuidString).tmp",
            isDirectory: false
        )
        do {
            try data.write(to: temporaryURL, options: .withoutOverwriting)
            setRestrictiveFilePermissions(temporaryURL)
            if try existingFileStatus() != nil {
                _ = try fileManager.replaceItemAt(fileURL, withItemAt: temporaryURL)
            } else {
                try fileManager.moveItem(at: temporaryURL, to: fileURL)
            }
            setRestrictiveFilePermissions(fileURL)
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
            return FileStatus(fileType: value.st_mode & S_IFMT, size: Int(clamping: value.st_size))
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
