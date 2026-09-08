import Darwin
import Foundation

// MARK: - PortableProjectCodecError

nonisolated enum PortableProjectCodecError: Error, Equatable, Sendable {
    case documentTooLarge(limit: Int)
    case unsupportedSchema(Int)
    case malformedDocument
    case invalidProject(ProjectCatalogValidationError)
    case directoryIsSymbolicLink
    case directoryIsNotDirectory
    case documentIsSymbolicLink
    case documentIsNotRegularFile
    case fileSystem(String)
}

// MARK: - PortableProjectDocumentIO

/// Fail-closed file boundary for portable project documents. UI callers never
/// need to perform an unbounded `Data(contentsOf:)` read or write through a
/// symlink. Existing destinations must be regular files; writes replace them
/// atomically from the same directory with private best-effort permissions.
nonisolated enum PortableProjectDocumentIO {
    // MARK: Internal

    static func read(from url: URL) throws -> Project {
        let standardizedURL = url.standardizedFileURL
        guard let status = try fileStatus(at: standardizedURL) else {
            throw PortableProjectCodecError.fileSystem("The project document does not exist.")
        }
        guard status.fileType != S_IFLNK else {
            throw PortableProjectCodecError.documentIsSymbolicLink
        }
        guard status.fileType == S_IFREG else {
            throw PortableProjectCodecError.documentIsNotRegularFile
        }
        guard status.size <= ProjectLimits.maximumPortableProjectBytes else {
            throw PortableProjectCodecError.documentTooLarge(
                limit: ProjectLimits.maximumPortableProjectBytes
            )
        }
        do {
            let data = try Data(contentsOf: standardizedURL, options: .mappedIfSafe)
            guard data.count <= ProjectLimits.maximumPortableProjectBytes else {
                throw PortableProjectCodecError.documentTooLarge(
                    limit: ProjectLimits.maximumPortableProjectBytes
                )
            }
            return try PortableProjectCodec.decode(data)
        } catch let error as PortableProjectCodecError {
            throw error
        } catch {
            throw PortableProjectCodecError.fileSystem(error.localizedDescription)
        }
    }

    static func write(_ project: Project, to url: URL) throws {
        let standardizedURL = url.standardizedFileURL
        let directoryURL = standardizedURL.deletingLastPathComponent()
        guard let directoryStatus = try fileStatus(at: directoryURL) else {
            throw PortableProjectCodecError.fileSystem("The destination folder does not exist.")
        }
        guard directoryStatus.fileType != S_IFLNK else {
            throw PortableProjectCodecError.directoryIsSymbolicLink
        }
        guard directoryStatus.fileType == S_IFDIR else {
            throw PortableProjectCodecError.directoryIsNotDirectory
        }
        if let status = try fileStatus(at: standardizedURL) {
            guard status.fileType != S_IFLNK else {
                throw PortableProjectCodecError.documentIsSymbolicLink
            }
            guard status.fileType == S_IFREG else {
                throw PortableProjectCodecError.documentIsNotRegularFile
            }
        }

        let data = try PortableProjectCodec.encode(project)
        let temporaryURL = directoryURL.appendingPathComponent(
            ".tracexyproject-\(UUID().uuidString).tmp",
            isDirectory: false
        )
        do {
            try data.write(to: temporaryURL, options: .withoutOverwriting)
            _ = chmod(temporaryURL.path, 0o600)
            if try fileStatus(at: standardizedURL) != nil {
                _ = try FileManager.default.replaceItemAt(standardizedURL, withItemAt: temporaryURL)
            } else {
                try FileManager.default.moveItem(at: temporaryURL, to: standardizedURL)
            }
            _ = chmod(standardizedURL.path, 0o600)
        } catch let error as PortableProjectCodecError {
            try? FileManager.default.removeItem(at: temporaryURL)
            throw error
        } catch {
            try? FileManager.default.removeItem(at: temporaryURL)
            throw PortableProjectCodecError.fileSystem(error.localizedDescription)
        }
    }

    // MARK: Private

    private struct FileStatus {
        let fileType: mode_t
        let size: Int
    }

    private static func fileStatus(at url: URL) throws -> FileStatus? {
        var value = stat()
        let result = url.path.withCString { lstat($0, &value) }
        if result == 0 {
            return FileStatus(fileType: value.st_mode & S_IFMT, size: Int(clamping: value.st_size))
        }
        if errno == ENOENT {
            return nil
        }
        throw PortableProjectCodecError.fileSystem(String(cString: strerror(errno)))
    }
}

// MARK: - PortableProjectCodec

/// Codec for configuration-only `.tracexyproject` documents.
///
/// Import always issues fresh project, workspace, and filter-row identities, so
/// a portable document can never alias an existing catalog object. The DTO has no
/// fields for capture bytes, payload, local paths, History, or selection evidence.
nonisolated enum PortableProjectCodec {
    // MARK: Internal

    static let fileExtension = "tracexyproject"
    static let schemaVersion = 1

    nonisolated static func encode(_ project: Project) throws -> Data {
        let validated = try validate(project)
        let envelope = Envelope(schemaVersion: schemaVersion, project: validated)
        do {
            let data = try encoder.encode(envelope)
            guard data.count <= ProjectLimits.maximumPortableProjectBytes else {
                throw PortableProjectCodecError.documentTooLarge(
                    limit: ProjectLimits.maximumPortableProjectBytes
                )
            }
            return data
        } catch let error as PortableProjectCodecError {
            throw error
        } catch {
            throw PortableProjectCodecError.malformedDocument
        }
    }

    nonisolated static func decode(_ data: Data, now: Date = Date()) throws -> Project {
        guard data.count <= ProjectLimits.maximumPortableProjectBytes else {
            throw PortableProjectCodecError.documentTooLarge(
                limit: ProjectLimits.maximumPortableProjectBytes
            )
        }
        let envelope: Envelope
        do {
            envelope = try decoder.decode(Envelope.self, from: data)
        } catch {
            throw PortableProjectCodecError.malformedDocument
        }
        guard envelope.schemaVersion == schemaVersion else {
            throw PortableProjectCodecError.unsupportedSchema(envelope.schemaVersion)
        }
        let validated = try validate(envelope.project)

        var workspaceIDMap: [UUID: UUID] = [:]
        let workspaces = validated.workspaces.map { workspace -> ProjectWorkspaceSnapshot in
            let newID = UUID()
            workspaceIDMap[workspace.id] = newID
            var copy = workspace
            copy.id = newID
            copy.filterRules = workspace.filterRules.map { rule in
                var newRule = rule
                newRule.id = UUID()
                return newRule
            }
            return copy
        }
        guard let activeWorkspaceID = workspaceIDMap[validated.activeWorkspaceID] else {
            throw PortableProjectCodecError.invalidProject(
                .activeWorkspaceMissing(
                    projectID: validated.id,
                    workspaceID: validated.activeWorkspaceID
                )
            )
        }
        return Project(
            id: UUID(),
            name: validated.name,
            workspaces: workspaces,
            activeWorkspaceID: activeWorkspaceID,
            createdAt: now,
            updatedAt: now
        )
    }

    // MARK: Private

    private struct Envelope: Codable {
        let schemaVersion: Int
        let project: Project
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

    nonisolated private static func validate(_ project: Project) throws -> Project {
        let catalog = ProjectCatalog(projects: [project], activeProjectID: project.id)
        do {
            return try catalog.normalizedValidated().projects[0]
        } catch let error as ProjectCatalogValidationError {
            throw PortableProjectCodecError.invalidProject(error)
        }
    }
}
