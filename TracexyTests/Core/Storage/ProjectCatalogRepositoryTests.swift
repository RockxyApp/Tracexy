import Darwin
import Foundation
import Testing
@testable import Tracexy

@Suite("JSON project catalog repository")
struct ProjectCatalogRepositoryTests {
    // MARK: Internal

    @Test("A missing catalog is seeded privately and reloads normalized v1 data")
    func missingFileSeed() async throws {
        let directory = Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let repository = JSONProjectCatalogRepository(directoryURL: directory)
        var seed = ProjectCatalog.defaultCatalog(now: Date(timeIntervalSince1970: 123))
        seed.projects[0].name = "  My Project  "

        let loaded = try await repository.load(seed: seed)
        #expect(loaded.projects[0].name == "My Project")
        let fileURL = directory.appendingPathComponent("projects.json")
        #expect(FileManager.default.fileExists(atPath: fileURL.path))
        let attributes = try FileManager.default.attributesOfItem(atPath: fileURL.path)
        let permissions = attributes[.posixPermissions] as? NSNumber
        #expect(permissions?.intValue == 0o600)
    }

    @Test("Save uses a stale-revision guard")
    func staleRevisionGuard() async throws {
        let directory = Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let first = JSONProjectCatalogRepository(directoryURL: directory)
        let second = JSONProjectCatalogRepository(directoryURL: directory)
        let seed = ProjectCatalog.defaultCatalog()
        let loaded = try await first.load(seed: seed)

        var update = loaded
        update.revision = 1
        update.projects[0].name = "First Writer"
        try await first.save(update, expectedRevision: 0)

        var stale = loaded
        stale.revision = 1
        stale.projects[0].name = "Stale Writer"
        await #expect(throws: ProjectCatalogRepositoryError.staleRevision(expected: 0, actual: 1)) {
            try await second.save(stale, expectedRevision: 0)
        }
    }

    @Test("Catalog symlinks are rejected without following their target")
    func symlinkRejected() async throws {
        let directory = Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let target = directory.appendingPathComponent("target.json")
        try Data("{}".utf8).write(to: target)
        let link = directory.appendingPathComponent("projects.json")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

        let repository = JSONProjectCatalogRepository(directoryURL: directory)
        await #expect(throws: ProjectCatalogRepositoryError.catalogIsSymbolicLink) {
            try await repository.load(seed: .defaultCatalog())
        }
    }

    @Test("Reset preserves the prior regular file as a recovery backup")
    func resetCreatesRecoveryBackup() async throws {
        let directory = Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let fileURL = directory.appendingPathComponent("projects.json")
        try Data("malformed".utf8).write(to: fileURL)

        let repository = JSONProjectCatalogRepository(directoryURL: directory)
        var reset = ProjectCatalog.defaultCatalog()
        reset.revision = 1
        _ = try await repository.reset(to: reset)

        let names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        #expect(names.contains(where: { $0.hasPrefix("projects.recovery-") }))
        #expect(try await repository.load(seed: .defaultCatalog()).revision == 1)
    }

    @Test("Oversized regular catalogs fail before decoding")
    func oversizedCatalogRejected() async throws {
        let directory = Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let fileURL = directory.appendingPathComponent("projects.json")
        let descriptor = open(fileURL.path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR)
        #expect(descriptor >= 0)
        defer {
            if descriptor >= 0 {
                close(descriptor)
            }
        }
        #expect(ftruncate(descriptor, off_t(ProjectLimits.maximumCatalogBytes + 1)) == 0)

        let repository = JSONProjectCatalogRepository(directoryURL: directory)
        await #expect(throws: ProjectCatalogRepositoryError.catalogTooLarge(
            limit: ProjectLimits.maximumCatalogBytes
        )) {
            try await repository.load(seed: .defaultCatalog())
        }
    }

    // MARK: Private

    private static func temporaryDirectory() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("project-repository-\(UUID().uuidString)", isDirectory: true)
    }
}
