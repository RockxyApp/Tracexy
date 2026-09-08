import Foundation
@testable import Tracexy

// MARK: - RecordingProjectDataProvider

/// A test provider that roots every Project's History database, capture Library,
/// live spool and preferences suite inside one throwaway directory / defaults
/// namespace, and records what it handed out so a test can tear all of it down.
///
/// It can also be told to refuse a Project's settings suite, which is how the
/// "storage failure stays fail-closed" behavior is exercised without corrupting a
/// real defaults domain.
@MainActor
final class RecordingProjectDataProvider: ProjectDataProviding {
    // MARK: Lifecycle

    init(root: URL, suitePrefix: String) {
        self.root = root
        self.suitePrefix = suitePrefix
        base = DefaultProjectDataProvider(
            applicationSupportRoot: root.appendingPathComponent("Support", isDirectory: true),
            cacheRoot: root.appendingPathComponent("Caches", isDirectory: true),
            settingsSuitePrefix: suitePrefix,
            // Never read the developer's real preferences while seeding.
            legacySettingsSource: nil
        )
    }

    // MARK: Internal

    let root: URL
    let suitePrefix: String

    /// Projects whose settings suite construction must fail.
    var failingSettingsProjectIDs: Set<UUID> = []
    /// When true, any Project that has not already been issued a suite is refused.
    var failsSettingsForNewProjects = false
    private(set) var issuedSuiteNames: Set<String> = []
    private(set) var issuedLocations: [UUID: ProjectDataLocation] = [:]

    func location(forProject projectID: UUID, isLegacyOwner: Bool) -> ProjectDataLocation {
        let location = base.location(forProject: projectID, isLegacyOwner: isLegacyOwner)
        issuedLocations[projectID] = location
        return location
    }

    func makeSessionStore(at location: ProjectDataLocation) async -> HistoryStoreFactory.Outcome {
        await base.makeSessionStore(at: location)
    }

    func makeLiveCaptureSpool(at location: ProjectDataLocation) -> LiveCaptureSpool {
        base.makeLiveCaptureSpool(at: location)
    }

    func makeSettingsDefaults(at location: ProjectDataLocation) -> UserDefaults? {
        guard !failingSettingsProjectIDs.contains(location.projectID) else {
            return nil
        }
        guard !failsSettingsForNewProjects
            || issuedSuiteNames.contains(location.settingsSuiteName) else
        {
            return nil
        }
        guard let defaults = base.makeSettingsDefaults(at: location) else {
            return nil
        }
        issuedSuiteNames.insert(location.settingsSuiteName)
        return defaults
    }

    func prepareCapturesDirectory(at location: ProjectDataLocation) async -> URL? {
        await base.prepareCapturesDirectory(at: location)
    }

    // MARK: Private

    private let base: DefaultProjectDataProvider
}

// MARK: - ControllableCatalogRepositoryError

nonisolated enum ControllableCatalogRepositoryError: Error, Equatable {
    case saveRefused
}

// MARK: - ControllableProjectCatalogRepository

/// An in-memory catalog repository whose durable write can be refused on demand,
/// so a catalog-save failure is exercised without touching or corrupting a file.
///
/// The refusal is keyed on the candidate's shape rather than on a call count, so a
/// test can fail exactly the transition's own write and leave the preceding
/// workspace flush alone.
actor ControllableProjectCatalogRepository: ProjectCatalogPersisting {
    // MARK: Lifecycle

    init(refusingSaveWithProjectCount: Int? = nil) {
        refusedProjectCount = refusingSaveWithProjectCount
    }

    // MARK: Internal

    private(set) var savedCatalog: ProjectCatalog?
    private(set) var refusedSaveCount = 0

    func refuseSaveWithProjectCount(_ count: Int?) {
        refusedProjectCount = count
    }

    func load(seed: ProjectCatalog) async throws -> ProjectCatalog {
        savedCatalog ?? seed
    }

    func save(_ catalog: ProjectCatalog, expectedRevision _: UInt64) async throws {
        if let refusedProjectCount, catalog.projects.count == refusedProjectCount {
            refusedSaveCount += 1
            throw ControllableCatalogRepositoryError.saveRefused
        }
        savedCatalog = catalog
    }

    func reset(to catalog: ProjectCatalog) async throws -> ProjectCatalog {
        savedCatalog = catalog
        return catalog
    }

    // MARK: Private

    private var refusedProjectCount: Int?
}

// MARK: - ProjectIsolationEnvironment

/// One isolated Projects world for a test: a temporary storage root, a throwaway
/// defaults namespace, and (optionally) a real on-disk catalog so "relaunch"
/// behavior can be exercised.
@MainActor
final class ProjectIsolationEnvironment {
    // MARK: Lifecycle

    init(name: String = "projects", persistsCatalog: Bool = false) {
        let token = UUID().uuidString
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-\(name)-\(token)", isDirectory: true)
        suitePrefix = "com.amunx.tracexy.tests.\(token)"
        bootSuiteName = "\(suitePrefix).boot"
        self.persistsCatalog = persistsCatalog
        provider = RecordingProjectDataProvider(root: root, suitePrefix: suitePrefix)
    }

    // MARK: Internal

    let root: URL
    let suitePrefix: String
    let bootSuiteName: String
    let provider: RecordingProjectDataProvider

    /// Overrides catalog persistence for this environment. Set it before calling
    /// ``makeCoordinator(policy:)`` to exercise a write that fails.
    var catalogRepository: (any ProjectCatalogPersisting)?

    var catalogDirectory: URL {
        root.appendingPathComponent("Catalog", isDirectory: true)
    }

    /// Build a coordinator whose every storage and preference reference lives
    /// inside this environment. Nothing here can reach a production path or the
    /// shared defaults domain.
    func makeCoordinator(policy: (any AppPolicy)? = nil) -> MainContentCoordinator {
        let repository: (any ProjectCatalogPersisting)? = catalogRepository
            ?? (persistsCatalog ? JSONProjectCatalogRepository(directoryURL: catalogDirectory) : nil)
        let bootDefaults = UserDefaults(suiteName: bootSuiteName)
        let coordinator = MainContentCoordinator(
            policy: policy,
            projectRepository: repository,
            projectDataProvider: provider,
            settingsDefaults: bootDefaults
        )
        coordinator.projectTransitionDrainTimeout = .milliseconds(200)
        return coordinator
    }

    /// Remove every defaults suite and temporary file this environment created.
    func tearDown() {
        for name in provider.issuedSuiteNames {
            UserDefaults.standard.removePersistentDomain(forName: name)
        }
        UserDefaults.standard.removePersistentDomain(forName: bootSuiteName)
        try? FileManager.default.removeItem(at: root)
    }

    // MARK: Private

    private let persistsCatalog: Bool
}
