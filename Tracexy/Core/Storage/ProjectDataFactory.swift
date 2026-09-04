import Foundation

// MARK: - ProjectDataLocation

/// The resolved, identity-derived home of one Project's runtime data.
///
/// Exactly one Project — the *legacy owner* recorded in the catalog — keeps the
/// pre-Projects locations (`History/history.sqlite`, `Captures`, the shared live
/// spool). Every other Project is rooted under `Projects/<uuid>/`. Nothing here
/// copies, moves, or deletes a user file: a location is only ever *resolved*.
nonisolated struct ProjectDataLocation: Sendable, Equatable {
    let projectID: UUID
    /// True when this Project owns the pre-Projects data written before Project
    /// isolation existed. Only one Project can ever be the legacy owner.
    let isLegacyOwner: Bool
    let historyDatabaseURL: URL
    let capturesDirectoryURL: URL
    let spoolDirectoryURL: URL
    let settingsSuiteName: String
}

// MARK: - ProjectDataProviding

/// Composition seam for everything a Project owns outside the JSON catalog:
/// its terminal History database, its managed capture library folder, its live
/// spool, and its preferences suite.
///
/// Tests inject a provider rooted at a temporary directory and a throwaway
/// defaults suite prefix, so no test can reach a production path or the shared
/// `UserDefaults` domain.
@MainActor
protocol ProjectDataProviding: AnyObject {
    func location(forProject projectID: UUID, isLegacyOwner: Bool) -> ProjectDataLocation
    /// Opening a Project's History database creates a folder and opens/migrates
    /// SQLite. It is `async` because that work is prepared off the main actor from
    /// the Sendable ``ProjectDataLocation`` descriptor, so changing Projects never
    /// blocks the UI on file I/O.
    func makeSessionStore(at location: ProjectDataLocation) async -> HistoryStoreFactory.Outcome
    func makeLiveCaptureSpool(at location: ProjectDataLocation) -> LiveCaptureSpool
    /// `nil` when Foundation cannot vend the suite. Callers must fail closed
    /// rather than silently falling back to the shared domain.
    func makeSettingsDefaults(at location: ProjectDataLocation) -> UserDefaults?
    /// Creating the managed capture Library folder is file I/O and is prepared off
    /// the main actor from the same Sendable descriptor.
    func prepareCapturesDirectory(at location: ProjectDataLocation) async -> URL?
}

// MARK: - DefaultProjectDataProvider

@MainActor
final class DefaultProjectDataProvider: ProjectDataProviding {
    // MARK: Lifecycle

    /// `applicationSupportRoot`/`cacheRoot`/`settingsSuitePrefix`/`legacySettingsSource`
    /// are injectable so tests never touch production storage or `.standard`.
    ///
    /// `identity` is optional rather than defaulted to `.current` so the default is
    /// resolved *inside* this main-actor init. A default argument is evaluated in a
    /// nonisolated context, where reading the main-actor-isolated `.current` is a
    /// concurrency violation.
    init(
        identity: TracexyIdentity? = nil,
        applicationSupportRoot: URL? = nil,
        cacheRoot: URL? = nil,
        settingsSuitePrefix: String? = nil,
        legacySettingsSource: UserDefaults? = .standard,
        fileManager: FileManager = .default
    ) {
        let resolvedIdentity = identity ?? .current
        self.identity = resolvedIdentity
        self.applicationSupportRoot = applicationSupportRoot
            ?? resolvedIdentity.appSupportDirectory(fileManager: fileManager)
        self.cacheRoot = cacheRoot
            ?? Self.defaultCacheRoot(identity: resolvedIdentity, fileManager: fileManager)
        self.settingsSuitePrefix = settingsSuitePrefix ?? "\(resolvedIdentity.defaultsPrefix).project"
        self.legacySettingsSource = legacySettingsSource
        self.fileManager = fileManager
    }

    // MARK: Internal

    func location(forProject projectID: UUID, isLegacyOwner: Bool) -> ProjectDataLocation {
        let root = isLegacyOwner
            ? applicationSupportRoot
            : applicationSupportRoot
            .appendingPathComponent("Projects", isDirectory: true)
            .appendingPathComponent(projectID.uuidString, isDirectory: true)
        let spool = isLegacyOwner
            ? cacheRoot.appendingPathComponent("LiveCaptureSpool", isDirectory: true)
            : cacheRoot
            .appendingPathComponent("LiveCaptureSpool", isDirectory: true)
            .appendingPathComponent("Projects", isDirectory: true)
            .appendingPathComponent(projectID.uuidString, isDirectory: true)
        return ProjectDataLocation(
            projectID: projectID,
            isLegacyOwner: isLegacyOwner,
            historyDatabaseURL: root.appendingPathComponent(
                HistoryStoreFactory.relativeDatabasePath
            ),
            capturesDirectoryURL: root.appendingPathComponent("Captures", isDirectory: true),
            spoolDirectoryURL: spool,
            settingsSuiteName: "\(settingsSuitePrefix).\(projectID.uuidString)"
        )
    }

    /// Prepared off the main actor. Only the Sendable descriptor crosses, and the
    /// detached work uses its own `FileManager` rather than the injected one, which
    /// stays on the main actor for path resolution.
    func makeSessionStore(at location: ProjectDataLocation) async -> HistoryStoreFactory.Outcome {
        let databaseURL = location.historyDatabaseURL
        return await Task.detached(priority: .userInitiated) {
            HistoryStoreFactory.make(databaseURL: databaseURL)
        }.value
    }

    func makeLiveCaptureSpool(at location: ProjectDataLocation) -> LiveCaptureSpool {
        LiveCaptureSpool(directory: location.spoolDirectoryURL)
    }

    func makeSettingsDefaults(at location: ProjectDataLocation) -> UserDefaults? {
        guard let defaults = UserDefaults(suiteName: location.settingsSuiteName) else {
            return nil
        }
        ProjectSettingsSeeding.prepare(
            defaults,
            suiteName: location.settingsSuiteName,
            seedingFrom: location.isLegacyOwner ? legacySettingsSource : nil
        )
        return defaults
    }

    /// Prepared off the main actor, for the same reason as ``makeSessionStore(at:)``.
    func prepareCapturesDirectory(at location: ProjectDataLocation) async -> URL? {
        let directoryURL = location.capturesDirectoryURL
        return await Task.detached(priority: .userInitiated) { () -> URL? in
            do {
                try FileManager.default.createDirectory(
                    at: directoryURL,
                    withIntermediateDirectories: true
                )
            } catch {
                return nil
            }
            return directoryURL
        }.value
    }

    // MARK: Private

    private let identity: TracexyIdentity
    private let applicationSupportRoot: URL
    private let cacheRoot: URL
    private let settingsSuitePrefix: String
    private let legacySettingsSource: UserDefaults?
    private let fileManager: FileManager

    private static func defaultCacheRoot(identity: TracexyIdentity, fileManager: FileManager) -> URL {
        let base = fileManager.urls(for: .cachesDirectory, in: .userDomainMask).first
            ?? fileManager.temporaryDirectory
        return base.appendingPathComponent(identity.appSupportDirectoryName, isDirectory: true)
    }
}

// MARK: - ProjectSettingsSeeding

/// Materializes the preference keys a Project owns into its own suite.
///
/// Two rules make this safe. First, `UserDefaults(suiteName:)` still searches the
/// application domain, so an *absent* key would silently read the shared value —
/// every project-scoped key is therefore written into the suite explicitly, and no
/// project ever falls through to `.standard`. Second, the legacy owner is seeded
/// from the pre-Projects keys and those keys are left exactly where they are: the
/// seed reads, it never moves or deletes.
///
/// Every safe default below reproduces the behavior the resolvers already applied
/// to an absent key, so materializing them changes no observable outcome.
enum ProjectSettingsSeeding {
    static let currentSeedVersion = 1

    static var seedVersionKey: String {
        TracexyIdentity.current.defaultsKey("project.settings.seedVersion")
    }

    /// The complete allowlist: key → the value a brand-new Project starts with.
    static func safeDefaultValues() -> [String: Any] {
        [
            SettingsKeys.defaultView: DefaultView.sessions.rawValue,
            SettingsKeys.defaultInterface: "",
            SettingsKeys.autoStartCapture: false,
            SettingsKeys.captureFilterMode: CaptureFilterMode.all.rawValue,
            SettingsKeys.bpfExpression: "",
            SettingsKeys.snapLength: CaptureConfiguration.defaultSnapLength,
            SettingsKeys.promiscuous: false,
            SettingsKeys.retainPackets: CaptureSettingsResolver.defaultRetainPackets,
            SettingsKeys.redactBodies: true,
            SettingsKeys.stripCredentials: true,
            SettingsKeys.maskIPs: false,
            SettingsKeys.autoClear: AutoClear.never.rawValue,
            ProjectScopedSettingsKeys.pinnedHosts: [String](),
            ProjectScopedSettingsKeys.focusSets: Data("[]".utf8),
            ProjectScopedSettingsKeys.mutedHosts: [String](),
            ProjectScopedSettingsKeys.mutedProtocols: [String](),
            ProjectScopedSettingsKeys.hiddenSourceApps: [String](),
            ProjectScopedSettingsKeys.hiddenSourceDomains: [String](),
            ProjectScopedSettingsKeys.hiddenSourceIPs: [String](),
            ProjectScopedSettingsKeys.inspectorLayout: InspectorLayout.hidden.rawValue,
            ProjectScopedSettingsKeys.contextDockVisible: false,
            ProjectScopedSettingsKeys.allowsAutomaticInspectorReveal: true,
        ]
    }

    /// Write every missing project-scoped key into `defaults`' own suite domain.
    /// `legacy` supplies the seed for the legacy owner only; a key absent there
    /// falls back to the same safe default a new Project receives.
    static func prepare(_ defaults: UserDefaults, suiteName: String, seedingFrom legacy: UserDefaults?) {
        let owned = UserDefaults.standard.persistentDomain(forName: suiteName) ?? [:]
        for (key, safeValue) in safeDefaultValues() where owned[key] == nil {
            let seeded = legacy?.object(forKey: key)
            defaults.set(seeded ?? safeValue, forKey: key)
        }
        if owned[seedVersionKey] == nil {
            defaults.set(currentSeedVersion, forKey: seedVersionKey)
        }
    }
}
