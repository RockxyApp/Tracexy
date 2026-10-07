import AppKit
import Foundation
import Observation
import SwiftUI
import UniformTypeIdentifiers

// MARK: - GeoIPDatabaseEntry

/// One database the active Project refers to, and how reading it went.
nonisolated struct GeoIPDatabaseEntry: Identifiable, Hashable, Sendable {
    enum Status: Hashable, Sendable {
        case reading
        case ready(GeoIPDatabaseInfo)
        case unavailable(String)
    }

    let id: UUID
    let url: URL?
    var status: Status

    var fileName: String {
        url?.lastPathComponent ?? String(localized: "Unknown file")
    }
}

// MARK: - GeoIPDatabaseInfo

/// What the sheet shows about a database that was read.
nonisolated struct GeoIPDatabaseInfo: Hashable, Sendable {
    let databaseType: String
    let buildDate: Date?
    let networkCount: Int
    let ipVersion: Int
}

// MARK: - GeoIPController

/// The active Project's GeoIP databases, and the locations the rest of the app
/// shows: Endpoints columns, a GeoIP layer in the Session Inspector, and the
/// `$geoip_…` Session Expression macros.
///
/// Privacy rules this type keeps:
/// - Databases are files the user chose. Tracexy never downloads one, never copies
///   one into the Project (it remembers where each file is, as a bookmark in the
///   Project's own settings), and never sends an address anywhere. Lookups read
///   the file's contents in memory on this Mac.
/// - Private, unique local, link-local, loopback and other special addresses are
///   never looked up.
/// - How many databases may be *added* is the coordinator's policy; databases a
///   Project already refers to beyond it are still read.
@MainActor
@Observable
final class GeoIPController {
    // MARK: Lifecycle

    init(environment: [String: String] = ProcessInfo.processInfo.environment) {
        #if DEBUG
        qaDatabaseFiles = environment[Self.qaDatabasesEnvironmentKey].map { value in
            value.split(separator: ":").map { URL(fileURLWithPath: String($0)) }
        } ?? []
        #endif
    }

    // MARK: Internal

    #if DEBUG
    /// Native QA only: Add… adds these files (colon-separated paths) instead of
    /// showing the Open panel.
    static let qaDatabasesEnvironmentKey = "TRACEXY_QA_GEOIP_DATABASES"
    #endif

    /// Where the active Project's databases are, in its settings, in lookup order.
    static let bookmarksKey = ProjectScopedSettingsKeys.geoIPDatabases
    /// Databases a Project may refer to — the storage ceiling. How many may be
    /// *added* is ``databaseLimit``.
    static let maximumDatabases = ProjectLimits.maximumGeoIPDatabases
    /// Answers remembered between renders; cleared whenever the databases change.
    static let maximumCachedAnswers = 50_000
    /// Distinct capture addresses a `$geoip_…` macro considers.
    static let maximumExpressionAddresses = 20_000

    private(set) var entries: [GeoIPDatabaseEntry] = []
    /// Bumped whenever the loaded databases change, so views that show answers
    /// render again.
    private(set) var generation = 0
    /// Why the last Add… left some files out, or `nil`.
    private(set) var addNotice: String?
    @ObservationIgnored private(set) weak var coordinator: MainContentCoordinator?
    /// The app's appearance preference, for the sheets this presents.
    @ObservationIgnored var colorScheme: ColorScheme?
    @ObservationIgnored private(set) var applicationDefaults: UserDefaults = .standard
    /// The Session Inspector's GeoIP layers by session, so their identities stay
    /// stable between renders. Cleared with the answers.
    @ObservationIgnored var inspectorLayerCache: [UUID: [DecodedLayer]] = [:]

    /// Whether any database is ready to answer.
    var hasReadyDatabase: Bool {
        _ = generation
        return !loaded.isEmpty
    }

    /// Databases that may be added now: the policy's number, never above the
    /// storage ceiling.
    var databaseLimit: Int {
        _ = attachment
        return min(max(0, coordinator?.policy.maxGeoIPDatabases ?? 0), Self.maximumDatabases)
    }

    var canAddDatabases: Bool {
        entries.count < databaseLimit
    }

    /// Connect to the workspace and read the active Project's databases.
    func attach(_ coordinator: MainContentCoordinator, applicationDefaults: UserDefaults) {
        self.coordinator = coordinator
        self.applicationDefaults = applicationDefaults
        attachment &+= 1
        syncProject()
    }

    /// Follow the active Project: drop the previous Project's databases and read
    /// this one's.
    func syncProject() {
        guard let coordinator else {
            return
        }
        let projectID = coordinator.projectStore.activeProjectID
        guard projectID != boundProjectID || entries.isEmpty && !bookmarks().isEmpty else {
            return
        }
        boundProjectID = projectID
        reloadAll()
    }

    // MARK: Answers

    /// What the databases say about `address`. Cached.
    func answer(for address: String) -> GeoIPAnswer {
        _ = generation
        guard !loaded.isEmpty else {
            return .notFound
        }
        if let cached = cache[address] {
            return cached
        }
        let answer = databaseSet.answer(for: address, language: language)
        if cache.count >= Self.maximumCachedAnswers {
            cache.removeAll(keepingCapacity: true)
        }
        cache[address] = answer
        return answer
    }

    /// Located addresses of the open capture, for the `$geoip_…` macros.
    func expressionEntries() -> [GeoIPExpressionBuiltIns.Entry] {
        guard let coordinator else {
            return []
        }
        var seen = Set<String>()
        var entries: [GeoIPExpressionBuiltIns.Entry] = []
        for session in coordinator.presentedSessions {
            for endpoint in [session.sourceEndpointValue, session.destinationEndpointValue] {
                guard let ip = endpoint?.ip, seen.count < Self.maximumExpressionAddresses,
                      seen.insert(ip).inserted else
                {
                    continue
                }
                if case let .located(location) = answer(for: ip),
                   let parsed = IPAddressValue(parsing: ip)
                {
                    entries.append(.init(address: GeoIPNetwork.embeddedIPv4(parsed) ?? parsed, location: location))
                }
            }
        }
        return entries
    }

    // MARK: Databases

    /// Show GeoIP Databases… for the active Project.
    func presentDatabasesSheet() {
        GeoIPDatabasesSheetPresenter.present(controller: self, colorScheme: colorScheme)
    }

    /// Choose database files to add to the active Project.
    func addDatabases() {
        guard canAddDatabases, let coordinator else {
            return
        }
        let urls = chosenFiles()
        guard !urls.isEmpty else {
            return
        }
        var stored = bookmarks()
        let existing = Set(entries.compactMap { $0.url?.resolvingSymlinksInPath().path })
        var skipped = 0
        var added = 0
        for url in urls {
            guard stored.count < databaseLimit else {
                skipped += 1
                continue
            }
            guard !existing.contains(url.resolvingSymlinksInPath().path), let bookmark = Self.bookmark(for: url) else {
                skipped += 1
                continue
            }
            stored.append(bookmark)
            added += 1
        }
        let notice = skipped == 0 ? nil : String(
            localized: "Some files weren’t added. They’re already in the list, can’t be referred to, or the list is full."
        )
        guard added > 0 else {
            addNotice = notice
            return
        }
        coordinator.activeProjectDefaults.set(stored, forKey: Self.bookmarksKey)
        reloadAll()
        // After the reload, which starts from a clean list and no notice.
        addNotice = notice
    }

    /// Forget one database for the active Project.
    func removeDatabase(_ id: UUID) {
        guard let index = entries.firstIndex(where: { $0.id == id }), let coordinator else {
            return
        }
        var stored = bookmarks()
        if index < stored.count {
            stored.remove(at: index)
        }
        if stored.isEmpty {
            coordinator.activeProjectDefaults.removeObject(forKey: Self.bookmarksKey)
        } else {
            coordinator.activeProjectDefaults.set(stored, forKey: Self.bookmarksKey)
        }
        entries.remove(at: index)
        loaded[id] = nil
        order.removeAll { $0 == id }
        addNotice = nil
        databasesChanged()
    }

    /// Read every file again (after a database update, for example).
    func reloadAll() {
        dropAll()
        guard let coordinator else {
            return
        }
        let projectID = coordinator.projectStore.activeProjectID
        boundProjectID = projectID
        loadGeneration &+= 1
        let load = loadGeneration
        for bookmark in bookmarks().prefix(Self.maximumDatabases) {
            let url = Self.resolve(bookmark, in: coordinator.activeProjectDefaults)
            let entry = GeoIPDatabaseEntry(
                id: UUID(),
                url: url,
                status: url == nil ? .unavailable(Self.message(for: nil)) : .reading
            )
            entries.append(entry)
            order.append(entry.id)
            if let url {
                read(url, id: entry.id, load: load, projectID: projectID)
            }
        }
    }

    // MARK: Private

    /// Observed stand-in for the unobserved coordinator reference, so a limit read
    /// before ``attach(_:applicationDefaults:)`` renders again once connected.
    private var attachment = 0

    /// The databases, by entry. Never observed.
    @ObservationIgnored private var loaded: [UUID: MaxMindDatabase] = [:]
    @ObservationIgnored private var order: [UUID] = []
    @ObservationIgnored private var databaseSet = GeoIPDatabaseSet(databases: [])
    @ObservationIgnored private var language = "en"
    @ObservationIgnored private var cache: [String: GeoIPAnswer] = [:]
    @ObservationIgnored private var boundProjectID: UUID?
    @ObservationIgnored private var loadGeneration = 0
    @ObservationIgnored private var tasks: [UUID: Task<Void, Never>] = [:]
    #if DEBUG
    @ObservationIgnored private let qaDatabaseFiles: [URL]
    #endif

    private static func bookmark(for url: URL) -> Data? {
        (try? url.bookmarkData(options: .withSecurityScope, includingResourceValuesForKeys: nil, relativeTo: nil))
            ?? (try? url.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil))
    }

    private static func resolve(_ data: Data, in defaults: UserDefaults) -> URL? {
        var stale = false
        let url = (try? URL(
            resolvingBookmarkData: data, options: [.withSecurityScope, .withoutUI], bookmarkDataIsStale: &stale
        )) ?? (try? URL(resolvingBookmarkData: data, options: [.withoutUI], bookmarkDataIsStale: &stale))
        if let url, stale, let fresh = bookmark(for: url),
           var stored = defaults.array(forKey: bookmarksKey) as? [Data],
           let index = stored.firstIndex(of: data)
        {
            stored[index] = fresh
            defaults.set(stored, forKey: bookmarksKey)
        }
        return url
    }

    nonisolated private static func message(for error: Error?) -> String {
        guard let error else {
            return String(localized: "The file is no longer where it was. Remove it and add it again.")
        }
        switch error as? MaxMindDatabaseError {
        case .notARegularFile:
            return String(localized: "Choose a database file, not a folder or a device.")
        case .tooLarge:
            return String(localized: "The file is larger than 512 MB.")
        case .noMetadata:
            return String(localized: "This isn’t a MaxMind database (.mmdb) file.")
        case .unsupportedFormat:
            return String(localized: "This database uses a format version Tracexy can’t read.")
        case .some:
            return String(localized: "The database is damaged and can’t be read.")
        case nil:
            break
        }
        let cocoa = error as NSError
        if cocoa.domain == NSCocoaErrorDomain,
           [NSFileReadNoSuchFileError, NSFileNoSuchFileError].contains(cocoa.code)
        {
            return String(localized: "The file is no longer there. Remove it and add it again.")
        }
        if cocoa.domain == NSCocoaErrorDomain, cocoa.code == NSFileReadNoPermissionError {
            return String(
                localized: "Tracexy isn’t allowed to read the file. Remove it and add it again."
            )
        }
        return String(localized: "The file couldn’t be read.")
    }

    private func bookmarks() -> [Data] {
        (coordinator?.activeProjectDefaults.array(forKey: Self.bookmarksKey) as? [Data]) ?? []
    }

    private func read(_ url: URL, id: UUID, load: Int, projectID: UUID?) {
        let work = Task.detached(priority: .userInitiated) { () -> Result<(MaxMindDatabase, Int), Error> in
            let scoped = url.startAccessingSecurityScopedResource()
            defer {
                if scoped {
                    url.stopAccessingSecurityScopedResource()
                }
            }
            do {
                let database = try MaxMindDatabase.read(contentsOf: url)
                guard let networks = database.networkCount(isCancelled: { Task.isCancelled }) else {
                    return .failure(CancellationError())
                }
                return .success((database, networks))
            } catch {
                return .failure(error)
            }
        }
        tasks[id] = Task { [weak self] in
            let outcome = await withTaskCancellationHandler {
                await work.value
            } onCancel: {
                work.cancel()
            }
            self?.finish(outcome, id: id, load: load, projectID: projectID)
        }
    }

    private func finish(_ outcome: Result<(MaxMindDatabase, Int), Error>, id: UUID, load: Int, projectID: UUID?) {
        tasks[id] = nil
        // A Project change, a removal or a reload while reading wins over this result.
        guard load == loadGeneration,
              coordinator?.projectStore.activeProjectID == projectID,
              let index = entries.firstIndex(where: { $0.id == id }) else
        {
            return
        }
        switch outcome {
        case let .success((database, networks)):
            loaded[id] = database
            entries[index].status = .ready(GeoIPDatabaseInfo(
                databaseType: database.metadata.databaseType,
                buildDate: database.metadata.buildDate,
                networkCount: networks,
                ipVersion: database.metadata.ipVersion
            ))
            databasesChanged()
        case let .failure(error):
            if error is CancellationError {
                return
            }
            entries[index].status = .unavailable(Self.message(for: error))
        }
    }

    private func databasesChanged() {
        let databases = order.compactMap { loaded[$0] }
        databaseSet = GeoIPDatabaseSet(databases: databases)
        language = GeoIPDatabaseSet.preferredLanguage(for: databases)
        cache.removeAll()
        inspectorLayerCache.removeAll()
        generation &+= 1
    }

    private func dropAll() {
        for task in tasks.values {
            task.cancel()
        }
        tasks.removeAll()
        loadGeneration &+= 1
        entries.removeAll()
        loaded.removeAll()
        order.removeAll()
        addNotice = nil
        databasesChanged()
    }

    private func chosenFiles() -> [URL] {
        #if DEBUG
        if !qaDatabaseFiles.isEmpty {
            return qaDatabaseFiles
        }
        #endif
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        if let type = UTType(filenameExtension: "mmdb") {
            panel.allowedContentTypes = [type]
        }
        panel.message = String(
            localized: "Choose MaxMind database files (.mmdb), such as GeoLite2 City, Country or ASN, or DB-IP files in the same format."
        )
        panel.prompt = String(localized: "Add")
        guard panel.runModal() == .OK else {
            return []
        }
        return panel.urls
    }
}

// MARK: ExpressionMacroBuiltInSource

extension GeoIPController: ExpressionMacroBuiltInSource {
    func expressionBuiltIns() -> (any ExpressionMacroBuiltIns)? {
        guard hasReadyDatabase else {
            return nil
        }
        return GeoIPExpressionBuiltIns(entries: expressionEntries())
    }
}
