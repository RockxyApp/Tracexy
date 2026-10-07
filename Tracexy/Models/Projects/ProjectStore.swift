import Foundation
import Observation

// MARK: - ProjectCatalogLoadState

enum ProjectCatalogLoadState: Equatable {
    case idle
    case loading
    case ready
    case failed(String)
}

// MARK: - ProjectCatalogPersistenceState

enum ProjectCatalogPersistenceState: Equatable {
    case idle
    case saving
    case saved
    case failed(String)
}

// MARK: - ProjectMutationError

enum ProjectMutationError: Error, Equatable {
    case nameInvalid(ProjectNameNormalizationError)
    case duplicateName
    case capacityReached(limit: Int)
    case workspaceCapacityReached(limit: Int)
    case filterRuleCapacityReached(limit: Int)
    case projectNotFound
    case cannotDeleteFinalProject
    case storeNotReady
    case revisionExhausted
    case invalidWorkspaceSnapshot(ProjectCatalogValidationError)
    case catalogStorageFull

    // MARK: Internal

    var userFacingDescription: String {
        switch self {
        case .nameInvalid(.empty):
            "Enter a project name."
        case let .nameInvalid(.tooLong(limit)):
            "Project names can contain at most \(limit) characters."
        case .nameInvalid(.containsControlCharacter):
            "That project name contains unsupported characters."
        case .duplicateName:
            "A project with that name already exists."
        case let .capacityReached(limit):
            "New projects can be added up to \(limit). Existing projects stay available."
        case let .workspaceCapacityReached(limit):
            "New workspaces can be added up to \(limit) per project. Open workspaces stay available."
        case let .filterRuleCapacityReached(limit):
            "A workspace in this project has more than \(limit) session filter rules, the most a workspace can add here."
        case .projectNotFound:
            "That project is no longer available."
        case .cannotDeleteFinalProject:
            "Tracexy must keep at least one project."
        case .storeNotReady:
            "Projects are not ready yet."
        case .revisionExhausted:
            "This project catalog can no longer be updated."
        case .invalidWorkspaceSnapshot:
            "One or more workspaces could not be saved."
        case .catalogStorageFull:
            "Projects have no room left to save this. Remove workspace tabs or filter rules you no longer need, then try again."
        }
    }
}

// MARK: - ProjectCatalogTransition

/// The catalog change one Project lifecycle transition intends to make. Kept
/// separate from the UI's confirmation request so the store validates a change
/// without knowing why it was asked for.
nonisolated enum ProjectCatalogTransition: Sendable {
    case select(UUID)
    case create(name: String)
    case adopt(Project)
    case delete(UUID)
}

// MARK: - PreparedProjectCatalogTransition

/// A validated catalog change that has **not** been published or written.
///
/// Preparing one freezes every other catalog mutation until it is committed or
/// discarded, so nothing can interleave between validation and the durable
/// write. A preparation that is never committed leaves the catalog — and the
/// Project the user is on — exactly as it was.
nonisolated struct PreparedProjectCatalogTransition: Sendable {
    // MARK: Internal

    let id: UUID
    /// The Project that becomes active once this transition is published. Its
    /// identity is minted at validation time, so a caller can name the
    /// destination before the change is durable.
    let destinationProject: Project
    /// The Project this transition removes from the catalog, if any. Only the
    /// JSON configuration is removed; its History database, Library folder and
    /// spool stay exactly where they are on disk.
    let deletedProjectID: UUID?

    // MARK: Fileprivate

    fileprivate let candidate: ProjectCatalog
    fileprivate let expectedRevision: UInt64
    fileprivate var resetsCatalog = false
    /// Whether committing adds a Project, so the limit is checked again then: it
    /// may have been lowered while the transition waited for a capture to drain.
    fileprivate var addsProject = false
    /// The Project an import adds, whose tabs and rule rows are checked again at
    /// commit for the same reason.
    fileprivate var importedProjectID: UUID?
}

// MARK: - ProjectStore

@MainActor
@Observable
final class ProjectStore {
    // MARK: Lifecycle

    init(
        maxProjects: Int,
        maxWorkspacesPerProject: Int,
        maxFilterRulesPerWorkspace: Int = ProjectLimits.maximumFilterRules,
        repository: ProjectCatalogPersisting? = nil,
        catalog: ProjectCatalog? = nil,
        maximumCatalogBytes: Int = ProjectLimits.maximumCatalogBytes,
        maximumProjectBytes: Int = ProjectLimits.maximumProjectBytes,
        now: @escaping () -> Date = { Date() }
    ) {
        self.maxProjects = min(max(1, maxProjects), ProjectLimits.maximumProjects)
        self.maxWorkspacesPerProject = min(
            max(1, maxWorkspacesPerProject),
            ProjectLimits.maximumWorkspacesPerProject
        )
        self.maxFilterRulesPerWorkspace = Self.boundedRuleLimit(maxFilterRulesPerWorkspace)
        self.repository = repository
        self.now = now

        let proposed = catalog ?? ProjectCatalog.defaultCatalog(now: now())
        let normalized = try? proposed.normalizedValidated()
        let initial = normalized ?? ProjectCatalog.defaultCatalog(now: now())
        self.catalog = initial
        self.seedCatalog = initial
        self.maximumCatalogBytes = maximumCatalogBytes
        self.maximumProjectBytes = maximumProjectBytes
        self.encodedCatalogBytes = ProjectCatalogCoding.encodedByteCount(of: initial)
        if repository == nil {
            loadState = .ready
            persistenceState = .saved
        }
    }

    // MARK: Internal

    private(set) var loadState: ProjectCatalogLoadState = .idle
    private(set) var persistenceState: ProjectCatalogPersistenceState = .idle

    /// How many Projects may exist before *creating* another is refused. The
    /// catalog itself is only ever checked against ``ProjectLimits``: a catalog
    /// that already holds more than this (imported, or edited by hand)
    /// loads, opens and edits normally, and only growth is refused.
    private(set) var maxProjects: Int
    /// How many workspace tabs a Project may grow to. Same rule: stored Projects
    /// above it stay intact, and only adding a tab is refused.
    private(set) var maxWorkspacesPerProject: Int
    /// How many session filter rules one workspace may grow to. Only an imported
    /// Project is checked against it here; the filter bar enforces it while editing.
    private(set) var maxFilterRulesPerWorkspace: Int

    /// Compatibility spelling used by coordinator presentation code.
    var persistenceStatus: ProjectCatalogPersistenceState {
        persistenceState
    }

    var loadFailureMessage: String? {
        guard case let .failed(message) = loadState else {
            return nil
        }
        return message
    }

    var projects: [Project] {
        catalog.projects
    }

    var activeProjectID: UUID {
        catalog.activeProjectID
    }

    var activeProject: Project {
        catalog.projects.first(where: { $0.id == catalog.activeProjectID }) ?? catalog.projects[0]
    }

    /// The Project that owns the pre-Projects History database and Captures
    /// folder, or `nil` before it has been assigned on first load.
    var legacyDataOwnerProjectID: UUID? {
        catalog.legacyDataOwnerProjectID
    }

    /// True while a prepared transition is holding the catalog. Every ordinary
    /// mutation is frozen until it commits or is discarded.
    var isCatalogTransitionPrepared: Bool {
        preparedTransitionID != nil
    }

    /// A failed save does not freeze the catalog: the next change saves the whole
    /// catalog again on top of the last revision known to be on disk, so a
    /// transient write error is recovered by carrying on rather than losing every
    /// later edit.
    var isMutable: Bool {
        loadState == .ready && preparedTransitionID == nil
    }

    var canCreateProject: Bool {
        isMutable && catalog.projects.count < maxProjects
    }

    /// True when the catalog holds more Projects than may currently be created.
    /// Nothing is hidden or removed; the UI states it so "New Project" being
    /// unavailable is explained rather than silent.
    var isOverProjectLimit: Bool {
        catalog.projects.count > maxProjects
    }

    /// Re-inject the growth limits. Never touches the catalog: lowering a limit
    /// below what already exists leaves every Project in place.
    func updateLimits(maxProjects: Int, maxWorkspacesPerProject: Int, maxFilterRulesPerWorkspace: Int? = nil) {
        let projects = min(max(1, maxProjects), ProjectLimits.maximumProjects)
        let workspaces = min(max(1, maxWorkspacesPerProject), ProjectLimits.maximumWorkspacesPerProject)
        if self.maxProjects != projects {
            self.maxProjects = projects
        }
        if self.maxWorkspacesPerProject != workspaces {
            self.maxWorkspacesPerProject = workspaces
        }
        if let maxFilterRulesPerWorkspace {
            let rules = Self.boundedRuleLimit(maxFilterRulesPerWorkspace)
            if self.maxFilterRulesPerWorkspace != rules {
                self.maxFilterRulesPerWorkspace = rules
            }
        }
    }

    func loadPersistedCatalog() async {
        guard let repository else {
            loadState = .ready
            persistenceState = .saved
            return
        }
        await waitForPendingPersistence()
        loadState = .loading
        persistenceState = .idle
        do {
            let loaded = try await repository.load(seed: seedCatalog)
            catalog = try loaded.normalizedValidated()
            persistedRevision = catalog.revision
            remeasure(catalog)
            loadState = .ready
            persistenceState = .saved
        } catch {
            loadState = .failed(Self.errorDescription(error))
            persistenceState = .idle
        }
    }

    func retryLoad() async {
        await loadPersistedCatalog()
    }

    /// Bind the pre-Projects data to exactly one Project, exactly once.
    ///
    /// A catalog written before Project isolation carries no owner, so the first
    /// listed Project adopts the existing History database and Captures folder and
    /// that choice is persisted before any capture, History write, or Library scan
    /// is allowed. A catalog that already names an owner — including the retired
    /// sentinel left by recovery — is returned unchanged: the owner is never
    /// reassigned when it is deleted or when the active Project changes.
    @discardableResult
    func assignLegacyDataOwnerIfNeeded() throws -> UUID {
        if let existing = catalog.legacyDataOwnerProjectID {
            return existing
        }
        try requireMutable()
        let owner = catalog.projects[0].id
        try commitMutation { catalog in
            catalog.legacyDataOwnerProjectID = owner
        }
        return owner
    }

    func resetToDefaultCatalog() async {
        // A prepared transition owns the catalog until it settles; replacing it
        // underneath would publish a catalog the transition never validated.
        guard preparedTransitionID == nil else {
            return
        }
        await waitForPendingPersistence()
        guard let nextRevision = try? nextRevision(after: catalog.revision) else {
            let message = ProjectMutationError.revisionExhausted.userFacingDescription
            loadState = .failed(message)
            persistenceState = .failed(message)
            return
        }
        var resetCatalog = ProjectCatalog.defaultCatalog(now: now())
        resetCatalog.revision = nextRevision
        // Recovery mints a brand-new Project. Handing it the pre-Projects History
        // and Captures would silently reassign someone else's data, so the owner
        // is either preserved (when the previous catalog was readable) or retired.
        // Either way the files stay on disk and no new Project inherits them.
        resetCatalog.legacyDataOwnerProjectID = catalog.legacyDataOwnerProjectID
            ?? ProjectCatalog.retiredLegacyDataOwnerID
        guard let validated = try? validatedForStorage(resetCatalog) else {
            let message = "The default project catalog could not be prepared."
            loadState = .failed(message)
            persistenceState = .failed(message)
            return
        }
        resetCatalog = validated

        loadState = .loading
        persistenceState = .saving
        do {
            if let repository {
                resetCatalog = try await repository.reset(to: resetCatalog)
            }
            catalog = resetCatalog
            seedCatalog = resetCatalog
            persistedRevision = resetCatalog.revision
            remeasure(resetCatalog)
            loadState = .ready
            persistenceState = .saved
        } catch {
            loadState = .failed(Self.errorDescription(error))
            persistenceState = .failed(Self.errorDescription(error))
        }
    }

    @discardableResult
    func createProject(name: String) throws -> Project {
        try requireMutable()
        guard catalog.projects.count < maxProjects else {
            throw ProjectMutationError.capacityReached(limit: maxProjects)
        }
        let normalizedName = try normalizeName(name)
        guard !containsProjectName(normalizedName, excluding: nil) else {
            throw ProjectMutationError.duplicateName
        }
        let timestamp = now()
        let workspace = ProjectWorkspaceSnapshot(title: "Live", isClosable: false)
        let project = Project(
            name: normalizedName,
            workspaces: [workspace],
            activeWorkspaceID: workspace.id,
            createdAt: timestamp,
            updatedAt: timestamp
        )
        try commitMutation { catalog in
            catalog.projects.append(project)
            catalog.activeProjectID = project.id
        }
        return project
    }

    /// Insert a configuration-only imported project as a new catalog object.
    /// All identities are regenerated even when the source happens not to
    /// collide, keeping repeated imports independent and preventing overwrite.
    @discardableResult
    func importProject(_ project: Project) throws -> Project {
        try requireMutable()
        let imported = try validatedImport(project)
        try commitMutation { catalog in
            catalog.projects.append(imported)
            catalog.activeProjectID = imported.id
        }
        return imported
    }

    // MARK: The durable prepared transition

    /// Explicit recovery prepares fresh ownership without publishing the new
    /// catalog. The coordinator can open its resources before replacing a file.
    func prepareResetTransition() throws -> PreparedProjectCatalogTransition {
        guard preparedTransitionID == nil, loadState != .loading else {
            throw ProjectMutationError.storeNotReady
        }
        var candidate = ProjectCatalog.defaultCatalog(now: now())
        candidate.revision = try nextRevision(after: catalog.revision)
        candidate.legacyDataOwnerProjectID = catalog.legacyDataOwnerProjectID
            ?? ProjectCatalog.retiredLegacyDataOwnerID
        candidate = try validatedForStorage(candidate)
        let prepared = PreparedProjectCatalogTransition(
            id: UUID(),
            destinationProject: candidate.projects[0],
            deletedProjectID: nil,
            candidate: candidate,
            expectedRevision: catalog.revision,
            resetsCatalog: true
        )
        preparedTransitionID = prepared.id
        return prepared
    }

    /// Validate `transition` against the current catalog and return the resulting
    /// candidate **without publishing or writing it**.
    ///
    /// The catalog is frozen from here until the returned value is committed or
    /// discarded, so a caller can resolve the destination Project's storage — and
    /// wait out a capture's final drain — knowing nothing else can move underneath.
    func prepareTransition(_ transition: ProjectCatalogTransition) throws -> PreparedProjectCatalogTransition {
        try requireMutable()
        let expectedRevision = catalog.revision
        var candidate = catalog
        var deletedProjectID: UUID?
        let destinationID: UUID

        switch transition {
        case let .select(id):
            guard candidate.projects.contains(where: { $0.id == id }) else {
                throw ProjectMutationError.projectNotFound
            }
            candidate.activeProjectID = id
            destinationID = id
        case let .create(name):
            guard candidate.projects.count < maxProjects else {
                throw ProjectMutationError.capacityReached(limit: maxProjects)
            }
            let normalizedName = try normalizeName(name)
            guard !containsProjectName(normalizedName, excluding: nil) else {
                throw ProjectMutationError.duplicateName
            }
            let timestamp = now()
            let workspace = ProjectWorkspaceSnapshot(title: "Live", isClosable: false)
            let project = Project(
                name: normalizedName,
                workspaces: [workspace],
                activeWorkspaceID: workspace.id,
                createdAt: timestamp,
                updatedAt: timestamp
            )
            candidate.projects.append(project)
            candidate.activeProjectID = project.id
            destinationID = project.id
        case let .adopt(project):
            let imported = try validatedImport(project)
            candidate.projects.append(imported)
            candidate.activeProjectID = imported.id
            destinationID = imported.id
        case let .delete(id):
            guard candidate.projects.count > ProjectLimits.minimumProjects else {
                throw ProjectMutationError.cannotDeleteFinalProject
            }
            guard let index = candidate.projects.firstIndex(where: { $0.id == id }) else {
                throw ProjectMutationError.projectNotFound
            }
            candidate.projects.remove(at: index)
            if candidate.activeProjectID == id {
                candidate.activeProjectID = candidate.projects[min(index, candidate.projects.count - 1)].id
            }
            deletedProjectID = id
            destinationID = candidate.activeProjectID
        }

        candidate.revision = try nextRevision(after: expectedRevision)
        do {
            candidate = try validatedForStorage(candidate)
        } catch let error as ProjectCatalogValidationError {
            throw ProjectMutationError.invalidWorkspaceSnapshot(error)
        }
        guard let destination = candidate.projects.first(where: { $0.id == destinationID }) else {
            throw ProjectMutationError.projectNotFound
        }

        var prepared = PreparedProjectCatalogTransition(
            id: UUID(),
            destinationProject: destination,
            deletedProjectID: deletedProjectID,
            candidate: candidate,
            expectedRevision: expectedRevision
        )
        prepared.addsProject = candidate.projects.count > catalog.projects.count
        if case .adopt = transition {
            prepared.importedProjectID = destination.id
        }
        preparedTransitionID = prepared.id
        return prepared
    }

    /// Publish a prepared transition, but only after it has been written durably.
    ///
    /// The candidate is never adopted before the write succeeds, so a failed save
    /// leaves both the in-memory catalog and the file on disk exactly as they
    /// were. Because nothing diverged, the persisted state is restored rather than
    /// marked failed and the transition stays retryable.
    func commitPreparedTransition(_ prepared: PreparedProjectCatalogTransition) async throws {
        guard preparedTransitionID == prepared.id else {
            throw ProjectMutationError.storeNotReady
        }
        // Every earlier write must have settled before the candidate is written, so
        // a slow previous save can never land on top of the new catalog.
        await waitForPendingPersistence()
        guard preparedTransitionID == prepared.id,
              catalog.revision == prepared.expectedRevision else
        {
            preparedTransitionID = nil
            throw ProjectMutationError.storeNotReady
        }
        if prepared.addsProject, catalog.projects.count >= maxProjects {
            preparedTransitionID = nil
            throw ProjectMutationError.capacityReached(limit: maxProjects)
        }
        if let id = prepared.importedProjectID,
           let imported = prepared.candidate.projects.first(where: { $0.id == id })
        {
            do {
                try checkImportCapacity(imported)
            } catch {
                preparedTransitionID = nil
                throw error
            }
        }
        if let repository {
            let previousPersistenceState = persistenceState
            persistenceState = .saving
            do {
                if prepared.resetsCatalog {
                    _ = try await repository.reset(to: prepared.candidate)
                } else {
                    try await repository.save(prepared.candidate, expectedRevision: prepared.expectedRevision)
                }
            } catch {
                persistenceState = previousPersistenceState
                preparedTransitionID = nil
                throw error
            }
        }
        catalog = prepared.candidate
        if repository != nil {
            persistedRevision = catalog.revision
        }
        remeasure(catalog)
        if prepared.resetsCatalog {
            seedCatalog = catalog
        }
        loadState = .ready
        persistenceState = .saved
        preparedTransitionID = nil
    }

    /// Release a prepared transition without publishing it. The catalog is
    /// unfrozen and nothing it described ever happened.
    func discardPreparedTransition(_ prepared: PreparedProjectCatalogTransition) {
        guard preparedTransitionID == prepared.id else {
            return
        }
        preparedTransitionID = nil
    }

    func selectProject(id: UUID) throws {
        try requireMutable()
        guard catalog.projects.contains(where: { $0.id == id }) else {
            throw ProjectMutationError.projectNotFound
        }
        guard catalog.activeProjectID != id else {
            return
        }
        try commitMutation { catalog in
            catalog.activeProjectID = id
        }
    }

    func renameProject(id: UUID, to name: String) throws {
        try requireMutable()
        guard let index = catalog.projects.firstIndex(where: { $0.id == id }) else {
            throw ProjectMutationError.projectNotFound
        }
        let normalizedName = try normalizeName(name)
        guard !containsProjectName(normalizedName, excluding: id) else {
            throw ProjectMutationError.duplicateName
        }
        guard catalog.projects[index].name != normalizedName else {
            return
        }
        try commitMutation { catalog in
            catalog.projects[index].name = normalizedName
            catalog.projects[index].updatedAt = now()
        }
    }

    func deleteProject(id: UUID) throws {
        try requireMutable()
        guard catalog.projects.count > ProjectLimits.minimumProjects else {
            throw ProjectMutationError.cannotDeleteFinalProject
        }
        guard let index = catalog.projects.firstIndex(where: { $0.id == id }) else {
            throw ProjectMutationError.projectNotFound
        }
        try commitMutation { catalog in
            catalog.projects.remove(at: index)
            if catalog.activeProjectID == id {
                catalog.activeProjectID = catalog.projects[min(index, catalog.projects.count - 1)].id
            }
        }
    }

    func updateActiveProjectWorkspaces(
        _ workspaces: [ProjectWorkspaceSnapshot],
        activeWorkspaceID: UUID
    )
        throws
    {
        try requireMutable()
        guard let projectIndex = catalog.projects.firstIndex(where: { $0.id == catalog.activeProjectID }) else {
            throw ProjectMutationError.projectNotFound
        }
        // Only growth past the limit is refused. A Project already holding more
        // tabs keeps saving its state, including while tabs are being closed.
        let storedCount = catalog.projects[projectIndex].workspaces.count
        guard workspaces.count <= max(maxWorkspacesPerProject, storedCount) else {
            throw ProjectMutationError.workspaceCapacityReached(limit: maxWorkspacesPerProject)
        }
        do {
            try commitMutation { catalog in
                catalog.projects[projectIndex].workspaces = workspaces
                catalog.projects[projectIndex].activeWorkspaceID = activeWorkspaceID
                catalog.projects[projectIndex].updatedAt = now()
            }
        } catch let error as ProjectCatalogValidationError {
            throw ProjectMutationError.invalidWorkspaceSnapshot(error)
        }
    }

    func waitForPendingPersistence() async {
        let pending = pendingPersistenceTask
        await pending?.value
    }

    // MARK: Private

    private var catalog: ProjectCatalog
    private var seedCatalog: ProjectCatalog

    /// The prepared-but-unpublished transition currently holding the catalog.
    /// Deliberately observed, so surfaces gated on ``isMutable`` refresh when the
    /// catalog freezes and unfreezes.
    private var preparedTransitionID: UUID?

    @ObservationIgnored private let repository: ProjectCatalogPersisting?

    @ObservationIgnored private let now: () -> Date

    @ObservationIgnored private var pendingPersistenceTask: Task<Void, Never>?

    @ObservationIgnored private var pendingPersistenceToken: UUID?

    /// The catalog revision last confirmed on disk.
    @ObservationIgnored private var persistedRevision: UInt64 = 0

    /// The encoded size of the catalog as last committed, for the growth check.
    @ObservationIgnored private var encodedCatalogBytes: Int

    /// Each committed Project's validated form and encoded size, reused while the
    /// Project is unchanged: a change costs the Projects it touched, not the
    /// whole catalog, however many Projects and tabs it holds.
    @ObservationIgnored private var projectMeasures: [UUID: ProjectMeasure] = [:]

    @ObservationIgnored private let maximumCatalogBytes: Int

    @ObservationIgnored private let maximumProjectBytes: Int

    private static func errorDescription(_ error: Error) -> String {
        if let error = error as? LocalizedError, let description = error.errorDescription {
            return description
        }
        return String(describing: error)
    }

    private static func boundedRuleLimit(_ limit: Int) -> Int {
        min(max(1, limit), ProjectLimits.maximumFilterRules)
    }

    private func requireMutable() throws {
        guard isMutable else {
            throw ProjectMutationError.storeNotReady
        }
        rebaseAfterFailedSave()
    }

    /// After a failed save the catalog in memory is ahead of the file. The next
    /// change is written on top of the revision that is on disk, carrying every
    /// change since, so nothing made in this session waits on a relaunch.
    private func rebaseAfterFailedSave() {
        guard case .failed = persistenceState, repository != nil,
              catalog.revision != persistedRevision else
        {
            return
        }
        catalog.revision = persistedRevision
    }

    private func normalizeName(_ name: String) throws -> String {
        do {
            return try ProjectNameNormalization.normalize(name)
        } catch let error as ProjectNameNormalizationError {
            throw ProjectMutationError.nameInvalid(error)
        }
    }

    private func containsProjectName(_ name: String, excluding projectID: UUID?) -> Bool {
        let key = ProjectNameNormalization.uniquenessKey(name)
        return catalog.projects.contains { project in
            project.id != projectID && ProjectNameNormalization.uniquenessKey(project.name) == key
        }
    }

    private func nextRevision(after revision: UInt64) throws -> UInt64 {
        guard revision < UInt64.max else {
            throw ProjectMutationError.revisionExhausted
        }
        return revision + 1
    }

    /// An imported Project's tabs and rule rows all arrive new, so the current
    /// limits apply to them just as they do to adding a tab or a row.
    private func checkImportCapacity(_ project: Project) throws {
        guard project.workspaces.count <= maxWorkspacesPerProject else {
            throw ProjectMutationError.workspaceCapacityReached(limit: maxWorkspacesPerProject)
        }
        guard project.workspaces.allSatisfy({ $0.filterRules.count <= maxFilterRulesPerWorkspace }) else {
            throw ProjectMutationError.filterRuleCapacityReached(limit: maxFilterRulesPerWorkspace)
        }
    }

    /// Validate an imported configuration and regenerate every identity. Shared by
    /// the direct insert and the prepared transition so both apply the same policy.
    private func validatedImport(_ project: Project) throws -> Project {
        guard catalog.projects.count < maxProjects else {
            throw ProjectMutationError.capacityReached(limit: maxProjects)
        }
        let normalizedName = try normalizeName(project.name)
        guard !containsProjectName(normalizedName, excluding: nil) else {
            throw ProjectMutationError.duplicateName
        }
        try checkImportCapacity(project)

        var source = project
        source.name = normalizedName
        let validated: Project
        do {
            let temporary = ProjectCatalog(projects: [source], activeProjectID: source.id)
            validated = try temporary.normalizedValidated(
                maxProjects: 1,
                maxWorkspacesPerProject: maxWorkspacesPerProject
            ).projects[0]
        } catch let error as ProjectCatalogValidationError {
            throw ProjectMutationError.invalidWorkspaceSnapshot(error)
        }
        return regeneratedProject(validated)
    }

    private func regeneratedProject(_ source: Project) -> Project {
        var workspaceIDs: [UUID: UUID] = [:]
        let workspaces = source.workspaces.map { workspace -> ProjectWorkspaceSnapshot in
            let newID = UUID()
            workspaceIDs[workspace.id] = newID
            var copy = workspace
            copy.id = newID
            copy.filterRules = workspace.filterRules.map { rule in
                var copy = rule
                copy.id = UUID()
                return copy
            }
            return copy
        }
        let timestamp = now()
        return Project(
            name: source.name,
            workspaces: workspaces,
            activeWorkspaceID: workspaceIDs[source.activeWorkspaceID] ?? workspaces[0].id,
            createdAt: timestamp,
            updatedAt: timestamp
        )
    }

    /// Structural validity only. Growth limits are checked where growth happens
    /// (create, adopt, new tab), so an edit to a catalog that is already above
    /// them — a rename, a switch, closing a tab — is never refused for it.
    /// The catalog is one file with a size ceiling, so a change that would not fit
    /// is refused up front instead of failing to save. Only growth is refused: a
    /// change that leaves the catalog no larger than it is (a rename, closing a
    /// tab, deleting a Project) always goes through.
    private func validatedForStorage(_ candidate: ProjectCatalog) throws -> ProjectCatalog {
        try sizedForStorage(candidate).catalog
    }

    /// A Project past its own ceiling, or a catalog past the file's, is refused
    /// only when the change makes it larger; each stored Project therefore always
    /// fits a `.tracexyproject` export.
    private func sizedForStorage(_ candidate: ProjectCatalog) throws -> SizedCatalog {
        var measures: [UUID: ProjectMeasure] = [:]
        let validated = try candidate.normalizedValidated(maxProjects: ProjectLimits.maximumProjects) { project in
            let measure = try measured(project)
            measures[measure.validated.id] = measure
            return measure.validated
        }
        var projectBytes: [Int] = []
        projectBytes.reserveCapacity(validated.projects.count)
        for project in validated.projects {
            let bytes = measures[project.id]?.bytes ?? Int.max
            if bytes > maximumProjectBytes, bytes > projectMeasures[project.id]?.bytes ?? 0 {
                throw ProjectMutationError.catalogStorageFull
            }
            projectBytes.append(bytes)
        }
        let bytes = ProjectCatalogCoding.encodedByteCount(of: validated, projectBytes: projectBytes)
        if bytes > maximumCatalogBytes, bytes > encodedCatalogBytes {
            throw ProjectMutationError.catalogStorageFull
        }
        return SizedCatalog(catalog: validated, bytes: bytes, measures: measures)
    }

    private func measured(_ project: Project) throws -> ProjectMeasure {
        if let cached = projectMeasures[project.id], cached.validated == project || cached.source == project {
            return cached
        }
        let validated = try project.normalizedValidated()
        return ProjectMeasure(
            source: project,
            validated: validated,
            bytes: ProjectCatalogCoding.encodedByteCount(of: validated)
        )
    }

    /// Records the committed catalog's sizes, reusing every unchanged Project.
    private func remeasure(_ committed: ProjectCatalog) {
        var measures: [UUID: ProjectMeasure] = [:]
        var projectBytes: [Int] = []
        for project in committed.projects {
            let measure = (try? measured(project))
                ?? ProjectMeasure(
                    source: project,
                    validated: project,
                    bytes: ProjectCatalogCoding.encodedByteCount(of: project)
                )
            measures[project.id] = measure
            projectBytes.append(measure.bytes)
        }
        projectMeasures = measures
        encodedCatalogBytes = ProjectCatalogCoding.encodedByteCount(of: committed, projectBytes: projectBytes)
    }

    private func commitMutation(_ mutation: (inout ProjectCatalog) -> Void) throws {
        let expectedRevision = catalog.revision
        var candidate = catalog
        mutation(&candidate)
        candidate.revision = try nextRevision(after: expectedRevision)
        let sized = try sizedForStorage(candidate)
        candidate = sized.catalog
        catalog = candidate
        encodedCatalogBytes = sized.bytes
        projectMeasures = sized.measures
        enqueuePersistence(candidate, expectedRevision: expectedRevision)
    }

    private func enqueuePersistence(_ snapshot: ProjectCatalog, expectedRevision: UInt64) {
        guard let repository else {
            persistenceState = .saved
            return
        }
        let previous = pendingPersistenceTask
        let token = UUID()
        pendingPersistenceToken = token
        persistenceState = .saving
        pendingPersistenceTask = Task { @MainActor [weak self] in
            await previous?.value
            do {
                try await repository.save(snapshot, expectedRevision: expectedRevision)
                self?.persistedRevision = snapshot.revision
                guard self?.pendingPersistenceToken == token else {
                    return
                }
                self?.persistenceState = .saved
            } catch {
                guard self?.pendingPersistenceToken == token else {
                    return
                }
                self?.persistenceState = .failed(Self.errorDescription(error))
            }
        }
    }
}

// MARK: - ProjectMeasure

/// One Project as the store last validated and encoded it.
nonisolated private struct ProjectMeasure: Sendable {
    let source: Project
    let validated: Project
    let bytes: Int
}

// MARK: - SizedCatalog

nonisolated private struct SizedCatalog: Sendable {
    let catalog: ProjectCatalog
    let bytes: Int
    let measures: [UUID: ProjectMeasure]
}
