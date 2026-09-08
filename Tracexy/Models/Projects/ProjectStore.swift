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
    case projectNotFound
    case cannotDeleteFinalProject
    case storeNotReady
    case revisionExhausted
    case invalidWorkspaceSnapshot(ProjectCatalogValidationError)

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
            "Tracexy supports up to \(limit) projects."
        case let .workspaceCapacityReached(limit):
            "This project supports up to \(limit) workspaces."
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
}

// MARK: - ProjectStore

@MainActor
@Observable
final class ProjectStore {
    // MARK: Lifecycle

    init(
        maxProjects: Int,
        maxWorkspacesPerProject: Int,
        repository: ProjectCatalogPersisting? = nil,
        catalog: ProjectCatalog? = nil,
        now: @escaping () -> Date = { Date() }
    ) {
        self.maxProjects = min(max(1, maxProjects), ProjectLimits.maximumProjects)
        self.maxWorkspacesPerProject = min(
            max(1, maxWorkspacesPerProject),
            ProjectLimits.maximumWorkspacesPerProject
        )
        self.repository = repository
        self.now = now

        let proposed = catalog ?? ProjectCatalog.defaultCatalog(now: now())
        let normalized = try? proposed.normalizedValidated(
            maxProjects: self.maxProjects,
            maxWorkspacesPerProject: self.maxWorkspacesPerProject
        )
        let initial = normalized ?? ProjectCatalog.defaultCatalog(now: now())
        self.catalog = initial
        self.seedCatalog = initial
        if repository == nil {
            loadState = .ready
            persistenceState = .saved
        }
    }

    // MARK: Internal

    private(set) var loadState: ProjectCatalogLoadState = .idle
    private(set) var persistenceState: ProjectCatalogPersistenceState = .idle

    let maxProjects: Int
    let maxWorkspacesPerProject: Int

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

    var isMutable: Bool {
        guard loadState == .ready, preparedTransitionID == nil else {
            return false
        }
        if case .failed = persistenceState {
            return false
        }
        return true
    }

    var canCreateProject: Bool {
        isMutable && catalog.projects.count < maxProjects
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
            catalog = try loaded.normalizedValidated(
                maxProjects: maxProjects,
                maxWorkspacesPerProject: maxWorkspacesPerProject
            )
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
        guard let validated = try? validatedForPolicy(resetCatalog) else {
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
        candidate = try validatedForPolicy(candidate)
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
            candidate = try validatedForPolicy(candidate)
        } catch let error as ProjectCatalogValidationError {
            throw ProjectMutationError.invalidWorkspaceSnapshot(error)
        }
        guard let destination = candidate.projects.first(where: { $0.id == destinationID }) else {
            throw ProjectMutationError.projectNotFound
        }

        let prepared = PreparedProjectCatalogTransition(
            id: UUID(),
            destinationProject: destination,
            deletedProjectID: deletedProjectID,
            candidate: candidate,
            expectedRevision: expectedRevision
        )
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
        guard workspaces.count <= maxWorkspacesPerProject else {
            throw ProjectMutationError.workspaceCapacityReached(limit: maxWorkspacesPerProject)
        }
        guard let projectIndex = catalog.projects.firstIndex(where: { $0.id == catalog.activeProjectID }) else {
            throw ProjectMutationError.projectNotFound
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

    private static func errorDescription(_ error: Error) -> String {
        if let error = error as? LocalizedError, let description = error.errorDescription {
            return description
        }
        return String(describing: error)
    }

    private func requireMutable() throws {
        guard isMutable else {
            throw ProjectMutationError.storeNotReady
        }
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
        guard project.workspaces.count <= maxWorkspacesPerProject else {
            throw ProjectMutationError.workspaceCapacityReached(limit: maxWorkspacesPerProject)
        }

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

    private func validatedForPolicy(_ candidate: ProjectCatalog) throws -> ProjectCatalog {
        try candidate.normalizedValidated(
            maxProjects: maxProjects,
            maxWorkspacesPerProject: maxWorkspacesPerProject
        )
    }

    private func commitMutation(_ mutation: (inout ProjectCatalog) -> Void) throws {
        let expectedRevision = catalog.revision
        var candidate = catalog
        mutation(&candidate)
        candidate.revision = try nextRevision(after: expectedRevision)
        candidate = try validatedForPolicy(candidate)
        catalog = candidate
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
