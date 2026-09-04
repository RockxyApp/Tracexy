import Foundation

// MARK: - ProjectLimits

nonisolated enum ProjectLimits {
    static let minimumProjects = 1
    static let maximumProjects = 128
    static let minimumWorkspaces = 1
    static let maximumWorkspacesPerProject = 32
    static let maximumNameLength = 80
    static let maximumStringLength = 512
    static let maximumFilterRules = 64
    static let maximumCatalogBytes = 2 * 1_024 * 1_024
    static let maximumPortableProjectBytes = 1 * 1_024 * 1_024
}

// MARK: - ProjectNameNormalizationError

nonisolated enum ProjectNameNormalizationError: Error, Equatable, Sendable {
    case empty
    case tooLong(limit: Int)
    case containsControlCharacter
}

// MARK: - ProjectNameNormalization

nonisolated enum ProjectNameNormalization {
    nonisolated static func normalize(_ value: String) throws -> String {
        let normalized = value
            .precomposedStringWithCanonicalMapping
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else {
            throw ProjectNameNormalizationError.empty
        }
        guard normalized.count <= ProjectLimits.maximumNameLength else {
            throw ProjectNameNormalizationError.tooLong(limit: ProjectLimits.maximumNameLength)
        }
        guard !normalized.unicodeScalars.contains(where: { scalar in
            if scalar.value == 0x200C || scalar.value == 0x200D {
                return false
            }
            switch scalar.properties.generalCategory {
            case .control,
                 .format,
                 .lineSeparator,
                 .paragraphSeparator:
                return true
            default:
                return false
            }
        }) else {
            throw ProjectNameNormalizationError.containsControlCharacter
        }
        return normalized
    }

    nonisolated static func uniquenessKey(_ normalizedName: String) -> String {
        normalizedName
            .precomposedStringWithCanonicalMapping
            .folding(
                options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive],
                locale: Locale(identifier: "en_US_POSIX")
            )
            .precomposedStringWithCanonicalMapping
    }
}

// MARK: - ProjectFilterRuleSnapshot

nonisolated struct ProjectFilterRuleSnapshot: Codable, Hashable, Sendable, Identifiable {
    // MARK: Lifecycle

    init(
        id: UUID = UUID(),
        isEnabled: Bool = true,
        connector: String = "and",
        field: String = "host",
        filterOperator: String = "contains",
        value: String = ""
    ) {
        self.id = id
        self.isEnabled = isEnabled
        self.connector = connector
        self.field = field
        self.filterOperator = filterOperator
        self.value = value
    }

    // MARK: Internal

    var id: UUID
    var isEnabled: Bool
    var connector: String
    var field: String
    var filterOperator: String
    var value: String
}

// MARK: - ProjectWorkspaceSnapshot

/// Configuration-only workspace state owned by a project.
///
/// Raw enum discriminators intentionally keep the persisted v1 schema independent
/// of UI enum source changes. Hydration applies conservative fallbacks for unknown
/// values. Selection, investigation results, capture bytes, source paths, History,
/// and evidence locators are deliberately absent.
nonisolated struct ProjectWorkspaceSnapshot: Codable, Hashable, Sendable, Identifiable {
    // MARK: Lifecycle

    init(
        id: UUID = UUID(),
        title: String,
        isClosable: Bool = true,
        sidebarSelection: String = "sessions",
        navigatorMode: String = "browse",
        isLiveChartExpanded: Bool = true,
        inspectorTab: String = "timeline",
        inspectorLayout: String = "hidden",
        isContextDockVisible: Bool = false,
        contextDockTab: String = "details",
        allowsAutomaticInspectorReveal: Bool? = nil,
        sessionGrouping: String = "none",
        filterText: String = "",
        searchField: String = "allFields",
        isSearchEnabled: Bool = true,
        categoryFilters: [String] = [],
        hostFilter: String? = nil,
        processFilter: String? = nil,
        ipFilter: String? = nil,
        filterRules: [ProjectFilterRuleSnapshot] = [ProjectFilterRuleSnapshot()],
        isAdvancedFilterVisible: Bool = false,
        isFilterBarVisible: Bool = true,
        isFollowingLiveSessions: Bool = false
    ) {
        self.id = id
        self.title = title
        self.isClosable = isClosable
        self.sidebarSelection = sidebarSelection
        self.navigatorMode = navigatorMode
        self.isLiveChartExpanded = isLiveChartExpanded
        self.inspectorTab = inspectorTab
        self.inspectorLayout = inspectorLayout
        self.isContextDockVisible = isContextDockVisible
        self.contextDockTab = contextDockTab
        self.allowsAutomaticInspectorReveal = allowsAutomaticInspectorReveal
        self.sessionGrouping = sessionGrouping
        self.filterText = filterText
        self.searchField = searchField
        self.isSearchEnabled = isSearchEnabled
        self.categoryFilters = categoryFilters
        self.hostFilter = hostFilter
        self.processFilter = processFilter
        self.ipFilter = ipFilter
        self.filterRules = filterRules
        self.isAdvancedFilterVisible = isAdvancedFilterVisible
        self.isFilterBarVisible = isFilterBarVisible
        self.isFollowingLiveSessions = isFollowingLiveSessions
    }

    // MARK: Internal

    var id: UUID
    var title: String
    var isClosable: Bool
    var sidebarSelection: String
    var navigatorMode: String
    var isLiveChartExpanded: Bool
    var inspectorTab: String
    var inspectorLayout: String
    var isContextDockVisible: Bool
    var contextDockTab: String
    var allowsAutomaticInspectorReveal: Bool?
    var sessionGrouping: String
    var filterText: String
    var searchField: String
    var isSearchEnabled: Bool
    var categoryFilters: [String]
    var hostFilter: String?
    var processFilter: String?
    var ipFilter: String?
    var filterRules: [ProjectFilterRuleSnapshot]
    var isAdvancedFilterVisible: Bool
    var isFilterBarVisible: Bool
    var isFollowingLiveSessions: Bool
}

// MARK: - Project

nonisolated struct Project: Codable, Hashable, Sendable, Identifiable {
    // MARK: Lifecycle

    init(
        id: UUID = UUID(),
        name: String,
        workspaces: [ProjectWorkspaceSnapshot],
        activeWorkspaceID: UUID,
        createdAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.workspaces = workspaces
        self.activeWorkspaceID = activeWorkspaceID
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    // MARK: Internal

    var id: UUID
    var name: String
    var workspaces: [ProjectWorkspaceSnapshot]
    var activeWorkspaceID: UUID
    var createdAt: Date
    var updatedAt: Date
}

// MARK: - ProjectCatalog

nonisolated struct ProjectCatalog: Codable, Hashable, Sendable {
    // MARK: Lifecycle

    init(
        schemaVersion: Int = ProjectCatalog.currentSchemaVersion,
        revision: UInt64 = 0,
        projects: [Project],
        activeProjectID: UUID,
        legacyDataOwnerProjectID: UUID? = nil
    ) {
        self.schemaVersion = schemaVersion
        self.revision = revision
        self.projects = projects
        self.activeProjectID = activeProjectID
        self.legacyDataOwnerProjectID = legacyDataOwnerProjectID
    }

    // MARK: Internal

    static let currentSchemaVersion = 1

    /// Marks the pre-Projects History/Captures data as deliberately unowned.
    ///
    /// Catalog recovery uses it instead of handing existing data to a freshly
    /// minted Project: the files stay on disk untouched, and no new Project can
    /// silently inherit another user's capture history.
    static let retiredLegacyDataOwnerID = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    var schemaVersion: Int
    var revision: UInt64
    var projects: [Project]
    var activeProjectID: UUID

    /// The single Project that owns the pre-Projects `History/` database and
    /// `Captures/` folder. Absent in a v1 catalog written before Project
    /// isolation; assigned exactly once on first load and never reassigned.
    var legacyDataOwnerProjectID: UUID?

    static func defaultCatalog(now: Date = Date()) -> ProjectCatalog {
        let workspace = ProjectWorkspaceSnapshot(title: "Live", isClosable: false)
        let project = Project(
            name: "My Project",
            workspaces: [workspace],
            activeWorkspaceID: workspace.id,
            createdAt: now,
            updatedAt: now
        )
        return ProjectCatalog(projects: [project], activeProjectID: project.id)
    }
}

// MARK: - ProjectCatalogValidationError

nonisolated enum ProjectCatalogValidationError: Error, Equatable, Sendable {
    case unsupportedSchema(Int)
    case projectCountOutOfBounds(count: Int, limit: Int)
    case duplicateProjectID(UUID)
    case activeProjectMissing(UUID)
    case invalidProjectName(projectID: UUID, ProjectNameNormalizationError)
    case duplicateProjectName(String)
    case workspaceCountOutOfBounds(projectID: UUID, count: Int, limit: Int)
    case duplicateWorkspaceID(UUID)
    case activeWorkspaceMissing(projectID: UUID, workspaceID: UUID)
    case invalidWorkspaceName(workspaceID: UUID, ProjectNameNormalizationError)
    case duplicateWorkspaceName(projectID: UUID, name: String)
    case tooManyFilterRules(workspaceID: UUID, count: Int)
    case stringTooLong(field: String, limit: Int)
    case invalidDate(projectID: UUID)
}

extension ProjectCatalog {
    nonisolated func normalizedValidated(
        maxProjects: Int = ProjectLimits.maximumProjects,
        maxWorkspacesPerProject: Int = ProjectLimits.maximumWorkspacesPerProject
    )
        throws -> ProjectCatalog
    {
        guard schemaVersion == Self.currentSchemaVersion else {
            throw ProjectCatalogValidationError.unsupportedSchema(schemaVersion)
        }
        let projectLimit = min(max(1, maxProjects), ProjectLimits.maximumProjects)
        guard projects.count >= ProjectLimits.minimumProjects, projects.count <= projectLimit else {
            throw ProjectCatalogValidationError.projectCountOutOfBounds(
                count: projects.count,
                limit: projectLimit
            )
        }

        var result = self
        var projectIDs = Set<UUID>()
        var projectNames = Set<String>()
        var workspaceIDs = Set<UUID>()

        for projectIndex in result.projects.indices {
            var project = result.projects[projectIndex]
            guard projectIDs.insert(project.id).inserted else {
                throw ProjectCatalogValidationError.duplicateProjectID(project.id)
            }
            guard project.createdAt.timeIntervalSinceReferenceDate.isFinite,
                  project.updatedAt.timeIntervalSinceReferenceDate.isFinite else
            {
                throw ProjectCatalogValidationError.invalidDate(projectID: project.id)
            }
            do {
                project.name = try ProjectNameNormalization.normalize(project.name)
            } catch let error as ProjectNameNormalizationError {
                throw ProjectCatalogValidationError.invalidProjectName(projectID: project.id, error)
            }
            let projectKey = ProjectNameNormalization.uniquenessKey(project.name)
            guard projectNames.insert(projectKey).inserted else {
                throw ProjectCatalogValidationError.duplicateProjectName(project.name)
            }

            let workspaceLimit = min(max(1, maxWorkspacesPerProject), ProjectLimits.maximumWorkspacesPerProject)
            guard project.workspaces.count >= ProjectLimits.minimumWorkspaces,
                  project.workspaces.count <= workspaceLimit else
            {
                throw ProjectCatalogValidationError.workspaceCountOutOfBounds(
                    projectID: project.id,
                    count: project.workspaces.count,
                    limit: workspaceLimit
                )
            }

            var workspaceNames = Set<String>()
            for workspaceIndex in project.workspaces.indices {
                var workspace = project.workspaces[workspaceIndex]
                guard workspaceIDs.insert(workspace.id).inserted else {
                    throw ProjectCatalogValidationError.duplicateWorkspaceID(workspace.id)
                }
                do {
                    workspace.title = try ProjectNameNormalization.normalize(workspace.title)
                } catch let error as ProjectNameNormalizationError {
                    throw ProjectCatalogValidationError.invalidWorkspaceName(workspaceID: workspace.id, error)
                }
                let workspaceKey = ProjectNameNormalization.uniquenessKey(workspace.title)
                guard workspaceNames.insert(workspaceKey).inserted else {
                    throw ProjectCatalogValidationError.duplicateWorkspaceName(
                        projectID: project.id,
                        name: workspace.title
                    )
                }
                guard workspace.filterRules.count <= ProjectLimits.maximumFilterRules else {
                    throw ProjectCatalogValidationError.tooManyFilterRules(
                        workspaceID: workspace.id,
                        count: workspace.filterRules.count
                    )
                }
                try workspace.validateStrings()
                project.workspaces[workspaceIndex] = workspace
            }
            guard project.workspaces.contains(where: { $0.id == project.activeWorkspaceID }) else {
                throw ProjectCatalogValidationError.activeWorkspaceMissing(
                    projectID: project.id,
                    workspaceID: project.activeWorkspaceID
                )
            }
            result.projects[projectIndex] = project
        }
        guard result.projects.contains(where: { $0.id == result.activeProjectID }) else {
            throw ProjectCatalogValidationError.activeProjectMissing(result.activeProjectID)
        }
        return result
    }
}

private extension ProjectWorkspaceSnapshot {
    nonisolated func validateStrings() throws {
        let required: [(String, String)] = [
            ("sidebarSelection", sidebarSelection),
            ("navigatorMode", navigatorMode),
            ("inspectorTab", inspectorTab),
            ("inspectorLayout", inspectorLayout),
            ("contextDockTab", contextDockTab),
            ("sessionGrouping", sessionGrouping),
            ("filterText", filterText),
            ("searchField", searchField),
        ]
        for (field, value) in required {
            try Self.validate(value, field: field)
        }
        for value in categoryFilters {
            try Self.validate(value, field: "categoryFilters")
        }
        for (field, value) in [
            ("hostFilter", hostFilter),
            ("processFilter", processFilter),
            ("ipFilter", ipFilter),
        ] {
            if let value {
                try Self.validate(value, field: field)
            }
        }
        for rule in filterRules {
            try Self.validate(rule.connector, field: "filterRules.connector")
            try Self.validate(rule.field, field: "filterRules.field")
            try Self.validate(rule.filterOperator, field: "filterRules.operator")
            try Self.validate(rule.value, field: "filterRules.value")
        }
    }

    nonisolated static func validate(_ value: String, field: String) throws {
        guard value.count <= ProjectLimits.maximumStringLength else {
            throw ProjectCatalogValidationError.stringTooLong(
                field: field,
                limit: ProjectLimits.maximumStringLength
            )
        }
    }
}
