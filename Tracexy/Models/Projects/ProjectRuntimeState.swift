import Foundation

// MARK: - ProjectRuntimeState

/// Everything one Project owns at runtime, held while that Project is parked.
///
/// The coordinator keeps one bucket per Project (bounded by
/// ``ProjectStore/maxProjects``) and moves state between the bucket and its own
/// observable properties at a Project boundary. Nothing is evicted: a parked
/// Project keeps its real ``WorkspaceStore`` instance — with its selection,
/// investigation drafts, query results and layout — its own ``SessionStore``,
/// its own preferences suite, and its own ``LiveCaptureSpool`` actor, so another
/// Project starting or resetting a capture can never destroy its evidence.
///
/// Deliberately absent: raw Follow Stream bytes and the derived evidence/cited
/// frame pipelines. Those are selection-scoped raw payload and are retired at
/// every boundary; they are rebuilt from the immutable snapshot on restore.
@MainActor
final class ProjectRuntimeState {
    // MARK: Lifecycle

    init(
        projectID: UUID?,
        location: ProjectDataLocation?,
        settingsDefaults: UserDefaults,
        layoutPreferences: WorkspaceLayoutPreferences,
        workspaces: WorkspaceStore,
        sessionStore: SessionStore?,
        historyUnavailableReason: String? = nil,
        liveCaptureSpool: LiveCaptureSpool,
        capturesDirectory: URL?,
        captureInterface: String
    ) {
        self.projectID = projectID
        self.location = location
        self.settingsDefaults = settingsDefaults
        self.layoutPreferences = layoutPreferences
        self.workspaces = workspaces
        self.sessionStore = sessionStore
        self.historyUnavailableReason = historyUnavailableReason
        self.liveCaptureSpool = liveCaptureSpool
        self.capturesDirectory = capturesDirectory
        self.captureInterface = captureInterface
        retainedFrames = RetainedFrameBuffer(capacity: MainContentCoordinator.retainedFrameLimit)
        historyAvailability = sessionStore == nil ? .unavailable : .idle
    }

    // MARK: Internal

    // MARK: Identity and resources

    /// `nil` only for the pre-hydration runtime, which is bound to the hydrated
    /// active Project instead of a provisional random identity.
    var projectID: UUID?
    var location: ProjectDataLocation?
    let settingsDefaults: UserDefaults
    let layoutPreferences: WorkspaceLayoutPreferences
    let workspaces: WorkspaceStore
    let liveCaptureSpool: LiveCaptureSpool
    var sessionStore: SessionStore?
    var historyUnavailableReason: String?
    var capturesDirectory: URL?

    // MARK: Parked capture/session state

    var sessions: [SessionSummary] = []
    var investigationSnapshot: InvestigationSnapshot = .empty
    var retainedFrames: RetainedFrameBuffer
    var throughputSamples: [ThroughputSample] = []
    var pendingChartBytes = 0
    var captureInterface: String
    var captureError: String?
    var captureStatistics: CaptureStatistics?
    var helperBufferDropCount: UInt64 = 0
    var currentLinkType: UInt32 = LinkType.ethernet
    var removedSessionIDs: Set<UUID> = []

    /// True when this Project's stopped live spool had already completed its exact
    /// final ingest boundary. The generation token itself is never carried across a
    /// switch — it is rebased onto a fresh, globally monotonic token on restore —
    /// while the spool's own opaque locator identities are untouched.
    var isStoppedCaptureReady = false

    // MARK: Parked saved-capture state

    var savedCaptures: [SavedCapture] = []
    var isViewingSavedCapture = false
    var activeSavedCapture: SavedCapture?
    var savedCaptureActivity: CaptureActivity?
    var savedCaptureWarning: String?
    var savedCaptureEvidence: [UUID: CaptureEvidenceReference] = [:]
    var savedCaptureEvidenceURL: URL?
    var selectedSessionEvidenceID: UUID?
    var selectedSessionEvidenceBytes: [UInt8] = []
    var selectedSessionEvidenceError: String?

    // MARK: Parked preference-backed state

    var pinnedHosts: [String] = []
    var focusSets: [FocusSet] = []
    var mutedHosts: Set<String> = []
    var mutedProtocols: Set<ProtocolKind> = []
    var hiddenSourceApps: Set<String> = []
    var hiddenSourceDomains: Set<String> = []
    var hiddenSourceIPs: Set<String> = []

    // MARK: Parked History read/write state

    var historyAvailability: HistoryAvailability
    var historyCaptures: [HistoryStoredCapture] = []
    var historyCaptureCursor: HistoryCaptureCursor?
    var selectedHistoryCaptureID: UUID?
    var historySessions: [HistorySessionRecord] = []
    var historySessionCursor: HistorySessionCursor?
    var historySessionsAvailability: HistoryAvailability = .idle
    var historyAutoClear: AutoClear = .never
    var historyError: String?
    var historyRetentionError: String?
    var scheduledHistoryTerminals: Set<HistoryTerminalToken> = []

    /// Load the preference-backed collections from this Project's own suite.
    func loadPreferenceBackedState() {
        pinnedHosts = settingsDefaults.stringArray(forKey: ProjectScopedSettingsKeys.pinnedHosts) ?? []
        if let data = settingsDefaults.data(forKey: ProjectScopedSettingsKeys.focusSets),
           let sets = try? JSONDecoder().decode([FocusSet].self, from: data)
        {
            focusSets = sets
        } else {
            focusSets = []
        }
        mutedHosts = Set(settingsDefaults.stringArray(forKey: ProjectScopedSettingsKeys.mutedHosts) ?? [])
        mutedProtocols = Set(
            (settingsDefaults.stringArray(forKey: ProjectScopedSettingsKeys.mutedProtocols) ?? [])
                .compactMap(ProtocolKind.init(rawValue:))
        )
        hiddenSourceApps = SourceVisibilityPreferences.loadApps(defaults: settingsDefaults)
        hiddenSourceDomains = SourceVisibilityPreferences.loadDomains(defaults: settingsDefaults)
        hiddenSourceIPs = SourceVisibilityPreferences.loadIPs(defaults: settingsDefaults)
        historyAutoClear = HistoryRetentionSettingsResolver.autoClear(defaults: settingsDefaults)
    }
}

// MARK: - ProjectTransitionStatus

/// Coarse state of the one Project lifecycle path. `pending` blocks capture start
/// and further transitions; `failed` keeps the outgoing Project active and offers
/// a retry rather than guessing that the outgoing capture drained.
nonisolated enum ProjectTransitionStatus: Equatable, Sendable {
    case idle
    case pending
    case failed(String)

    // MARK: Internal

    var isPending: Bool {
        self == .pending
    }

    var failureMessage: String? {
        guard case let .failed(message) = self else {
            return nil
        }
        return message
    }
}

// MARK: - ProjectSwitchConfirmationRequest

/// A Project change the user must confirm because it will stop a running or
/// starting capture first. Cancelling leaves the outgoing Project untouched.
nonisolated struct ProjectSwitchConfirmationRequest: Identifiable, Equatable, Sendable {
    enum Kind: Equatable, Sendable {
        case switchProject(UUID)
        case createProject(String)
        case importProject(Project)
        case deleteProject(UUID)
    }

    let id: UUID
    let kind: Kind
    /// The Project the capture belongs to, for the confirmation copy.
    let outgoingProjectName: String
    let destinationDescription: String
}
