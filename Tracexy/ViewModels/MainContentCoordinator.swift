import Foundation
import Observation
import SwiftUI

// MARK: - MainContentCoordinator

@Observable
@MainActor
final class MainContentCoordinator {
    // MARK: Lifecycle

    /// `layoutPreferences` is optional rather than defaulted so the default is
    /// built *inside* the main-actor init. A default argument is evaluated in a
    /// nonisolated context, which makes constructing a main-actor-isolated value
    /// there a concurrency warning today and an error under Swift 6. `policy` uses
    /// the same optional-default pattern for that reason.
    /// `sessionStore` is optional and defaults to `nil` so unit tests run with no
    /// persistent database and never touch the production file. The app
    /// composition root injects one writable store (see ``HistoryStoreFactory``);
    /// a `nil` store simply leaves History unavailable and never affects capture.
    init(
        policy: (any AppPolicy)? = nil,
        layoutPreferences: WorkspaceLayoutPreferences? = nil,
        sessionStore: SessionStore? = nil,
        projectRepository: ProjectCatalogPersisting? = nil,
        isHistoryDemoMode: Bool = false,
        historyNow: @escaping @Sendable () -> Date = { Date() },
        liveCaptureSpool: LiveCaptureSpool? = nil
    ) {
        self.sessionStore = sessionStore
        self.isHistoryDemoMode = isHistoryDemoMode
        self.historyNow = historyNow
        self.liveCaptureSpool = liveCaptureSpool ?? LiveCaptureSpool(
            directoryName: TracexyIdentity.current.appSupportDirectoryName
        )
        let resolvedPolicy = policy ?? DefaultAppPolicy()
        self.policy = resolvedPolicy
        projectStore = ProjectStore(
            maxProjects: resolvedPolicy.maxProjects,
            maxWorkspacesPerProject: resolvedPolicy.maxWorkspaceTabs,
            repository: projectRepository
        )
        focusGate = FocusPolicyGate(
            maxFocusSets: resolvedPolicy.maxFocusSets,
            maxPinnedHosts: resolvedPolicy.maxPinnedHosts
        )
        let preferences = layoutPreferences ?? WorkspaceLayoutPreferences()
        self.layoutPreferences = preferences
        workspaces = WorkspaceStore(
            maxWorkspaces: resolvedPolicy.maxWorkspaceTabs,
            layoutPreferences: preferences
        )
        // Boot empty: nothing is shown until a real capture streams real frames.
        // Default to the *active* interface (up + has an IPv4), not the first
        // non-loopback one — virtual interfaces (awdl0/anpi0/bridge0) carry no
        // traffic, so capturing on them looks like "no data".
        let interfaces = NetworkInterfaces.available()
        let active = interfaces.first { !$0.isLoopback && $0.isUp && $0.ipv4 != nil }
        let anyReal = interfaces.first { !$0.isLoopback }
        // Honor the Capture → "Default interface" preference when it names a real,
        // currently-available interface; otherwise fall back to the active one.
        let preferred = UserDefaults.standard.string(forKey: SettingsKeys.defaultInterface)
        if let preferred, !preferred.isEmpty, interfaces.contains(where: { $0.id == preferred }) {
            captureInterface = preferred
        } else {
            captureInterface = active?.id ?? anyReal?.id ?? "en0"
        }
        localIPv4 = NetworkInterfaces.primaryIPv4()
        pinnedHosts = Self.loadPinnedHosts()
        // History is unavailable until a store is injected; otherwise it begins idle
        // and loads lazily on the first refresh.
        historyAvailability = sessionStore == nil ? .unavailable : .idle
        refreshSavedCaptures()
        // Before any destructive/privileged helper op (force reset), stop active
        // capture and invalidate polling so nothing keeps touching a helper that
        // is about to be torn down.
        helper.willBeginDestructiveReset = { [weak self] in
            self?.stopCapture()
        }
    }

    // MARK: Internal

    /// True when the app was launched in direct-capture dev mode — via the env
    /// var `TRACEXY_DIRECT_CAPTURE=1` or the launch argument `--direct-capture`
    /// (both set by `scripts/run.sh`). Bypasses the privileged helper and captures
    /// through libpcap directly, and suppresses the first-run helper-install sheet.
    static let forceDirectCapture: Bool =
        ProcessInfo.processInfo.environment["TRACEXY_DIRECT_CAPTURE"] == "1"
            || CommandLine.arguments.contains("--direct-capture")

    /// Most recent sessions considered for correlation. Keeps grouping cost
    /// bounded on a long-running capture.
    static let maxCorrelatedSessions = 5_000

    /// How many recent raw frames are retained for immediate UI inspection.
    ///
    /// This is a bound on *memory*, not on capture fidelity. Sessions accumulate
    /// incrementally in `LiveSessionEngine` and do not depend on this window, so
    /// evicting an old raw frame here never drops a session, truncates a saved
    /// capture, or forces a re-decode of history. Complete live capture bytes are
    /// written independently to ``LiveCaptureSpool``. Every memory-window eviction
    /// is counted in `retainedFrameEvictionCount`, and that count is a UI-side
    /// figure that must never be presented as kernel/interface loss.
    static let retainedFrameLimit = 8_000

    static let fileStampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH.mm.ss"
        return formatter
    }()

    /// The capacity limits this build runs under. Held so the views that need
    /// to *show* a limit can read it; nothing reads it to decide behaviour —
    /// that is the gates' job.
    let policy: any AppPolicy

    /// Capacity gate for focus sets and pinned hosts.
    let focusGate: FocusPolicyGate

    let workspaces: WorkspaceStore

    /// Local, configuration-only Project catalog. Projects own durable workspace
    /// view intent; capture bytes, current sessions, and terminal History remain
    /// app-wide and are never stored here.
    let projectStore: ProjectStore

    /// Project presentation and orchestration state. Stored on the app-level
    /// coordinator so toolbar, commands, and sheets share one source of truth.
    var projectNameEditorContext: ProjectNameEditorContext?
    var projectDeletionRequest: ProjectDeletionRequest?
    var isProjectManagerPresented = false
    var isProjectRecoveryPresented = false
    var lastProjectOperationError: ProjectMutationError?
    var projectTransferErrorMessage: String?

    /// Launch hydration and Observation-backed workspace autosave are coalesced
    /// here rather than being owned by a view lifecycle.
    var hasHydratedProjects = false
    var isApplyingProjectSnapshot = false
    var isObservingProjectWorkspaces = false
    var projectHydrationTask: Task<Void, Never>?
    var projectWorkspaceAutosaveTask: Task<Void, Never>?

    /// The most recent capacity limit the user ran into, in their words.
    /// Cleared when they acknowledge it or when the next successful action
    /// makes it stale.
    var policyNotice: String?

    /// Session id → the action it belongs to. Rebuilt only when the decoded set
    /// changes, never per row: correlation is O(capture) and the table asks for
    /// it once per visible row.
    private(set) var activityIndex: [UUID: Activity] = [:]

    /// Actions in the current capture, newest first.
    private(set) var activities: [Activity] = []

    /// Rolling real-time throughput samples (bytes/sec), for the live chart.
    var throughputSamples: [ThroughputSample] = []

    // MARK: Capture state

    /// True while a live libpcap capture is running.
    var isCapturing = false
    /// True between pressing Start and the capture actually coming up (the helper
    /// / libpcap confirms asynchronously) — drives the "Starting" status.
    var isStarting = false
    var captureInterface = "en0"
    var captureError: String?
    /// Prevents overlapping export panels while a selected session is being
    /// scoped and serialized away from the main actor.
    private(set) var isExportingSession = false

    /// When the current capture started (drives the status-bar timer).
    var captureStartedAt: Date?

    /// Kernel-side capture accounting for the running capture. `nil` before the
    /// first sample, or when the source cannot report it (savefiles, and any
    /// libpcap without `pcap_stats`). Everything derived from the capture is
    /// conditional on this, so the UI must show its absence rather than assume
    /// a clean capture.
    var captureStatistics: CaptureStatistics?

    /// Cumulative frames the *helper's* staging buffer evicted this capture
    /// because the app drained too slowly. Capture-source loss at the helper
    /// stage — reported separately from kernel/interface loss (`captureStatistics`)
    /// and from local retention eviction below, because they are different stages
    /// and conflating them would misstate where fidelity was lost.
    var helperBufferDropCount: UInt64 = 0

    /// This Mac's primary IPv4, discovered once at launch (no hardcoded IP).
    let localIPv4: String?

    /// Pinned favorite hosts. Persisted across launches via `UserDefaults`;
    /// loaded in `init` and written on every change (see `togglePinHost`).
    var pinnedHosts: [String] = []

    /// Saved capture files on disk (real `.pcap` files under Application Support).
    /// Refreshed from disk; written by `saveCurrentCapture`.
    var savedCaptures: [SavedCapture] = []

    /// True while the session list shows an opened saved capture rather than a
    /// live one (so the UI can label it and Start replaces it).
    var isViewingSavedCapture = false

    /// The saved file currently open in this workspace, or `nil` during a live
    /// capture or an idle session. Held so the Overview can label the file
    /// truthfully (name, format, size, provenance) instead of guessing. Cleared at
    /// every live/new/clear boundary so a stale file identity can never outlive the
    /// capture it described.
    var activeSavedCapture: SavedCapture?

    /// Bounded, deterministic frames-over-time aggregation for the open saved
    /// capture, computed once at open/import and cached here. `nil` for live and
    /// idle captures. Derived from real frame timestamps/lengths behind this seam,
    /// so the Overview chart draws from per-bucket totals and never re-scans frames
    /// or receives packet bytes.
    var savedCaptureActivity: CaptureActivity?

    /// Saved-file opening is an off-main, final-only transaction. The previous
    /// workspace remains intact while this is true; only monotonic byte progress
    /// crosses back to the UI before the immutable result is adopted.
    var isOpeningSavedCapture = false
    var savedCaptureOpenProgress: PcapStreamProgress?
    /// A successfully recovered truncated tail is usable, but must remain visibly
    /// distinct from a clean file.
    var savedCaptureWarning: String?

    /// At most one saved session's representative bytes are resident outside the
    /// bounded raw tail. They are loaded lazily from the selected file offset.
    var selectedSessionEvidenceBytes: [UInt8] = []
    var isLoadingSelectedSessionEvidence = false
    var selectedSessionEvidenceError: String?

    // Saved-open/evidence task state is kept here so the separate activation
    // extension can own the workflow without weakening the coordinator's actor
    // boundary. Request IDs retire every late progress/result callback.
    var savedCaptureOpenRequestID = 0
    var pendingSavedCaptureOpen: SavedCaptureOpenRequest?
    var savedCaptureBoundaryTask: Task<Void, Never>?
    var savedCaptureOpenTask: Task<Void, Never>?
    var savedCaptureEvidence: [UUID: CaptureEvidenceReference] = [:]
    var savedCaptureEvidenceURL: URL?
    var selectedSessionEvidenceID: UUID?
    var selectedSessionEvidenceRequestID = 0
    var selectedSessionEvidenceTask: Task<Void, Never>?

    // MARK: Evidence navigation (U2D1)

    // The selected session's presentation-neutral connection/TLS projection and the
    // one explicitly cited frame, each with its own request/task pipeline. Native
    // inspector surfaces consume these bounded values without rescanning the immutable
    // snapshot. Both are retired at every selection/capture/source boundary so stale
    // evidence can never outlive the selection or source it described.
    var evidenceProjection = EvidenceProjectionPipeline()
    var citedFrame = CitedFramePipeline()

    /// Explicit, selection-scoped Follow Stream state. Raw application bytes enter
    /// coordinator memory only after the user requests this operation and are
    /// retired at every selection/capture/source boundary.
    var followStreamResult: FollowStreamResult?
    var followStreamProgress: PcapStreamProgress?
    var followStreamError: String?
    var isLoadingFollowStream = false
    var followStreamRequestID = 0
    var followStreamTask: Task<Void, Never>?
    /// A stopped live spool is safe to copy only after its exact final ingest and
    /// publication boundary has completed for this generation.
    var stoppedCaptureReadyGeneration: Int?

    /// Link type of the current capture, needed for faithful decode and capture-file export.
    var currentLinkType: UInt32 = LinkType.ethernet

    /// Shared privileged-helper manager (install/version/update/uninstall).
    let helper = HelperClient.shared

    // MARK: Terminal history persistence

    /// The injected terminal-history store, or `nil` when no persistent database
    /// is composed (all unit tests, and any production launch where the factory
    /// could not open one). It is written to exactly once per terminated live or
    /// opened saved capture; it is never on the live 0.8-second publication path.
    let sessionStore: SessionStore?

    /// True only for the explicit synthetic History launch path. Production
    /// composition always leaves this false and never sees the demo fixture.
    let isHistoryDemoMode: Bool

    /// Guards the root launch task from reseeding if SwiftUI remounts the view.
    var hasPreparedHistoryDemo = false

    /// Injectable wall clock for History age policy. Production uses `Date()`;
    /// integration tests freeze it so cutoff behavior never depends on timing.
    let historyNow: @Sendable () -> Date

    /// The currently effective Auto-clear preference. The composition root sets
    /// it from persisted defaults at launch; Settings updates it synchronously
    /// before requesting another bounded retention pass.
    var historyAutoClear: AutoClear = .never

    /// A retention-specific recoverable failure. It is separate from general
    /// History read/write errors so Settings can explain the exact failed action.
    var historyRetentionError: String?

    /// Durable identity of the *running* live capture, minted once on confirmed
    /// backend start. It is never keyed on the capture generation (which repeats
    /// across launches). Cleared/retired at every clear/new/start boundary and
    /// frozen at stop.
    var liveHistoryLifetime: LiveHistoryLifetime?

    /// The frozen terminal inputs captured at stop *before* the UI timer is
    /// cleared, so the terminal hook never reads the already-cleared
    /// ``captureStartedAt``. Consumed by the exact stopped generation.
    var frozenHistoryLifetime: FrozenHistoryLifetime?

    /// Terminal generations (live) and saved-open request IDs whose History write
    /// has already been scheduled, so a duplicate/stale terminal callback cannot
    /// schedule a second write for the same capture.
    var scheduledHistoryTerminals: Set<HistoryTerminalToken> = []

    /// A recoverable, History-specific error from a failed projection/write or
    /// read. It is deliberately distinct from ``captureError``: a History failure
    /// never stops capture, replaces sessions, or claims success.
    var historyError: String?

    /// The bounded read model's coarse availability, distinguishable between
    /// unavailable (no store), idle, loading, loaded (possibly empty) and failed.
    var historyAvailability: HistoryAvailability = .unavailable

    /// The newest-first captures loaded so far, and the cursor to resume after
    /// them (`nil` when the last page was not full).
    var historyCaptures: [HistoryStoredCapture] = []
    var historyCaptureCursor: HistoryCaptureCursor?

    /// The currently selected History capture and its ordinal-ascending session
    /// page state.
    var selectedHistoryCaptureID: UUID?
    var historySessions: [HistorySessionRecord] = []
    var historySessionCursor: HistorySessionCursor?
    var historySessionsAvailability: HistoryAvailability = .idle

    /// Retires late History read callbacks. Every refresh/clear bumps this so a
    /// superseded capture page can never overwrite newer read-model state.
    var historyRequestID = 0
    var historyTask: Task<Void, Never>?
    /// Independent staleness guard/handle for the selected capture's session page,
    /// so selecting a capture never cancels capture-list paging and vice versa.
    var historySessionRequestID = 0
    var historySessionTask: Task<Void, Never>?
    /// Serialized tail for every History mutation: terminal writes, automatic
    /// retention and explicit clear. Keeping one queue prevents a late write from
    /// reviving rows after a clear or racing a preference-triggered cleanup.
    var historyMutationTask: Task<Void, Never>?
    /// Identifies the current mutation tail. Only the tail clears the handle and
    /// refreshes the read model after all earlier mutations have settled.
    var historyMutationRequestID = 0
    /// Invalidates a queued automatic retention pass when the user changes the
    /// preference again before that pass reaches the store actor.
    var historyRetentionRequestID = 0

    // MARK: Focus Sets

    /// Saved named filter collections (sidebar Focus mode). Persisted as JSON.
    private(set) var focusSets: [FocusSet] = MainContentCoordinator.loadFocusSets()

    /// The focus set currently open in the editor window (`nil` = window closed).
    var editingFocusSet: FocusSet?

    // MARK: Noise Control

    /// Hosts muted from the session list (sidebar Focus → Noise Control).
    private(set) var mutedHosts: Set<String> = MainContentCoordinator.loadMutedHosts()
    /// Protocols muted from the session list.
    private(set) var mutedProtocols: Set<ProtocolKind> = MainContentCoordinator.loadMutedProtocols()

    // MARK: Source visibility

    /// Source rows the user removed from the Browse sidebar. This is presentation
    /// state only: captured sessions and packet evidence remain untouched and can
    /// still be found from Sessions. Each category can restore its hidden rows.
    var hiddenSourceApps = SourceVisibilityPreferences.loadApps()
    var hiddenSourceDomains = SourceVisibilityPreferences.loadDomains()
    var hiddenSourceIPs = SourceVisibilityPreferences.loadIPs()

    /// Session rows removed from the current capture's presentation. This is
    /// deliberately capture-scoped and reversible: packet evidence and the
    /// save/export source stay intact, while every UI-derived surface reads
    /// ``presentedSessions`` so a removed sensitive row cannot reappear in an
    /// Overview rollup, Flow Map, Sources, finding, or related-session card.
    var removedSessionIDs: Set<UUID> = []

    /// Complete local raw-frame retention for save/export. The in-memory frame
    /// window remains bounded independently for responsive UI.
    let liveCaptureSpool: LiveCaptureSpool
    /// Serializes engine access so batches fold in arrival order even though each
    /// call hops onto the engine actor, and so a boundary reset is ordered ahead
    /// of the ingests that follow it.
    var ingestChain: Task<Void, Never>?
    /// Bounded FIFO window of raw frames kept for immediate UI state. Complete
    /// save/export reads the disk-backed spool instead.
    var retainedFrames = RetainedFrameBuffer(capacity: MainContentCoordinator.retainedFrameLimit)

    var pendingChartBytes = 0
    /// Bumped every time a start attempt begins or ends. A late helper reply or a
    /// start watchdog compares its captured token against this so a stale callback
    /// from an abandoned attempt can't revive `isCapturing`/`isStarting`.
    var startGeneration = 0

    /// The immutable passive connection-table snapshot for the current capture,
    /// published in lock-step with ``sessions`` behind the same generation guard.
    ///
    /// It is additive evidence adopted alongside the session summaries and reset
    /// to an empty snapshot at every capture boundary so stale connection state
    /// can never outlive the capture it described.
    private(set) var connectionSnapshot = ConnectionTable.Snapshot.empty

    /// The immutable passive connection *analysis* for the current capture,
    /// published in lock-step with ``connectionSnapshot`` and ``sessions`` behind
    /// the same generation guard, and only ever through ``adoptInvestigation``.
    ///
    /// This is the exact N3A2a assessment of ``connectionSnapshot`` — never
    /// re-derived on the main actor — adopted alongside the session summaries and
    /// reset to the empty analysis at every capture boundary so stale findings can
    /// never outlive the capture they described.
    private(set) var connectionAnalysisSnapshot = ConnectionAnalysisSnapshot.empty

    /// The immutable passive *datagram* analysis for the current capture, published
    /// in lock-step with ``connectionAnalysisSnapshot``, ``connectionSnapshot`` and
    /// ``sessions`` behind the same generation guard, and only ever through
    /// ``adoptInvestigation``.
    ///
    /// This is the exact N3B3a assessment of the same fold's datagram evidence —
    /// never re-derived on the main actor — adopted alongside the connection
    /// evidence/analysis and reset to the empty analysis at every capture boundary
    /// so stale findings can never outlive the capture they described.
    private(set) var datagramAnalysisSnapshot = DatagramAnalysisSnapshot.empty

    /// The complete immutable query input matching the currently published sessions
    /// and analyses. Live publication replaces its sessions only with the process-
    /// attributed copies shown by the UI; every evidence projection remains verbatim.
    private(set) var investigationSnapshot = InvestigationSnapshot.empty

    /// At most one off-main query evaluation per workspace. Superseding Apply/live
    /// refresh and capture boundaries cancel the prior task before issuing a new request.
    var investigationQueryTasks: [UUID: Task<Void, Never>] = [:]

    /// Cumulative frames evicted from the local in-memory inspection window. This
    /// is a UI memory bound, never kernel/interface loss; sessions and the complete
    /// disk-backed save/export spool are unaffected.
    var retainedFrameEvictionCount: UInt64 {
        retainedFrames.evictionCount
    }

    /// Raw frames currently held for immediate UI inspection. Distinct from the session count:
    /// this is only the recent tail kept in memory, bounded by
    /// ``retainedFrameLimit``. Surfaced as retention state, never as capture loss.
    var retainedFrameCount: Int {
        retainedFrames.count
    }

    /// The retention window's capacity — the denominator in the Overview's
    /// "N / capacity frames" retention readout. Reads the live buffer so it
    /// reflects the configured "Retain up to" size a running capture adopted.
    var retainedFrameCapacity: Int {
        retainedFrames.capacity
    }

    /// Sum of the captured lengths in the in-memory window. Used only as a bounded
    /// live-buffer estimate; it is neither
    /// capture fidelity nor total captured traffic.
    var retainedCapturedByteCount: Int {
        retainedFrames.capturedByteCount
    }

    /// All sessions decoded from the current capture's real frames.
    var sessions: [SessionSummary] = [] {
        didSet { rebuildActivities() }
    }

    var activeWorkspace: WorkspaceState {
        workspaces.activeWorkspace
    }

    /// Sessions visible in the active workspace, after sidebar + pill + text filtering.
    var visibleSessions: [SessionSummary] {
        visibleSessions(in: activeWorkspace)
    }

    var selectedSession: SessionSummary? {
        guard let id = activeWorkspace.selectedSessionID else {
            return nil
        }
        return presentedSessions.first { $0.id == id }
    }

    // MARK: Dashboard rollups

    var errorCount: Int {
        presentedSessions.filter { $0.status == .error }.count
    }

    var warningCount: Int {
        presentedSessions.filter { $0.status == .warning }.count
    }

    /// Severity-ranked UI projections of the accepted Core analysis snapshots.
    /// This layer adds fixed copy and session navigation only; it never re-derives
    /// policy from session status, protocol presence, DNS answers or latency.
    var findings: [Finding] {
        let presented = presentedSessions
        let presentedIDs = Set(presented.map(\.id))
        let hostBySessionID = Dictionary(uniqueKeysWithValues: presented.map { ($0.id, $0.host) })
        var result: [Finding] = []
        for finding in connectionAnalysisSnapshot.findings {
            let sessionID = SessionBuilder.sessionID(for: finding.tuple)
            guard presentedIDs.contains(sessionID), let host = hostBySessionID[sessionID] else {
                continue
            }
            result.append(Finding(finding, host: host))
        }
        for finding in datagramAnalysisSnapshot.findings {
            guard presentedIDs.contains(finding.sessionID), let host = hostBySessionID[finding.sessionID] else {
                continue
            }
            result.append(Finding(finding, host: host))
        }
        // Stable sort: worst severity first, insertion order preserved within a rank.
        return result.enumerated()
            .sorted { lhs, rhs in
                lhs.element.severity.rawValue == rhs.element.severity.rawValue
                    ? lhs.offset < rhs.offset
                    : lhs.element.severity.rawValue < rhs.element.severity.rawValue
            }
            .map(\.element)
    }

    /// Exact session membership of the current typed findings. Quick filtering
    /// consumes this set instead of duplicating analysis rules over summaries.
    var findingSessionIDs: Set<UUID> {
        Set(findings.map(\.sessionID))
    }

    /// Unique processes with session counts, for the sidebar "All" group.
    var processes: [(name: String, count: Int)] {
        groupCounts { $0.processName ?? "—" }
    }

    /// Unique hosts with session counts.
    var hosts: [(name: String, count: Int)] {
        groupCounts(\.host)
    }

    /// Domains grouped by name, each carrying the set of server IPs it resolved
    /// to (the "sub-IPs"), for the sidebar "Domains" tree — sibling-app-style.
    var domainGroups: [DomainGroup] {
        var byDomain: [String: (ips: Set<String>, count: Int)] = [:]
        for session in presentedSessions where Self.isDomainName(session.host) {
            var entry = byDomain[session.host] ?? (ips: [], count: 0)
            entry.count += 1
            for answer in session.dnsAnswers where !answer.hasPrefix("CNAME") {
                entry.ips.insert(answer)
            }
            if let ip = Self.ipPart(session.destinationEndpoint) {
                entry.ips.insert(ip)
            }
            byDomain[session.host] = entry
        }
        return byDomain
            .map { DomainGroup(domain: $0.key, ips: $0.value.ips.sorted(), count: $0.value.count) }
            .sorted { $0.count > $1.count }
    }

    /// Bare-IP hosts (no domain name resolved) with session counts.
    var ipHosts: [(name: String, count: Int)] {
        groupCounts { $0.host }.filter { !Self.isDomainName($0.name) }
    }

    /// Apps that originated traffic, each carrying the hosts/IPs it contacted
    /// (the "sub-links"), for an expandable sidebar "Apps" tree — sibling-app-style.
    var appGroups: [AppGroup] {
        var byApp: [String: (hosts: Set<String>, count: Int)] = [:]
        for session in presentedSessions {
            let app = session.processName ?? "—"
            var entry = byApp[app] ?? (hosts: [], count: 0)
            entry.count += 1
            entry.hosts.insert(session.host)
            byApp[app] = entry
        }
        return byApp
            .map { AppGroup(app: $0.key, hosts: $0.value.hosts.sorted(), count: $0.value.count) }
            .sorted { $0.count > $1.count }
    }

    /// Coarse capture state for the toolbar status capsule.
    var captureDisplayState: CaptureDisplayState {
        if captureError != nil {
            return .error
        }
        if isCapturing {
            return .capturing
        }
        if isStarting {
            return .starting
        }
        return .stopped
    }

    var captureStatusLine: String {
        if let captureError {
            return "capture error — \(captureError)"
        }
        if isCapturing {
            return "\(captureInterface) · live · \(presentedSessions.count.formatted()) sessions"
        }
        if sessions.isEmpty {
            return "idle — press Start to capture"
        }
        return "\(presentedSessions.count.formatted()) sessions"
    }

    /// The immutable settings the running/starting capture actually adopted, or
    /// the freshly resolved next-start settings while stopped. The readiness
    /// popover uses this seam so changing Settings mid-capture never rewrites the
    /// truth about the active source.
    var readinessCaptureConfiguration: CaptureConfiguration {
        activeCaptureConfiguration
            ?? CaptureSettingsResolver.configuration(interface: captureInterface)
    }

    var readinessRetentionCapacity: Int {
        if isCapturing || isStarting {
            return retainedFrames.capacity
        }
        return CaptureSettingsResolver.retainCapacity()
    }

    // MARK: Aggregate rollups (status bar)

    var totalBytes: Int {
        presentedSessions.reduce(0) { $0 + $1.totalBytes }
    }

    var totalBytesUp: Int {
        presentedSessions.reduce(0) { $0 + $1.bytesUp }
    }

    var totalBytesDown: Int {
        presentedSessions.reduce(0) { $0 + $1.bytesDown }
    }

    // MARK: Saved captures

    /// Whether there is anything to save (frames retained from a live or open capture).
    var canSaveCapture: Bool {
        !retainedFrames.isEmpty
    }

    var isNoiseControlActive: Bool {
        !mutedHosts.isEmpty || !mutedProtocols.isEmpty
    }

    var noiseRuleCount: Int {
        mutedHosts.count + mutedProtocols.count
    }

    /// Distinct protocols present across the current capture, for the Noise sheet.
    var presentProtocols: [ProtocolKind] {
        var seen = Set<ProtocolKind>()
        var ordered: [ProtocolKind] = []
        for session in presentedSessions {
            let proto = session.primaryProtocol
            if seen.insert(proto).inserted {
                ordered.append(proto)
            }
        }
        return ordered.sorted { $0.label < $1.label }
    }

    // MARK: Panel layout

    // The evidence inspector and the Context Dock are independent panels on
    // different axes, so each has its own toggle and neither closes the other.

    var inspectorLayout: InspectorLayout {
        activeWorkspace.inspectorLayout
    }

    var isContextDockVisible: Bool {
        activeWorkspace.isContextDockVisible
    }

    /// Rows for the session list, honouring the workspace's grouping mode.
    ///
    /// Actions whose every session was filtered out disappear; an action with
    /// some sessions filtered still shows, carrying only the sessions that
    /// survived — the list must never imply a filter matched more than it did.
    var sessionRows: [SessionRow] {
        let visible = visibleSessions
        switch activeWorkspace.sessionGrouping {
        case .none:
            return visible.map(SessionRow.session)
        case .host:
            return observedGroups(visible, kind: .host) { $0.host }
        case .process:
            return observedGroups(visible, kind: .process) { $0.processName }
        case .action:
            break
        }
        let visibleIDs = Set(visible.map(\.id))
        var rows: [SessionRow] = []
        var emitted: Set<UUID> = []

        for session in visible {
            if emitted.contains(session.id) {
                continue
            }
            guard let activity = activityIndex[session.id] else {
                rows.append(.session(session))
                emitted.insert(session.id)
                continue
            }
            let survivors = activity.sessions.filter { visibleIDs.contains($0.id) }
            survivors.forEach { emitted.insert($0.id) }
            // A lone survivor is not an action any more — showing a disclosure
            // triangle over one child would overstate what is there.
            if survivors.count > 1 {
                rows.append(.action(Activity(
                    id: activity.id,
                    sessions: survivors,
                    evidence: activity.evidence,
                    competingNames: activity.competingNames
                )))
            } else if let only = survivors.first {
                rows.append(.session(only))
            }
        }
        return rows
    }

    /// Traffic grouped by the registry region administering the remote address.
    ///
    /// Regional, not geographic — see `EndpointRegion`. Sorted by volume so the
    /// map draws the heaviest routes last and they land on top.
    var regionTraffic: [(region: EndpointRegion, bytes: Int, sessions: Int)] {
        var totals: [EndpointRegion: (bytes: Int, sessions: Int)] = [:]
        for session in visibleSessions {
            let region = EndpointRegionResolver.region(forEndpoint: session.destinationEndpoint)
            let current = totals[region] ?? (0, 0)
            totals[region] = (current.bytes + session.totalBytes, current.sessions + 1)
        }
        return totals
            .map { (region: $0.key, bytes: $0.value.bytes, sessions: $0.value.sessions) }
            .sorted { $0.bytes < $1.bytes }
    }

    /// One row per remote address in view — the Flow surface's list side.
    var flowEndpoints: [FlowEndpoint] {
        FlowEndpoint.endpoints(from: visibleSessions)
    }

    /// Whether a *new* focus set still fits. Drives the editor's Save button so
    /// the cap is visible before the user commits to a name and rules.
    var canAddFocusSet: Bool {
        focusGate.canInsertFocusSet(into: focusSets)
    }

    /// `~/Library/Application Support/<bundle id>/Captures`, created on demand.
    static func capturesDirectory() -> URL? {
        guard let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        let directory = base
            .appendingPathComponent(TracexyIdentity.current.appBundleIdentifier, isDirectory: true)
            .appendingPathComponent("Captures", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    /// A host is a domain name (not a bare IPv4/IPv6 literal).
    static func isDomainName(_ host: String) -> Bool {
        if host.contains(":") {
            return false // IPv6 literal
        }
        let parts = host.split(separator: ".")
        if parts.count == 4, parts.allSatisfy({ UInt8($0) != nil }) {
            return false // IPv4 literal
        }
        return host.contains(".") && host.contains { $0.isLetter }
    }

    func setSessionExporting(_ isExporting: Bool) {
        isExportingSession = isExporting
    }

    // MARK: Correlation

    /// The action the given session belongs to, or `nil` when nothing could
    /// attribute it.
    ///
    /// Correlation is computed over a time-bounded slice around the session
    /// rather than the whole capture. Grouping every session on demand would be
    /// O(capture) on the main actor, and `CLAUDE.md` §7.7 keeps that work off the
    /// hot path; a causal window of tens of seconds cannot reach further than
    /// this slice anyway, so the narrower input costs no accuracy.
    func activity(containing session: SessionSummary) -> Activity? {
        let window = ActivityBuilder.dnsCausalWindow
        let slice = presentedSessions.filter {
            abs($0.startTime.timeIntervalSince(session.startTime)) <= window
        }
        guard slice.count > 1 else {
            return nil
        }
        return ActivityBuilder.build(from: slice)
            .activities
            .first { $0.sessions.contains { $0.id == session.id } }
    }

    func select(_ session: SessionSummary) {
        cancelFollowStream(clearResult: true)
        activeWorkspace.selectedSessionID = session.id
        loadSelectedSavedCaptureEvidence()
        evidenceNavigationDidChangeSelection()
        revealPanelsForSelection()
    }

    /// Saved-opening activation is split into its own file, while the engine
    /// reset implementation remains private to this file's live pipeline.
    func resetSessionEngineForSavedCapture(token: Int) {
        resetSessionEngine(token: token)
    }

    /// The only cross-file mutation seam for published investigation state. It adopts
    /// the complete immutable snapshot, projects the existing analysis properties and
    /// refreshes only accepted capture-local queries, so sessions/evidence/results can
    /// never drift across a publication boundary.
    ///
    /// Both analyses are passed in pre-assessed (off the main actor, from a saved
    /// load result or a live ``InvestigationSnapshot``); this seam never runs an
    /// assessor itself.
    func adoptInvestigation(_ snapshot: InvestigationSnapshot) {
        investigationSnapshot = snapshot
        connectionSnapshot = snapshot.connections
        connectionAnalysisSnapshot = snapshot.connectionAnalysis
        datagramAnalysisSnapshot = snapshot.datagramAnalysis
        refreshActiveInvestigationQueries()
        refreshSelectedSessionEvidenceProjection()
    }

    // MARK: Search

    /// ⌘F: bring the user to the session search box and put the cursor in it.
    ///
    /// Routes to the Sessions surface if they are elsewhere, reveals the filter
    /// bar, and switches the search on — the three states the box needs to be
    /// usable — then bumps a focus token the existing field observes. It does
    /// *not* touch the query text or any active filter (host/process/IP drill-down,
    /// category chips, advanced rules), so an in-progress investigation is
    /// preserved; ⌘F only reveals and focuses the box that is already there.
    func beginSessionSearch() {
        let ws = activeWorkspace
        ws.sidebarSelection = .sessions
        ws.isFilterBarVisible = true
        ws.isSearchEnabled = true
        ws.searchFocusRequest = UUID()
    }

    // MARK: Sidebar selection

    /// Selects a top-level sidebar item, clearing any host/process/IP drill-down.
    func selectSidebarItem(_ item: SidebarItem) {
        let ws = activeWorkspace
        ws.sidebarSelection = item
        ws.hostFilter = nil
        ws.processFilter = nil
        ws.ipFilter = nil
    }

    /// Drills into a single host/domain (from the sidebar "Domains"/"Pinned" groups).
    func selectHost(_ host: String) {
        let ws = activeWorkspace
        ws.sidebarSelection = .sessions
        ws.processFilter = nil
        ws.ipFilter = nil
        ws.hostFilter = host
    }

    /// Drills into a single process (from the sidebar "Apps" group).
    func selectProcess(_ process: String) {
        let ws = activeWorkspace
        ws.sidebarSelection = .sessions
        ws.hostFilter = nil
        ws.ipFilter = nil
        ws.processFilter = process
    }

    /// Drills into a single IP address (a sub-IP under a domain).
    func selectIP(_ ip: String) {
        let ws = activeWorkspace
        ws.sidebarSelection = .sessions
        ws.hostFilter = nil
        ws.processFilter = nil
        ws.ipFilter = ip
    }

    // MARK: Pinned hosts (Favorites)

    func isHostPinned(_ host: String) -> Bool {
        pinnedHosts.contains(host)
    }

    /// Pins or unpins a host and persists the new set immediately.
    func togglePinHost(_ host: String) {
        guard !host.isEmpty, host != "—" else {
            return
        }
        if let index = pinnedHosts.firstIndex(of: host) {
            pinnedHosts.remove(at: index)
        } else {
            do {
                try focusGate.validatePinningHost(host, into: pinnedHosts)
            } catch {
                policyNotice = error.localizedDescription
                return
            }
            pinnedHosts.append(host)
        }
        policyNotice = nil
        UserDefaults.standard.set(pinnedHosts, forKey: Self.pinnedHostsKey)
    }

    /// Bottom evidence inspector. Hiding it by hand also cancels the automatic
    /// reveal — a panel the user dismissed must not reappear on the next
    /// selection.
    func toggleInspectorBottom() {
        let ws = activeWorkspace
        let willHide = ws.inspectorLayout == .bottom
        withAnimation(.smooth(duration: 0.18)) {
            ws.inspectorLayout = willHide ? .hidden : .bottom
        }
        layoutPreferences.rememberInspectorLayout(ws.inspectorLayout)
        // Opening it by hand is the user asking for it back, so it cancels an
        // earlier dismissal. Without this the two rules fight: panels start
        // closed at launch, and a user who had once dismissed the inspector
        // could never get it to come back on its own again — they would be
        // re-opening it manually every single launch.
        ws.allowsAutomaticInspectorReveal = !willHide
        layoutPreferences.rememberAutomaticInspectorReveal(!willHide)
    }

    /// Right-hand interpretation column. Never auto-revealed: it earns its space
    /// only once the user asks for it.
    func toggleContextDock() {
        let ws = activeWorkspace
        withAnimation(.smooth(duration: 0.18)) {
            ws.isContextDockVisible.toggle()
        }
        layoutPreferences.rememberContextDockVisible(ws.isContextDockVisible)
    }

    /// Bring back the panels the user works with, once there is something for
    /// them to describe.
    ///
    /// This is the other half of starting with both closed. The panels are not
    /// *suppressed* at launch, only deferred to the first selection — which is
    /// the earliest moment either of them has anything true to say. Each side
    /// still respects its own rule:
    ///
    /// - the evidence inspector opens unless the user has dismissed it by hand;
    /// - the Context Dock opens only if the user had it open before, because it
    ///   is never revealed on its own initiative.
    ///
    /// Both are guarded on the panel currently being hidden, so nothing fights
    /// the user if they close one mid-session.
    func revealPanelsForSelection() {
        let ws = activeWorkspace
        if ws.allowsAutomaticInspectorReveal != false, ws.inspectorLayout == .hidden {
            withAnimation(.smooth(duration: 0.18)) {
                ws.inspectorLayout = .bottom
            }
        }
        if layoutPreferences.preferredContextDockVisible == true, !ws.isContextDockVisible {
            withAnimation(.smooth(duration: 0.18)) {
                ws.isContextDockVisible = true
            }
        }
    }

    /// Clears all captured sessions (status-bar "Clear").
    func clearSessions() {
        cancelFollowStream(clearResult: true)
        cancelSavedCaptureOpen(clearPublishedEvidence: true)
        // Supersede any in-flight engine work so a late snapshot can't repopulate
        // the list after a clear, and zero the accounting counters.
        startGeneration &+= 1
        resetSessionEngine(token: startGeneration)
        captureStatistics = nil
        helperBufferDropCount = 0
        retainedFrames.reset()
        removedSessionIDs.removeAll()
        sessions = []
        // Clear connection + analysis publication at the boundary so a late
        // generation can never revive any of them alongside the cleared sessions.
        clearAllInvestigationQueries()
        adoptInvestigation(.empty)
        throughputSamples = []
        pendingChartBytes = 0
        isViewingSavedCapture = false
        activeSavedCapture = nil
        savedCaptureActivity = nil
        savedCaptureWarning = nil
        stoppedCaptureReadyGeneration = nil
        // Clearing discards the pre-clear lifetime but does not stop an active
        // backend. Start a fresh lifetime for the post-clear engine generation so
        // its eventual terminal snapshot can still enter History.
        retireLiveHistoryLifetime()
        if isCapturing {
            beginLiveHistoryLifetime(captureGeneration: startGeneration)
        }
        for workspace in workspaces.workspaces {
            workspace.selectedSessionID = nil
        }
    }

    /// Inserts or updates a focus set (used by the editor sheet), then persists.
    /// A save that would exceed the focus-set cap leaves the stored sets
    /// untouched and reports why through ``policyNotice``.
    func saveFocusSet(_ set: FocusSet) {
        var normalizedSet = set
        normalizedSet.rules = SessionFilterRule.normalized(
            set.rules,
            limit: policy.maxSessionFilterRules
        )
        do {
            try focusGate.validateSavingFocusSet(normalizedSet, into: focusSets)
        } catch {
            policyNotice = error.localizedDescription
            return
        }
        if let index = focusSets.firstIndex(where: { $0.id == normalizedSet.id }) {
            focusSets[index] = normalizedSet
        } else {
            focusSets.append(normalizedSet)
        }
        policyNotice = nil
        persistFocusSets()
    }

    /// Loads a focus set's rules into the active workspace's advanced filter.
    func applyFocusSet(_ set: FocusSet) {
        let ws = activeWorkspace
        ws.sidebarSelection = .sessions
        ws.hostFilter = nil
        ws.processFilter = nil
        ws.ipFilter = nil
        // A saved set may hold more rows than this build allows (it was saved on
        // a different build, or the cap changed). Clamp to capacity, and never
        // leave the builder with zero rows.
        ws.filterRules = SessionFilterRule.normalized(set.rules, limit: policy.maxSessionFilterRules)
        ws.isFilterBarVisible = true
        ws.isAdvancedFilterVisible = true
    }

    func deleteFocusSet(_ set: FocusSet) {
        focusSets.removeAll { $0.id == set.id }
        persistFocusSets()
    }

    /// A blank draft seeded from the active workspace's current active rules, so
    /// "Add" captures whatever the user is already filtering by.
    func draftFocusSet() -> FocusSet {
        let active = activeWorkspace.activeFilterRules
        return FocusSet(
            name: "",
            rules: active.isEmpty ? [SessionFilterRule()] : active
        )
    }

    func isHostMuted(_ host: String) -> Bool {
        mutedHosts.contains(host)
    }

    func isProtocolMuted(_ proto: ProtocolKind) -> Bool {
        mutedProtocols.contains(proto)
    }

    func toggleMuteHost(_ host: String) {
        if mutedHosts.contains(host) {
            mutedHosts.remove(host)
        } else {
            mutedHosts.insert(host)
        }
        persistMutedNoise()
    }

    func toggleMuteProtocol(_ proto: ProtocolKind) {
        if mutedProtocols.contains(proto) {
            mutedProtocols.remove(proto)
        } else {
            mutedProtocols.insert(proto)
        }
        persistMutedNoise()
    }

    func clearNoiseControl() {
        mutedHosts = []
        mutedProtocols = []
        persistMutedNoise()
    }

    /// Toolbar Start/Stop. Starts a real libpcap capture (or surfaces why not).
    func toggleCapture() {
        if isCapturing {
            stopCapture()
        } else {
            startCapture()
        }
    }

    func startCapture() {
        // Serialize: ignore a second Start while an attempt is already in flight
        // so double-clicks can't overlap two capture backends.
        guard !isStarting else {
            return
        }
        cancelFollowStream(clearResult: true)
        cancelSavedCaptureOpen(clearPublishedEvidence: true)
        // Read the current Capture-Settings preferences fresh at each start and map
        // them to a validated, bounded configuration (interface, snap length,
        // promiscuous mode, optional BPF). An invalid custom filter — or any
        // out-of-bounds value — surfaces here, before any capture backend is asked
        // to start, rather than failing silently mid-capture.
        let resolvedConfiguration = CaptureSettingsResolver.configuration(interface: captureInterface)
        let configuration: CaptureConfiguration
        switch resolvedConfiguration.validated() {
        case let .success(valid):
            configuration = valid
        case let .failure(error):
            captureError = "Capture couldn’t start — \(error.message)"
            return
        }
        activeCaptureConfiguration = configuration
        captureError = nil
        isStarting = true
        startGeneration &+= 1
        isViewingSavedCapture = false
        activeSavedCapture = nil
        savedCaptureActivity = nil
        savedCaptureWarning = nil
        stoppedCaptureReadyGeneration = nil
        // New capture boundary: retire any stale live/frozen History identity so a
        // superseded lifetime can never be persisted against this generation.
        retireLiveHistoryLifetime()
        // Size the in-memory inspection window from the configured
        // "Retain up to" preference, resetting it to a clean, zeroed window. This
        // bounds memory only — sessions accumulate independently (see
        // ``retainedFrameLimit``).
        retainedFrames = RetainedFrameBuffer(capacity: CaptureSettingsResolver.retainCapacity())
        removedSessionIDs.removeAll()
        sessions = []
        // Clear stale connection + analysis publication at the start boundary
        // before any new capture work can publish over it.
        clearAllInvestigationQueries()
        adoptInvestigation(.empty)
        throughputSamples = []
        pendingChartBytes = 0
        lastSessionsUpdate = .distantPast
        // Capture boundary: clear engine state + all drop/eviction counters so a
        // new capture starts from a clean, zeroed accounting.
        resetSessionEngine(token: startGeneration)
        helperBufferDropCount = 0
        captureStatistics = nil
        // Surface the live session table so captured traffic is actually visible
        // (a non-session surface may be selected when capture starts).
        if [.overview, .saved].contains(activeWorkspace.sidebarSelection) {
            selectSidebarItem(.sessions)
        }
        // Explicit development fast path: bypass the signed helper and capture
        // straight through libpcap. `scripts/run.sh -d` opts into this mode; the
        // default script path remains production-shaped and exercises the helper.
        // Direct mode works whenever the user can access a free BPF device (for
        // example through ChmodBPF / access_bpf). No sudo or helper approval.
        if Self.forceDirectCapture {
            startDirect()
            return
        }
        // Prefer the signed privileged helper (no sudo). Unlike the old fast path,
        // this verifies signing + XPC reachability before starting: a broken or
        // wedged helper surfaces a clear error instead of spinning on "Starting"
        // or being silently masked by an unprivileged fallback.
        let token = startGeneration
        Task { @MainActor in
            let availability = await self.helper.prepareForCaptureViaHelper()
            // The user may have stopped or restarted since; honor only the live attempt.
            guard self.isStarting, self.startGeneration == token else {
                return
            }
            switch availability {
            case .ready:
                self.startViaHelper(token: token)
            case .requiresApproval:
                self.captureError = "Approve “\(TracexyIdentity.current.displayName)” in System Settings → " +
                    "Login Items, then press Start again."
                self.isCapturing = false
                self.isStarting = false
                self.startGeneration &+= 1
            case let .unavailable(detail):
                self.handleCaptureError("Capture helper unavailable — \(detail)")
            }
        }
    }

    func stopCapture() {
        pollTimer?.invalidate()
        pollTimer = nil
        // A fetch destructively drains the helper buffer. Let the one outstanding
        // request return and enqueue its frames before sending Stop; invalidating
        // it now would discard an already-drained batch in transit. The normal
        // reply path calls `performStopCapture()` immediately afterward.
        if !Self.forceDirectCapture, helperFetchInFlight {
            helperStopRequested = true
            isStarting = false
            return
        }
        performStopCapture()
    }

    // MARK: Private

    private static let pinnedHostsKey = TracexyIdentity.current.defaultsKey("pinnedHosts")

    // MARK: Focus / Noise persistence

    private static let focusSetsKey = TracexyIdentity.current.defaultsKey("focusSets")
    private static let mutedHostsKey = TracexyIdentity.current.defaultsKey("noise.mutedHosts")
    private static let mutedProtocolsKey = TracexyIdentity.current.defaultsKey("noise.mutedProtocols")

    /// Remembers the user's inspector-dock choice across launches.
    private let layoutPreferences: WorkspaceLayoutPreferences

    private let live = try? LiveCapture()
    /// Off-main incremental session engine: decodes and groups each captured frame
    /// exactly once, so the main actor never re-decodes retained history.
    private let sessionEngine = LiveSessionEngine()
    private var lastSessionsUpdate = Date.distantPast

    /// The validated configuration for the capture currently starting/running,
    /// built from the live Capture-Settings preferences at ``startCapture()`` and
    /// consumed by both the direct and helper backends so neither re-reads defaults.
    private var activeCaptureConfiguration: CaptureConfiguration?

    private var pollTimer: Timer?
    /// At most one helper frame-drain request may be outstanding. Without this
    /// guard, a wedged helper would accumulate a new XPC request every 350 ms.
    private var helperFetchInFlight = false
    /// Stop waits behind the single destructive helper drain already in flight,
    /// so frames removed from the helper buffer are never invalidated in transit.
    private var helperStopRequested = false
    /// Retires late frame replies and timeout watchdogs when capture stops or a
    /// newer drain request replaces them.
    private var helperFetchGeneration = 0

    private static func loadPinnedHosts() -> [String] {
        UserDefaults.standard.stringArray(forKey: pinnedHostsKey) ?? []
    }

    private static func loadFocusSets() -> [FocusSet] {
        guard let data = UserDefaults.standard.data(forKey: focusSetsKey),
              let sets = try? JSONDecoder().decode([FocusSet].self, from: data) else
        {
            return []
        }
        return sets
    }

    private static func loadMutedHosts() -> Set<String> {
        Set(UserDefaults.standard.stringArray(forKey: mutedHostsKey) ?? [])
    }

    private static func loadMutedProtocols() -> Set<ProtocolKind> {
        let raw = UserDefaults.standard.stringArray(forKey: mutedProtocolsKey) ?? []
        return Set(raw.compactMap(ProtocolKind.init(rawValue:)))
    }

    /// The IP portion of an "ip:port" endpoint (handles IPv6's inner colons).
    private static func ipPart(_ endpoint: String) -> String? {
        guard !endpoint.isEmpty, endpoint != "—" else {
            return nil
        }
        let comps = endpoint.split(separator: ":")
        guard comps.count >= 2 else {
            return endpoint
        }
        return comps.dropLast().joined(separator: ":")
    }

    private func performStopCapture() {
        helperStopRequested = false
        let captureToken = startGeneration
        // Invalidate any in-flight start attempt so its watchdog/reply is ignored.
        startGeneration &+= 1
        let stoppedToken = startGeneration
        helperFetchGeneration &+= 1
        helperFetchInFlight = false
        var awaitsHelperStopReply = false
        if !Self.forceDirectCapture, let proxy = try? helper.proxy() {
            awaitsHelperStopReply = true
            proxy.stopCapture { [weak self] batch in
                // The helper worker has now finished its read loop, sampled final
                // pcap_stats, flushed its last frames, and closed its own handle.
                // The same typed reply carries the bounded final tail atomically,
                // so a rapid next Start cannot make a separate fetch drain the
                // wrong capture generation.
                let frames = batch.frames.compactMap(CapturedFrame.init(message:))
                let rejectedFrameCount = batch.frames.count - frames.count
                let statistics = batch.stats.map(CaptureStatistics.init(helperStats:))
                Task { @MainActor in
                    guard let self,
                          self.startGeneration == stoppedToken,
                          !self.isCapturing else
                    {
                        return
                    }
                    guard rejectedFrameCount == 0 else {
                        let detail = "The capture helper returned \(rejectedFrameCount) frame(s) with invalid metadata."
                        self.helper.recordRuntimeConnectionFailure(detail)
                        self.captureError = detail
                        self.queuePendingSavedCaptureOpenAfterCurrentIngest()
                        return
                    }
                    self.helperBufferDropCount = batch.bufferDroppedCount
                    self.captureStatistics = statistics
                    self.ingestFinalHelperBatch(
                        frames,
                        linkType: batch.captureLinkType,
                        captureToken: captureToken,
                        stoppedToken: stoppedToken
                    )
                }
            }
            if let pendingRequest = pendingSavedCaptureOpen {
                Task { @MainActor [weak self] in
                    try? await Task.sleep(nanoseconds: 5_000_000_000)
                    guard let self,
                          self.pendingSavedCaptureOpen?.id == pendingRequest.id,
                          self.savedCaptureOpenRequestID == pendingRequest.id,
                          self.startGeneration == stoppedToken else
                    {
                        return
                    }
                    self.captureError = "Couldn’t open “\(pendingRequest.capture.name)” because the capture helper "
                        + "didn’t finish its final drain. Recover the helper in Settings, then try again."
                    self.cancelSavedCaptureOpen(clearPublishedEvidence: false)
                }
            }
        }
        // Freeze the durable History identity for this exact stopped generation
        // *before* clearing the UI timer below: the terminal hook must never read
        // the cleared `captureStartedAt`. A capture that never confirmed start has
        // no live lifetime, so nothing is frozen and no History is created.
        freezeLiveHistoryLifetime(captureGeneration: captureToken, stoppedGeneration: stoppedToken)
        live?.stop()
        isCapturing = false
        isStarting = false
        captureStartedAt = nil
        if !awaitsHelperStopReply {
            publishStoppedSnapshotAfterCurrentIngest(captureToken: captureToken, stoppedToken: stoppedToken)
        }
    }

    /// Groups sessions by an attribute read straight off them, in first-seen
    /// order so a live list doesn't reshuffle as traffic arrives.
    ///
    /// A session whose attribute is missing — an unnamed process on an imported
    /// file — stays a top-level row of its own rather than being swept into an
    /// "Unknown" bucket. An empty value is not a thing they have in common, and
    /// a bucket would claim it was.
    ///
    /// A lone member is emitted flat for the same reason the action path does it:
    /// a disclosure triangle over one child overstates what is there.
    private func observedGroups(
        _ sessions: [SessionSummary],
        kind: SessionGroup.Kind,
        key: (SessionSummary) -> String?
    )
        -> [SessionRow]
    {
        var order: [String] = []
        var buckets: [String: [SessionSummary]] = [:]
        var rows: [SessionRow] = []

        for session in sessions {
            guard let value = key(session), !value.isEmpty else {
                rows.append(.session(session))
                continue
            }
            if buckets[value] == nil {
                order.append(value)
            }
            buckets[value, default: []].append(session)
        }

        let grouped: [SessionRow] = order.compactMap { value in
            guard let members = buckets[value] else {
                return nil
            }
            if members.count == 1, let only = members.first {
                return .session(only)
            }
            return .group(SessionGroup(kind: kind, key: value, sessions: members))
        }
        return (grouped + rows).sorted { $0.startTime < $1.startTime }
    }

    private func rebuildActivities() {
        // Bounded on purpose. Correlation is a convenience over the recent past,
        // and a causal window of tens of seconds cannot reach the far end of a
        // long capture anyway — so paying O(capture) on every ingest to group
        // sessions nobody is looking at would be waste, not thoroughness.
        let slice = sessions.count > Self.maxCorrelatedSessions
            ? Array(sessions.suffix(Self.maxCorrelatedSessions))
            : sessions
        let result = ActivityBuilder.build(from: slice)
        activities = result.activities
        var index: [UUID: Activity] = [:]
        for activity in result.activities {
            for session in activity.sessions {
                index[session.id] = activity
            }
        }
        activityIndex = index
    }

    private func persistFocusSets() {
        guard let data = try? JSONEncoder().encode(focusSets) else {
            return
        }
        UserDefaults.standard.set(data, forKey: Self.focusSetsKey)
    }

    private func persistMutedNoise() {
        UserDefaults.standard.set(Array(mutedHosts), forKey: Self.mutedHostsKey)
        UserDefaults.standard.set(mutedProtocols.map(\.rawValue), forKey: Self.mutedProtocolsKey)
    }
}

// MARK: - Live capture pipeline

private extension MainContentCoordinator {
    func startViaHelper(token: Int) {
        guard let configuration = activeCaptureConfiguration else {
            handleCaptureError("Capture configuration was unavailable.")
            return
        }
        do {
            let proxy = try helper.proxy()
            proxy.startCapture(configuration: configuration) { [weak self] started, message in
                Task { @MainActor in
                    guard let self, self.startGeneration == token else {
                        return
                    }
                    if started {
                        self.isCapturing = true
                        self.isStarting = false
                        self.captureStartedAt = Date()
                        // Confirmed backend start: mint one durable History identity
                        // for this generation. A failed start never reaches here.
                        self.beginLiveHistoryLifetime(captureGeneration: token)
                        self.startPolling()
                    } else {
                        self.handleCaptureError("helper: \(message)")
                    }
                }
            }
            // Watchdog: even a signed, previously-reachable helper can wedge after
            // the probe. If no reply lands, don't leave the UI stuck on "Starting".
            Task { @MainActor in
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                guard self.isStarting, self.startGeneration == token else {
                    return
                }
                let detail = "The capture helper didn’t confirm the capture started."
                self.helper.recordRuntimeConnectionFailure(detail)
                self.handleCaptureError("\(detail) Recover it in Settings → Helper.")
            }
        } catch {
            let detail = "Couldn’t reach the capture helper: \(error.localizedDescription)"
            helper.recordRuntimeConnectionFailure(detail)
            handleCaptureError(detail)
        }
    }

    private func startPolling() {
        pollTimer?.invalidate()
        helperFetchGeneration &+= 1
        helperFetchInFlight = false
        helperStopRequested = false
        pollTimer = Timer.scheduledTimer(withTimeInterval: 0.35, repeats: true) { [weak self] _ in
            guard let coordinator = self else {
                return
            }
            Task { @MainActor in coordinator.pollHelper() }
        }
    }

    private func pollHelper() {
        guard isCapturing, !helperFetchInFlight else {
            return
        }
        guard let proxy = try? helper.proxy() else {
            failActiveHelperCapture("The capture helper connection could not be opened.")
            return
        }

        helperFetchInFlight = true
        helperFetchGeneration &+= 1
        let fetchToken = helperFetchGeneration
        let captureToken = startGeneration

        proxy.fetchFrames { [weak self] batch in
            // Each frame carries its own libpcap timestamp, captured length,
            // original on-wire length, and link type — no shared batch `Date`,
            // no length inferred from `bytes.count`. Malformed metadata fails the
            // active capture clearly rather than being silently omitted.
            let frames = batch.frames.compactMap(CapturedFrame.init(message:))
            let rejectedFrameCount = batch.frames.count - frames.count
            let bufferDrops = batch.bufferDroppedCount
            let statistics = batch.stats.map(CaptureStatistics.init(helperStats:))
            let batchLinkType = batch.captureLinkType
            Task { @MainActor in
                guard let self,
                      self.isCapturing,
                      self.startGeneration == captureToken,
                      self.helperFetchGeneration == fetchToken else
                {
                    return
                }
                self.helperFetchInFlight = false
                guard rejectedFrameCount == 0 else {
                    self.failActiveHelperCapture(
                        "The capture helper returned \(rejectedFrameCount) frame(s) with invalid metadata."
                    )
                    return
                }
                // Capture-source loss and kernel/interface accounting, surfaced
                // as their own figures (never folded into UI-retention eviction).
                self.helperBufferDropCount = bufferDrops
                // Always assign — including `nil`. When `pcap_stats` becomes
                // unavailable, clearing stale accounting keeps the UI honest
                // (unknown, not a lingering clean figure) rather than freezing
                // the last sample.
                self.captureStatistics = statistics
                self.ingest(frames, linkType: batchLinkType)
                if self.helperStopRequested {
                    self.performStopCapture()
                }
            }
        }

        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            guard self.isCapturing,
                  self.helperFetchInFlight,
                  self.startGeneration == captureToken,
                  self.helperFetchGeneration == fetchToken else
            {
                return
            }
            if self.helperStopRequested {
                // The outstanding drain did not reply within its normal bound.
                // Continue teardown instead of leaving Stop stuck indefinitely;
                // the helper's atomic stop reply still returns everything that
                // remains in its bounded buffer. The timed-out request may have
                // destructively drained frames before its reply was lost, though,
                // so surface that uncertainty instead of retaining a misleading
                // zero-loss state from the last pcap_stats sample.
                let detail = "Capture stopped, but one in-flight helper batch did not return; final completeness is unknown."
                self.captureError = detail
                self.helper.recordRuntimeConnectionFailure(detail)
                self.helperFetchInFlight = false
                self.performStopCapture()
                return
            }
            self.failActiveHelperCapture("The capture helper stopped responding while capture was active.")
        }
    }

    private func failActiveHelperCapture(_ detail: String) {
        // A failed drain/validation path must not leave the privileged helper
        // capturing unattended after the app has moved to an error state.
        if let proxy = try? helper.proxy() {
            proxy.stopCapture { _ in }
        }
        helperFetchGeneration &+= 1
        helperFetchInFlight = false
        helperStopRequested = false
        helper.recordRuntimeConnectionFailure(detail)
        handleCaptureError("\(detail) Recover it in Settings → Helper.")
    }

    private func startDirect() {
        guard let live else {
            captureError = "libpcap unavailable"
            isStarting = false
            return
        }
        guard let configuration = activeCaptureConfiguration else {
            handleCaptureError("Capture configuration was unavailable.")
            return
        }
        // Open + compile the filter synchronously so a bad snap length or BPF fails
        // before the capture is reported started, rather than after.
        do {
            try live.start(
                configuration: configuration,
                onBatch: { [weak self] frames, linkType in
                    guard let coordinator = self else {
                        return
                    }
                    Task { @MainActor in coordinator.ingest(frames, linkType: linkType) }
                },
                onStatistics: { [weak self] sample in
                    guard let coordinator = self else {
                        return
                    }
                    Task { @MainActor in coordinator.captureStatistics = sample }
                }
            )
        } catch {
            handleCaptureError((error as? LiveCapture.Failure)?.message ?? error.localizedDescription)
            return
        }
        isCapturing = true
        isStarting = false
        captureStartedAt = Date()
        captureStatistics = nil
        // Confirmed direct backend start: mint one durable History identity.
        beginLiveHistoryLifetime(captureGeneration: startGeneration)
    }

    private func ingest(_ frames: [CapturedFrame], linkType: UInt32) {
        currentLinkType = linkType
        appendRetainedFrames(frames)
        pendingChartBytes += frames.reduce(0) { $0 + $1.originalLength }

        // Coalesce UI refreshes to ~1.2×/sec, but decode/group *every* batch off
        // the main actor so each frame is folded exactly once.
        let now = Date()
        let shouldSnapshot = now.timeIntervalSince(lastSessionsUpdate) > 0.8
        if shouldSnapshot {
            // Append a real-time throughput sample (bytes/sec over the interval).
            let interval = min(max(now.timeIntervalSince(lastSessionsUpdate), 0.1), 5)
            throughputSamples.append(ThroughputSample(bytesPerSecond: Double(pendingChartBytes) / interval))
            if throughputSamples.count > 60 {
                throughputSamples.removeFirst(throughputSamples.count - 60)
            }
            pendingChartBytes = 0
            lastSessionsUpdate = now
        }

        // Snapshot capture-loss knowledge on the main actor before enqueueing, so
        // the value folded into the connection provenance reflects the accounting
        // observed for this batch (never a later one, never UI-retention eviction).
        let loss = currentCaptureLoss

        // Hand decode/group to the engine actor (off-main), chained so batches
        // fold in arrival order. Snapshots are guarded by the capture generation
        // so a late result from a superseded capture can never overwrite newer
        // UI state.
        let token = startGeneration
        let previous = ingestChain
        ingestChain = Task { @MainActor in
            await previous?.value
            // Append to the spool before engine ingest. Only a successful current
            // append yields locators; a stale result or a failure offers the frames
            // to the engine with nil locators so evidence failure never silently
            // deletes session/connection observations.
            var locators: [SessionEvidenceLocator]?
            do {
                if case let .appended(appended) = try await self.liveCaptureSpool.append(
                    frames, defaultLinkType: linkType, epoch: token
                ) {
                    locators = appended
                }
            } catch {
                self.captureError = "Capture stopped: the local spool failed — \(error.localizedDescription). "
                    + "Frames written before the failure remain available to save."
                if self.isCapturing {
                    self.stopCapture()
                }
            }
            await self.sessionEngine.ingest(
                frames, linkType: linkType, epoch: token, locators: locators, loss: loss
            )
            guard shouldSnapshot,
                  self.startGeneration == token,
                  self.isCapturing,
                  let snapshot = await self.sessionEngine.investigationSnapshot(epoch: token) else
            {
                return
            }
            self.publishLiveDetailed(snapshot, expectedGeneration: token, isCapturing: true)
        }
    }

    /// Fold the helper worker's final post-stop drain after all previously queued
    /// ingests, then publish one stopped snapshot. The capture token addresses the
    /// engine epoch that just ended; the stopped token prevents a late reply from
    /// overwriting a capture or savefile opened in the meantime.
    private func ingestFinalHelperBatch(
        _ frames: [CapturedFrame],
        linkType: UInt32,
        captureToken: Int,
        stoppedToken: Int
    ) {
        currentLinkType = linkType
        appendRetainedFrames(frames)
        // Snapshot loss on the main actor before enqueueing, matching the live path.
        let loss = currentCaptureLoss
        let previous = ingestChain
        ingestChain = Task { @MainActor in
            await previous?.value
            var locators: [SessionEvidenceLocator]?
            do {
                if case let .appended(appended) = try await self.liveCaptureSpool.append(
                    frames,
                    defaultLinkType: linkType,
                    epoch: captureToken
                ) {
                    locators = appended
                }
            } catch {
                self.captureError = "Capture stopped: the local spool failed — \(error.localizedDescription). "
                    + "Frames written before the failure remain available to save."
            }
            await self.sessionEngine.ingest(
                frames, linkType: linkType, epoch: captureToken, locators: locators, loss: loss
            )
            if self.startGeneration == stoppedToken,
               !self.isCapturing,
               let snapshot = await self.sessionEngine.investigationSnapshot(epoch: captureToken)
            {
                let spoolIncomplete = await self.liveCaptureSpool.incompletenessReason() != nil
                let completeness: HistoryCompleteness = self.currentCaptureLoss == .lossReported || spoolIncomplete
                    ? .incomplete
                    : .complete
                self.publishLiveDetailed(
                    snapshot,
                    expectedGeneration: stoppedToken,
                    isCapturing: false,
                    terminalHistoryCompleteness: completeness
                )
            }
            self.resumePendingSavedCaptureOpenAfterLiveDrain()
        }
    }

    /// Publish the complete stopped snapshot for a direct capture (or a helper
    /// stop that could not obtain a final reply) after every already-enqueued
    /// batch has folded. Stop advances the coordinator generation immediately,
    /// so ordinary coalesced live publications intentionally fail their old-token
    /// guard; this final hop uses the old engine epoch for the snapshot and the
    /// new stopped token for publication, matching the helper final-drain path.
    private func publishStoppedSnapshotAfterCurrentIngest(captureToken: Int, stoppedToken: Int) {
        let previous = ingestChain
        ingestChain = Task { @MainActor in
            await previous?.value
            if self.startGeneration == stoppedToken,
               !self.isCapturing,
               let snapshot = await self.sessionEngine.investigationSnapshot(epoch: captureToken)
            {
                let spoolIncomplete = await self.liveCaptureSpool.incompletenessReason() != nil
                let completeness: HistoryCompleteness = self.currentCaptureLoss == .lossReported || spoolIncomplete
                    ? .incomplete
                    : .complete
                self.publishLiveDetailed(
                    snapshot,
                    expectedGeneration: stoppedToken,
                    isCapturing: false,
                    terminalHistoryCompleteness: completeness
                )
            }
            self.resumePendingSavedCaptureOpenAfterLiveDrain()
        }
    }

    /// Stage recent raw frames for UI inspection within a bounded window. The window and
    /// its saturating eviction count live in ``RetainedFrameBuffer``; this is a
    /// thin hop so the ingest path reads clearly. Independent of session
    /// accumulation — see ``retainedFrameLimit``.
    private func appendRetainedFrames(_ frames: [CapturedFrame]) {
        retainedFrames.append(contentsOf: frames)
    }

    /// Clears the engine and adopts a new capture generation. Enqueued on the
    /// ingest chain so it is ordered ahead of subsequent ingests; older in-flight
    /// work carries the previous token and is dropped by the engine's epoch guard.
    func resetSessionEngine(token: Int) {
        let engine = sessionEngine
        let spool = liveCaptureSpool
        let previous = ingestChain
        ingestChain = Task { @MainActor in
            await previous?.value
            await engine.reset(epoch: token)
            do {
                try await spool.reset(epoch: token)
            } catch {
                self.captureError = "Capture spool unavailable — \(error.localizedDescription)"
            }
        }
    }

    private func handleCaptureError(_ message: String) {
        pollTimer?.invalidate()
        pollTimer = nil
        helperFetchGeneration &+= 1
        helperFetchInFlight = false
        captureError = message
        isCapturing = false
        isStarting = false
        // Retire this attempt so a late reply/watchdog can't flip state back.
        startGeneration &+= 1
        captureStartedAt = nil
    }

    private func groupCounts(_ key: (SessionSummary) -> String) -> [(name: String, count: Int)] {
        var totals: [String: Int] = [:]
        for session in presentedSessions {
            totals[key(session), default: 0] += 1
        }
        return totals.sorted { $0.value > $1.value }.map { (name: $0.key, count: $0.value) }
    }
}
