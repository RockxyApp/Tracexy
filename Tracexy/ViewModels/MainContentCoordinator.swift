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
    /// there a concurrency warning today and an error under Swift 6.
    init(
        policy: any AppPolicy = DefaultAppPolicy(),
        layoutPreferences: WorkspaceLayoutPreferences? = nil
    ) {
        self.policy = policy
        focusGate = FocusPolicyGate(
            maxFocusSets: policy.maxFocusSets,
            maxPinnedHosts: policy.maxPinnedHosts
        )
        let preferences = layoutPreferences ?? WorkspaceLayoutPreferences()
        self.layoutPreferences = preferences
        workspaces = WorkspaceStore(
            maxWorkspaces: policy.maxWorkspaceTabs,
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

    /// Severity-ranked findings for the Overview panel, derived only from real
    /// decoded signals (status, plaintext-HTTP, empty DNS answers, high latency) —
    /// never a fabricated anomaly. Sorted error→warning→note; stable within a rank.
    /// Cap on findings built per pass — bounds the Overview findings array under
    /// a huge (100k+) capture.
    static let maxFindings = 1_000

    /// Most recent sessions considered for correlation. Keeps grouping cost
    /// bounded on a long-running capture.
    static let maxCorrelatedSessions = 5_000

    /// How many raw frames are retained for save/export.
    ///
    /// This is a bound on *memory*, not on capture fidelity. Sessions accumulate
    /// incrementally in `LiveSessionEngine` and do not depend on this window, so
    /// evicting an old raw frame here never drops a session or forces a re-decode
    /// of history — it leaves only the recent tail available to a `.pcap` save. Every
    /// eviction is counted in `retainedFrameEvictionCount`, and that count is a
    /// UI-side figure that must never be presented as kernel/interface loss.
    static let retainedFrameLimit = 8_000

    /// The capacity limits this build runs under. Held so the views that need
    /// to *show* a limit can read it; nothing reads it to decide behaviour —
    /// that is the gates' job.
    let policy: any AppPolicy

    /// Capacity gate for focus sets and pinned hosts.
    let focusGate: FocusPolicyGate

    let workspaces: WorkspaceStore

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
    private(set) var throughputSamples: [ThroughputSample] = []

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
    private(set) var helperBufferDropCount: UInt64 = 0

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
    private(set) var activeSavedCapture: SavedCapture?

    /// Bounded, deterministic frames-over-time aggregation for the open saved
    /// capture, computed once at open/import and cached here. `nil` for live and
    /// idle captures. Derived from real frame timestamps/lengths behind this seam,
    /// so the Overview chart draws from per-bucket totals and never re-scans frames
    /// or receives packet bytes.
    private(set) var savedCaptureActivity: CaptureActivity?

    /// Link type of the current capture, needed to write a faithful `.pcap`.
    var currentLinkType: UInt32 = LinkType.ethernet

    /// Shared privileged-helper manager (install/version/update/uninstall).
    let helper = HelperClient.shared

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

    /// Cumulative frames dropped from the *local* raw-retention window (kept only
    /// for save/export; see ``retainedFrameLimit``). This is a UI-side memory
    /// bound, never kernel/interface loss, and must never be surfaced as capture
    /// fidelity. Sessions are unaffected by it. Read straight off the retention
    /// buffer so there is a single source of truth for the count.
    var retainedFrameEvictionCount: UInt64 {
        retainedFrames.evictionCount
    }

    /// Raw frames currently held for save/export. Distinct from the session count:
    /// this is only the recent tail kept in memory, bounded by
    /// ``retainedFrameLimit``. Surfaced as retention state, never as capture loss.
    var retainedFrameCount: Int {
        retainedFrames.count
    }

    /// The retention window's capacity — the denominator in the Overview's
    /// "N / capacity frames" retention readout.
    var retainedFrameCapacity: Int {
        Self.retainedFrameLimit
    }

    /// Sum of the captured lengths of the retained frames — the payload bytes a
    /// `.pcap` save would write. Used only to estimate a save size; it is neither
    /// capture fidelity nor total captured traffic.
    var retainedCapturedByteCount: Int {
        retainedFrames.capturedByteCount
    }

    /// All sessions decoded from the current capture's real frames.
    private(set) var sessions: [SessionSummary] = [] {
        didSet { rebuildActivities() }
    }

    var activeWorkspace: WorkspaceState {
        workspaces.activeWorkspace
    }

    /// Sessions visible in the active workspace, after sidebar + pill + text filtering.
    var visibleSessions: [SessionSummary] {
        let ws = activeWorkspace
        let protocolFilter = ws.sidebarSelection.protocolFilter
        let categories = ws.categoryFilters
        // A disabled search keeps its text but stops constraining the list.
        let query = ws.isSearchActive
            ? ws.filterText.trimmingCharacters(in: .whitespaces).lowercased()
            : ""
        let searchField = ws.searchField
        let advancedRules = ws.activeFilterRules
        // Compile the advanced rules' regex patterns once for the whole pass,
        // not once per session.
        let preparedRules = SessionFilterRuleEvaluator.prepared(advancedRules)

        return sessions.filter { session in
            // Noise Control (sidebar Focus) hides muted hosts/protocols everywhere.
            if mutedHosts.contains(session.host) {
                return false
            }
            if mutedProtocols.contains(session.primaryProtocol) {
                return false
            }
            if let proto = protocolFilter, !session.protocolStack.contains(proto) {
                return false
            }
            if !Self.categoryFilterMatches(session, categories: categories) {
                return false
            }
            if let host = ws.hostFilter, session.host != host {
                return false
            }
            if let process = ws.processFilter, (session.processName ?? "—") != process {
                return false
            }
            if let ip = ws.ipFilter,
               !session.sourceEndpoint.contains(ip), !session.destinationEndpoint.contains(ip),
               !session.dnsAnswers.contains(ip)
            {
                return false
            }
            if !query.isEmpty, !searchField.haystack(in: session).contains(query) {
                return false
            }
            // Advanced rule builder: AND/OR rows, applied on top of everything above.
            if !advancedRules.isEmpty, !preparedRules.matches(session) {
                return false
            }
            return true
        }
    }

    var selectedSession: SessionSummary? {
        guard let id = activeWorkspace.selectedSessionID else {
            return nil
        }
        return sessions.first { $0.id == id }
    }

    // MARK: Dashboard rollups

    var errorCount: Int {
        sessions.filter { $0.status == .error }.count
    }

    var warningCount: Int {
        sessions.filter { $0.status == .warning }.count
    }

    /// Severity-ranked findings across the whole capture, derived only from real
    /// decoded signals (status, plaintext HTTP, empty DNS answers, high DNS
    /// response time). The Overview scopes these to the active filter before
    /// display, so a filtered list and its findings summary never disagree.
    var findings: [Finding] {
        var result: [Finding] = []
        for session in sessions {
            if result.count >= Self.maxFindings {
                break
            }
            switch session.status {
            case .error:
                result.append(Finding(
                    severity: .error, title: session.host, subtitle: session.infoSummary, sessionID: session.id
                ))
            case .warning:
                result.append(Finding(
                    severity: .warning, title: session.host, subtitle: session.infoSummary, sessionID: session.id
                ))
            case .ok:
                break
            }
            if session.protocolStack.contains(.http), !session.protocolStack.contains(.tls) {
                // State only the decoded fact — the traffic was unencrypted.
                // We decode the plaintext HTTP; we do not observe that any
                // credentials or PII were actually present, so the copy must
                // not claim they were exposed.
                result.append(Finding(
                    severity: .warning,
                    title: "Plaintext HTTP",
                    subtitle: "Unencrypted HTTP traffic to \(session.host)",
                    sessionID: session.id
                ))
            }
            if let query = session.dnsQuery, !query.isEmpty, session.dnsAnswers.isEmpty {
                result.append(Finding(
                    severity: .note, title: "DNS returned no answer", subtitle: query, sessionID: session.id
                ))
            }
            if let latency = session.latencyMilliseconds, latency > 400 {
                // `latencyMilliseconds` is the DNS query→response time only (see
                // `SessionAccumulator`), so the finding names that specifically
                // rather than claiming a general network-latency figure we do not
                // measure.
                result.append(Finding(
                    severity: .note,
                    title: "High DNS response time",
                    subtitle: "\(Int(latency)) ms to resolve \(session.host)",
                    sessionID: session.id
                ))
            }
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
        for session in sessions where Self.isDomainName(session.host) {
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
        for session in sessions {
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
            return "\(captureInterface) · live · \(sessions.count.formatted()) sessions"
        }
        if sessions.isEmpty {
            return "idle — press Start to capture"
        }
        return "\(sessions.count.formatted()) sessions"
    }

    // MARK: Aggregate rollups (status bar)

    var totalBytes: Int {
        sessions.reduce(0) { $0 + $1.totalBytes }
    }

    var totalBytesUp: Int {
        sessions.reduce(0) { $0 + $1.bytesUp }
    }

    var totalBytesDown: Int {
        sessions.reduce(0) { $0 + $1.bytesDown }
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
        for session in sessions {
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

    /// Read-only copy used by the session-export extension before it leaves the
    /// main actor to scope and serialize packet data.
    var retainedFrameSnapshotForExport: [CapturedFrame] {
        retainedFrames.frames
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
        let slice = sessions.filter {
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
        activeWorkspace.selectedSessionID = session.id
        revealPanelsForSelection()
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

    /// Writes the retained frames to a timestamped `.pcap` under Application Support,
    /// then refreshes the saved list. Returns the new file (nil if nothing to save).
    @discardableResult
    func saveCurrentCapture() -> SavedCapture? {
        guard !retainedFrames.isEmpty, let directory = Self.capturesDirectory() else {
            return nil
        }
        let stamp = Self.fileStampFormatter.string(from: Date())
        let url = directory.appendingPathComponent("Capture \(stamp).pcap")
        do {
            try PcapWriter.write(linkType: currentLinkType, frames: retainedFrames.frames, to: url)
        } catch {
            captureError = "Couldn’t save capture: \(error.localizedDescription)"
            return nil
        }
        refreshSavedCaptures()
        return savedCaptures.first { $0.url == url }
    }

    /// Loads a saved `.pcap`/`.pcapng` into the session list (read-only) and stops live.
    func openSavedCapture(_ capture: SavedCapture) {
        do {
            let parsed = try CaptureFileReader.read(contentsOf: capture.url)
            if isCapturing {
                stopCapture()
            }
            // Supersede any in-flight live engine work and clear its state so a
            // late snapshot can't overwrite the file being opened.
            startGeneration &+= 1
            resetSessionEngine(token: startGeneration)
            currentLinkType = parsed.linkType
            // A savefile carries no kernel accounting: whatever loss happened
            // during the original capture is not recoverable from the file, so
            // the fidelity figure must read as unknown rather than perfect. The
            // helper-buffer and local-retention counters are live-only, so they
            // reset to zero for a static file too. The file is shown in full —
            // `replace` bypasses the live retention bound and zeroes its count.
            captureStatistics = nil
            helperBufferDropCount = 0
            retainedFrames.replace(with: parsed.frames)
            sessions = SessionBuilder.build(from: parsed.frames, linkType: parsed.linkType)
            isViewingSavedCapture = true
            // Remember which file this is and aggregate its activity once, here at
            // the open boundary, so the Overview can label the file truthfully and
            // draw its frames-over-time chart without re-scanning frames on every
            // body update.
            activeSavedCapture = capture
            savedCaptureActivity = CaptureActivityBuilder.build(frames: parsed.frames)
            captureError = nil
            activeWorkspace.selectedSessionID = nil
            selectSidebarItem(.sessions)
        } catch {
            captureError = "Couldn’t open “\(capture.name)”: \(error.localizedDescription)"
        }
    }

    /// Imports an external `.pcap` file: copies it into the captures folder and opens it.
    func importCapture(from source: URL) {
        guard let directory = Self.capturesDirectory() else {
            return
        }
        let destination = directory.appendingPathComponent(source.lastPathComponent)
        do {
            if FileManager.default.fileExists(atPath: destination.path) {
                try FileManager.default.removeItem(at: destination)
            }
            try FileManager.default.copyItem(at: source, to: destination)
            refreshSavedCaptures()
            if let imported = savedCaptures.first(where: { $0.url == destination }) {
                openSavedCapture(imported)
            }
        } catch {
            captureError = "Couldn’t import “\(source.lastPathComponent)”: \(error.localizedDescription)"
        }
    }

    func deleteSavedCapture(_ capture: SavedCapture) {
        try? FileManager.default.removeItem(at: capture.url)
        refreshSavedCaptures()
    }

    /// Rescans the captures folder and rebuilds `savedCaptures`, newest first.
    func refreshSavedCaptures() {
        guard let directory = Self.capturesDirectory(),
              let urls = try? FileManager.default.contentsOfDirectory(
                  at: directory,
                  includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey]
              ) else
        {
            savedCaptures = []
            return
        }
        savedCaptures = urls
            .filter { ["pcap", "pcapng"].contains($0.pathExtension.lowercased()) }
            .map { url in
                let values = try? url.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey])
                return SavedCapture(
                    url: url,
                    name: url.deletingPathExtension().lastPathComponent,
                    date: values?.contentModificationDate ?? .distantPast,
                    byteCount: values?.fileSize ?? 0
                )
            }
            .sorted { $0.date > $1.date }
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
        // Supersede any in-flight engine work so a late snapshot can't repopulate
        // the list after a clear, and zero the accounting counters.
        startGeneration &+= 1
        resetSessionEngine(token: startGeneration)
        captureStatistics = nil
        helperBufferDropCount = 0
        retainedFrames.reset()
        sessions = []
        throughputSamples = []
        pendingChartBytes = 0
        isViewingSavedCapture = false
        activeSavedCapture = nil
        savedCaptureActivity = nil
        activeWorkspace.selectedSessionID = nil
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
        captureError = nil
        isStarting = true
        startGeneration &+= 1
        isViewingSavedCapture = false
        activeSavedCapture = nil
        savedCaptureActivity = nil
        retainedFrames.reset()
        sessions = []
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
        // Dev fast path: bypass the signed helper and capture straight through
        // libpcap. The helper needs one-time Login-Items approval; a dev build
        // launched by `scripts/run.sh` (which passes `--direct-capture`) instead
        // opens /dev/bpf directly — which works whenever the user can access BPF
        // (e.g. a member of the ChmodBPF / access_bpf group). No sudo, no approval.
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

    /// Top talkers by total bytes, for the dashboard.
    func topHosts(limit: Int = 5) -> [(host: String, bytes: Int)] {
        var totals: [String: Int] = [:]
        for session in visibleSessions {
            totals[session.host, default: 0] += session.totalBytes
        }
        return totals.sorted { $0.value > $1.value }
            .prefix(limit)
            .map { (host: $0.key, bytes: $0.value) }
    }

    func count(for proto: ProtocolKind) -> Int {
        visibleSessions.filter { $0.protocolStack.contains(proto) }.count
    }

    /// Whether a session matches a single quick-filter chip. Delegates to the
    /// pure ``categoryMatches(_:category:)`` so the decision lives in one place.
    func matches(_ session: SessionSummary, category: SessionFilterCategory) -> Bool {
        Self.categoryMatches(session, category: category)
    }

    // MARK: Private

    private static let pinnedHostsKey = TracexyIdentity.current.defaultsKey("pinnedHosts")

    private static let fileStampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH.mm.ss"
        return formatter
    }()

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
    /// Serializes engine access so batches fold in arrival order even though each
    /// call hops onto the engine actor, and so a boundary reset is ordered ahead
    /// of the ingests that follow it.
    private var ingestChain: Task<Void, Never>?
    private var lastSessionsUpdate = Date.distantPast
    private var pendingChartBytes = 0
    /// Bounded FIFO window of raw frames kept only for save/export. Independent of
    /// session accumulation — evicting here never drops a session — and its
    /// cumulative eviction count is surfaced only as retention truncation.
    private var retainedFrames = RetainedFrameBuffer(capacity: MainContentCoordinator.retainedFrameLimit)

    private var pollTimer: Timer?
    /// Bumped every time a start attempt begins or ends. A late helper reply or a
    /// start watchdog compares its captured token against this so a stale callback
    /// from an abandoned attempt can't revive `isCapturing`/`isStarting`.
    private var startGeneration = 0
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

    /// `~/Library/Application Support/<bundle id>/Captures`, created on demand.
    private static func capturesDirectory() -> URL? {
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
    private static func isDomainName(_ host: String) -> Bool {
        if host.contains(":") {
            return false // IPv6 literal
        }
        let parts = host.split(separator: ".")
        if parts.count == 4, parts.allSatisfy({ UInt8($0) != nil }) {
            return false // IPv4 literal
        }
        return host.contains(".") && host.contains { $0.isLetter }
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
        if !Self.forceDirectCapture, let proxy = try? helper.proxy() {
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
        }
        live?.stop()
        isCapturing = false
        isStarting = false
        captureStartedAt = nil
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
        do {
            let proxy = try helper.proxy()
            proxy.startCapture(interface: captureInterface) { [weak self] started, message in
                Task { @MainActor in
                    guard let self, self.startGeneration == token else {
                        return
                    }
                    if started {
                        self.isCapturing = true
                        self.isStarting = false
                        self.captureStartedAt = Date()
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
        isCapturing = true
        isStarting = false
        captureStartedAt = Date()
        captureStatistics = nil
        live.start(
            interface: captureInterface,
            onBatch: { [weak self] frames, linkType in
                guard let coordinator = self else {
                    return
                }
                Task { @MainActor in coordinator.ingest(frames, linkType: linkType) }
            },
            onError: { [weak self] message in
                guard let coordinator = self else {
                    return
                }
                Task { @MainActor in coordinator.handleCaptureError(message) }
            },
            onStatistics: { [weak self] sample in
                guard let coordinator = self else {
                    return
                }
                Task { @MainActor in coordinator.captureStatistics = sample }
            }
        )
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

        // Hand decode/group to the engine actor (off-main), chained so batches
        // fold in arrival order. Snapshots are guarded by the capture generation
        // so a late result from a superseded capture can never overwrite newer
        // UI state.
        let token = startGeneration
        let previous = ingestChain
        ingestChain = Task { @MainActor in
            await previous?.value
            await self.sessionEngine.ingest(frames, linkType: linkType, epoch: token)
            guard shouldSnapshot,
                  self.startGeneration == token,
                  self.isCapturing,
                  let snapshot = await self.sessionEngine.snapshot(epoch: token) else
            {
                return
            }
            self.publishLiveSessions(snapshot, expectedGeneration: token, isCapturing: true)
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
        let previous = ingestChain
        ingestChain = Task { @MainActor in
            await previous?.value
            await self.sessionEngine.ingest(frames, linkType: linkType, epoch: captureToken)
            guard self.startGeneration == stoppedToken,
                  !self.isCapturing,
                  let snapshot = await self.sessionEngine.snapshot(epoch: captureToken) else
            {
                return
            }
            self.publishLiveSessions(
                snapshot,
                expectedGeneration: stoppedToken,
                isCapturing: false
            )
        }
    }

    /// Stage raw frames for save/export within a bounded window. The window and
    /// its saturating eviction count live in ``RetainedFrameBuffer``; this is a
    /// thin hop so the ingest path reads clearly. Independent of session
    /// accumulation — see ``retainedFrameLimit``.
    private func appendRetainedFrames(_ frames: [CapturedFrame]) {
        retainedFrames.append(contentsOf: frames)
    }

    /// Enrich an engine snapshot with app-side process attribution and publish it
    /// to `sessions` on the next runloop turn.
    ///
    /// Process attribution stays here (main actor, off the decode/group path):
    /// it reads the local socket table, which is an app concern, not the engine's.
    /// The assignment hops one runloop turn so it can't reload an `NSTableView`
    /// reentrantly from inside a click currently being handled, and it re-checks
    /// the capture generation so a stale enrichment can't revive old state.
    private func publishLiveSessions(
        _ snapshot: [SessionSummary],
        expectedGeneration: Int,
        isCapturing expectedCaptureState: Bool
    ) {
        ProcessResolver.shared.refresh()
        var built = snapshot
        for index in built.indices where built[index].processName == nil {
            if let app = ProcessResolver.shared.appName(
                forEndpoints: built[index].sourceEndpoint, built[index].destinationEndpoint
            ) {
                built[index].processName = app
            }
        }
        let applied = built
        Task { @MainActor in
            guard self.startGeneration == expectedGeneration,
                  self.isCapturing == expectedCaptureState else
            {
                return
            }
            self.sessions = applied
            if self.activeWorkspace.autoSelectLatest,
               // Newest by timestamp, tie-broken by id so the choice never depends
               // on the array's (first-seen) order.
               let latest = applied.max(by: {
                   ($0.startTime, $0.id.uuidString) < ($1.startTime, $1.id.uuidString)
               }),
               self.activeWorkspace.selectedSessionID != latest.id
            {
                self.activeWorkspace.selectedSessionID = latest.id
            }
        }
    }

    /// Clears the engine and adopts a new capture generation. Enqueued on the
    /// ingest chain so it is ordered ahead of subsequent ingests; older in-flight
    /// work carries the previous token and is dropped by the engine's epoch guard.
    private func resetSessionEngine(token: Int) {
        let engine = sessionEngine
        ingestChain = Task { @MainActor in
            await engine.reset(epoch: token)
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
        for session in sessions {
            totals[key(session), default: 0] += 1
        }
        return totals.sorted { $0.value > $1.value }.map { (name: $0.key, count: $0.value) }
    }
}

// MARK: - CaptureDisplayState

/// Coarse capture state shown in the toolbar status capsule. Drives both the dot color and the trailing word.
enum CaptureDisplayState {
    case stopped
    case starting
    case capturing
    case error

    // MARK: Internal

    var title: String {
        switch self {
        case .stopped: String(localized: "Stopped")
        case .starting: String(localized: "Starting")
        case .capturing: String(localized: "Capturing")
        case .error: String(localized: "Error")
        }
    }
}

// MARK: - SavedCapture

/// One saved `.pcap` file on disk, listed under the sidebar's "Saved Captures".
struct SavedCapture: Identifiable, Hashable {
    let url: URL
    let name: String
    let date: Date
    let byteCount: Int

    var id: URL {
        url
    }
}

// MARK: - DomainGroup

/// A domain and the set of server IPs it resolved to, for the sidebar tree.
struct DomainGroup: Identifiable {
    let domain: String
    let ips: [String]
    let count: Int

    var id: String {
        domain
    }
}

// MARK: - ThroughputSample

/// One point on the real-time throughput chart (bytes/sec over an interval).
struct ThroughputSample: Identifiable {
    let id = UUID()
    let bytesPerSecond: Double
}

// MARK: - AppGroup

/// An app and the set of hosts/IPs it contacted, for the expandable sidebar tree.
struct AppGroup: Identifiable {
    let app: String
    let hosts: [String]
    let count: Int

    var id: String {
        app
    }
}
