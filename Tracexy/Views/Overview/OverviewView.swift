import Charts
import SwiftUI

/// The capture report: what this capture is, how its bytes moved over time, who
/// carried them, what needs attention, and where it lives — one chart-led page
/// whose every panel ends in an existing Tracexy flow (Sessions, Flow Map,
/// Findings, Sources, Library, Save).
///
/// Capture-wide figures (frames, wire bytes, the traffic timeline) come from the
/// adopted investigation snapshot and describe every accepted frame. Scoped panels
/// (talkers, protocols, findings, sources) describe the visible session set and
/// say so through the scope notice. A live capture reports kernel/helper fidelity
/// and local retention; a saved file reports provenance and an explicitly
/// *unknown* fidelity — never a fabricated clean figure.
struct OverviewView: View {
    // MARK: Internal

    var coordinator: MainContentCoordinator

    var body: some View {
        // Every scoped figure on this page derives from one filtered session set
        // and one findings projection, both computed exactly once per render.
        // Panels read the report rather than re-filtering the coordinator, so a
        // 1 Hz live refresh costs one pass over the sessions, not ten.
        let report = Report(coordinator: coordinator)
        GeometryReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: Theme.Metrics.spacingL + 4) {
                    if report.hasTraffic {
                        figuresCard(report)
                        activityCard(report)
                        if proxy.size.width >= Self.wideDashboardMinimumWidth {
                            wideBody(report)
                        } else {
                            compactBody(report)
                        }
                    } else {
                        emptyCard
                        healthCard
                    }
                }
                // A vertical ScrollView otherwise accepts the dashboard's ideal
                // width. When that ideal width is wider than the workspace left
                // after the native sidebar opens, SwiftUI centers the overflow and
                // its leading edge disappears underneath the sidebar. Constrain the
                // proposal to the actual workspace viewport so the explicit
                // breakpoint can choose the compact layout and every card remains
                // inside the split.
                .frame(
                    width: max(0, proxy.size.width - Theme.Metrics.spacingL * 2),
                    alignment: .leading
                )
                .padding(Theme.Metrics.spacingL)
            }
            .tracexyDenseScrollEdge()
            .tracexySafeAreaBar(edge: .top) { reportShelf(report) }
        }
    }

    /// Explains, without guessing, that the plotted range covers only the frames the
    /// capture file gave a time — or that none of them had one.
    nonisolated static func untimedCoverageLabel(_ activity: CaptureActivity) -> String {
        let untimed = activity.untimedFrameCount.formatted()
        guard activity.timedFrameCount > 0 else {
            return "This capture file records no time for any of its \(untimed) frames, "
                + "so there is no capture timeline to show."
        }
        return "Timed frames only — \(untimed) of \(activity.totalFrames.formatted()) frames "
            + "have no capture time, so this range isn’t the whole capture."
    }

    /// The same statement for the traffic timeline, which counts every accepted
    /// frame of a live or saved capture.
    nonisolated static func untimedCoverageLabel(_ timeline: TrafficTimeline) -> String {
        let untimed = timeline.untimedFrameCount.formatted()
        let total = timeline.totals.frames
        guard total - timeline.untimedFrameCount > 0 else {
            return "This capture records no time for any of its \(untimed) frames, "
                + "so there is no capture timeline to show."
        }
        return "Timed frames only — \(untimed) of \(total.formatted()) frames "
            + "have no capture time, so this range isn’t the whole capture."
    }

    /// Every `count / limit`-th element of an ordered list, deterministic, keeping
    /// the first element; the whole list when it already fits.
    nonisolated static func sampled<Element>(_ elements: [Element], limit: Int) -> [Element] {
        guard limit > 0 else {
            return []
        }
        guard elements.count > limit else {
            return elements
        }
        let stride = Double(elements.count) / Double(limit)
        return (0 ..< limit).map { elements[Int((Double($0) * stride).rounded(.down))] }
    }

    // MARK: Private

    /// The per-render snapshot of everything scoped: the visible sessions, the
    /// findings among them, the traffic timeline and its rendered columns, and
    /// the rollups the panels draw. Built once at the top of `body`.
    private struct Report {
        // MARK: Lifecycle

        init(coordinator: MainContentCoordinator) {
            let sessions = coordinator.visibleSessions
            let visibleIDs = Set(sessions.map(\.id))
            let findings = coordinator.findings.filter { visibleIDs.contains($0.sessionID) }
            let timeline = coordinator.trafficTimeline
            self.sessions = sessions
            self.findings = findings
            self.timeline = timeline
            points = timeline.points()
            scopedBytes = sessions.reduce(0) { $0 + $1.totalBytes }
            protocolShare = MainContentCoordinator.protocolByteShare(of: sessions, limit: 5)
            topHosts = MainContentCoordinator.topHostTraffic(of: sessions, limit: 10)
            topApps = MainContentCoordinator.topProcesses(of: sessions, limit: 10)
            sources = MainContentCoordinator.sourceSummary(of: sessions)
            findingMarkers = OverviewView.findingMarkers(for: findings)
            presentedSessionCount = coordinator.presentedSessions.count
            hasTraffic = !timeline.isEmpty || presentedSessionCount > 0
        }

        // MARK: Internal

        let sessions: [SessionSummary]
        let findings: [Finding]
        let timeline: TrafficTimeline
        let points: [TrafficTimelinePoint]
        let scopedBytes: Int
        let protocolShare: [(kind: ProtocolKind?, bytes: Int)]
        let topHosts: [TrafficRankingEntry]
        let topApps: [TrafficRankingEntry]
        let sources: (apps: Int, domains: Int, addresses: Int)
        let findingMarkers: [OverviewFindingMarker]
        let hasTraffic: Bool
        let presentedSessionCount: Int

        /// Width of one rendered column; chooses whether the axis needs seconds.
        var columnWidth: TimeInterval {
            guard points.count >= 2 else {
                return timeline.bucketWidth
            }
            return points[1].date.timeIntervalSince(points[0].date)
        }
    }

    private static let percent: NumberFormatter = {
        let formatter = NumberFormatter()
        formatter.numberStyle = .percent
        formatter.maximumFractionDigits = 2
        return formatter
    }()

    /// The two-column rows need enough *workspace* width to keep the talker bars
    /// and the protocol legend readable side by side. Below this point they stack
    /// instead of relying on intrinsic measurement that can extend beneath the
    /// native sidebar.
    private static let wideDashboardMinimumWidth: CGFloat = 960
    private static let figuresRowMinimumWidth: CGFloat = 720
    private static let chartHeight: CGFloat = 250
    private static let secondaryChartHeight: CGFloat = 132
    /// Findings pinned onto the activity axis are bounded; the findings panel
    /// still counts every finding in scope.
    private static let maximumFindingMarkers = 64

    @Environment(\.openWindow) private var openWindow

    private var isSaved: Bool {
        coordinator.isViewingSavedCapture
    }

    // MARK: Presentation values

    private var identityTitle: String {
        if isSaved {
            return coordinator.activeSavedCapture?.name ?? "Saved capture"
        }
        return coordinator.captureInterface
    }

    private var identitySubtitle: String {
        if isSaved {
            return "\(savedFormat) file, \(linkTypeName)"
        }
        return "Live capture on \(linkTypeName)"
    }

    private var statusTint: Color {
        if coordinator.isOpeningSavedCapture {
            return .secondary
        }
        if isSaved {
            return .purple
        }
        return switch coordinator.captureDisplayState {
        case .capturing: .green
        case .starting: .blue
        case .error: .red
        case .stopped: .secondary
        }
    }

    private var savedFormat: String {
        if let properties = coordinator.savedCaptureProperties {
            return switch properties.container {
            case .pcap: "PCAP"
            case .pcapng: "PCAPNG"
            }
        }
        let ext = coordinator.activeSavedCapture?.url.pathExtension ?? "pcap"
        return ext.isEmpty ? "PCAP" : ext.uppercased()
    }

    private var savedInterfacesText: String? {
        guard let properties = coordinator.savedCaptureProperties, properties.interfaceCount > 0 else {
            return nil
        }
        let names = properties.allInterfaces.prefix(3).map(\.displayName)
        let remainder = properties.interfaceCount - names.count
        return remainder > 0 ? names.joined(separator: ", ") + " +\(remainder.formatted())" : names
            .joined(separator: ", ")
    }

    private var savedLoss: CaptureReportedLoss? {
        coordinator.savedCaptureProperties?.reportedLoss
    }

    private var linkTypeName: String {
        if let metadata = coordinator.savedCaptureMetadata, metadata.hasMixedLinkTypes {
            return "mixed link types"
        }
        return switch coordinator.currentLinkType {
        case LinkType.ethernet: "Ethernet"
        case LinkType.linuxSLL: "Linux cooked SLL"
        case LinkType.linuxSLL2: "Linux cooked SLL2"
        case LinkType.raw: "raw IP"
        case LinkType.null: "loopback"
        default: "link type \(coordinator.currentLinkType)"
        }
    }

    private var fidelityValue: String {
        if isSaved {
            guard let fidelity = savedLoss?.fidelity else {
                return "Not recorded"
            }
            return Self.percent.string(from: fidelity as NSNumber) ?? "—"
        }
        guard let fidelity = coordinator.captureStatistics?.fidelity else {
            return "Unknown"
        }
        return Self.percent.string(from: fidelity as NSNumber) ?? "—"
    }

    private var fidelityTint: Color {
        if isSaved {
            guard let loss = savedLoss, loss.fidelity != nil else {
                return .orange
            }
            return (loss.dropped > 0 || loss.isPartial) ? .orange : .green
        }
        guard let stats = coordinator.captureStatistics, stats.fidelity != nil else {
            return .orange
        }
        return (stats.isLossy || coordinator.helperBufferDropCount > 0) ? .orange : .green
    }

    private var savedHealthRows: [OverviewFactTable.Row] {
        var rows: [OverviewFactTable.Row] = [
            .init(label: "Format", value: savedFormat),
            .init(label: "Size", value: byteString(coordinator.activeSavedCapture?.byteCount ?? 0)),
            .init(label: "Frames", value: frameCount(coordinator.trafficTimeline).formatted()),
        ]
        if let savedInterfacesText {
            rows.append(.init(label: "Interfaces", value: savedInterfacesText))
        }
        if let loss = savedLoss {
            let suffix = loss.isPartial
                ? " on \(loss.reportingInterfaceCount.formatted()) of \(loss.interfaceCount.formatted()) interfaces"
                : ""
            rows.append(.init(
                label: "Dropped", value: loss.dropped.formatted() + suffix,
                tint: loss.dropped > 0 ? .orange : .primary
            ))
        } else {
            rows.append(.init(label: "Dropped", value: "Not recorded in the file"))
        }
        return rows
    }

    private var liveHealthRows: [OverviewFactTable.Row] {
        let stats = coordinator.captureStatistics
        let helperDrops = coordinator.helperBufferDropCount
        var rows: [OverviewFactTable.Row] = [
            .init(
                label: "Dropped",
                value: "Kernel \(stats.map { $0.totalDropped.formatted() } ?? "—"), helper \(helperDrops.formatted())",
                tint: (stats?.isLossy == true || helperDrops > 0) ? .orange : .primary
            ),
            .init(
                label: "In memory",
                value: "\(coordinator.retainedFrameCount.formatted()) of \(coordinator.retainedFrameCapacity.formatted()) frames"
            ),
            .init(label: "Save format", value: "PCAPNG"),
        ]
        if coordinator.retainedFrameEvictionCount > 0 {
            rows.append(.init(
                label: "On disk only",
                value: "\(coordinator.retainedFrameEvictionCount.formatted()) older frames"
            ))
        }
        return rows
    }

    private var figureDivider: some View {
        Divider().padding(.vertical, Theme.Metrics.spacingL)
    }

    // MARK: Capture health and storage

    /// Where the capture lives and how complete it is. Drops are reported here so
    /// a green figure never implies a complete capture and an absent one never
    /// reads as clean.
    private var healthCard: some View {
        OverviewPanel(
            isSaved ? "File" : "Capture health",
            caption: isSaved ? "Saved on disk" : "Unsaved live capture"
        ) {
            HStack(alignment: .firstTextBaseline, spacing: Theme.Metrics.spacingM) {
                Text(fidelityValue)
                    .font(Theme.Typography.metric)
                    .foregroundStyle(fidelityTint)
                    .monospacedDigit()
                Text("fidelity")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
            .accessibilityElement(children: .combine)
            OverviewFactTable(rows: isSaved ? savedHealthRows : liveHealthRows)
        } accessory: {
            if isSaved {
                HStack(spacing: Theme.Metrics.spacingL) {
                    Button("Get Info") { openWindow(id: TracexyApp.captureInfoWindowID) }
                        .buttonStyle(.link)
                        .font(Theme.Typography.captionMedium)
                        .disabled(!coordinator.canShowCaptureInfo)
                    Button("Show in Library") { coordinator.activeWorkspace.navigatorMode = .library }
                        .buttonStyle(.link)
                        .font(Theme.Typography.captionMedium)
                }
            } else {
                Button("Save Capture…") { coordinator.saveCurrentCapture() }
                    .buttonStyle(.link)
                    .font(Theme.Typography.captionMedium)
                    .disabled(!coordinator.canSaveCapture)
                    .help("Write the complete disk-backed capture to a .pcapng under Application Support")
            }
        }
    }

    // MARK: Empty state

    private var emptyCard: some View {
        card {
            ContentUnavailableView {
                Label(isSaved ? "No frames in this file" : "No traffic yet", systemImage: "waveform.path.ecg")
            } description: {
                Text(isSaved
                    ? "This file holds no accepted frames."
                    : "Start a capture or open a file. The report fills in as frames arrive.")
            }
            .frame(maxWidth: .infinity, minHeight: 220)
        }
    }

    // MARK: Layout

    /// Hero chart, then a row of compact secondary charts, then the detail
    /// tables — the report reads top-down from shape to figures.
    private func wideBody(_ report: Report) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL + 4) {
            HStack(alignment: .top, spacing: Theme.Metrics.spacingL + 4) {
                protocolsCard(report)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                sessionStartCard(report)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                findingsCard(report)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
            .fixedSize(horizontal: false, vertical: true)
            HStack(alignment: .top, spacing: Theme.Metrics.spacingL + 4) {
                hostsTableCard(report)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                appsTableCard(report)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
            .fixedSize(horizontal: false, vertical: true)
            HStack(alignment: .top, spacing: Theme.Metrics.spacingL + 4) {
                sourcesCard(report)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                healthCard
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
            .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func compactBody(_ report: Report) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL + 4) {
            protocolsCard(report)
            sessionStartCard(report)
            findingsCard(report)
            hostsTableCard(report)
            appsTableCard(report)
            sourcesCard(report)
            healthCard
        }
    }

    /// Says out loud when the numbers below describe a filtered subset, naming
    /// every layer doing the narrowing. Overview has no filter shelf of its own,
    /// so it carries the shared reset.
    private func scopeNotice(_ report: Report) -> some View {
        SessionScopeNotice(
            coordinator: coordinator,
            shownCount: report.sessions.count,
            showsResetAction: true
        )
    }

    // MARK: Report shelf

    /// The page's functional chrome — what this capture is, its state, and the
    /// routes out of the report — on one Liquid Glass shelf in the safe area,
    /// the same surface family the Sessions shelf and History header use. The
    /// cards below stay opaque content surfaces.
    private func reportShelf(_ report: Report) -> some View {
        let shape = RoundedRectangle(
            cornerRadius: Theme.Glass.sessionShelfCornerRadius,
            style: .continuous
        )
        return VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            TracexyGlassEffectGroup(spacing: Theme.Glass.sessionShelfSectionSpacing) {
                ViewThatFits(in: .horizontal) {
                    HStack(alignment: .center, spacing: Theme.Metrics.spacingL) {
                        identityBlock(report)
                        Spacer(minLength: Theme.Metrics.spacingL)
                        headerActions(report)
                    }
                    .frame(minWidth: 640)
                    VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
                        identityBlock(report)
                        headerActions(report)
                    }
                }
                .padding(.horizontal, Theme.Metrics.spacingL)
                .padding(.vertical, Theme.Metrics.spacingM)
                .tracexyGlassEffect(in: shape)
            }
            .padding(.horizontal, Theme.Glass.sessionShelfOuterPadding)
            .padding(.top, Theme.Glass.sessionShelfOuterPadding)
            scopeNotice(report)
                .padding(.horizontal, Theme.Metrics.spacingL)
        }
        .padding(.bottom, Theme.Glass.sessionShelfBottomPadding)
        .fixedSize(horizontal: false, vertical: true)
    }

    private func identityBlock(_ report: Report) -> some View {
        let status = statusTitle(hasTraffic: report.hasTraffic)
        return VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: Theme.Metrics.spacingM) {
                Label("Overview", systemImage: "chart.xyaxis.line")
                    .font(Theme.Typography.title)
                Text(identityTitle)
                    .font(Theme.Typography.title)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                statusPill(status)
            }
            Text(identitySubtitle)
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .accessibilityElement(children: .combine)
    }

    private func statusPill(_ statusTitle: String) -> some View {
        HStack(spacing: Theme.Metrics.controlSpacing) {
            StatusDot(statusTint, size: 6)
            Text(statusTitle).font(Theme.Typography.microEmphasis)
        }
        .foregroundStyle(statusTint)
        .padding(.horizontal, Theme.Metrics.spacingM)
        .padding(.vertical, 3)
        .background(statusTint.opacity(Theme.Glass.semanticFillOpacity), in: Capsule())
        .accessibilityLabel("Capture status, \(statusTitle)")
    }

    private func headerActions(_ report: Report) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Button {
                coordinator.openSessionsPreservingScope()
            } label: {
                Label("Sessions", systemImage: "list.bullet.rectangle")
            }
            .tracexyGlassButtonStyle(prominent: true)
            .help("Open these sessions in the full table, keeping the current scope")
            Button {
                coordinator.openFlowPreservingScope()
            } label: {
                Label("Flow Map", systemImage: "point.3.connected.trianglepath.dotted")
            }
            .tracexyGlassButtonStyle()
            .disabled(report.sessions.isEmpty)
            .help("See where this traffic is going")
            if isSaved {
                Button {
                    coordinator.activeWorkspace.navigatorMode = .library
                } label: {
                    Label("Library", systemImage: "books.vertical")
                }
                .tracexyGlassButtonStyle()
                .help("Reveal this file in the Library navigator")
            }
        }
        .controlSize(.small)
    }

    // MARK: Headline figures

    private func figuresCard(_ report: Report) -> some View {
        let frames = frameCount(report.timeline).formatted()
        let sessions = report.presentedSessionCount.formatted()
        let traffic = byteString(report.timeline.totals.bytes)
        return card(padding: 0) {
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 0) {
                    figure("Frames", value: frames)
                    figureDivider
                    figure("Sessions", value: sessions)
                    figureDivider
                    figure("Traffic", value: traffic)
                    figureDivider
                    durationFigure(report.timeline)
                    figureDivider
                    figure("Fidelity", value: fidelityValue, tint: fidelityTint)
                }
                .frame(minWidth: Self.figuresRowMinimumWidth)
                LazyVGrid(
                    columns: Array(repeating: GridItem(.flexible(minimum: 120), spacing: 0), count: 3),
                    spacing: 0
                ) {
                    figure("Frames", value: frames)
                    figure("Sessions", value: sessions)
                    figure("Traffic", value: traffic)
                    durationFigure(report.timeline)
                    figure("Fidelity", value: fidelityValue, tint: fidelityTint)
                }
            }
            .padding(.vertical, Theme.Metrics.spacingS)
        }
    }

    /// The only figure that ticks: a running capture's elapsed time. Scoping the
    /// timeline to this cell keeps the 1 Hz tick from re-rendering the page.
    private func durationFigure(_ timeline: TrafficTimeline) -> some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            figure("Duration", value: durationValue(at: context.date, timeline: timeline))
        }
    }

    private func figure(_ label: String, value: String, tint: Color = .primary) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            Text(label)
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(Theme.Typography.metric)
                .foregroundStyle(tint)
                .monospacedDigit()
                .lineLimit(1)
                .minimumScaleFactor(0.7)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, Theme.Metrics.spacingL + 4)
        .padding(.vertical, Theme.Metrics.spacingL)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label): \(value)")
    }

    // MARK: Traffic over time

    /// Every accepted frame's wire bytes on the real capture clock, split by
    /// session direction, with the scoped findings pinned where their evidence
    /// sits. Capture-wide: session filters narrow the panels below, not the frames.
    private func activityCard(_ report: Report) -> some View {
        let timeline = report.timeline
        return OverviewPanel("Traffic over time", caption: activityCaption(timeline)) {
            activityChart(report)
            activityFooter(report)
        } accessory: {
            HStack(spacing: Theme.Metrics.spacingL) {
                if timeline.hasStableDirectionalBytes {
                    valueChip("Sent", value: byteString(timeline.totals.sentBytes), color: Theme.Traffic.sent)
                    valueChip(
                        "Received",
                        value: byteString(timeline.totals.receivedBytes),
                        color: Theme.Traffic.received
                    )
                } else {
                    valueChip("Total", value: byteString(timeline.totals.bytes), color: .accentColor)
                }
            }
        }
    }

    @ViewBuilder
    private func activityChart(_ report: Report) -> some View {
        let timeline = report.timeline
        if timeline.firstTimedFrame != nil {
            OverviewTrafficTimelineChart(
                timeline: timeline, points: report.points, findingMarkers: report.findingMarkers
            )
            .frame(height: Self.chartHeight)
        } else if !timeline.isEmpty {
            Text(Self.untimedCoverageLabel(timeline))
                .font(Theme.Typography.body)
                .foregroundStyle(.secondary)
                .frame(height: Self.chartHeight, alignment: .center)
                .frame(maxWidth: .infinity)
                .accessibilityIdentifier("saved-activity-untimed-notice")
        } else {
            Text("Waiting for traffic…")
                .font(Theme.Typography.body)
                .foregroundStyle(.tertiary)
                .frame(height: Self.chartHeight, alignment: .center)
                .frame(maxWidth: .infinity)
        }
    }

    @ViewBuilder
    private func activityFooter(_ report: Report) -> some View {
        let timeline = report.timeline
        let markers = report.findingMarkers
        let total = report.findings.count
        if !markers.isEmpty || timeline.untimedFrameCount > 0 || timeline.directionMayHaveChanged {
            HStack(spacing: Theme.Metrics.spacingL) {
                if !markers.isEmpty {
                    HStack(spacing: Theme.Metrics.spacingS) {
                        Image(systemName: "diamond.fill")
                            .font(.system(size: Theme.Icon.small))
                            .foregroundStyle(.secondary)
                        Text(findingAxisLabel(placed: markers.count, total: total))
                            .font(Theme.Typography.caption)
                            .foregroundStyle(.secondary)
                    }
                    .accessibilityElement(children: .combine)
                }
                if timeline.untimedFrameCount > 0 {
                    Text(Self.untimedCoverageLabel(timeline))
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .accessibilityIdentifier("saved-activity-untimed-notice")
                }
                if timeline.directionMayHaveChanged {
                    Text("Client/server orientation changed during capture; this chart shows exact total bytes only.")
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
        }
    }

    // MARK: Secondary charts

    /// Session bytes partitioned by innermost protocol — every session lands in
    /// exactly one bar, so the bars sum to the scope. Tap a bar to drill in.
    private func protocolsCard(_ report: Report) -> some View {
        let share = report.protocolShare
        let total = max(1, share.reduce(0) { $0 + $1.bytes })
        let rows = share.map { entry in
            OverviewProtocolShare(
                id: entry.kind?.rawValue ?? "other",
                title: entry.kind?.label ?? "Other",
                bytes: entry.bytes,
                fraction: Double(entry.bytes) / Double(total),
                color: entry.kind.map(Theme.color(for:)) ?? .secondary,
                kind: entry.kind
            )
        }
        return OverviewPanel("Protocols", caption: "Session bytes in scope") {
            if rows.isEmpty {
                emptyLine(coordinator.sessions.isEmpty ? "No sessions yet" : "Nothing in the current scope")
                    .frame(height: Self.secondaryChartHeight)
            } else {
                OverviewProtocolChart(rows: rows) { kind in
                    coordinator.showSessionsForAggregateProtocol(kind)
                }
                .frame(height: Self.secondaryChartHeight)
                .help("Click a bar to narrow the scope to sessions that carry that protocol")
            }
        }
    }

    /// New conversations per slice on the same clock as the traffic chart.
    private func sessionStartCard(_ report: Report) -> some View {
        let columns = Self.sessionStartColumns(report)
        return OverviewPanel("Sessions started", caption: "New conversations in scope") {
            if columns.isEmpty {
                emptyLine(report.timeline.isEmpty ? "No sessions yet" : "No timed sessions in scope")
                    .frame(height: Self.secondaryChartHeight)
            } else {
                OverviewSessionStartChart(columns: columns, width: report.columnWidth)
                    .frame(height: Self.secondaryChartHeight)
            }
        }
    }

    // MARK: Detail tables

    private func hostsTableCard(_ report: Report) -> some View {
        let rows = report.topHosts
        return OverviewPanel("Top hosts", caption: "By bytes in scope") {
            if rows.isEmpty {
                emptyLine(coordinator.sessions.isEmpty ? "No sessions yet" : "Nothing in the current scope")
            } else {
                OverviewTalkerTable(kind: .hosts, rows: rows, scopedBytes: report.scopedBytes) { row in
                    coordinator.showSessionsForAggregateHost(row.name)
                }
                .help("Double-click a host to narrow the scope to its sessions")
            }
        } accessory: {
            Button("Open Sessions") { coordinator.openSessionsPreservingScope() }
                .buttonStyle(.link)
                .font(Theme.Typography.captionMedium)
                .help("Open these sessions in the full table, keeping the current scope")
        }
    }

    private func appsTableCard(_ report: Report) -> some View {
        let rows = report.topApps
        return OverviewPanel("Top apps", caption: "Attributed processes by bytes in scope") {
            if rows.isEmpty {
                emptyLine(report.sessions.isEmpty ? "Nothing in the current scope" : "No app attribution in scope")
            } else {
                OverviewTalkerTable(kind: .apps, rows: rows, scopedBytes: report.scopedBytes) { row in
                    coordinator.showSessionsForAggregateProcess(row.name)
                }
                .help("Double-click an app to narrow the scope to its sessions")
            }
        }
    }

    // MARK: Findings

    private func findingsCard(_ report: Report) -> some View {
        OverviewPanel("Findings", caption: "Typed observations in scope") {
            findingSummaryBar(report.findings)
        }
    }

    /// The severity rollup and its single route into the Sessions workflow.
    /// Overview never duplicates the finding evidence list.
    @ViewBuilder
    private func findingSummaryBar(_ all: [Finding]) -> some View {
        let sessionCount = Set(all.map(\.sessionID)).count
        if all.isEmpty {
            Label("None in scope", systemImage: "checkmark.seal")
                .font(Theme.Typography.body)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, minHeight: Self.secondaryChartHeight, alignment: .center)
        } else {
            OverviewSeverityChart(rows: Finding.Severity.allCases.map { severity in
                OverviewSeverityChart.Row(
                    severity: severity,
                    title: severityTitle(severity),
                    count: all.filter { $0.severity == severity }.count
                )
            })
            .frame(height: Self.secondaryChartHeight - 26)
            Button(sessionCount == 1 ? "Review 1 Session" : "Review \(sessionCount.formatted()) Sessions") {
                coordinator.showAggregateFindingSessions()
            }
            .buttonStyle(.link)
            .font(Theme.Typography.captionMedium)
            .help("Show sessions with typed findings in the full session table")
        }
    }

    // MARK: Sources

    /// Who is involved, from the same observed data the sidebar's Sources groups
    /// build on — no fabricated apps, domains, or IPs.
    private func sourcesCard(_ report: Report) -> some View {
        let sources = report.sources
        return OverviewPanel("Sources", caption: "Observed in scope") {
            HStack(alignment: .firstTextBaseline, spacing: Theme.Metrics.spacingL + 8) {
                sourceFigure(sources.apps, label: "Apps", missing: "No attribution")
                sourceFigure(sources.domains, label: "Domains", missing: "None")
                sourceFigure(sources.addresses, label: "Addresses", missing: "None")
            }
        } accessory: {
            Button("Open Flow Map") { coordinator.openFlowPreservingScope() }
                .buttonStyle(.link)
                .font(Theme.Typography.captionMedium)
                .disabled(report.sessions.isEmpty)
                .help("See where this traffic is going")
        }
    }

    private func sourceFigure(_ count: Int, label: String, missing: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            if count > 0 {
                Text(count.formatted())
                    .font(Theme.Typography.metric)
                    .monospacedDigit()
            } else {
                Text(missing)
                    .font(Theme.Typography.body)
                    .foregroundStyle(.orange)
                    .frame(minHeight: 31, alignment: .bottomLeading)
            }
            Text(label)
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label): \(count > 0 ? count.formatted() : missing)")
    }

    // MARK: Building blocks

    private func card(
        padding: CGFloat = Theme.Metrics.spacingL + 4,
        @ViewBuilder _ content: () -> some View
    )
        -> some View
    {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            content()
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .padding(padding)
        .tracexyContentSurface(
            in: RoundedRectangle(cornerRadius: Theme.Metrics.cornerRadius + 4, style: .continuous)
        )
    }

    /// A legend chip: series colour, name and (optionally) its total.
    private func valueChip(_ title: String, value: String?, color: Color) -> some View {
        HStack(spacing: Theme.Metrics.controlSpacing) {
            StatusDot(color, size: 8)
            Text(title)
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
            if let value {
                Text(value)
                    .font(Theme.Typography.captionEmphasis)
                    .monospacedDigit()
            }
        }
        .accessibilityElement(children: .combine)
    }

    private func emptyLine(_ text: String) -> some View {
        Text(text)
            .font(Theme.Typography.body)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, minHeight: 60, alignment: .center)
    }

    /// Scoped findings placed at the instant of their first timed cited frame, in
    /// time order, sampled evenly past the cap so the axis shows where findings
    /// cluster across the whole capture. A finding whose evidence carries no
    /// capture time cannot be placed and is counted only in the findings panel.
    private static func findingMarkers(for findings: [Finding]) -> [OverviewFindingMarker] {
        let placed = findings
            .compactMap { finding -> OverviewFindingMarker? in
                guard let date = finding.citedFrames.compactMap(\.timestamp).min() else {
                    return nil
                }
                return OverviewFindingMarker(
                    id: finding.id, date: date, severity: finding.severity, title: finding.title
                )
            }
            .sorted { ($0.date, $0.id.uuidString) < ($1.date, $1.id.uuidString) }
        return Self.sampled(placed, limit: Self.maximumFindingMarkers)
    }

    /// Visible sessions bucketed by start instant onto the rendered traffic
    /// columns, so the two charts share one axis and one slice width.
    private static func sessionStartColumns(_ report: Report) -> [OverviewSessionStartChart.Column] {
        let points = report.points
        guard let first = points.first else {
            return []
        }
        let width = report.columnWidth
        var counts = [Int](repeating: 0, count: points.count)
        for session in report.sessions {
            guard let start = session.startTime else {
                continue
            }
            let offset = start.timeIntervalSince(first.date)
            let index = width > 0 ? Int((offset / width).rounded(.down)) : 0
            guard index >= 0, index < counts.count else {
                continue
            }
            counts[index] += 1
        }
        guard counts.contains(where: { $0 > 0 }) else {
            return []
        }
        return points.indices.map { OverviewSessionStartChart.Column(date: points[$0].date, count: counts[$0]) }
    }

    private func statusTitle(hasTraffic: Bool) -> String {
        if coordinator.isOpeningSavedCapture {
            return "Loading"
        }
        if isSaved {
            return "Saved"
        }
        return switch coordinator.captureDisplayState {
        case .capturing: "Running"
        case .starting: "Starting"
        case .error: "Error"
        case .stopped: hasTraffic ? "Stopped" : "Ready"
        }
    }

    /// Exact for a saved file; the kernel-received count for a live capture when
    /// available, otherwise the frames the fold accepted. Never a fabricated total.
    private func frameCount(_ timeline: TrafficTimeline) -> Int {
        if isSaved {
            return coordinator.savedCaptureActivity?.totalFrames ?? timeline.totals.frames
        }
        if let received = coordinator.captureStatistics?.received {
            return Int(received)
        }
        return timeline.totals.frames
    }

    private func activityCaption(_ timeline: TrafficTimeline) -> String {
        if timeline.firstTimedFrame == nil {
            return timeline.isEmpty ? "Waiting for traffic" : "No timed frames"
        }
        let width = timeline.bucketWidth
        let slices = width < 60 ? "\(Int(width))-second" : "\(Int(width / 60))-minute"
        return "Wire bytes in \(slices) slices across the whole capture"
    }

    private func findingAxisLabel(placed: Int, total: Int) -> String {
        if placed < total {
            return "\(placed.formatted()) of \(total.formatted()) findings on the axis"
        }
        return total == 1 ? "1 finding on the axis" : "\(total.formatted()) findings on the axis"
    }

    private func durationValue(at now: Date, timeline: TrafficTimeline) -> String {
        if isSaved {
            guard let activity = coordinator.savedCaptureActivity else {
                return "—"
            }
            guard let duration = activity.duration else {
                return "Unknown"
            }
            return durationLabel(duration)
        }
        if coordinator.captureDisplayState == .capturing,
           let startedAt = coordinator.captureStartedAt
        {
            return durationLabel(now.timeIntervalSince(startedAt))
        }
        guard timeline.firstTimedFrame != nil else {
            return timeline.isEmpty ? "—" : "Unknown"
        }
        return timeline.untimedFrameCount == 0 ? durationLabel(timeline.timedSpan) : "Unknown"
    }

    private func percentText(_ fraction: Double) -> String {
        let clamped = min(max(fraction, 0), 1)
        if clamped > 0, clamped < 0.01 {
            return "<1%"
        }
        return clamped.formatted(.percent.precision(.fractionLength(0)))
    }

    private func byteString(_ bytes: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .binary)
    }

    private func durationLabel(_ seconds: TimeInterval) -> String {
        let value = max(0, seconds)
        if value == 0 {
            return "0 s"
        }
        if value < 1 {
            return "\(Int((value * 1_000).rounded())) ms"
        }
        if value < 60 {
            return String(format: "%.1f s", value)
        }
        let whole = Int(value.rounded(.down))
        if whole < 3_600 {
            return "\(whole / 60)m \(whole % 60)s"
        }
        return "\(whole / 3_600)h \((whole % 3_600) / 60)m"
    }

    private func severityTitle(_ severity: Finding.Severity) -> String {
        switch severity {
        case .error: String(localized: "Errors")
        case .warning: String(localized: "Warnings")
        case .note: String(localized: "Notes")
        }
    }
}
