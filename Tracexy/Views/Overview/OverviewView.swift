import Charts
import SwiftUI

/// The capture-centric Overview: a bounded, truthful summary of the capture the
/// user is looking at, answering *what am I looking at, what happened, who is
/// involved, what needs attention, and where is it stored* — for both a live
/// capture and an opened saved file.
///
/// Every number is derived from real decoded/captured data via the coordinator.
/// Live and saved are deliberately distinguished: a live capture reports running
/// state, live throughput, kernel/helper fidelity, and local save-buffer
/// retention; a saved file reports its provenance, an activity-over-time chart
/// built from real frame timestamps, and an explicitly *unknown* fidelity — never
/// a fabricated clean figure, and never the live "waiting for traffic" state.
struct OverviewView: View {
    // MARK: Internal

    var coordinator: MainContentCoordinator

    var body: some View {
        GeometryReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
                    scopeNotice
                    summaryStrip
                    if proxy.size.width >= Self.wideDashboardMinimumWidth {
                        wideBody
                    } else {
                        compactBody
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
        }
    }

    // MARK: Private

    private static let percent: NumberFormatter = {
        let formatter = NumberFormatter()
        formatter.numberStyle = .percent
        formatter.maximumFractionDigits = 2
        return formatter
    }()

    private static let summaryHorizontalMinimumWidth: CGFloat = 760
    /// The three-column dashboard needs enough *workspace* width to preserve its
    /// readable card columns. Below this point it reflows instead of relying on
    /// intrinsic measurement that can extend beneath the native sidebar.
    private static let wideDashboardMinimumWidth: CGFloat = 1_280

    private let compactColumns = [
        GridItem(.adaptive(minimum: 260), spacing: Theme.Metrics.spacingL),
    ]

    /// True while an opened saved capture is on screen (versus a live/idle one).
    private var isSaved: Bool {
        coordinator.isViewingSavedCapture
    }

    /// Scoped like every other rollup here. This summary describes the same
    /// filtered session set as the surrounding charts.
    private var scopedFindings: [Finding] {
        let visibleIDs = Set(coordinator.visibleSessions.map(\.id))
        return coordinator.findings.filter { finding in
            visibleIDs.contains(finding.sessionID)
        }
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
            return "Saved capture · \(savedFormat) · \(linkTypeName)"
        }
        let state = switch coordinator.captureDisplayState {
        case .capturing: "Live capture"
        case .starting: "Starting"
        case .error: "Capture error"
        case .stopped: coordinator.sessions.isEmpty ? "Idle" : "Stopped capture"
        }
        return "\(state) · \(linkTypeName)"
    }

    private var savedFormat: String {
        let ext = coordinator.activeSavedCapture?.url.pathExtension ?? "pcap"
        return ext.isEmpty ? "PCAP" : ext.uppercased()
    }

    private var linkTypeName: String {
        switch coordinator.currentLinkType {
        case LinkType.ethernet: "Ethernet"
        case LinkType.raw: "Raw IP"
        case LinkType.null: "Loopback"
        default: "Link type \(coordinator.currentLinkType)"
        }
    }

    /// Frames shown in the KPI strip: exact for a saved file; the kernel-received
    /// count for a live capture when available, otherwise the frames currently
    /// held. Never a fabricated total.
    private var frameCount: Int {
        if isSaved {
            return coordinator.savedCaptureActivity?.totalFrames ?? coordinator.retainedFrameCount
        }
        if let received = coordinator.captureStatistics?.received {
            return Int(received)
        }
        return coordinator.retainedFrameCount
    }

    /// The span of the currently accumulated live sessions, for a stopped capture.
    private var sessionsSpanLabel: String {
        let sessions = coordinator.presentedSessions
        guard let earliest = sessions.map(\.startTime).min() else {
            return "—"
        }
        let latest = sessions
            .map { $0.startTime.addingTimeInterval($0.duration) }
            .max() ?? earliest
        return secondsLabel(max(0, latest.timeIntervalSince(earliest)))
    }

    private var activitySubtitle: String {
        if isSaved {
            return "Frames over capture time"
        }
        return "Throughput · live bytes per second"
    }

    private var fidelityValue: String {
        if isSaved {
            return "Unknown"
        }
        guard let fidelity = coordinator.captureStatistics?.fidelity else {
            return "Unknown"
        }
        return Self.percent.string(from: fidelity as NSNumber) ?? "—"
    }

    private var fidelityTint: Color {
        if isSaved {
            return .orange
        }
        guard let stats = coordinator.captureStatistics, stats.fidelity != nil else {
            return .orange
        }
        return (stats.isLossy || coordinator.helperBufferDropCount > 0) ? .orange : .green
    }

    /// Captured payload currently available for immediate packet inspection.
    /// This is deliberately not labelled as a save estimate: the complete live
    /// capture is stored independently in the disk-backed pcapng spool.
    private var inspectionWindowBytes: Int {
        coordinator.retainedCapturedByteCount
    }

    // MARK: Layout

    private var wideBody: some View {
        Grid(
            alignment: .topLeading,
            horizontalSpacing: Theme.Metrics.spacingL,
            verticalSpacing: Theme.Metrics.spacingL
        ) {
            GridRow(alignment: .top) {
                activityCard
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                    .gridCellColumns(2)
                storageCard
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
            GridRow(alignment: .top) {
                topTalkersCard
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                protocolMixCard
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                sourceSummaryCard
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
        }
    }

    private var compactBody: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            activityCard
            storageCard
            LazyVGrid(columns: compactColumns, alignment: .leading, spacing: Theme.Metrics.spacingL) {
                topTalkersCard
                protocolMixCard
                sourceSummaryCard
            }
        }
    }

    /// Says out loud when the numbers below describe a filtered subset. Without
    /// this the surface and the session list can disagree with no visible reason.
    @ViewBuilder private var scopeNotice: some View {
        if coordinator.activeWorkspace.hasActiveFilters {
            Label(
                "Showing \(coordinator.visibleSessions.count.formatted()) of "
                    + "\(coordinator.presentedSessions.count.formatted()) sessions — a filter is active.",
                systemImage: "line.3.horizontal.decrease.circle"
            )
            .font(Theme.Typography.caption)
            .foregroundStyle(.secondary)
        }
    }

    // MARK: Summary strip (identity + KPIs + fidelity)

    private var summaryStrip: some View {
        card {
            ViewThatFits(in: .horizontal) {
                HStack(alignment: .top, spacing: Theme.Metrics.spacingL) {
                    identityBlock
                        .frame(maxWidth: .infinity, alignment: .leading)
                    kpiRow
                }
                .frame(minWidth: Self.summaryHorizontalMinimumWidth, alignment: .topLeading)
                VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
                    identityBlock
                    kpiRow
                }
            }
            Divider()
            findingSummaryBar
        }
    }

    private var identityBlock: some View {
        VStack(alignment: .leading, spacing: 2) {
            SectionHeader("Overview")
            Text(identityTitle)
                .font(Theme.Typography.title)
                .lineLimit(1)
            Text(identitySubtitle)
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            if isSaved {
                Button("View in Library") {
                    coordinator.activeWorkspace.navigatorMode = .library
                }
                .buttonStyle(.link)
                .font(Theme.Typography.captionMedium)
                .help("Reveal this file in the Library navigator")
                .padding(.top, 2)
            }
        }
    }

    private var kpiRow: some View {
        HStack(alignment: .top, spacing: Theme.Metrics.spacingL) {
            kpi("Frames", value: frameCount.formatted())
            kpi("Sessions", value: coordinator.presentedSessions.count.formatted())
            kpi("Traffic", value: byteString(coordinator.totalBytes))
            TimelineView(.periodic(from: .now, by: 1)) { context in
                kpi("Duration", value: durationValue(at: context.date))
            }
            kpi("Fidelity", value: fidelityValue, tint: fidelityTint)
        }
        .fixedSize(horizontal: false, vertical: true)
    }

    // MARK: Capture activity

    /// Live shows the live throughput plot; a saved file shows a bounded
    /// frames-over-time chart built from real captured timestamps — never the
    /// live "waiting for traffic" empty state.
    private var activityCard: some View {
        card {
            HStack(spacing: Theme.Metrics.spacingM) {
                sectionLabel("Capture Activity", systemImage: "waveform.path.ecg")
                Spacer()
                Button(
                    isSaved
                        ? "Open all \(coordinator.presentedSessions.count.formatted()) sessions"
                        : "Open live sessions"
                ) {
                    coordinator.selectSidebarItem(.sessions)
                }
                .buttonStyle(.link)
                .font(Theme.Typography.captionMedium)
                .help("Open the session list")
            }
            Text(activitySubtitle)
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
            if isSaved {
                savedActivityChart
            } else {
                ThroughputChart(samples: coordinator.throughputSamples)
                    .frame(height: 168)
                    .overlay(alignment: .center) {
                        if coordinator.throughputSamples.isEmpty {
                            Text("Waiting for traffic…")
                                .font(Theme.Typography.caption)
                                .foregroundStyle(.tertiary)
                        }
                    }
            }
        }
    }

    @ViewBuilder private var savedActivityChart: some View {
        if let activity = coordinator.savedCaptureActivity, !activity.isEmpty {
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
                Chart(activity.buckets) { bucket in
                    BarMark(
                        x: .value("Bucket", bucket.index),
                        y: .value("Frames", bucket.frameCount)
                    )
                    .foregroundStyle(Color.accentColor.gradient)
                    .cornerRadius(2)
                }
                .chartXAxis(.hidden)
                .chartYAxis {
                    AxisMarks(position: .leading, values: .automatic(desiredCount: 3)) { value in
                        AxisGridLine().foregroundStyle(.quaternary)
                        AxisValueLabel {
                            if let frames = value.as(Int.self) {
                                Text(frames.formatted()).font(Theme.Typography.micro)
                            }
                        }
                    }
                }
                .frame(height: 168)
                HStack {
                    Text("0 s").font(Theme.Typography.micro).foregroundStyle(.tertiary)
                    Spacer()
                    Text(secondsLabel(activity.duration))
                        .font(Theme.Typography.micro).foregroundStyle(.tertiary)
                }
            }
        } else {
            Text("No frames in this capture")
                .font(Theme.Typography.body)
                .foregroundStyle(.secondary)
                .frame(height: 168, alignment: .center)
                .frame(maxWidth: .infinity)
        }
    }

    // MARK: Storage

    /// Where the capture lives: a live capture's bounded inspection buffer plus
    /// complete disk-backed spool, or a saved file's on-disk provenance. Fidelity and drops
    /// are reported here so a green figure never implies a complete capture and an
    /// absent one never reads as clean.
    private var storageCard: some View {
        card {
            sectionLabel(isSaved ? "Local Storage" : "Live Buffer", systemImage: "internaldrive")
            Text(isSaved ? "Saved file" : "Unsaved capture")
                .font(Theme.Typography.bodyMedium)
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
                if isSaved {
                    savedStorageRows
                } else {
                    liveStorageRows
                }
            }
            Divider()
            if isSaved {
                Button("Open in Saved Captures") {
                    coordinator.activeWorkspace.navigatorMode = .library
                }
                .buttonStyle(.link)
                .font(Theme.Typography.captionMedium)
            } else {
                Button("Save Capture…", systemImage: "square.and.arrow.down") {
                    coordinator.saveCurrentCapture()
                }
                .buttonStyle(.link)
                .font(Theme.Typography.captionMedium)
                .disabled(!coordinator.canSaveCapture)
                .help("Write the complete disk-backed capture to a .pcapng under Application Support")
            }
        }
    }

    @ViewBuilder private var savedStorageRows: some View {
        storageRow("Format", savedFormat)
        storageRow("File size", byteString(coordinator.activeSavedCapture?.byteCount ?? 0))
        storageRow("Frames", frameCount.formatted())
        storageRow("Fidelity", "Unknown", tint: .orange)
        storageRow("Drop counters", "Unavailable in file")
        Text(
            "A saved file carries no kernel accounting; any loss during the original capture is not recoverable from it."
        )
        .font(Theme.Typography.micro)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder private var liveStorageRows: some View {
        let stats = coordinator.captureStatistics
        let helperDrops = coordinator.helperBufferDropCount
        storageRow(
            "Retention",
            "\(coordinator.retainedFrameCount.formatted()) / \(coordinator.retainedFrameCapacity.formatted()) frames"
        )
        storageRow("Window bytes", byteString(inspectionWindowBytes))
        storageRow("Save format", "PCAPNG")
        if let fidelity = stats?.fidelity {
            let incomplete = (stats?.isLossy ?? false) || helperDrops > 0
            storageRow(
                "Capture health",
                Self.percent.string(from: fidelity as NSNumber) ?? "—",
                tint: incomplete ? .orange : .green
            )
        } else {
            storageRow("Capture health", "Unknown", tint: .orange)
        }
        storageRow("Drop counters", dropCountersText(stats, helperDrops: helperDrops))
        if stats?.isLossy == true {
            Text("Packets were dropped by the capture source, so the figures above understate the traffic.")
                .font(Theme.Typography.micro)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
        }
        if coordinator.retainedFrameEvictionCount > 0 {
            Text(
                "\(coordinator.retainedFrameEvictionCount.formatted()) older frames left the inspection window — the complete disk-backed capture and sessions are unaffected."
            )
            .font(Theme.Typography.micro)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: Top talkers

    private var topTalkersCard: some View {
        let talkers = coordinator.topHosts()
        let maxBytes = talkers.map(\.bytes).max() ?? 0
        return card {
            HStack(spacing: Theme.Metrics.spacingM) {
                sectionLabel("Top Talkers", systemImage: "chart.bar.xaxis")
                Spacer()
                if !talkers.isEmpty {
                    Button("Open Sessions") { coordinator.selectSidebarItem(.sessions) }
                        .buttonStyle(.link)
                        .font(Theme.Typography.captionMedium)
                }
            }
            if talkers.isEmpty {
                Text("No traffic yet").font(Theme.Typography.body).foregroundStyle(.secondary)
            } else {
                ForEach(talkers, id: \.host) { entry in
                    talkerRow(host: entry.host, bytes: entry.bytes, maxBytes: maxBytes)
                }
            }
        }
    }

    // MARK: Protocol mix

    private var protocolMixCard: some View {
        let kinds: [ProtocolKind] = [.dns, .tcp, .udp, .tls, .http, .http2, .quic, .stun]
        let entries = kinds
            .map { (kind: $0, hits: coordinator.count(for: $0)) }
            .filter { $0.hits > 0 }
        let maxHits = entries.map(\.hits).max() ?? 0
        return card {
            sectionLabel("Protocol Mix", systemImage: "chart.bar")
            if entries.isEmpty {
                Text("No protocols decoded yet").font(Theme.Typography.body).foregroundStyle(.secondary)
            } else {
                ForEach(entries, id: \.kind) { entry in
                    protocolRow(kind: entry.kind, hits: entry.hits, maxHits: maxHits)
                }
            }
        }
    }

    // MARK: Source summary

    /// Who is involved, from the same observed data the sidebar's Sources groups
    /// build on — no fabricated apps, domains, or IPs.
    private var sourceSummaryCard: some View {
        let attributedApps = coordinator.appGroups.filter { $0.app != "—" }.count
        return card {
            sectionLabel("Source Summary", systemImage: "person.2")
            sourceRow(
                "Apps",
                attributedApps > 0 ? "\(attributedApps.formatted()) observed" : "No attribution",
                tint: attributedApps > 0 ? .primary : .orange
            )
            sourceRow("Domains", "\(coordinator.domainGroups.count.formatted()) observed")
            sourceRow("IP Addresses", "\(coordinator.ipHosts.count.formatted()) observed")
            Divider()
            Button("Open Flow Map") { coordinator.selectSidebarItem(.flow) }
                .buttonStyle(.link)
                .font(Theme.Typography.captionMedium)
                .help("See where this traffic is going")
        }
    }

    // MARK: Findings summary

    /// Overview summarizes typed observations without duplicating the evidence list.
    /// Individual sessions belong in the scalable Sessions/Findings workflow.
    private var findingSummaryBar: some View {
        let all = scopedFindings
        return HStack(spacing: Theme.Metrics.spacingM) {
            sectionLabel("Findings", systemImage: "sparkle.magnifyingglass")
            if all.isEmpty {
                emptyFindings
            } else {
                findingSeveritySummary(all)
                Spacer(minLength: Theme.Metrics.spacingM)
                Button("Review \(all.count.formatted()) in Sessions") {
                    coordinator.showFindingSessions()
                }
                .buttonStyle(.link)
                .font(Theme.Typography.captionMedium)
                .help("Show sessions with typed findings in the full session table")
            }
        }
    }

    private var emptyFindings: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Image(systemName: "checkmark.seal").foregroundStyle(.green)
            Text("No findings in the current scope")
                .font(Theme.Typography.body)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }

    private func kpi(_ label: String, value: String, tint: Color = .primary) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label.uppercased())
                .font(Theme.Typography.micro)
                .tracking(0.5)
                .foregroundStyle(.secondary)
            Text(value)
                .font(Theme.Typography.title)
                .foregroundStyle(tint)
                .monospacedDigit()
                .lineLimit(1)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label): \(value)")
    }

    private func storageRow(_ label: String, _ value: String, tint: Color = .primary) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label)
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
            Spacer(minLength: Theme.Metrics.spacingM)
            Text(value)
                .font(Theme.Typography.caption)
                .foregroundStyle(tint)
                .monospacedDigit()
                .multilineTextAlignment(.trailing)
        }
    }

    private func talkerRow(host: String, bytes: Int, maxBytes: Int) -> some View {
        Button {
            coordinator.selectHost(host)
        } label: {
            HStack(spacing: Theme.Metrics.spacingM) {
                Text(host)
                    .font(Theme.Typography.caption)
                    .lineLimit(1)
                    .frame(width: 118, alignment: .leading)
                proportionBar(fraction: maxBytes > 0 ? Double(bytes) / Double(maxBytes) : 0, tint: .accentColor)
                Text(byteString(bytes))
                    .font(Theme.Typography.monoMicro)
                    .foregroundStyle(.secondary)
                    .frame(width: 62, alignment: .trailing)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Show sessions for \(host)")
    }

    @ViewBuilder
    private func protocolRow(kind: ProtocolKind, hits: Int, maxHits: Int) -> some View {
        let destination = protocolDestination(kind)
        Button {
            if let destination {
                coordinator.selectSidebarItem(destination)
            }
        } label: {
            HStack(spacing: Theme.Metrics.spacingM) {
                Text(kind.label)
                    .font(Theme.Typography.caption)
                    .lineLimit(1)
                    .frame(width: 60, alignment: .leading)
                proportionBar(fraction: maxHits > 0 ? Double(hits) / Double(maxHits) : 0, tint: Theme.color(for: kind))
                Text(hits.formatted())
                    .font(Theme.Typography.monoMicro)
                    .foregroundStyle(.secondary)
                    .frame(width: 40, alignment: .trailing)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(destination == nil)
        .help(destination == nil
            ? "\(kind.label): \(hits.formatted()) sessions"
            : "Filter the session list to \(kind.label)")
    }

    private func sourceRow(_ label: String, _ value: String, tint: Color = .primary) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label).font(Theme.Typography.caption).foregroundStyle(.secondary)
            Spacer(minLength: Theme.Metrics.spacingM)
            Text(value).font(Theme.Typography.caption).foregroundStyle(tint).monospacedDigit()
        }
    }

    private func findingSeveritySummary(_ findings: [Finding]) -> some View {
        HStack(spacing: Theme.Metrics.spacingS) {
            ForEach(Finding.Severity.allCases, id: \.self) { severity in
                let count = findings.filter { $0.severity == severity }.count
                if count > 0 {
                    Label(count.formatted(), systemImage: severity.systemImage)
                        .font(Theme.Typography.microMedium)
                        .foregroundStyle(severity.tint)
                        .padding(.horizontal, Theme.Metrics.spacingM)
                        .padding(.vertical, Theme.Metrics.spacingS)
                        .background(severity.tint.opacity(0.1), in: Capsule())
                        .accessibilityLabel("\(severityTitle(severity)): \(count.formatted())")
                }
            }
        }
    }

    // MARK: Building blocks

    private func card(@ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            content()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .padding(Theme.Metrics.spacingL)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: Theme.Metrics.cornerRadius))
    }

    private func sectionLabel(_ title: String, systemImage: String) -> some View {
        SectionHeader(title, systemImage: systemImage)
    }

    /// A thin proportional fill over a track — the row-level bar used by Top
    /// Talkers and Protocol Mix. Bounded to `0...1`; a zero fraction shows the bare
    /// track rather than trapping.
    private func proportionBar(fraction: Double, tint: Color) -> some View {
        let clamped = min(max(fraction, 0), 1)
        return GeometryReader { proxy in
            ZStack(alignment: .leading) {
                Capsule().fill(.quaternary.opacity(0.5))
                Capsule().fill(tint.gradient)
                    .frame(width: max(0, proxy.size.width * clamped))
            }
        }
        .frame(height: 6)
        .frame(maxWidth: .infinity)
    }

    private func durationValue(at now: Date) -> String {
        if isSaved {
            return secondsLabel(coordinator.savedCaptureActivity?.duration ?? 0)
        }
        if coordinator.captureDisplayState == .capturing,
           let startedAt = coordinator.captureStartedAt
        {
            return secondsLabel(now.timeIntervalSince(startedAt))
        }
        return sessionsSpanLabel
    }

    private func dropCountersText(_ stats: CaptureStatistics?, helperDrops: UInt64) -> String {
        let kernel = stats.map { $0.totalDropped.formatted() } ?? "—"
        return "Kernel \(kernel) · helper \(helperDrops.formatted())"
    }

    private func protocolDestination(_ kind: ProtocolKind) -> SidebarItem? {
        switch kind {
        case .dns: .dns
        case .tcp: .tcp
        case .tls: .tls
        case .http: .http
        case .quic: .quic
        case .stun: .stun
        default: nil
        }
    }

    private func byteString(_ bytes: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .binary)
    }

    /// A human duration for the KPI strip and activity axis: milliseconds under a
    /// second, seconds otherwise, always non-negative.
    private func secondsLabel(_ seconds: TimeInterval) -> String {
        let value = max(0, seconds)
        if value == 0 {
            return "0 s"
        }
        if value < 1 {
            return "\(Int((value * 1_000).rounded())) ms"
        }
        return String(format: "%.2f s", value)
    }

    private func severityTitle(_ severity: Finding.Severity) -> String {
        switch severity {
        case .error: String(localized: "Errors")
        case .warning: String(localized: "Warnings")
        case .note: String(localized: "Notes")
        }
    }
}
