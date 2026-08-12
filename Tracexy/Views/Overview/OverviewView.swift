import Charts
import SwiftUI

/// The earned intelligence surface: a bounded dashboard that only becomes
/// valuable once sessions exist. Capture health and traffic charts stay visible
/// near the top; findings are a severity summary plus a short actionable preview,
/// never an unbounded list that pushes every chart below the fold.
///
/// Live capture state — interface, running/stopped, current throughput — is
/// deliberately absent: the toolbar and status bar already carry it on every
/// surface, and repeating it here made this surface open with something both
/// redundant and instantaneous while its unique content sat below the fold.
///
/// Every number is derived from real decoded data via the coordinator; nothing
/// here is fabricated.
struct OverviewView: View {
    // MARK: Internal

    var coordinator: MainContentCoordinator

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
                scopeNotice
                ViewThatFits(in: .horizontal) {
                    wideDashboard
                    compactDashboard
                }
            }
            .padding(Theme.Metrics.spacingL)
        }
    }

    // MARK: Private

    private static let percent: NumberFormatter = {
        let formatter = NumberFormatter()
        formatter.numberStyle = .percent
        formatter.maximumFractionDigits = 2
        return formatter
    }()

    private static let findingPreviewLimit = 5

    private let compactColumns = [
        GridItem(.adaptive(minimum: 260), spacing: Theme.Metrics.spacingL),
    ]

    /// Scoped like every other rollup here. The sidebar badge and Security
    /// surface remain capture-wide on purpose; this preview describes the same
    /// filtered session set as the surrounding charts.
    private var scopedFindings: [Finding] {
        let visibleIDs = Set(coordinator.visibleSessions.map(\.id))
        return coordinator.findings.filter { finding in
            guard let id = finding.sessionID else {
                return true
            }
            return visibleIDs.contains(id)
        }
    }

    private var wideDashboard: some View {
        HStack(alignment: .top, spacing: Theme.Metrics.spacingL) {
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
                captureHealthCard
                throughputCard
                HStack(alignment: .top, spacing: Theme.Metrics.spacingL) {
                    topTalkersCard
                    protocolMixCard
                }
            }
            .frame(minWidth: 520)

            findingsCard
                .frame(width: 340)
        }
    }

    private var compactDashboard: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            captureHealthCard
            throughputCard
            LazyVGrid(columns: compactColumns, alignment: .leading, spacing: Theme.Metrics.spacingL) {
                topTalkersCard
                protocolMixCard
            }
            findingsCard
        }
    }

    /// Says out loud when the numbers below describe a filtered subset. Without
    /// this the surface and the session list can disagree with no visible reason.
    @ViewBuilder private var scopeNotice: some View {
        if coordinator.activeWorkspace.hasActiveFilters {
            Label(
                "Showing \(coordinator.visibleSessions.count.formatted()) of "
                    + "\(coordinator.sessions.count.formatted()) sessions — a filter is active.",
                systemImage: "line.3.horizontal.decrease.circle"
            )
            .font(Theme.Typography.caption)
            .foregroundStyle(.secondary)
        }
    }

    // MARK: Capture health

    /// Capture fidelity and decoded latency share one compact health card. Both
    /// qualify the charts below, and neither needs a full-width card of its own.
    private var captureHealthCard: some View {
        card {
            sectionLabel("Capture Health", systemImage: "checkmark.seal")
            ViewThatFits(in: .horizontal) {
                HStack(alignment: .center, spacing: Theme.Metrics.spacingL) {
                    fidelitySummary
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Divider()
                        .frame(height: 68)
                    latencySummary
                }
                VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
                    fidelitySummary
                    Divider()
                    latencySummary
                }
            }
        }
    }

    @ViewBuilder private var fidelitySummary: some View {
        let stats = coordinator.captureStatistics
        // Helper-stage loss is a separate figure from the kernel `pcap_stats`
        // fidelity below. It can be non-zero even when the kernel reports a
        // perfect capture, so it must pull the presentation off green and warn
        // rather than being folded into (or hidden behind) the percent.
        let helperDrops = coordinator.helperBufferDropCount
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            Text("Fidelity")
                .font(Theme.Typography.captionMedium)
                .foregroundStyle(.secondary)
            if let stats, let fidelity = stats.fidelity {
                let incomplete = stats.isLossy || helperDrops > 0
                HStack(alignment: .firstTextBaseline, spacing: Theme.Metrics.spacingM) {
                    Text(Self.percent.string(from: fidelity as NSNumber) ?? "—")
                        .font(Theme.Typography.metric)
                        .foregroundStyle(incomplete ? Color.orange : Color.green)
                        .monospacedDigit()
                    Text("captured")
                        .font(Theme.Typography.body)
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                Text(Self.lossDetail(stats))
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
                if stats.isLossy {
                    Text("Packets were dropped, so the figures below understate the traffic.")
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.orange)
                }
                helperDropNotice(helperDrops)
            } else {
                Text("Not measured")
                    .font(Theme.Typography.surfaceTitle)
                    .foregroundStyle(.secondary)
                Text(coordinator.isViewingSavedCapture
                    ? "A saved capture carries no kernel accounting — any loss during the original capture is not recoverable from the file."
                    : "Capture loss is reported once a live capture is running.")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                // Even with no kernel figure, known helper-stage loss is reported
                // truthfully rather than left implied by "Not measured".
                helperDropNotice(helperDrops)
            }
        }
    }

    private var latencySummary: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            Text("Latency")
                .font(Theme.Typography.captionMedium)
                .foregroundStyle(.secondary)
            HStack(alignment: .firstTextBaseline, spacing: Theme.Metrics.spacingL) {
                latencyStat("Median", coordinator.medianLatencyMilliseconds)
                latencyStat("p95", coordinator.p95LatencyMilliseconds)
            }
        }
    }

    // MARK: Findings

    private var findingsCard: some View {
        let all = scopedFindings
        let shown = Array(all.prefix(Self.findingPreviewLimit))
        return card {
            HStack(spacing: Theme.Metrics.spacingM) {
                sectionLabel("Findings", systemImage: "sparkle.magnifyingglass")
                Spacer()
                Text(all.count.formatted())
                    .font(Theme.Typography.monoSmall)
                    .foregroundStyle(.secondary)
                if !all.isEmpty {
                    Button("Open Security") {
                        coordinator.selectSidebarItem(.security)
                    }
                    .buttonStyle(.link)
                    .font(Theme.Typography.captionMedium)
                    .help("Show the capture-wide Security findings list")
                }
            }
            if all.isEmpty {
                emptyFindings
            } else {
                findingSeveritySummary(all)
                Divider()
                ForEach(shown) { finding in
                    findingRow(finding)
                }
                if all.count > shown.count {
                    Text("Showing \(shown.count.formatted()) of \(all.count.formatted())")
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.tertiary)
                }
            }
        }
    }

    private var emptyFindings: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Image(systemName: "checkmark.seal").foregroundStyle(.green)
            Text("No findings — traffic looks healthy")
                .font(Theme.Typography.body)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }

    // MARK: Top talkers

    private var topTalkersCard: some View {
        let talkers = coordinator.topHosts()
        return card {
            sectionLabel("Top Talkers", systemImage: "chart.bar.xaxis")
            if talkers.isEmpty {
                Text("No traffic yet").font(Theme.Typography.body).foregroundStyle(.secondary)
            } else {
                Chart(talkers, id: \.host) { entry in
                    BarMark(
                        x: .value("Bytes", entry.bytes),
                        y: .value("Host", entry.host)
                    )
                    .foregroundStyle(Color.accentColor.gradient)
                    .cornerRadius(3)
                    .annotation(position: .trailing, alignment: .leading, spacing: 4) {
                        Text(ByteCountFormatter.string(fromByteCount: Int64(entry.bytes), countStyle: .binary))
                            .font(Theme.Typography.monoSmall)
                            .foregroundStyle(.secondary)
                    }
                }
                .chartXAxis(.hidden)
                .chartYAxis {
                    AxisMarks(preset: .aligned, position: .leading) { value in
                        AxisValueLabel {
                            if let host = value.as(String.self) {
                                Text(host).font(Theme.Typography.micro).lineLimit(1)
                            }
                        }
                    }
                }
                .frame(height: CGFloat(talkers.count) * 24 + 8)
                .animation(.smooth, value: talkers.map(\.bytes))
            }
        }
    }

    // MARK: Throughput

    private var throughputCard: some View {
        RealtimeChart(samples: coordinator.throughputSamples)
            .frame(height: 184)
    }

    // MARK: Protocol mix

    private var protocolMixCard: some View {
        let kinds: [ProtocolKind] = [.dns, .tcp, .udp, .tls, .http, .http2, .quic]
        let entries = kinds
            .map { (kind: $0, hits: coordinator.count(for: $0)) }
            .filter { $0.hits > 0 }
        return card {
            sectionLabel("Protocol Mix", systemImage: "chart.bar")
            if entries.isEmpty {
                Text("No protocols decoded yet").font(Theme.Typography.body).foregroundStyle(.secondary)
            } else {
                Chart(entries, id: \.kind) { entry in
                    BarMark(
                        x: .value("Sessions", entry.hits),
                        y: .value("Protocol", entry.kind.label)
                    )
                    .foregroundStyle(Theme.color(for: entry.kind))
                    .cornerRadius(3)
                    .annotation(position: .trailing, alignment: .leading, spacing: 4) {
                        Text(entry.hits.formatted())
                            .font(Theme.Typography.monoSmall)
                            .foregroundStyle(.secondary)
                    }
                }
                .chartXAxis(.hidden)
                .chartYAxis {
                    AxisMarks(preset: .aligned, position: .leading) { value in
                        AxisValueLabel {
                            if let label = value.as(String.self) {
                                Text(label).font(Theme.Typography.micro)
                            }
                        }
                    }
                }
                .frame(height: CGFloat(entries.count) * 26 + 8)
                .animation(.smooth, value: entries.map(\.hits))
            }
        }
    }

    /// A compact warning that the capture helper dropped frames before they
    /// reached the app — shown whenever the count is non-zero, so a green kernel
    /// fidelity never implies a complete capture when the helper stage lost data.
    @ViewBuilder
    private func helperDropNotice(_ helperDrops: UInt64) -> some View {
        if helperDrops > 0 {
            Text("\(helperDrops.formatted()) frames were dropped by the capture helper before reaching the app.")
                .font(Theme.Typography.caption)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
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

    private func latencyStat(_ label: String, _ milliseconds: Double?) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(milliseconds.map { "\(Int($0)) ms" } ?? "—")
                .font(Theme.Typography.metricRounded)
                .foregroundStyle(Theme.latencyColor(milliseconds: milliseconds))
            Text(label).font(Theme.Typography.micro).foregroundStyle(.secondary)
        }
    }

    // MARK: Building blocks

    private func card(@ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(Theme.Metrics.spacingL)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: Theme.Metrics.cornerRadius))
    }

    private func sectionLabel(_ title: String, systemImage: String) -> some View {
        // Centralize casing, tracking, font and colour in `SectionHeader` so every
        // Overview card titles the same way; the glyph keeps its secondary tint.
        SectionHeader(title, systemImage: systemImage)
    }

    private func findingRow(_ finding: Finding) -> some View {
        Button {
            guard let id = finding.sessionID,
                  let session = coordinator.sessions.first(where: { $0.id == id }) else
            {
                return
            }
            coordinator.selectSidebarItem(.sessions)
            coordinator.select(session)
        } label: {
            HStack(spacing: Theme.Metrics.spacingM) {
                Image(systemName: finding.severity.systemImage)
                    .foregroundStyle(finding.severity.tint)
                    .frame(width: 18)
                VStack(alignment: .leading, spacing: 1) {
                    Text(finding.title).font(Theme.Typography.bodyMedium).lineLimit(1)
                    Text(finding.subtitle).font(Theme.Typography.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
                Image(systemName: "chevron.right").font(.system(size: Theme.Icon.small)).foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private static func lossDetail(_ stats: CaptureStatistics) -> String {
        let dropped = stats.totalDropped
        guard dropped > 0 else {
            return "\(stats.received.formatted()) packets · none dropped by the kernel buffer or the interface"
        }
        return "\(stats.received.formatted()) captured · "
            + "\(stats.droppedByKernel.formatted()) dropped by the kernel buffer · "
            + "\(stats.droppedByInterface.formatted()) dropped by the interface"
    }

    private func severityTitle(_ severity: Finding.Severity) -> String {
        switch severity {
        case .error: String(localized: "Errors")
        case .warning: String(localized: "Warnings")
        case .note: String(localized: "Notes")
        }
    }
}
