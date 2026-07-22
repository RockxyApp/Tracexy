import Charts
import SwiftUI

/// The earned intelligence surface: a scrollable set of cards that only becomes
/// valuable once sessions exist. Capture *fidelity* leads, because every figure
/// below it is conditional on it; then findings (the centerpiece), top talkers,
/// throughput, protocol mix and latency.
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
                captureFidelityCard
                findingsCard
                LazyVGrid(columns: columns, alignment: .leading, spacing: Theme.Metrics.spacingL) {
                    topTalkersCard
                    throughputCard
                    protocolMixCard
                    latencyCard
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

    private let columns = [GridItem(.adaptive(minimum: 240), spacing: Theme.Metrics.spacingL)]

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

    // MARK: Capture fidelity

    /// The first thing on this surface, because every figure below it is
    /// conditional on it. Interface, capture state and throughput used to lead
    /// here; they were already on the toolbar and the status bar on every
    /// surface, so the surface opened with the one thing that was both redundant
    /// and instantaneous, and pushed its only unique content below the fold.
    ///
    /// What belongs here instead is the question none of that chrome answers:
    /// are these numbers computed over all the traffic, or only some of it?
    private var captureFidelityCard: some View {
        let stats = coordinator.captureStatistics
        return card {
            sectionLabel("Capture fidelity", systemImage: "checkmark.seal")
            if let stats, let fidelity = stats.fidelity {
                HStack(alignment: .firstTextBaseline, spacing: Theme.Metrics.spacingM) {
                    Text(Self.percent.string(from: fidelity as NSNumber) ?? "—")
                        .font(Theme.Typography.metric)
                        .foregroundStyle(stats.isLossy ? Color.orange : Color.green)
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
            }
        }
    }

    // MARK: Findings

    private var findingsCard: some View {
        // Scoped like every other rollup here. The sidebar badge and the Security
        // surface stay capture-wide on purpose — those answer "does this capture
        // have problems", not "does what I am looking at have problems".
        let visibleIDs = Set(coordinator.visibleSessions.map(\.id))
        let all = coordinator.findings.filter { finding in
            guard let id = finding.sessionID else {
                return true
            }
            return visibleIDs.contains(id)
        }
        let shown = Array(all.prefix(20))
        return card {
            sectionLabel("Findings", systemImage: "sparkle.magnifyingglass")
            if all.isEmpty {
                emptyFindings
            } else {
                ForEach(shown) { finding in
                    findingRow(finding)
                }
                if all.count > shown.count {
                    Text("+\(all.count - shown.count) more")
                        .font(Theme.Typography.monoSmall)
                        .foregroundStyle(.tertiary)
                        .padding(.top, 2)
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
            .frame(height: 140)
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

    // MARK: Latency

    private var latencyCard: some View {
        card {
            sectionLabel("Latency", systemImage: "clock")
            HStack(alignment: .firstTextBaseline, spacing: 20) {
                latencyStat("Median", coordinator.medianLatencyMilliseconds)
                latencyStat("p95", coordinator.p95LatencyMilliseconds)
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
        Label(title, systemImage: systemImage)
            .font(Theme.Typography.sectionHeader)
            .foregroundStyle(.secondary)
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
}
