import SwiftUI

// MARK: - ContextDockView

/// The right-hand **interpretation** column.
///
/// It is a separate object from the evidence inspector, not a second orientation
/// of it. The evidence inspector answers *what does this session contain*; the
/// dock answers *what does it mean* — how this session compares with the rest of
/// the capture, what else is related to it, and what was flagged about it.
///
/// The division matters because it is what stops the two panels duplicating each
/// other. Anything that is a literal fact about the selected session (headers,
/// payload, decoded layers, hex) belongs in the evidence inspector. Anything that
/// requires looking at *other* sessions to state — a baseline, a peer, a
/// concentration — can only be said here, and is the reason the column exists.
///
/// Scope is always the current selection. Capture-wide aggregation belongs to the
/// Overview surface, never to this dock.
///
/// The dock has to hold four selection states, and the approved design treats
/// them as one component rather than four screens:
///
/// - **A · single session** — one conversation; the layer's own facts lead.
/// - **B · correlated group** — the recommended default unit; the action leads.
/// - **C · multi-selection** — many actions; only cross-selection aggregates can
///   be stated, because the evidence inspector structurally cannot show N things.
/// - **D · no selection** — must teach, not blank.
struct ContextDockView: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        VStack(spacing: 0) {
            tabStrip
            Divider()
            ScrollView {
                content
                    .padding(.horizontal, Theme.Metrics.spacingL)
                    .padding(.vertical, Theme.Metrics.spacingL)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.regularMaterial)
    }

    // MARK: Private

    /// The facet picker. Always three tabs, unlike the evidence inspector's
    /// progressive disclosure: the dock's tabs are *places* the user learns once,
    /// and a strip that changes width per selection is what made them un-learnable.
    /// A facet with nothing to say says so in its body instead of vanishing.
    private var tabStrip: some View {
        Picker("Context", selection: Binding(
            get: { coordinator.activeWorkspace.contextDockTab },
            set: { coordinator.activeWorkspace.contextDockTab = $0 }
        )) {
            ForEach(ContextDockTab.allCases) { tab in
                Text(tab.title).tag(tab)
            }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .padding(.horizontal, Theme.Metrics.spacingM)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    @ViewBuilder private var content: some View {
        switch coordinator.activeWorkspace.contextDockTab {
        case .insight: insight
        case .related: relatedTab
        case .security: securityTab
        }
    }

    // MARK: State D — no selection

    /// Must teach, not blank. The empty state states the dock's job so the column
    /// is legible before anything is selected.
    private var noSelection: some View {
        VStack(spacing: Theme.Metrics.spacingM) {
            Spacer(minLength: 40)
            Image(systemName: "circle.dashed")
                .font(.system(size: Theme.Icon.hero))
                .foregroundStyle(.tertiary)
            Text("No selection")
                .font(Theme.Typography.surfaceTitle)
            Text("Select an action to see how it compares with its own history.")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, Theme.Metrics.spacingL)
            Spacer(minLength: 40)
        }
        .frame(maxWidth: .infinity)
    }

    // MARK: Insight

    @ViewBuilder private var insight: some View {
        if let session = coordinator.selectedSession {
            let activity = coordinator.activity(containing: session)
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
                identity(for: session, activity: activity)
                verdict(for: session)
                // State B leads with how the action spent its time; state A has a
                // single span, so its own layer's facts lead instead.
                if let activity, activity.sessions.count > 1 {
                    whereTheTimeWent(activity)
                } else {
                    thisLayer(session)
                }
                hostBaseline(for: session)
                relatedActions(for: session)
                if let activity, activity.sessions.count > 1 {
                    whyGrouped(activity)
                } else if let activity {
                    partOfAnAction(activity, selected: session)
                }
                askButton(activity == nil ? "Ask about this session" : "Ask about this action")
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } else {
            noSelection
        }
    }

    // MARK: Related tab

    @ViewBuilder private var relatedTab: some View {
        if let session = coordinator.selectedSession {
            let peers = relatedSessions(for: session)
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
                SectionHeader("OTHER SESSIONS")
                if peers.isEmpty {
                    facetEmpty("Nothing else in this capture shares this host or process.")
                } else {
                    ForEach(peers) { peer in
                        relatedCard(peer, to: session)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } else {
            noSelection
        }
    }

    // MARK: Security tab

    @ViewBuilder private var securityTab: some View {
        if let session = coordinator.selectedSession {
            let items = findings(for: session)
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
                SectionHeader("FLAGGED HERE")
                if items.isEmpty {
                    facetEmpty("Nothing was flagged on this selection.")
                } else {
                    ForEach(items) { finding in
                        HStack(alignment: .top, spacing: Theme.Metrics.spacingM) {
                            Image(systemName: finding.severity.systemImage)
                                .foregroundStyle(finding.severity.tint)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(finding.title)
                                    .font(Theme.Typography.bodyMedium)
                                Text(finding.subtitle)
                                    .font(Theme.Typography.micro)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer(minLength: 0)
                        }
                        .padding(.vertical, 3)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } else {
            noSelection
        }
    }

    private func identity(for session: SessionSummary, activity: Activity?) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(activity?.title ?? session.host)
                .font(Theme.Typography.title)
                .lineLimit(1)
                .truncationMode(.middle)
            Text(subtitle(for: session, activity: activity))
                .font(Theme.Typography.body)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
        }
    }

    /// The one-line judgement. Stated only when there is enough history on this
    /// host to make a comparison — otherwise the dock says so rather than
    /// implying a baseline it does not have.
    @ViewBuilder
    private func verdict(for session: SessionSummary) -> some View {
        let peers = peerLatencies(for: session)
        if let latency = session.latencyMilliseconds, let median = median(of: peers), peers.count >= 3 {
            let isSlow = median > 0 && latency / median >= 1.5
            HStack(alignment: .top, spacing: Theme.Metrics.spacingM) {
                Image(systemName: isSlow ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                    .font(.system(size: Theme.Icon.medium))
                    .foregroundStyle(isSlow ? Color.orange : Color.green)
                VStack(alignment: .leading, spacing: 2) {
                    Text(isSlow ? "Slower than usual for this host" : "Normal for this host")
                        .font(Theme.Typography.bodyEmphasis)
                    Text("\(Self.ms(latency)) vs \(Self.ms(median)) median over the last hour")
                        .font(Theme.Typography.micro)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(Theme.Metrics.spacingM)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: Theme.Metrics.cornerRadius)
                    .fill((isSlow ? Color.orange : Color.green).opacity(0.10))
            )
        } else {
            Text("Not enough history on this host to compare yet.")
                .font(Theme.Typography.micro)
                .foregroundStyle(.tertiary)
        }
    }

    // MARK: Where the time went

    /// How the action's wall-clock time divided across its protocols.
    ///
    /// This is the dock's headline for a correlated group because it is the
    /// question a grouped action exists to answer — *which step was slow* — and
    /// it cannot be asked of a single conversation.
    @ViewBuilder
    private func whereTheTimeWent(_ activity: Activity) -> some View {
        let phases = timePhases(activity)
        let total = phases.reduce(0) { $0 + $1.milliseconds }
        if total > 0 {
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
                SectionHeader("WHERE THE TIME WENT")
                GeometryReader { geo in
                    HStack(spacing: 1) {
                        ForEach(phases) { phase in
                            phase.color
                                .frame(width: max(geo.size.width * phase.milliseconds / total, 2))
                        }
                        Spacer(minLength: 0)
                    }
                }
                .frame(height: 6)
                .clipShape(Capsule())

                VStack(alignment: .leading, spacing: 3) {
                    ForEach(phases) { phase in
                        HStack(spacing: Theme.Metrics.spacingM) {
                            StatusDot(phase.color)
                            Text(phase.name)
                                .font(Theme.Typography.caption)
                            Spacer(minLength: Theme.Metrics.spacingM)
                            Text(Self.ms(phase.milliseconds))
                                .font(Theme.Typography.caption)
                                .monospacedDigit()
                                .foregroundStyle(.secondary)
                            Text("\(Int((phase.milliseconds / total * 100).rounded()))%")
                                .font(Theme.Typography.caption)
                                .monospacedDigit()
                                .foregroundStyle(.secondary)
                                .frame(width: 34, alignment: .trailing)
                        }
                    }
                }
            }
        }
    }

    /// State A's counterpart to "where the time went": the facts of the layer the
    /// selected session actually terminated in, read off its own decode rather
    /// than compared with anything.
    @ViewBuilder
    private func thisLayer(_ session: SessionSummary) -> some View {
        let fields = topLayerFields(session)
        if !fields.isEmpty {
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
                SectionHeader("THIS LAYER")
                ForEach(Array(fields.enumerated()), id: \.offset) { _, field in
                    HStack(alignment: .top, spacing: Theme.Metrics.spacingM) {
                        Text(field.name)
                            .font(Theme.Typography.caption)
                            .foregroundStyle(.secondary)
                            .frame(width: 78, alignment: .leading)
                        Text(field.value)
                            .font(Theme.Typography.caption)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                        Spacer(minLength: 0)
                    }
                }
            }
        }
    }

    // MARK: Host baseline

    /// The host's recent latency history as a sparkline, with the selected
    /// session called out inside it.
    ///
    /// A min/median/max triple was what this used to be, and it could not answer
    /// the question the panel is for: whether *this* run is unusual. The shape of
    /// the distribution is the answer, so it is drawn rather than summarised.
    @ViewBuilder
    private func hostBaseline(for session: SessionSummary) -> some View {
        let history = baselineHistory(for: session)
        if history.count >= 3 {
            let peak = history.map(\.milliseconds).max() ?? 1
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
                SectionHeader("HOST BASELINE · LAST 60 MIN")
                HStack(alignment: .bottom, spacing: 2) {
                    ForEach(history) { point in
                        RoundedRectangle(cornerRadius: 1)
                            .fill(point.isCurrent ? Color.accentColor : Color.secondary.opacity(0.35))
                            .frame(height: max(28 * point.milliseconds / peak, 2))
                            .frame(maxWidth: .infinity)
                    }
                }
                .frame(height: 28)
                HStack(spacing: Theme.Metrics.spacingM) {
                    Text("p50 \(Self.ms(median(of: history.map(\.milliseconds)) ?? 0))")
                        .foregroundStyle(.secondary)
                    Spacer(minLength: 0)
                    if let now = session.latencyMilliseconds {
                        Text("now \(Self.ms(now))")
                            .foregroundStyle(Color.accentColor)
                    }
                }
                .font(Theme.Typography.micro)
                .monospacedDigit()
            }
        }
    }

    // MARK: Related actions

    /// Where else this host or process shows up — the cross-selection navigation
    /// a per-session tab structurally cannot offer, surfaced inline in Insight
    /// because it is part of reading the selection, not a separate errand.
    @ViewBuilder
    private func relatedActions(for session: SessionSummary) -> some View {
        let peers = relatedSessions(for: session)
        if !peers.isEmpty {
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
                SectionHeader("RELATED ACTIONS")
                ForEach(peers.prefix(4)) { peer in
                    relatedCard(peer, to: session)
                }
            }
        }
    }

    private func relatedCard(_ peer: SessionSummary, to session: SessionSummary) -> some View {
        Button {
            coordinator.select(peer)
        } label: {
            HStack(spacing: Theme.Metrics.spacingM) {
                Image(systemName: peer.status.systemImage)
                    .font(.system(size: Theme.Icon.small))
                    .foregroundStyle(Theme.color(for: peer.status))
                VStack(alignment: .leading, spacing: 1) {
                    Text(relationLabel(peer, to: session))
                        .font(Theme.Typography.body)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(peer.host)
                        .font(Theme.Typography.micro)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer(minLength: Theme.Metrics.spacingM)
                if let latency = peer.latencyMilliseconds {
                    Text(Self.ms(latency))
                        .font(Theme.Typography.caption)
                        .monospacedDigit()
                        .foregroundStyle(peer.status == .error ? Color.red : .secondary)
                }
                Image(systemName: "chevron.right")
                    .font(.system(size: Theme.Icon.small))
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, Theme.Metrics.spacingM)
            .padding(.vertical, 7)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 6)
                    .fill(Color.primary.opacity(0.04))
                    .overlay(
                        RoundedRectangle(cornerRadius: 6)
                            .stroke(Color.primary.opacity(0.08), lineWidth: 1)
                    )
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    // MARK: Why grouped

    /// Why these sessions were grouped, and how strongly.
    ///
    /// Correlation is inference, so the claim travels with its evidence and its
    /// confidence. A contested attribution — the same address claimed by more
    /// than one name, which is the normal case behind a CDN — is shown as
    /// contested rather than resolved silently in favour of the first candidate.
    /// The escape hatch ships with the claim: a grouping the user can't undo is
    /// a guess they can't disagree with.
    private func whyGrouped(_ activity: Activity) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            SectionHeader("WHY THESE ARE GROUPED")

            Text(activity.protocolPath.map(\.label).joined(separator: " → "))
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)

            ForEach(Array(activity.evidence.enumerated()), id: \.offset) { _, item in
                HStack(alignment: .top, spacing: Theme.Metrics.spacingM) {
                    Image(systemName: Self.symbol(for: item.tier))
                        .font(.system(size: Theme.Icon.small))
                        .foregroundStyle(Self.tint(for: item.tier))
                        .padding(.top, 2)
                    Text(item.summary)
                        .font(Theme.Typography.caption)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: Theme.Metrics.spacingM)
                    confidencePill(item.tier)
                }
            }

            if activity.isContested {
                Text("Also resolved to this address: \(activity.competingNames.joined(separator: ", ")). "
                    + "The grouping cannot be confirmed from DNS alone.")
                    .font(Theme.Typography.micro)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Button("Ungroup · edit grouping") {
                coordinator.activeWorkspace.sessionGrouping = .none
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .frame(maxWidth: .infinity)
            .padding(.top, 2)
        }
    }

    /// State A's grouping affordance: the single session says which action owns
    /// it and offers the way up, instead of explaining a grouping it isn't part of.
    private func partOfAnAction(_ activity: Activity, selected: SessionSummary) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            SectionHeader("PART OF AN ACTION")
            Button {
                if let first = activity.sessions.first(where: { $0.id != selected.id }) {
                    coordinator.select(first)
                }
            } label: {
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: Theme.Metrics.spacingM) {
                        Text(activity.title)
                            .font(Theme.Typography.bodyMedium)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer(minLength: 0)
                        confidencePill(activity.confidence)
                    }
                    Text("1 of \(activity.sessions.count) sessions · view whole action ›")
                        .font(Theme.Typography.micro)
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, Theme.Metrics.spacingM)
                .padding(.vertical, 7)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    RoundedRectangle(cornerRadius: 6)
                        .fill(Color.accentColor.opacity(0.06))
                        .overlay(
                            RoundedRectangle(cornerRadius: 6)
                                .stroke(Color.accentColor.opacity(0.25), lineWidth: 1)
                        )
                )
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
        }
    }

    // MARK: Shared chrome

    /// A facet with nothing to say says so, rather than removing its own tab —
    /// a strip whose width changes per selection cannot be learned.
    private func facetEmpty(_ text: String) -> some View {
        Text(text)
            .font(Theme.Typography.caption)
            .foregroundStyle(.tertiary)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func confidencePill(_ tier: ConfidenceTier) -> some View {
        Text(tier.title)
            .font(Theme.Typography.badge)
            .padding(.horizontal, 6)
            .padding(.vertical, 1)
            .background(Capsule().fill(Self.tint(for: tier).opacity(0.15)))
            .foregroundStyle(Self.tint(for: tier))
    }

    /// The handoff to the assistant, carrying the current scope. Disabled rather
    /// than hidden until the session API lands, so the affordance's place in the
    /// panel is already learnable.
    private func askButton(_ title: String) -> some View {
        Button {
            // TODO: routes to the in-app session API once TracexyMCP lands.
        } label: {
            Text(title)
                .font(Theme.Typography.bodyMedium)
                .frame(maxWidth: .infinity)
        }
        .buttonStyle(.bordered)
        .controlSize(.small)
        .tint(Color.accentColor)
        .disabled(true)
        .help("Ask the assistant about this selection — available once the session API ships.")
    }

    /// A glyph per tier, so confidence is legible without relying on colour —
    /// the tier is the one thing in this panel a colour-blind user most needs.
    private static func symbol(for tier: ConfidenceTier) -> String {
        switch tier {
        case .causal: "arrow.triangle.branch"
        case .strong: "checkmark.circle.fill"
        case .weak: "questionmark.circle"
        }
    }

    private static func tint(for tier: ConfidenceTier) -> Color {
        switch tier {
        case .causal: .green
        case .strong: .blue
        case .weak: .orange
        }
    }

    private static func ms(_ value: Double) -> String {
        value >= 1_000
            ? String(format: "%.2f s", value / 1_000)
            : String(format: "%.0f ms", value)
    }

    /// What the span of a session of this protocol actually measures, so the
    /// legend names the work rather than just the layer.
    private static func phaseName(for proto: ProtocolKind) -> String {
        switch proto {
        case .tls: "TLS handshake"
        case .tcp: "TCP connect"
        default: proto.label
        }
    }

    // MARK: Derivation

    private func subtitle(for session: SessionSummary, activity: Activity?) -> String {
        var parts: [String] = []
        if let process = session.processName {
            parts.append(process)
        }
        if let activity, activity.sessions.count > 1 {
            parts.append("\(activity.sessions.count) sessions")
        } else {
            parts.append(session.protocolStack.map(\.label).joined(separator: " · "))
        }
        return parts.joined(separator: " · ")
    }

    /// One bar per protocol of the action, summing the time its sessions held.
    ///
    /// Derived from the members' real durations only — no phase is invented. When
    /// decoders start emitting typed sub-phases (DNS · connect · handshake ·
    /// TTFB), they map onto this same shape and the bar renders unchanged.
    private func timePhases(_ activity: Activity) -> [TimeShare] {
        var order: [ProtocolKind] = []
        var totals: [ProtocolKind: Double] = [:]
        for session in activity.sessions {
            let proto = session.primaryProtocol
            if totals[proto] == nil {
                order.append(proto)
            }
            totals[proto, default: 0] += session.duration * 1_000
        }
        return order
            .map {
                TimeShare(
                    name: Self.phaseName(for: $0),
                    milliseconds: totals[$0] ?? 0,
                    color: Theme.color(for: $0)
                )
            }
            .sorted { $0.milliseconds > $1.milliseconds }
    }

    /// The host's measured latencies over the last hour, oldest first, with the
    /// selected session marked so the sparkline can call it out.
    private func baselineHistory(for session: SessionSummary) -> [BaselinePoint] {
        let cutoff = session.startTime.addingTimeInterval(-3_600)
        return coordinator.sessions
            .filter { $0.host == session.host && $0.startTime >= cutoff }
            .sorted { $0.startTime < $1.startTime }
            .compactMap { peer in
                peer.latencyMilliseconds.map {
                    BaselinePoint(id: peer.id, milliseconds: $0, isCurrent: peer.id == session.id)
                }
            }
    }

    /// The fields of the outermost decoded layer — the one the session actually
    /// terminated in, which is what "this layer" means to the user.
    private func topLayerFields(_ session: SessionSummary) -> [DecodedField] {
        var deepest: DecodedLayer?
        var stack = session.decodedLayers
        while let next = stack.popLast() {
            if !next.fields.isEmpty {
                deepest = next
            }
            stack.append(contentsOf: next.children)
        }
        return Array((deepest?.fields ?? []).prefix(6))
    }

    private func relationLabel(_ peer: SessionSummary, to session: SessionSummary) -> String {
        let time = peer.startTime.formatted(date: .omitted, time: .standard)
        if peer.host == session.host {
            return "Same host · \(time)"
        }
        if let process = session.processName, peer.processName == process {
            return "Same process · \(process)"
        }
        return "Related · \(time)"
    }

    /// Peers worth offering: the same host first, then the same process. Capped —
    /// this is a navigation aid, not a second session list.
    private func relatedSessions(for session: SessionSummary) -> [SessionSummary] {
        let sameHost = coordinator.sessions.filter { $0.id != session.id && $0.host == session.host }
        let sameProcess = coordinator.sessions.filter {
            $0.id != session.id
                && $0.host != session.host
                && $0.processName != nil
                && $0.processName == session.processName
        }
        return Array((sameHost + sameProcess).prefix(8))
    }

    private func findings(for session: SessionSummary) -> [Finding] {
        coordinator.findings.filter { $0.sessionID == session.id }
    }

    private func peerLatencies(for session: SessionSummary) -> [Double] {
        coordinator.sessions
            .filter { $0.host == session.host }
            .compactMap(\.latencyMilliseconds)
    }

    private func median(of values: [Double]) -> Double? {
        guard !values.isEmpty else {
            return nil
        }
        let sorted = values.sorted()
        let mid = sorted.count / 2
        return sorted.count.isMultiple(of: 2) ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid]
    }
}

// MARK: - TimeShare

/// One protocol's slice of a correlated action's wall-clock time.
private struct TimeShare: Identifiable {
    let name: String
    let milliseconds: Double
    let color: Color

    var id: String {
        name
    }
}

// MARK: - BaselinePoint

/// One measured latency in the host's recent history.
private struct BaselinePoint: Identifiable {
    let id: UUID
    let milliseconds: Double
    let isCurrent: Bool
}
