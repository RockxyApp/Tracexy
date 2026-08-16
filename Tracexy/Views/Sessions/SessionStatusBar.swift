import Combine
import SwiftUI

// MARK: - StatusSurface

/// Which central surface the status bar sits under. Only the session list owns
/// the feature launchers and List Options — those act on the session stream, so
/// on Overview / Flow they would be dead affordances. Those intelligence
/// surfaces get a quiet summary of the same real capture instead; Security now
/// runs inside the session list as a quick filter.
nonisolated enum StatusSurface {
    case sessionList
    case overview
    case flow

    // MARK: Internal

    var showsSessionControls: Bool {
        self == .sessionList
    }
}

// MARK: - FooterActionDescriptor

/// A stable, pure description of one footer control.
///
/// It carries no view and no closure, so its ordering, identity, placement and
/// enabled/active/destructive state can be asserted directly in a unit test. The
/// view maps `kind` to the matching effect through the `onAction` callback; the
/// descriptor itself never mutates capture or session data. `systemImage` is the
/// *base* symbol — the active fill/check treatment is applied at render time, so
/// the descriptor stays a value with no rendering concerns.
nonisolated struct FooterActionDescriptor: Identifiable, Equatable {
    /// Every real footer effect, in one place. The first three are the inline
    /// feature launchers; the rest are contextual List Options that live in the
    /// More menu.
    enum Kind: String, CaseIterable {
        case saveCapture
        case newFocusSet
        case noiseControl
        case clearSessions
        case advancedFilters
        case autoSelectLatest
    }

    /// Where a descriptor is allowed to appear. Primary tools are the inline quick
    /// launchers; list options are the contextual menu items.
    enum Placement: String {
        case primary
        case listOptions
    }

    let kind: Kind
    let title: String
    let help: String
    let systemImage: String
    let placement: Placement
    /// Stable rank used for ordering; primaries precede list options.
    let priority: Int
    let isEnabled: Bool
    let isActive: Bool
    let isDestructive: Bool

    var id: Kind {
        kind
    }
}

// MARK: - FooterTelemetry

/// A stable, pure description of one right-hand telemetry chip.
///
/// Ordered by importance and emitted only when the underlying data exists, so the
/// footer never shows a zeroed or invented figure. `role` drives colour at render
/// time and encodes the app's status semantics: green is reserved for live
/// capture, red for session errors, orange only for material packet loss, and
/// everything else stays neutral.
nonisolated struct FooterTelemetry: Identifiable, Equatable {
    enum Kind {
        case packetDrops
        case helperDrops
        case sessionErrors
        case captureDuration
        case liveRate
        case totalBytes
        case bytesUp
        case bytesDown
        case retentionTruncation
    }

    enum Role {
        case neutral
        case warning
        case error
        case live
    }

    let kind: Kind
    /// Pre-formatted display text. Empty for `captureDuration`, which the view
    /// renders as a live ticking timer from `FooterSnapshot.captureStartedAt`.
    let text: String
    let help: String
    let systemImage: String?
    let role: Role

    var id: Kind {
        kind
    }
}

// MARK: - FooterSnapshot

/// The complete, pre-derived state the footer needs to render. Built once by the
/// owning view (`MainDetailView`) from the coordinator and handed to the
/// presentation-only `SessionStatusBar`, which never reads the coordinator itself.
nonisolated struct FooterSnapshot: Equatable {
    let summary: String
    let telemetry: [FooterTelemetry]
    /// Present only while a capture is running, so the view can drive the live
    /// duration timer without owning capture state.
    let captureStartedAt: Date?
}

// MARK: - CaptureLoss

/// The three independent loss figures a capture can accrue, grouped so the footer
/// derivation stays under a sane parameter count and — more importantly — so the
/// three stages are named and kept distinct at the call site:
///
/// - kernel/interface loss (`hasStatistics` + `totalDropped` + `isMaterialLoss`),
///   from `pcap_stats`; unknown when no statistics are available;
/// - `helperDropCount`, frames the privileged helper evicted before the app drained
///   them — capture-source loss that is *not* part of the kernel figure;
/// - `retentionEvictionCount`, frames trimmed from the local inspection window —
///   a memory bound, never captured-packet or savefile loss.
nonisolated struct CaptureLoss: Equatable {
    let hasStatistics: Bool
    let totalDropped: UInt64
    let isMaterialLoss: Bool
    let helperDropCount: UInt64
    let retentionEvictionCount: UInt64
}

// MARK: - SessionStatusBarModel

/// Pure derivations for the footer: the ordered action descriptors, the ordered
/// telemetry chips, and the center status string. Kept free of SwiftUI so all
/// three are unit-testable and so every responsive presentation reads from one
/// source of truth rather than re-deriving state per layout.
nonisolated enum SessionStatusBarModel {
    // MARK: Internal

    /// The footer's feature launchers and List Options, always in the same order:
    /// Save Capture → New Focus Set → Noise Control, then Clear Current Sessions →
    /// Advanced Filters → Auto Select Latest. Order and identity are stable so the
    /// inline row, the More menu and the compact menu never disagree about which
    /// control is which.
    static func actions(
        canSaveCapture: Bool,
        canAddFocusSet: Bool,
        isNoiseControlActive: Bool,
        hasSessions: Bool,
        activeFilterRuleCount: Int,
        isAdvancedFilterVisible: Bool,
        autoSelectLatest: Bool
    )
        -> [FooterActionDescriptor]
    {
        [
            // Primary launchers — the three inline quick feature tools.
            FooterActionDescriptor(
                kind: .saveCapture,
                title: "Save Capture",
                help: "Save the complete current capture to a .pcapng file.",
                systemImage: "square.and.arrow.down",
                placement: .primary,
                priority: 0,
                // Nothing to save until frames have been retained.
                isEnabled: canSaveCapture,
                isActive: false,
                isDestructive: false
            ),
            FooterActionDescriptor(
                kind: .newFocusSet,
                title: "New Focus Set",
                help: "Create a focus set from the current advanced filter rules.",
                systemImage: "scope",
                placement: .primary,
                priority: 1,
                isEnabled: canAddFocusSet,
                isActive: false,
                isDestructive: false
            ),
            FooterActionDescriptor(
                kind: .noiseControl,
                title: "Noise Control",
                help: "Mute noisy hosts or protocols so the list stops flooding.",
                systemImage: "speaker.slash",
                placement: .primary,
                priority: 2,
                // Always available: muting is useful before anything is captured.
                isEnabled: true,
                isActive: isNoiseControlActive,
                isDestructive: false
            ),

            // Contextual List Options — the More menu.
            FooterActionDescriptor(
                kind: .clearSessions,
                title: "Clear Capture Data…",
                help: "Remove decoded sessions, retained packets, capture statistics, and throughput history.",
                systemImage: "trash",
                placement: .listOptions,
                priority: 3,
                // A disabled Clear is more honest than one that silently no-ops.
                isEnabled: hasSessions,
                isActive: false,
                isDestructive: true
            ),
            FooterActionDescriptor(
                kind: .advancedFilters,
                title: activeFilterRuleCount > 0 ? "Advanced Filters (on)" : "Advanced Filters",
                help: "Show the advanced filter rule builder.",
                systemImage: "line.3.horizontal.decrease.circle",
                placement: .listOptions,
                priority: 4,
                isEnabled: true,
                isActive: isAdvancedFilterVisible || activeFilterRuleCount > 0,
                isDestructive: false
            ),
            FooterActionDescriptor(
                kind: .autoSelectLatest,
                title: "Auto Select Latest",
                help: "Automatically select the newest session as it arrives.",
                systemImage: "arrow.down.circle",
                placement: .listOptions,
                priority: 5,
                isEnabled: true,
                isActive: autoSelectLatest,
                isDestructive: false
            ),
        ]
    }

    /// The right-hand telemetry chips, ordered by importance and emitted only when
    /// their data exists: kernel/interface drops → helper-stage drops → session
    /// errors → capture duration → combined live rate → session-attributed total →
    /// directional totals → retention truncation.
    ///
    /// The three loss figures are deliberately distinct chips for three distinct
    /// stages. Kernel/interface loss (`totalDropped`) and helper-stage loss
    /// (`helperBufferDropCount`) are both capture-source loss and warn; retention
    /// truncation (`retainedFrameEvictionCount`) is a save/export memory bound and
    /// is never dressed up as captured-packet loss. Folding any of them into
    /// another would misstate where fidelity was lost.
    static func telemetry(
        isCapturing: Bool,
        loss: CaptureLoss,
        errorCount: Int,
        hasCaptureDuration: Bool,
        liveBytesPerSecond: Double?,
        totalBytes: Int,
        bytesUp: Int,
        bytesDown: Int
    )
        -> [FooterTelemetry]
    {
        var items: [FooterTelemetry] = []

        // Packet drops — only when the source reports stats and something was
        // actually lost. Material loss warns (orange); anything below the
        // threshold is shown neutrally rather than dressed up as an alarm. With no
        // statistics at all the chip is omitted, never faked as "none dropped".
        if loss.hasStatistics, loss.totalDropped > 0 {
            items.append(FooterTelemetry(
                kind: .packetDrops,
                text: "\(loss.totalDropped.formatted()) dropped",
                help: loss.isMaterialLoss
                    ? "Material packet loss — the derived numbers may understate the real traffic."
                    : "Some packets were dropped, but below the level that skews the numbers.",
                systemImage: "exclamationmark.triangle.fill",
                role: loss.isMaterialLoss ? .warning : .neutral
            ))
        }

        // Helper-stage drops — frames the privileged helper's staging buffer had
        // to evict before the app drained them. This is real capture-source loss,
        // separate from kernel/interface loss above: it can be non-zero even while
        // `pcap_stats` reports a perfect kernel capture, so it always warns rather
        // than hiding behind a green fidelity figure.
        if loss.helperDropCount > 0 {
            items.append(FooterTelemetry(
                kind: .helperDrops,
                text: "\(loss.helperDropCount.formatted()) helper drops",
                help: "Frames the capture helper dropped before reaching the app — "
                    + "capture-stage loss, not counted in the kernel fidelity figure.",
                systemImage: "exclamationmark.triangle.fill",
                role: .warning
            ))
        }

        // Session errors — labelled "session errors", never a bare "errors".
        if errorCount > 0 {
            items.append(FooterTelemetry(
                kind: .sessionErrors,
                text: errorCount == 1 ? "1 session error" : "\(errorCount.formatted()) session errors",
                help: "Sessions that ended in an error state.",
                systemImage: "xmark.octagon.fill",
                role: .error
            ))
        }

        // Elapsed capture duration — a live timer; the view renders it.
        if hasCaptureDuration {
            items.append(FooterTelemetry(
                kind: .captureDuration,
                text: "",
                help: "Elapsed time since this capture started.",
                systemImage: nil,
                role: .neutral
            ))
        }

        // Combined live rate — only while capturing and only once a sample exists.
        // A single combined figure: directional live speeds are never invented.
        if isCapturing, let bps = liveBytesPerSecond {
            items.append(FooterTelemetry(
                kind: .liveRate,
                text: "\(formatBytes(Int(bps)))/s",
                help: "Combined live throughput across both directions.",
                systemImage: "waveform.path.ecg",
                role: .live
            ))
        }

        // Session-attributed total — the sum of each session's accounted bytes,
        // explicitly not raw payload.
        if totalBytes > 0 {
            items.append(FooterTelemetry(
                kind: .totalBytes,
                text: "\(formatBytes(totalBytes)) total",
                help: "Session-attributed bytes — the sum of each session's accounted bytes, not raw payload.",
                systemImage: nil,
                role: .neutral
            ))
        }

        // Directional cumulative totals (first-observed ↑, reverse ↓). Neutral —
        // green is reserved for live capture status, so a static total never
        // borrows it.
        if bytesUp > 0 {
            items.append(FooterTelemetry(
                kind: .bytesUp,
                text: "↑ \(formatBytes(bytesUp))",
                help: "First-observed direction — cumulative bytes.",
                systemImage: nil,
                role: .neutral
            ))
        }
        if bytesDown > 0 {
            items.append(FooterTelemetry(
                kind: .bytesDown,
                text: "↓ \(formatBytes(bytesDown))",
                help: "Reverse direction — cumulative bytes.",
                systemImage: nil,
                role: .neutral
            ))
        }

        // Memory-window eviction — the immediate inspection window trimmed its
        // oldest frames to stay bounded. This is emphatically *not* capture loss:
        // sessions remain accounted for and the complete raw stream continues to
        // the disk-backed spool used by save/export. Neutral and last, so it never
        // reads as an alarm about missed traffic.
        if loss.retentionEvictionCount > 0 {
            items.append(FooterTelemetry(
                kind: .retentionTruncation,
                text: "\(loss.retentionEvictionCount.formatted()) outside memory window",
                help: "Older raw frames left the bounded inspection window — sessions and the complete "
                    + "disk-backed save remain unaffected.",
                systemImage: "tray.full",
                role: .neutral
            ))
        }

        return items
    }

    /// The center status string. Session-list summaries follow a strict
    /// hierarchy; the intelligence surfaces keep their own quiet summaries.
    static func statusText(
        surface: StatusSurface,
        totalSessions: Int,
        visibleCount: Int,
        hasSelection: Bool
    )
        -> String
    {
        switch surface {
        case .overview:
            return totalSessions == 0 ? "Capture overview · No sessions" : "Capture overview · \(totalSessions) sessions"
        case .flow:
            return totalSessions == 0 ? "Flow map · No sessions" : "Flow map · \(totalSessions) sessions"
        case .sessionList:
            break
        }

        if totalSessions == 0 {
            return "No sessions"
        }
        // Single-selection model: the count is derived from the flag, never a
        // hardcoded "1", so it stays honest if selection is ever cleared.
        let selectedCount = hasSelection ? 1 : 0
        let isFiltered = visibleCount != totalSessions
        if selectedCount > 0 {
            return isFiltered
                ? "\(selectedCount) selected · \(visibleCount) of \(totalSessions) shown"
                : "\(selectedCount) selected · \(totalSessions) sessions"
        }
        if isFiltered {
            return "\(visibleCount) of \(totalSessions) sessions"
        }
        return "\(totalSessions) sessions"
    }

    // MARK: Private

    private static func formatBytes(_ bytes: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .binary)
    }
}

// MARK: - SessionStatusBar

/// Bottom status bar showing the feature launchers, the session/capture summary,
/// and health/telemetry. **Presentation-only**: it receives a pure snapshot,
/// ordered descriptors and an `onAction` callback, and owns no coordinator and no
/// workspace mutation. It lays out as one row in three zones — quick tools on the
/// left, the summary centred, telemetry trailing — inside the shared
/// `WorkspaceFooterBar`.
struct SessionStatusBar: View {
    // MARK: Internal

    let snapshot: FooterSnapshot
    let descriptors: [FooterActionDescriptor]
    let onAction: (FooterActionDescriptor.Kind) -> Void

    var body: some View {
        WorkspaceFooterBar(surface: .workspace) {
            HStack(spacing: 0) {
                quickTools
                Spacer(minLength: 24)
                centerSummary
                Spacer(minLength: 24)
                telemetryRow
            }
            .padding(.horizontal, Theme.Metrics.spacingL)
        }
    }

    // MARK: Private

    private var primaryDescriptors: [FooterActionDescriptor] {
        descriptors.filter { $0.placement == .primary }
    }

    private var listOptionDescriptors: [FooterActionDescriptor] {
        descriptors.filter { $0.placement == .listOptions }
    }

    @ViewBuilder private var quickTools: some View {
        if descriptors.isEmpty {
            // Non-session surfaces expose no actions — status/telemetry only.
            EmptyView()
        } else {
            HStack(spacing: 6) {
                ForEach(primaryDescriptors) { descriptor in
                    FooterActionButton(descriptor: descriptor) {
                        onAction(descriptor.kind)
                    }
                }
                if !listOptionDescriptors.isEmpty {
                    moreMenu(primary: [], options: listOptionDescriptors, help: "List options")
                }
            }
        }
    }

    private var centerSummary: some View {
        Text(snapshot.summary)
            .font(Theme.Typography.chromeSecondary)
            .foregroundStyle(.secondary)
            .lineLimit(1)
            .truncationMode(.tail)
            .layoutPriority(2)
    }

    private var telemetryRow: some View {
        HStack(spacing: 8) {
            ForEach(snapshot.telemetry) { item in
                telemetryChip(item)
            }
        }
        .lineLimit(1)
    }

    private func moreMenu(
        primary: [FooterActionDescriptor],
        options: [FooterActionDescriptor],
        help: String
    )
        -> some View
    {
        Menu {
            ForEach(primary) { menuButton($0) }
            if !primary.isEmpty, !options.isEmpty {
                Divider()
            }
            if !options.isEmpty {
                Section("List Options") {
                    ForEach(options) { menuButton($0) }
                }
            }
        } label: {
            Image(systemName: "ellipsis.circle")
                .font(.system(size: Theme.Icon.medium))
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .help(help)
        .accessibilityLabel(help)
    }

    @ViewBuilder
    private func menuButton(_ descriptor: FooterActionDescriptor) -> some View {
        if descriptor.kind == .autoSelectLatest {
            Toggle(
                isOn: Binding(
                    get: { descriptor.isActive },
                    set: { _ in onAction(descriptor.kind) }
                )
            ) {
                Label(descriptor.title, systemImage: descriptor.systemImage)
            }
            .disabled(!descriptor.isEnabled)
            .help(descriptor.help)
        } else {
            Button(role: descriptor.isDestructive ? .destructive : nil) {
                onAction(descriptor.kind)
            } label: {
                // Active manager/filter states read as a check in compact menus.
                Label(descriptor.title, systemImage: descriptor.isActive ? "checkmark" : descriptor.systemImage)
            }
            .disabled(!descriptor.isEnabled)
            .help(descriptor.help)
            .accessibilityValue(descriptor.isActive ? "Active" : "Inactive")
        }
    }

    private func telemetryChip(_ item: FooterTelemetry) -> some View {
        HStack(spacing: 3) {
            if let symbol = item.systemImage {
                Image(systemName: symbol).font(.system(size: Theme.Icon.small))
            }
            if item.kind == .captureDuration, let startedAt = snapshot.captureStartedAt {
                CaptureDurationView(startedAt: startedAt)
            } else {
                Text(item.text)
                    .font(item.role == .neutral ? Theme.Typography.chromeSecondary : Theme.Typography.chrome)
            }
        }
        .foregroundStyle(color(for: item.role))
        .help(item.help)
    }

    private func color(for role: FooterTelemetry.Role) -> Color {
        switch role {
        case .neutral: .secondary
        case .warning: Color(nsColor: .systemOrange)
        case .error: Color(nsColor: .systemRed)
        case .live: Color(nsColor: .systemGreen)
        }
    }
}

// MARK: - FooterActionButton

/// One inline footer launcher rendered from a `FooterActionDescriptor`: a compact
/// badge capsule pairing the SF Symbol with its title in white. The capsule fills
/// with the accent colour when active, a secondary-label wash on hover, and a
/// tertiary-label wash otherwise, dimming when disabled. Help and accessibility
/// label come straight from the descriptor.
private struct FooterActionButton: View {
    // MARK: Internal

    let descriptor: FooterActionDescriptor
    let perform: () -> Void

    var body: some View {
        Button(action: perform) {
            Label(descriptor.title, systemImage: descriptor.systemImage)
                .font(Theme.Typography.badge)
                .foregroundStyle(Color.white)
                .lineLimit(1)
                .padding(.horizontal, 7)
                .padding(.vertical, 2)
                .background(background, in: Capsule())
                .opacity(descriptor.isEnabled ? 1 : 0.45)
        }
        .buttonStyle(.plain)
        .disabled(!descriptor.isEnabled)
        .onHover { isHovered = $0 }
        .help(descriptor.help)
        .accessibilityLabel(descriptor.title)
        .accessibilityAddTraits(descriptor.isActive ? .isSelected : [])
    }

    // MARK: Private

    @State private var isHovered = false

    private var background: Color {
        if descriptor.isActive {
            return Color.accentColor
        }
        if isHovered, descriptor.isEnabled {
            return Color(nsColor: .secondaryLabelColor).opacity(0.86)
        }
        return Color(nsColor: .tertiaryLabelColor)
    }
}

// MARK: - CaptureDurationView

/// Elapsed capture time, updating every second. Neutral by design — the parent
/// telemetry chip owns the colour.
private struct CaptureDurationView: View {
    // MARK: Internal

    let startedAt: Date

    var body: some View {
        HStack(spacing: 3) {
            Image(systemName: "clock").font(.system(size: Theme.Icon.small))
            Text(formatted).font(Theme.Typography.chromeSecondary.monospacedDigit())
        }
        .onReceive(timer) { now = $0 }
    }

    // MARK: Private

    @State private var now = Date()

    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    private var formatted: String {
        let interval = max(0, Int(now.timeIntervalSince(startedAt)))
        let hours = interval / 3_600
        let minutes = (interval % 3_600) / 60
        let seconds = interval % 60
        if hours > 0 {
            return String(format: "%d:%02d:%02d", hours, minutes, seconds)
        }
        return String(format: "%d:%02d", minutes, seconds)
    }
}
