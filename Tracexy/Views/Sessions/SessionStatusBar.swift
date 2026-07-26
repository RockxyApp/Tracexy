import Combine
import SwiftUI

// MARK: - StatusSurface

/// Which central surface the status bar sits under. Only the session list owns
/// the Clear / Filter / Auto Select controls — those act on the session stream,
/// so on Overview / Flow / Security they would be dead affordances. The
/// intelligence surfaces get a quiet summary of the same real capture instead.
enum StatusSurface {
    case sessionList
    case overview
    case flow
    case security

    // MARK: Internal

    var showsSessionControls: Bool {
        self == .sessionList
    }
}

// MARK: - SessionFooterAction

/// A stable, pure description of one session-footer control.
///
/// It carries no view and no closure, so its ordering, identity and
/// active/enabled state can be asserted directly in a unit test. The view maps
/// `kind` to the matching coordinator/workspace callback; the descriptor itself
/// never mutates capture or session data. `systemImage` is the *base* symbol —
/// the active fill variant is applied at render time, so the descriptor stays a
/// value with no rendering concerns.
struct SessionFooterAction: Identifiable, Equatable {
    enum Kind: String, CaseIterable {
        case clear
        case filter
        case autoSelect
    }

    let kind: Kind
    let title: String
    let systemImage: String
    let isActive: Bool
    let isEnabled: Bool

    var id: Kind {
        kind
    }
}

// MARK: - SessionStatusBarModel

/// Pure derivations for the session footer: the ordered action descriptors and
/// the center status string. Kept free of SwiftUI so both are unit-testable and
/// so every responsive presentation reads from one source of truth rather than
/// re-deriving state per layout.
enum SessionStatusBarModel {
    /// The footer actions, always in the same order (Clear → Filter → Auto
    /// Select). Order and identity are stable so the overflow menu and the inline
    /// variants never disagree about which control is which.
    static func actions(
        activeFilterRuleCount: Int,
        isAdvancedFilterVisible: Bool,
        autoSelectLatest: Bool,
        hasSessions: Bool
    )
        -> [SessionFooterAction]
    {
        [
            SessionFooterAction(
                kind: .clear,
                title: "Clear",
                systemImage: "trash",
                isActive: false,
                // Nothing to clear on an empty capture — a disabled Clear is more
                // honest than one that silently no-ops.
                isEnabled: hasSessions
            ),
            SessionFooterAction(
                kind: .filter,
                title: activeFilterRuleCount > 0 ? "Filter (on)" : "Filter",
                systemImage: "line.3.horizontal.decrease.circle",
                isActive: isAdvancedFilterVisible || activeFilterRuleCount > 0,
                isEnabled: true
            ),
            SessionFooterAction(
                kind: .autoSelect,
                title: "Auto Select",
                systemImage: "arrow.down.circle",
                isActive: autoSelectLatest,
                isEnabled: true
            ),
        ]
    }

    /// The center status string. This is the exact behaviour the footer shipped
    /// with, lifted verbatim into a pure function so it can be tested and reused.
    static func statusText(
        surface: StatusSurface,
        totalSessions: Int,
        visibleCount: Int,
        hasSelection: Bool,
        findingCount: Int
    )
        -> String
    {
        switch surface {
        case .security:
            return findingCount == 0
                ? "No findings"
                : "\(findingCount) \(findingCount == 1 ? "finding" : "findings")"
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
        if selectedCount > 0 {
            return "\(visibleCount) shown · \(selectedCount) selected"
        }
        if visibleCount != totalSessions {
            return "\(visibleCount) of \(totalSessions) sessions"
        }
        return "\(totalSessions) sessions"
    }
}

// MARK: - SessionStatusBar

/// Bottom status bar showing session counts, error count, capture duration, and
/// byte totals. Surface-aware: session controls appear only over the session
/// list; every surface still gets the shared summary + capture stats footer.
///
/// The left-hand controls are descriptor-driven (`SessionStatusBarModel`) and
/// responsive: `ViewThatFits` steps from labelled icon buttons, to icon-only
/// buttons, to a single native overflow menu as the window narrows.
struct SessionStatusBar: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    let visibleCount: Int

    var surface: StatusSurface = .sessionList

    var body: some View {
        let workspace = coordinator.activeWorkspace
        WorkspaceFooterBar(surface: .workspace) {
            HStack(spacing: 0) {
                if surface.showsSessionControls {
                    leftControls(workspace)
                }
                Spacer(minLength: Theme.Metrics.spacingL)
                Text(statusText(workspace))
                    .font(Theme.Typography.body)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .layoutPriority(1)
                Spacer(minLength: Theme.Metrics.spacingL)
                rightStats
            }
            .padding(.horizontal, Theme.Metrics.spacingL)
        }
    }

    // MARK: Private

    /// Full and compact variants share one `ViewThatFits`: as the window
    /// narrows the bandwidth breakdown drops away, but the error state and byte
    /// total — the two things worth knowing at a glance — always survive.
    private var rightStats: some View {
        ViewThatFits(in: .horizontal) {
            fullStats
            compactStats
        }
        .lineLimit(1)
    }

    private var fullStats: some View {
        HStack(spacing: 10) {
            errorBadge

            if let startedAt = coordinator.captureStartedAt {
                CaptureDurationView(startedAt: startedAt)
            }

            Text("\(formattedBytes(coordinator.totalBytes)) total")
                .font(Theme.Typography.body)
                .foregroundStyle(.tertiary)
                .help("Total captured payload bytes")

            Text("↑ \(formattedBytes(coordinator.totalBytesUp))")
                .font(Theme.Typography.body)
                .foregroundStyle(Color(nsColor: .systemGreen))
                .help("Total bytes sent")

            Text("↓ \(formattedBytes(coordinator.totalBytesDown))")
                .font(Theme.Typography.body)
                .foregroundStyle(Color.accentColor)
                .help("Total bytes received")
        }
    }

    private var compactStats: some View {
        HStack(spacing: 8) {
            errorBadge

            Text("\(formattedBytes(coordinator.totalBytes)) total")
                .font(Theme.Typography.body)
                .foregroundStyle(.tertiary)
                .help("Total captured payload bytes")
        }
    }

    @ViewBuilder private var errorBadge: some View {
        if coordinator.errorCount > 0 {
            HStack(spacing: 3) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: Theme.Icon.small))
                Text("\(coordinator.errorCount) errors")
                    .font(Theme.Typography.body)
            }
            .foregroundStyle(Color(nsColor: .systemRed))
        }
    }

    /// The Clear / Filter / Auto Select controls, responsive by width: labelled
    /// icon buttons first, then icon-only buttons, then a single overflow menu.
    /// All three read from the same ordered descriptors, so they never disagree.
    private func leftControls(_ workspace: WorkspaceState) -> some View {
        let actions = footerActions(workspace)
        return ViewThatFits(in: .horizontal) {
            actionRow(actions, workspace, showsLabels: true)
            actionRow(actions, workspace, showsLabels: false)
            overflowMenu(actions, workspace)
        }
    }

    private func actionRow(
        _ actions: [SessionFooterAction],
        _ workspace: WorkspaceState,
        showsLabels: Bool
    )
        -> some View
    {
        HStack(spacing: 6) {
            ForEach(actions) { action in
                FooterActionButton(action: action, showsLabel: showsLabels) {
                    performAction(action.kind, workspace)
                }
            }
        }
    }

    private func overflowMenu(_ actions: [SessionFooterAction], _ workspace: WorkspaceState) -> some View {
        Menu {
            ForEach(actions) { action in
                Button {
                    performAction(action.kind, workspace)
                } label: {
                    Label(action.title, systemImage: action.systemImage)
                }
                .disabled(!action.isEnabled)
            }
        } label: {
            Image(systemName: "ellipsis.circle")
                .font(.system(size: Theme.Icon.medium))
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .help("Session actions")
        .accessibilityLabel("Session actions")
    }

    private func footerActions(_ workspace: WorkspaceState) -> [SessionFooterAction] {
        SessionStatusBarModel.actions(
            activeFilterRuleCount: workspace.activeFilterRules.count,
            isAdvancedFilterVisible: workspace.isAdvancedFilterVisible,
            autoSelectLatest: workspace.autoSelectLatest,
            hasSessions: !coordinator.sessions.isEmpty
        )
    }

    /// Maps a descriptor's identity to its existing real callback. These are the
    /// same three effects the footer always had; nothing new is wired here.
    private func performAction(_ kind: SessionFooterAction.Kind, _ workspace: WorkspaceState) {
        switch kind {
        case .clear:
            coordinator.clearSessions()
        case .filter:
            // Keep the category tabs visible and reveal/hide the advanced rule
            // builder directly beneath them.
            workspace.isFilterBarVisible = true
            workspace.isAdvancedFilterVisible.toggle()
        case .autoSelect:
            workspace.autoSelectLatest.toggle()
        }
    }

    private func statusText(_ workspace: WorkspaceState) -> String {
        SessionStatusBarModel.statusText(
            surface: surface,
            totalSessions: coordinator.sessions.count,
            visibleCount: visibleCount,
            hasSelection: workspace.selectedSessionID != nil,
            findingCount: coordinator.findings.count
        )
    }

    private func formattedBytes(_ bytes: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .binary)
    }
}

// MARK: - FooterActionButton

/// One footer control rendered from a `SessionFooterAction`: an SF Symbol with an
/// optional label, an accent fill when active, and a subtle hover fill otherwise.
/// Help and accessibility label come straight from the descriptor's title so the
/// icon-only variant stays legible to VoiceOver and on hover.
private struct FooterActionButton: View {
    // MARK: Internal

    let action: SessionFooterAction
    var showsLabel: Bool
    let perform: () -> Void

    var body: some View {
        Button(action: perform) {
            HStack(spacing: 4) {
                Image(systemName: action.systemImage)
                    .symbolVariant(action.isActive ? .fill : .none)
                    .font(.system(size: Theme.Icon.medium))
                if showsLabel {
                    Text(action.title)
                        .font(Theme.Typography.captionEmphasis)
                        .lineLimit(1)
                }
            }
            .foregroundStyle(foreground)
            .padding(.horizontal, showsLabel ? 9 : 6)
            .padding(.vertical, 3)
            .background(background, in: Capsule())
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .disabled(!action.isEnabled)
        .onHover { isHovered = $0 }
        .help(action.title)
        .accessibilityLabel(action.title)
        .accessibilityAddTraits(action.isActive ? .isSelected : [])
    }

    // MARK: Private

    @State private var isHovered = false

    private var foreground: Color {
        if action.isActive {
            return .white
        }
        return isHovered ? .primary : .secondary
    }

    private var background: Color {
        if action.isActive {
            return Color.accentColor
        }
        return isHovered ? Color.secondary.opacity(0.18) : .clear
    }
}

// MARK: - CaptureDurationView

/// Elapsed capture time, updating every second.
private struct CaptureDurationView: View {
    // MARK: Internal

    let startedAt: Date

    var body: some View {
        HStack(spacing: 3) {
            Image(systemName: "clock").font(.system(size: Theme.Icon.small))
            Text(formatted).font(Theme.Typography.caption.monospacedDigit())
        }
        .foregroundStyle(.tertiary)
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
