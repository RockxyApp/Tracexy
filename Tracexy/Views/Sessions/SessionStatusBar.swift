import Combine
import SwiftUI

// MARK: - SessionStatusBar

/// Bottom status bar showing session counts, error count, capture duration, and
/// byte totals. Mirrors the sibling app's `StatusBarView` layout, adapted to capture data.
struct SessionStatusBar: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    let visibleCount: Int

    var body: some View {
        let workspace = coordinator.activeWorkspace
        HStack(spacing: 0) {
            leftButtons(workspace)
            Spacer(minLength: 24)
            Text(statusText(workspace))
                .font(Theme.Typography.body)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            Spacer(minLength: 24)
            rightStats
        }
        .padding(.horizontal, 12)
        .frame(height: Theme.Metrics.statusBarHeight)
        .background(.bar)
        .overlay(alignment: .top) { Divider() }
    }

    // MARK: Private

    private var rightStats: some View {
        HStack(spacing: 10) {
            if coordinator.errorCount > 0 {
                HStack(spacing: 3) {
                    Image(systemName: "exclamationmark.triangle.fill").font(.system(size: Theme.Icon.small))
                    Text("\(coordinator.errorCount) errors").font(.system(size: Theme.Icon.medium))
                }
                .foregroundStyle(.red)
            }

            if let startedAt = coordinator.captureStartedAt {
                CaptureDurationView(startedAt: startedAt)
            }

            Text("\(formattedBytes(coordinator.totalBytes)) total")
                .font(Theme.Typography.body)
                .foregroundStyle(.tertiary)
                .help("Total captured payload bytes")

            Text("↑ \(formattedBytes(coordinator.totalBytesUp))")
                .font(Theme.Typography.body)
                .foregroundStyle(.green)
                .help("Total bytes sent")

            Text("↓ \(formattedBytes(coordinator.totalBytesDown))")
                .font(Theme.Typography.body)
                .foregroundStyle(Color.accentColor)
                .help("Total bytes received")
        }
        .lineLimit(1)
    }

    private func leftButtons(_ workspace: WorkspaceState) -> some View {
        HStack(spacing: 6) {
            StatusBarButton(title: "Clear") { coordinator.clearSessions() }
            StatusBarButton(
                title: workspace.activeFilterRules.isEmpty ? "Filter" : "Filter (on)",
                isActive: workspace.isAdvancedFilterVisible || !workspace.activeFilterRules.isEmpty
            ) {
                // Keep the category tabs visible, and reveal/hide the advanced rule
                // builder directly beneath them.
                workspace.isFilterBarVisible = true
                workspace.isAdvancedFilterVisible.toggle()
            }
            StatusBarButton(
                title: "Auto Select",
                isActive: workspace.autoSelectLatest
            ) {
                workspace.autoSelectLatest.toggle()
            }
        }
    }

    private func statusText(_ workspace: WorkspaceState) -> String {
        let total = coordinator.sessions.count
        if total == 0 {
            return "No sessions"
        }
        if workspace.selectedSessionID != nil {
            return "\(visibleCount) shown · 1 selected"
        }
        if visibleCount != total {
            return "\(visibleCount) of \(total) sessions"
        }
        return "\(total) sessions"
    }

    private func formattedBytes(_ bytes: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .binary)
    }
}

// MARK: - StatusBarButton

/// A compact capsule chip in the status bar, matching the sibling app's
/// `FooterToolingChrome`: semibold label, accent fill when active, a subtle
/// hover fill otherwise.
private struct StatusBarButton: View {
    // MARK: Internal

    let title: String
    var isActive = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(Theme.Typography.captionEmphasis)
                .foregroundStyle(foreground)
                .lineLimit(1)
                .padding(.horizontal, 9)
                .padding(.vertical, 3)
                .background(background, in: Capsule())
        }
        .buttonStyle(.plain)
        .onHover { isHovered = $0 }
    }

    // MARK: Private

    @State private var isHovered = false

    private var foreground: Color {
        if isActive {
            return .white
        }
        return isHovered ? .primary : .secondary
    }

    private var background: Color {
        if isActive {
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
