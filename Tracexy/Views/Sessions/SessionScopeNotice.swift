import SwiftUI

// MARK: - SessionScopeNotice

/// One compact line naming what the surface is showing and why, shared by
/// Sessions, Overview and Flow.
///
/// It is informational by default. Recovery belongs to the surface that owns it —
/// the filter shelf already carries Reset Session Filters, and an empty session
/// list owns the full recovery set — so this never adds a second reset control to
/// a shelf that already has one. Surfaces with no shelf of their own (Overview,
/// Flow) opt into the same single action with `showsResetAction`.
///
/// Back to Previous Scope is the exception to that rule: it undoes one explicit
/// drill-in rather than clearing filtering, no shelf owns it, and it is the only
/// part of this line that can appear on its own — a scope the user has already
/// widened by hand still has somewhere to go back to.
///
/// Long values are elided in the line and spelled out in full in `help` and the
/// accessibility label, because a scope the user cannot read is a scope they
/// cannot undo.
struct SessionScopeNotice: View {
    // MARK: Internal

    var coordinator: MainContentCoordinator

    /// The caller's already-filtered count, when it has one. Avoids filtering the
    /// capture a second time purely to draw this line.
    var shownCount: Int?

    /// Whether this notice also offers the shared reset. Off by default so a
    /// shelf that already owns the action never shows it twice.
    var showsResetAction = false

    var body: some View {
        let scope = coordinator.sessionScope(shownCount: shownCount)
        let canReturn = coordinator.canReturnToPreviousSessionScope
        if scope.isConstrained {
            HStack(spacing: Theme.Metrics.spacingS) {
                summary(scope)
                if canReturn {
                    backButton
                }
                if showsResetAction, scope.hasClearableFilters {
                    resetButton
                } else if showsResetAction {
                    Button("Open Sessions") { coordinator.selectSidebarItem(.sessions) }
                        .buttonStyle(.borderless)
                        .help("Review Noise Control or restore sessions removed from view in Sessions.")
                }
                Spacer(minLength: 0)
            }
            .font(Theme.Typography.caption)
            .foregroundStyle(.secondary)
            .accessibilityElement(children: .contain)
        } else if canReturn {
            // A drill-in the user has since widened by hand leaves nothing to
            // describe but still has somewhere to go back to, so the line shrinks
            // to the one action rather than disappearing with it.
            HStack(spacing: Theme.Metrics.spacingS) {
                backButton
                Spacer(minLength: 0)
            }
            .font(Theme.Typography.caption)
            .foregroundStyle(.secondary)
            .accessibilityElement(children: .contain)
        }
    }

    // MARK: Private

    /// The one way back out of an explicit host/process/IP/Findings drill-in.
    /// Compact by design: it sits beside the scope it undoes, not above it.
    private var backButton: some View {
        Button {
            coordinator.returnToPreviousSessionScope()
        } label: {
            ViewThatFits(in: .horizontal) {
                Label(SessionScopeReturnAction.title, systemImage: SessionScopeReturnAction.systemImage)
                Label(SessionScopeReturnAction.shortTitle, systemImage: SessionScopeReturnAction.systemImage)
                Image(systemName: SessionScopeReturnAction.systemImage)
            }
        }
        .buttonStyle(.borderless)
        .font(Theme.Typography.chromeAction)
        .help(SessionScopeReturnAction.help)
        .accessibilityLabel(SessionScopeReturnAction.title)
        .accessibilityHint(SessionScopeReturnAction.help)
    }

    private var resetButton: some View {
        Button {
            coordinator.resetSessionFilters()
        } label: {
            ViewThatFits(in: .horizontal) {
                Label(SessionScopeAction.resetTitle, systemImage: SessionScopeAction.resetSystemImage)
                Label(SessionScopeAction.resetShortTitle, systemImage: SessionScopeAction.resetSystemImage)
                Image(systemName: SessionScopeAction.resetSystemImage)
            }
        }
        .buttonStyle(.borderless)
        .font(Theme.Typography.chromeAction)
        .help(SessionScopeAction.resetHelp)
        .accessibilityLabel(SessionScopeAction.resetTitle)
        .accessibilityHint(SessionScopeAction.resetHelp)
    }

    private func summary(_ scope: SessionScopeSummary) -> some View {
        HStack(spacing: Theme.Metrics.spacingS) {
            Image(systemName: "line.3.horizontal.decrease.circle")
                .accessibilityHidden(true)
            Text(scope.countLine)
                .monospacedDigit()
                .fixedSize(horizontal: true, vertical: false)
            Text(scope.scopeLine)
                .lineLimit(1)
                .truncationMode(.tail)
        }
        .help(scope.accessibilityLabel)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(scope.accessibilityLabel)
    }
}
