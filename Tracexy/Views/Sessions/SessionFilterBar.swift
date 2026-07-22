import SwiftUI

// MARK: - SessionFilterBar

/// Flat category-tab filter bar above the session table — a direct port of
/// the sibling app's `ProtocolFilterBar`: an "All" tab, a protocol group, an independent
/// status group (Errors), and a trailing "Reset Filters" action.
struct SessionFilterBar: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let workspace = coordinator.activeWorkspace
        HStack(spacing: 8) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 2) {
                    FilterPillButton(title: "All", isActive: workspace.categoryFilters.isEmpty) {
                        workspace.categoryFilters = []
                    }

                    ForEach(SessionFilterCategory.allCases) { category in
                        FilterPillButton(
                            title: category.title,
                            isActive: workspace.categoryFilters.contains(category)
                        ) {
                            toggle(category, in: workspace)
                        }
                    }
                }
                .padding(.horizontal, 8)
            }

            if workspace.hasActiveFilters {
                Button {
                    reset(workspace)
                } label: {
                    Label("Reset Filters", systemImage: "arrow.clockwise")
                }
                .buttonStyle(.borderless)
                .font(Theme.Typography.body)
                .foregroundStyle(.secondary)
            }

            groupByMenu(workspace)
                .padding(.trailing, 8)
        }
        .padding(.vertical, 5)
        .background(Color(nsColor: .windowBackgroundColor))
        .overlay(alignment: .bottom) { Divider() }
        .fixedSize(horizontal: false, vertical: true)
    }

    // MARK: Private

    /// Grouping, as a trailing icon menu on the filter row.
    ///
    /// It began as a labelled segmented control on its own strip, which was
    /// wrong twice over. It cost a full row of height to express one setting
    /// that is changed rarely — and a permanently-visible segmented control is
    /// how a *filter* looks on macOS, not how a view option does. Finder, Mail
    /// and Xcode all put grouping behind a small toolbar menu, so this does too.
    ///
    /// The icon carries the state rather than a text label: tinted when a
    /// grouping is applied, secondary when the list is flat, which is the same
    /// signal the filter pills beside it already use.
    private func groupByMenu(_ workspace: WorkspaceState) -> some View {
        let isGrouped = workspace.sessionGrouping != .none
        return Menu {
            Picker("Group By", selection: Binding(
                get: { workspace.sessionGrouping },
                set: { workspace.sessionGrouping = $0 }
            )) {
                ForEach(SessionGrouping.allCases) { mode in
                    Label(mode.title, systemImage: mode.systemImage).tag(mode)
                }
            }
            .pickerStyle(.inline)
        } label: {
            Image(systemName: "square.grid.3x1.below.line.grid.1x2")
                .font(.system(size: Theme.Icon.medium))
                .foregroundStyle(isGrouped ? Color.accentColor : Color.secondary)
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .help(isGrouped
            ? "Grouping by \(workspace.sessionGrouping.title) — click to change"
            : "Group the session list")
    }

    private func toggle(_ category: SessionFilterCategory, in workspace: WorkspaceState) {
        if workspace.categoryFilters.contains(category) {
            workspace.categoryFilters.remove(category)
        } else {
            workspace.categoryFilters.insert(category)
        }
    }

    private func reset(_ workspace: WorkspaceState) {
        workspace.categoryFilters = []
        workspace.filterText = ""
        workspace.hostFilter = nil
        workspace.processFilter = nil
        workspace.ipFilter = nil
        workspace.filterRules = [SessionFilterRule()]
    }
}

// MARK: - FilterPillButton

/// Compact flat toggle button used in the filter bar — the sibling app's `FilterPillButton`
/// styling: accent-tinted background + text when active, plain secondary when not.
struct FilterPillButton: View {
    let title: String
    let isActive: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(isActive ? Theme.Typography.bodyEmphasis : Theme.Typography.body)
                .foregroundStyle(isActive ? Color.accentColor : Color.secondary)
                .padding(.horizontal, 8)
                .padding(.vertical, 3)
                .background(isActive ? Color.accentColor.opacity(0.15) : Color.clear)
                .cornerRadius(4)
        }
        .buttonStyle(.borderless)
    }
}
