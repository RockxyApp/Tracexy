import SwiftUI

// MARK: - SessionFilterBar

/// The session filter area above the table. Two native rows, mirroring the
/// interaction architecture used across the app's sibling products:
///
///   1. a horizontally-scrolling **protocol/category pill row** ("All" + the
///      protocol group + the independent status group), with a trailing
///      "Reset Filters" action when anything is active;
///   2. a **search row** — an enable checkbox, a field-scope dropdown, a rounded
///      search field with a clear button, an "Add Field" button that drives the
///      advanced rule builder, a disclosure showing the active rule count, and
///      the Group By menu.
///
/// Every field here is a Tracexy session attribute. There is deliberately no
/// URL, HTTP method/status-code, header, body, mapping, proxy, or interception
/// concept anywhere in this surface.
struct SessionFilterBar: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let workspace = coordinator.activeWorkspace
        VStack(spacing: 0) {
            categoryRow(workspace)
                .padding(.vertical, 5)
            Divider()
            searchRow(workspace)
                .padding(.vertical, 5)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .overlay(alignment: .bottom) { Divider() }
        .fixedSize(horizontal: false, vertical: true)
    }

    // MARK: Private

    private var maxRules: Int {
        coordinator.policy.maxSessionFilterRules
    }

    // MARK: Category pills

    private func categoryRow(_ workspace: WorkspaceState) -> some View {
        HStack(spacing: 8) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 2) {
                    let hasProtocolFilter = workspace.categoryFilters.contains { !$0.isStatusFilter }
                    FilterPillButton(title: "All", isActive: !hasProtocolFilter) {
                        workspace.categoryFilters = workspace.categoryFilters.filter(\.isStatusFilter)
                    }
                    .accessibilityLabel("All protocols")
                    .accessibilityAddTraits(!hasProtocolFilter ? [.isSelected] : [])

                    ForEach(SessionFilterCategory.protocolFilters) { category in
                        let isActive = workspace.categoryFilters.contains(category)
                        FilterPillButton(title: category.title, isActive: isActive) {
                            toggle(category, in: workspace)
                        }
                        .accessibilityLabel(category.title)
                        .accessibilityAddTraits(isActive ? [.isSelected] : [])
                        .accessibilityHint(isActive ? "Active filter" : "Inactive filter")
                    }

                    Divider()
                        .frame(height: 16)
                        .padding(.horizontal, 4)

                    ForEach(SessionFilterCategory.statusFilters) { category in
                        let isActive = workspace.categoryFilters.contains(category)
                        FilterPillButton(title: category.title, isActive: isActive) {
                            toggle(category, in: workspace)
                        }
                        .accessibilityLabel(category.title)
                        .accessibilityAddTraits(isActive ? [.isSelected] : [])
                        .accessibilityHint(isActive ? "Active filter" : "Inactive filter")
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
                .padding(.trailing, 8)
                .help("Clear all session filters")
                .accessibilityLabel("Reset filters")
            }
        }
    }

    // MARK: Search row

    private func searchRow(_ workspace: WorkspaceState) -> some View {
        ViewThatFits(in: .horizontal) {
            searchRowContent(workspace, pickerWidth: 130, showsAddFieldTitle: true)
            searchRowContent(workspace, pickerWidth: 100, showsAddFieldTitle: false)
        }
        .padding(.horizontal, 8)
    }

    /// The whole search row participates in the responsive decision. This keeps
    /// the field selector and the Add Field title at their comfortable native
    /// sizes until the center pane genuinely cannot fit them.
    private func searchRowContent(
        _ workspace: WorkspaceState,
        pickerWidth: CGFloat,
        showsAddFieldTitle: Bool
    )
        -> some View
    {
        HStack(spacing: 8) {
            Toggle("", isOn: Binding(
                get: { workspace.isSearchEnabled },
                set: { workspace.isSearchEnabled = $0 }
            ))
            .toggleStyle(.checkbox)
            .tint(.green)
            .labelsHidden()
            .help(workspace.isSearchEnabled ? "Search is on — uncheck to ignore it" : "Search is off")
            .accessibilityLabel("Enable search")

            searchFieldPicker(workspace, width: pickerWidth)

            searchField(workspace)
                .layoutPriority(1)

            Divider()
                .frame(height: 18)

            actionCluster(workspace, showsAddFieldTitle: showsAddFieldTitle)
        }
    }

    /// The field-scope dropdown: which session attribute(s) the query matches.
    private func searchFieldPicker(_ workspace: WorkspaceState, width: CGFloat) -> some View {
        Picker("", selection: Binding(
            get: { workspace.searchField },
            set: { workspace.searchField = $0 }
        )) {
            ForEach(SessionSearchField.allCases) { field in
                Text(field.displayName).tag(field)
            }
        }
        .labelsHidden()
        .frame(width: width)
        .help("Choose which session fields the search matches")
        .accessibilityLabel("Search field")
    }

    /// Free-text session filtering. Kept here (not in the sidebar navigator) so
    /// it lives with the filters it belongs to; the sidebar footer searches only
    /// sidebar rows.
    private func searchField(_ workspace: WorkspaceState) -> some View {
        HStack(spacing: 4) {
            TextField(
                "Search sessions",
                text: Binding(
                    get: { workspace.filterText },
                    set: { workspace.filterText = $0 }
                )
            )
            .textFieldStyle(.roundedBorder)
            .font(Theme.Typography.body)
            .accessibilityLabel("Search sessions")
            if !workspace.filterText.isEmpty {
                Button {
                    workspace.filterText = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: Theme.Icon.small))
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.borderless)
                .help("Clear the search text")
                .accessibilityLabel("Clear session search")
            }
        }
        .frame(minWidth: 220, maxWidth: .infinity)
    }

    /// The trailing controls: Add Field, the active-rule disclosure, and Group
    /// By. The outer responsive row decides whether Add Field keeps its title.
    private func actionCluster(_ workspace: WorkspaceState, showsAddFieldTitle: Bool) -> some View {
        HStack(spacing: 6) {
            addFieldButton(workspace, showsTitle: showsAddFieldTitle)
            advancedDisclosure(workspace)
            groupByMenu(workspace)
        }
        .fixedSize()
    }

    private func addFieldButton(_ workspace: WorkspaceState, showsTitle: Bool) -> some View {
        let disabled = isAddFilterDisabled(workspace)
        return Button {
            addFilter(workspace)
        } label: {
            if showsTitle {
                Label("Add Field", systemImage: "plus")
            } else {
                Image(systemName: "plus")
            }
        }
        .buttonStyle(.bordered)
        .controlSize(.small)
        .disabled(disabled)
        .help(disabled
            ? "Filter limit reached — this build allows \(maxRules) rules"
            : "Add a field to the advanced filter")
        .accessibilityLabel("Add field")
    }

    private func advancedDisclosure(_ workspace: WorkspaceState) -> some View {
        let count = workspace.activeFilterRules.count
        let isOn = workspace.isAdvancedFilterVisible
        return Button {
            workspace.isAdvancedFilterVisible.toggle()
        } label: {
            HStack(spacing: 4) {
                Image(systemName: "line.3.horizontal.decrease")
                if count > 0 {
                    Text("\(count)")
                        .font(Theme.Typography.body)
                        .monospacedDigit()
                }
                Image(systemName: isOn ? "chevron.up" : "chevron.down")
                    .font(Theme.Typography.micro)
            }
        }
        .buttonStyle(.borderless)
        .controlSize(.small)
        .help(count > 0
            ? "\(count) advanced rule\(count == 1 ? "" : "s") active — click to \(isOn ? "hide" : "show") the builder"
            : "Show the advanced filter rule builder")
        .accessibilityLabel("Advanced filters")
        .accessibilityValue("\(count) active")
    }

    /// Grouping, as a trailing icon menu. Finder, Mail and Xcode all put grouping
    /// behind a small toolbar menu rather than a permanently-visible segmented
    /// control (which is how a *filter* looks on macOS, not a view option). The
    /// icon carries the state: tinted when grouped, secondary when flat.
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
        .accessibilityLabel("Group sessions")
        .accessibilityValue(isGrouped ? workspace.sessionGrouping.title : "None")
    }

    /// "Add Field": if the advanced editor is hidden, reveal it *without* adding
    /// a duplicate blank row; if it is already visible, append a blank row up to
    /// the capacity cap.
    private func addFilter(_ workspace: WorkspaceState) {
        guard workspace.isAdvancedFilterVisible else {
            workspace.isAdvancedFilterVisible = true
            return
        }
        guard workspace.filterRules.count < maxRules else {
            return
        }
        workspace.filterRules.append(SessionFilterRule())
    }

    private func isAddFilterDisabled(_ workspace: WorkspaceState) -> Bool {
        workspace.isAdvancedFilterVisible && workspace.filterRules.count >= maxRules
    }

    private func toggle(_ category: SessionFilterCategory, in workspace: WorkspaceState) {
        if workspace.categoryFilters.contains(category) {
            workspace.categoryFilters.remove(category)
        } else {
            workspace.categoryFilters.insert(category)
        }
    }

    /// Reset clears the quick categories, the search text, the sidebar drill-down
    /// scopes, and the advanced rules (back to a single blank row), then hides the
    /// advanced editor. It does not touch Noise Control or any capture state.
    private func reset(_ workspace: WorkspaceState) {
        workspace.categoryFilters = []
        workspace.filterText = ""
        workspace.hostFilter = nil
        workspace.processFilter = nil
        workspace.ipFilter = nil
        workspace.filterRules = [SessionFilterRule()]
        workspace.isAdvancedFilterVisible = false
    }
}

// MARK: - FilterPillButton

/// Compact flat toggle button used in the filter bar: accent-tinted background + text
/// when active, plain secondary when not.
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
