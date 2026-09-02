import SwiftUI

// MARK: - SessionFilterBar

/// The session control shelf above the table. Two rounded functional surfaces,
/// mirroring the interaction architecture used across the app's sibling
/// products without importing their proxy-specific vocabulary:
///
///   1. a stable **command + search row** — fixed immediate commands, a divider,
///      field-scope search, Add Field, advanced disclosure, and Group By. At a
///      narrow width the same two clusters stack without changing command order;
///   2. an adaptive **protocol/category pill row** ("All" + the protocol group
///      + the independent investigation group). Narrow widths move lower-priority
///      protocols into a labelled overflow menu instead of clipping or scrolling.
///
/// Every field here is a Tracexy session attribute. There is deliberately no
/// URL, HTTP method/status-code, header, body, mapping, proxy, or interception
/// concept anywhere in this surface.
struct SessionFilterBar: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    let commandDescriptors: [SessionCommandDescriptor]
    let onCommandAction: (SessionCommandKind) -> Void

    var body: some View {
        let workspace = coordinator.activeWorkspace
        let shape = RoundedRectangle(
            cornerRadius: Theme.Glass.sessionShelfCornerRadius,
            style: .continuous
        )
        TracexyGlassEffectGroup(spacing: Theme.Glass.sessionShelfSectionSpacing) {
            VStack(spacing: Theme.Glass.sessionShelfSectionSpacing) {
                commandAndSearchRow(workspace)
                    .tracexyGlassEffect(in: shape)
                categoryRow(workspace)
                    .padding(.vertical, 4)
                    .tracexyGlassEffect(in: shape)

                if workspace.isAdvancedFilterVisible {
                    StructuredFilterBar(coordinator: coordinator)
                        .tracexyGlassEffect(in: shape)
                        .transition(.move(edge: .top).combined(with: .opacity))
                }
            }
        }
        .padding(.horizontal, Theme.Glass.sessionShelfOuterPadding)
        .padding(.top, Theme.Glass.sessionShelfOuterPadding)
        .padding(.bottom, Theme.Glass.sessionShelfBottomPadding)
        .animation(.easeInOut(duration: 0.18), value: workspace.isAdvancedFilterVisible)
        .fixedSize(horizontal: false, vertical: true)
        // ⌘F focus. `.task(id:)` fires both on first appear and on every token
        // change, so a press that *mounts* this bar (coming from Overview/Flow)
        // and a press while it is already visible both land the cursor in the
        // field. The nil guard keeps a freshly-created workspace from stealing
        // focus before the user has ever asked for it.
        .task(id: workspace.searchFocusRequest) {
            guard workspace.searchFocusRequest != nil else {
                return
            }
            isSearchFieldFocused = true
        }
    }

    // MARK: Private

    @State private var showsInvestigationCoverage = false

    /// Drives the native cursor for the existing search field; set by the ⌘F
    /// focus token above. No layout or styling changes hang off this.
    @FocusState private var isSearchFieldFocused: Bool

    private var maxRules: Int {
        coordinator.policy.maxSessionFilterRules
    }

    // MARK: Category pills

    private func categoryRow(_ workspace: WorkspaceState) -> some View {
        HStack(spacing: 8) {
            ViewThatFits(in: .horizontal) {
                categoryTier(workspace, visibleProtocolCount: SessionFilterCategory.protocolFilters.count)
                categoryTier(workspace, visibleProtocolCount: 7)
                categoryTier(workspace, visibleProtocolCount: 5)
                categoryTier(workspace, visibleProtocolCount: 3)
            }
            .layoutPriority(1)

            Spacer(minLength: Theme.Metrics.spacingM)

            if workspace.hasActiveInvestigationQuery || workspace.isEvaluatingInvestigationQuery {
                InvestigationQueryChip(
                    coordinator: coordinator,
                    workspace: workspace,
                    showsCoverage: $showsInvestigationCoverage
                )
            }

            if workspace.hasActiveFilters {
                Button {
                    reset(workspace)
                } label: {
                    ViewThatFits(in: .horizontal) {
                        Label("Reset Filters", systemImage: "arrow.clockwise")
                        Image(systemName: "arrow.clockwise")
                    }
                }
                .buttonStyle(.borderless)
                .font(Theme.Typography.chromeAction)
                .foregroundStyle(.secondary)
                .help("Clear all session filters")
                .accessibilityLabel("Reset filters")
            }
        }
        .padding(.horizontal, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func categoryTier(_ workspace: WorkspaceState, visibleProtocolCount: Int) -> some View {
        let protocols = Array(SessionFilterCategory.protocolFilters.prefix(visibleProtocolCount))
        let hasProtocolFilter = workspace.categoryFilters.contains { !$0.isInvestigationFilter }
        return HStack(spacing: 2) {
            FilterPillButton(title: "All", isActive: !hasProtocolFilter) {
                workspace.categoryFilters = workspace.categoryFilters.filter(\.isInvestigationFilter)
            }
            .accessibilityLabel("All protocols")
            .accessibilityAddTraits(!hasProtocolFilter ? [.isSelected] : [])

            ForEach(protocols) { category in
                categoryPill(category, workspace: workspace)
            }

            filterOverflowMenu(workspace, visibleProtocols: protocols)
                .padding(.horizontal, 4)

            Divider()
                .frame(height: 16)
                .padding(.horizontal, 4)

            ForEach(SessionFilterCategory.investigationFilters) { category in
                categoryPill(category, workspace: workspace)
            }
        }
        .fixedSize(horizontal: true, vertical: false)
    }

    private func categoryPill(_ category: SessionFilterCategory, workspace: WorkspaceState) -> some View {
        let isActive = workspace.categoryFilters.contains(category)
        return FilterPillButton(
            title: category.title,
            systemImage: category == .security ? "list.bullet.clipboard" : nil,
            tint: category.protocolKind.map { Theme.color(for: $0) } ?? .accentColor,
            isActive: isActive
        ) {
            toggle(category, in: workspace)
        }
        .accessibilityLabel(category.title)
        .accessibilityAddTraits(isActive ? [.isSelected] : [])
        .accessibilityHint(isActive ? "Active filter" : "Inactive filter")
    }

    private func filterOverflowMenu(
        _ workspace: WorkspaceState,
        visibleProtocols: [SessionFilterCategory]
    )
        -> some View
    {
        let visible = Set(visibleProtocols)
        let hiddenProtocols = SessionFilterCategory.protocolFilters.filter { !visible.contains($0) }
        let hasHiddenActiveFilter = hiddenProtocols.contains { workspace.categoryFilters.contains($0) }
        return Menu {
            Section("Protocols") {
                Button("All Protocols", systemImage: "line.3.horizontal.decrease") {
                    workspace.categoryFilters = workspace.categoryFilters.filter(\.isInvestigationFilter)
                }
                ForEach(hiddenProtocols) { category in
                    Toggle(category.title, isOn: Binding(
                        get: { workspace.categoryFilters.contains(category) },
                        set: { _ in toggle(category, in: workspace) }
                    ))
                }
            }
            Section("Investigation") {
                ForEach(SessionFilterCategory.investigationFilters) { category in
                    Toggle(category.title, isOn: Binding(
                        get: { workspace.categoryFilters.contains(category) },
                        set: { _ in toggle(category, in: workspace) }
                    ))
                }
            }
        } label: {
            Image(systemName: hasHiddenActiveFilter ? "ellipsis.circle.fill" : "ellipsis.circle")
                .font(.system(size: Theme.Icon.medium))
                .foregroundStyle(hasHiddenActiveFilter ? Color.accentColor : Color.secondary)
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .help("More session filters")
        .accessibilityLabel("More session filters")
        .accessibilityValue(hasHiddenActiveFilter ? "Hidden filters active" : "No hidden filters active")
    }

    // MARK: Search row

    private func commandAndSearchRow(_ workspace: WorkspaceState) -> some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: Theme.Metrics.controlSpacing) {
                SessionCommandBar(
                    descriptors: commandDescriptors,
                    onAction: onCommandAction
                )
                Divider()
                    .frame(height: 22)
                searchRow(workspace)
                    .layoutPriority(1)
            }

            VStack(alignment: .leading, spacing: 0) {
                SessionCommandBar(
                    descriptors: commandDescriptors,
                    onAction: onCommandAction
                )
                Divider()
                    .opacity(0.55)
                searchRow(workspace)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func searchRow(_ workspace: WorkspaceState) -> some View {
        ViewThatFits(in: .horizontal) {
            searchRowContent(workspace, pickerWidth: 130, showsAddFieldTitle: true)
            searchRowContent(workspace, pickerWidth: 100, showsAddFieldTitle: false)
        }
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
            .focused($isSearchFieldFocused)
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
        HStack(spacing: Theme.Metrics.spacingM) {
            addFieldButton(workspace, showsTitle: showsAddFieldTitle)
            advancedDisclosure(workspace)
            Divider()
                .frame(height: 18)
            groupByMenu(workspace)
        }
        .font(Theme.Typography.chromeAction)
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
        .tracexyGlassButtonStyle()
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
        .tracexyGlassButtonStyle()
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
                .frame(
                    width: Theme.Metrics.sessionShelfControlLength,
                    height: Theme.Metrics.sessionShelfControlLength
                )
        }
        .menuStyle(.button)
        .menuIndicator(.hidden)
        .tracexyGlassButtonStyle()
        .controlSize(.small)
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
        coordinator.clearInvestigationQuery(in: workspace)
    }
}

// MARK: - FilterPillButton

/// Compact flat toggle button used in the filter bar: accent-tinted background + text
/// when active, plain secondary when not.
struct FilterPillButton: View {
    // MARK: Lifecycle

    init(
        title: String,
        systemImage: String? = nil,
        tint: Color = .accentColor,
        isActive: Bool,
        action: @escaping () -> Void
    ) {
        self.title = title
        self.systemImage = systemImage
        self.tint = tint
        self.isActive = isActive
        self.action = action
    }

    // MARK: Internal

    let title: String
    let systemImage: String?
    let tint: Color
    let isActive: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 4) {
                if let systemImage {
                    Image(systemName: systemImage)
                        .accessibilityHidden(true)
                }
                Text(title)
            }
            .font(isActive ? Theme.Typography.bodyEmphasis : Theme.Typography.body)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
        }
        .buttonStyle(.borderless)
        .tracexyChipStyle(tint: tint, isActive: isActive, isHovered: isHovered)
        .onHover { isHovered = $0 }
    }

    // MARK: Private

    @State private var isHovered = false
}
