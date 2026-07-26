import AppKit
import SwiftUI
import UniformTypeIdentifiers

// MARK: - SidebarView

/// Source-list sidebar: a Browse / Focus / Library navigator segmented control
/// swaps the whole body so each kind of work stands alone, instead of stacking
/// Monitor + Protocols + Sources + Favorites into one crowded list.
///
/// - Browse  — Monitor destinations (Sessions/Overview/Security), the Protocols
///             lens group, and Sources (Apps/Domains/IPs). Protocols is a single
///             disclosure group, collapsed by default: those rows filter the same
///             list rather than navigating anywhere, so they stay secondary to the
///             destinations above them and to the list's own category tab bar.
/// - Focus   — saved Focus Sets (named filters) + Noise Control (mute hosts /
///             protocols so a chatty capture stops flooding the list).
/// - Library — Favorites (Pinned hosts / Saved captures).
struct SidebarView: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let workspace = coordinator.activeWorkspace
        VStack(spacing: 0) {
            Picker("Navigator", selection: navigatorBinding(workspace)) {
                ForEach(SidebarNavigatorMode.allCases) { mode in
                    Text(mode.title).tag(mode)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(.horizontal, 10)
            .padding(.vertical, 8)

            Divider()

            switch workspace.navigatorMode {
            case .browse: browseList(workspace)
            case .focus: focusList
            case .library: libraryList
            }

            // Final sibling of the root VStack (not a `safeAreaInset`) so the
            // footer is a real member of the source-list pane and sits inside the
            // native sidebar column rather than floating above its scroll edge.
            SidebarBottomBar(filterText: filterBinding(workspace)) {
                Button("Save Current Capture", systemImage: "square.and.arrow.down") {
                    coordinator.saveCurrentCapture()
                }
                .disabled(!coordinator.canSaveCapture)
                Button("Import Capture…", systemImage: "tray.and.arrow.down") { importCapture() }
            }
        }
    }

    // MARK: Private

    @Environment(\.openWindow) private var openWindow

    /// Live sidebar-search text. Deliberately *local* to the sidebar: it scopes
    /// the navigator's own rows and never touches `WorkspaceState.filterText` or
    /// the session list, which have their own filter controls.
    @State private var sidebarSearch = ""

    @State private var protocolsExpanded = false
    @State private var savedExpanded = false
    @State private var pinnedExpanded = true
    // Large, dynamic source lists start collapsed so the sidebar stays scannable;
    // the user opens what they want, and search re-opens matches automatically.
    @State private var appsExpanded = false
    @State private var domainsExpanded = false
    @State private var ipsExpanded = false

    // MARK: Sidebar search

    /// Normalized query. Empty means "not searching" — every list shows its full
    /// contents and honors the user's own disclosure state.
    private var query: String {
        sidebarSearch.trimmingCharacters(in: .whitespaces).lowercased()
    }

    private var isSearching: Bool {
        !query.isEmpty
    }

    private var filteredMonitorItems: [SidebarItem] {
        if isSearching, matches("Monitor") {
            return SidebarSection.monitor.items
        }
        return SidebarSection.monitor.items.filter { matches($0.title) }
    }

    private var filteredProtocolItems: [SidebarItem] {
        if isSearching, matches(SidebarSection.protocols.title) {
            return SidebarSection.protocols.items
        }
        return SidebarSection.protocols.items.filter { matches($0.title) }
    }

    /// Apps whose name matches, or that contacted a matching host. A name match
    /// keeps every child; otherwise only the matching hosts are shown.
    private var filteredAppGroups: [AppGroup] {
        guard isSearching else {
            return coordinator.appGroups
        }
        if matches("Apps") || matches("Sources") {
            return coordinator.appGroups
        }
        return coordinator.appGroups.compactMap { group in
            if matches(group.app) {
                return group
            }
            let hosts = group.hosts.filter { matches($0) }
            return hosts.isEmpty ? nil : AppGroup(app: group.app, hosts: hosts, count: group.count)
        }
    }

    private var filteredDomainGroups: [DomainGroup] {
        guard isSearching else {
            return coordinator.domainGroups
        }
        if matches("Domains") || matches("Sources") {
            return coordinator.domainGroups
        }
        return coordinator.domainGroups.compactMap { group in
            if matches(group.domain) {
                return group
            }
            let ips = group.ips.filter { matches($0) }
            return ips.isEmpty ? nil : DomainGroup(domain: group.domain, ips: ips, count: group.count)
        }
    }

    private var filteredIPHosts: [(name: String, count: Int)] {
        guard isSearching else {
            return coordinator.ipHosts
        }
        if matches("IP Addresses") || matches("Sources") {
            return coordinator.ipHosts
        }
        return coordinator.ipHosts.filter { matches($0.name) }
    }

    private var filteredPinnedHosts: [String] {
        guard isSearching else {
            return coordinator.pinnedHosts
        }
        if matches("Pinned") || matches("Favorites") {
            return coordinator.pinnedHosts
        }
        return coordinator.pinnedHosts.filter { matches($0) }
    }

    private var filteredSavedCaptures: [SavedCapture] {
        guard isSearching else {
            return coordinator.savedCaptures
        }
        if matches("Saved") || matches("Favorites") {
            return coordinator.savedCaptures
        }
        return coordinator.savedCaptures.filter { matches($0.name) }
    }

    private var filteredFocusSets: [FocusSet] {
        guard isSearching else {
            return coordinator.focusSets
        }
        if matches("Focus Sets") {
            return coordinator.focusSets
        }
        return coordinator.focusSets.filter { matches($0.name) || matches($0.subtitle) }
    }

    private var browseHasResults: Bool {
        !filteredMonitorItems.isEmpty
            || !filteredProtocolItems.isEmpty
            || !filteredAppGroups.isEmpty
            || !filteredDomainGroups.isEmpty
            || !filteredIPHosts.isEmpty
    }

    // MARK: Active source scope

    /// The sidebar's Sources rows drill the session list into a single
    /// host/process/IP scope (see `MainContentCoordinator.select*`). Those live
    /// outside the native `List(selection:)`, so the active one is shown with an
    /// accent treatment rather than the system selection highlight.
    private var isSessionsScope: Bool {
        coordinator.activeWorkspace.sidebarSelection == .sessions
    }

    /// Noise Control belongs to Focus mode's chrome, so it stays visible while
    /// browsing but bows out of a search unless the query is about muting.
    private var showsNoiseControl: Bool {
        !isSearching || matches("noise control") || matches("muted") || matches("mute")
    }

    /// Honest empty state — shown only while searching, so an idle capture with
    /// nothing to browse doesn't get labelled "No results".
    private var noResultsRow: some View {
        Text("No results for “\(sidebarSearch)”")
            .font(Theme.Typography.caption)
            .foregroundStyle(.tertiary)
    }

    // MARK: Focus mode

    private var focusList: some View {
        List {
            Section {
                if filteredFocusSets.isEmpty {
                    Text(isSearching ? "No matching focus sets" : "No focus sets yet")
                        .font(Theme.Typography.caption).foregroundStyle(.tertiary)
                } else {
                    ForEach(filteredFocusSets) { set in
                        FocusSetRow(set: set, coordinator: coordinator) { openFocusEditor(set) }
                    }
                }
            } header: {
                focusHeader("Focus Sets") {
                    Button { newFocusSet() } label: {
                        Label("New", systemImage: "plus")
                    }
                    .controlSize(.small)
                    .help("Create a focus set")
                }
            }

            if showsNoiseControl {
                Section {
                    Button {
                        openWindow(id: TracexyApp.noiseControlWindowID)
                    } label: {
                        HStack {
                            Label(
                                coordinator.isNoiseControlActive
                                    ? "\(coordinator.noiseRuleCount) muted"
                                    : "Nothing muted",
                                systemImage: "speaker.slash"
                            )
                            .foregroundStyle(coordinator.isNoiseControlActive ? Color.accentColor : .secondary)
                            Spacer()
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                } header: {
                    focusHeader("Noise Control") {
                        Button("Configure…") { openWindow(id: TracexyApp.noiseControlWindowID) }
                            .controlSize(.small)
                    }
                }
            }
        }
        .listStyle(.sidebar)
    }

    // MARK: Library mode

    private var libraryList: some View {
        let hasPinned = !isSearching || !filteredPinnedHosts.isEmpty
        let hasSaved = !isSearching || !filteredSavedCaptures.isEmpty
        return List {
            Section("Favorites") {
                if hasPinned {
                    pinnedDisclosure
                }
                if hasSaved {
                    savedDisclosure
                }
                if isSearching, !hasPinned, !hasSaved {
                    noResultsRow
                }
            }
        }
        .listStyle(.sidebar)
    }

    private var pinnedDisclosure: some View {
        DisclosureGroup(isExpanded: searchExpansion($pinnedExpanded)) {
            if filteredPinnedHosts.isEmpty {
                Text("No pinned hosts")
                    .font(Theme.Typography.caption).foregroundStyle(.tertiary)
            } else {
                ForEach(filteredPinnedHosts, id: \.self) { host in
                    Label(host, systemImage: "globe")
                        .foregroundStyle(isActiveHost(host) ? Color.accentColor : .secondary)
                        .fontWeight(isActiveHost(host) ? .medium : .regular)
                        .lineLimit(1)
                        .contentShape(Rectangle())
                        .onTapGesture { coordinator.selectHost(host) }
                        .accessibilityAddTraits(.isButton)
                        .accessibilityAddTraits(isActiveHost(host) ? .isSelected : [])
                        .accessibilityAction { coordinator.selectHost(host) }
                        .contextMenu {
                            Button("Unpin", systemImage: "pin.slash") {
                                coordinator.togglePinHost(host)
                            }
                        }
                }
            }
        } label: {
            Label("Pinned", systemImage: "pin.fill").badge(coordinator.pinnedHosts.count)
        }
    }

    /// Saved captures, expandable inline like Pinned — the list lives in the
    /// sidebar and a tap opens that capture in the main session view.
    private var savedDisclosure: some View {
        DisclosureGroup(isExpanded: searchExpansion($savedExpanded)) {
            if filteredSavedCaptures.isEmpty {
                Text("No saved captures")
                    .font(Theme.Typography.caption).foregroundStyle(.tertiary)
            } else {
                ForEach(filteredSavedCaptures) { capture in
                    Label(capture.name, systemImage: "doc.text.magnifyingglass")
                        .foregroundStyle(.secondary).lineLimit(1)
                        .contentShape(Rectangle())
                        .onTapGesture { coordinator.openSavedCapture(capture) }
                        .contextMenu {
                            Button("Open", systemImage: "eye") { coordinator.openSavedCapture(capture) }
                            Button("Reveal in Finder", systemImage: "folder") {
                                NSWorkspace.shared.activateFileViewerSelecting([capture.url])
                            }
                            Divider()
                            Button("Delete", systemImage: "trash", role: .destructive) {
                                coordinator.deleteSavedCapture(capture)
                            }
                        }
                }
            }
            Button { importCapture() } label: {
                Label("Import…", systemImage: "tray.and.arrow.down")
                    .font(Theme.Typography.caption).foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
        } label: {
            Label("Saved", systemImage: "folder").badge(coordinator.savedCaptures.count)
                .contextMenu {
                    Button("Save Current Capture", systemImage: "square.and.arrow.down") {
                        coordinator.saveCurrentCapture()
                    }
                    .disabled(!coordinator.canSaveCapture)
                    Button("Import…", systemImage: "tray.and.arrow.down") { importCapture() }
                }
        }
    }

    // MARK: Sources (Browse)

    /// Apps that originated traffic, each with its real icon, expandable to the
    /// hosts/IPs that app contacted.
    private var appsDisclosure: some View {
        DisclosureGroup(isExpanded: searchExpansion($appsExpanded)) {
            ForEach(filteredAppGroups) { group in
                AppRow(group: group, coordinator: coordinator, forceExpanded: isSearching)
            }
        } label: {
            Label("Apps", systemImage: "app.badge").badge(coordinator.appGroups.count)
        }
    }

    /// Domains, each expandable to the server IPs it resolved to (sub-IPs).
    private var domainsDisclosure: some View {
        DisclosureGroup(isExpanded: searchExpansion($domainsExpanded)) {
            ForEach(filteredDomainGroups) { group in
                DomainRow(group: group, coordinator: coordinator, forceExpanded: isSearching)
            }
        } label: {
            Label("Domains", systemImage: "globe").badge(coordinator.domainGroups.count)
        }
    }

    /// Hosts seen only as a bare IP (no domain name resolved). Capped while
    /// browsing to stay scannable; a search widens the net to every match.
    private var ipAddressesDisclosure: some View {
        let hosts = isSearching ? filteredIPHosts : Array(filteredIPHosts.prefix(20))
        return DisclosureGroup(isExpanded: searchExpansion($ipsExpanded)) {
            ForEach(hosts, id: \.name) { host in
                Label(host.name, systemImage: "number")
                    .foregroundStyle(isActiveIP(host.name) ? Color.accentColor : .secondary)
                    .fontWeight(isActiveIP(host.name) ? .medium : .regular)
                    .lineLimit(1).badge(host.count)
                    .contentShape(Rectangle())
                    .onTapGesture { coordinator.selectIP(host.name) }
                    .accessibilityAddTraits(.isButton)
                    .accessibilityAddTraits(isActiveIP(host.name) ? .isSelected : [])
                    .accessibilityAction { coordinator.selectIP(host.name) }
                    .help("Show sessions for \(host.name)")
                    .contextMenu { PinHostButton(host: host.name, coordinator: coordinator) }
            }
        } label: {
            Label("IP Addresses", systemImage: "number").badge(coordinator.ipHosts.count)
        }
    }

    /// A section header with a trailing native push button (clear, not a faint
    /// label) — the visible "New" / "Configure…" affordances in Focus mode.
    private func focusHeader(_ title: String, @ViewBuilder button: () -> some View) -> some View {
        HStack {
            Text(title)
            Spacer()
            button()
        }
    }

    // MARK: Browse mode

    private func browseList(_ workspace: WorkspaceState) -> some View {
        List(selection: selectionBinding(workspace)) {
            if !filteredMonitorItems.isEmpty {
                Section("Monitor") {
                    ForEach(filteredMonitorItems) { item in
                        navRow(item, workspace: workspace)
                    }
                }
            }

            // Protocol lenses are secondary: they filter the same list rather than
            // navigating anywhere new, so they stay collapsed until asked for —
            // but search forces the group open and prunes it to matches.
            if !filteredProtocolItems.isEmpty {
                Section {
                    DisclosureGroup(isExpanded: searchExpansion($protocolsExpanded)) {
                        ForEach(filteredProtocolItems) { item in
                            navRow(item, workspace: workspace)
                        }
                    } label: {
                        Label(SidebarSection.protocols.title, systemImage: SidebarSection.protocols.systemImage)
                    }
                }
            }

            if !filteredAppGroups.isEmpty || !filteredDomainGroups.isEmpty || !filteredIPHosts.isEmpty {
                Section("Sources") {
                    if !filteredAppGroups.isEmpty {
                        appsDisclosure
                    }
                    if !filteredDomainGroups.isEmpty {
                        domainsDisclosure
                    }
                    if !filteredIPHosts.isEmpty {
                        ipAddressesDisclosure
                    }
                }
            }

            if isSearching, !browseHasResults {
                noResultsRow
            }
        }
        .listStyle(.sidebar)
    }

    // MARK: Rows / helpers

    private func navRow(_ item: SidebarItem, workspace: WorkspaceState) -> some View {
        // No forced foreground on selection: `List(.sidebar)` renders the accent
        // (or graphite, in an inactive window) highlight itself and keeps the
        // label legible against it. A hardcoded white icon broke the inactive
        // case, where the highlight is light grey.
        Label {
            Text(item.title)
        } icon: {
            if workspace.sidebarSelection == item {
                Image(systemName: item.systemImage)
            } else {
                Image(systemName: item.systemImage)
                    .foregroundStyle(tint(item))
            }
        }
        .badge(badge(for: item))
        .tag(item)
    }

    private func filterBinding(_ workspace: WorkspaceState) -> Binding<String> {
        Binding(
            get: { workspace.filterText },
            set: { workspace.filterText = $0 }
        )
    }

    /// Case-insensitive substring match; always true when not searching so call
    /// sites read the same in both modes.
    private func matches(_ text: String) -> Bool {
        query.isEmpty || text.lowercased().contains(query)
    }

    /// Force a disclosure open while searching so matching children are visible,
    /// but hand control straight back to the user during normal browsing.
    private func searchExpansion(_ state: Binding<Bool>) -> Binding<Bool> {
        Binding(
            get: { isSearching || state.wrappedValue },
            set: { state.wrappedValue = $0 }
        )
    }

    private func isActiveHost(_ host: String) -> Bool {
        isSessionsScope && coordinator.activeWorkspace.hostFilter == host
    }

    private func isActiveIP(_ ip: String) -> Bool {
        isSessionsScope && coordinator.activeWorkspace.ipFilter == ip
    }

    /// A section header with a trailing action button (the "+ Add" pattern).
    private func newFocusSet() {
        coordinator.editingFocusSet = coordinator.draftFocusSet()
        openWindow(id: TracexyApp.focusSetEditorWindowID)
    }

    private func openFocusEditor(_ set: FocusSet) {
        coordinator.editingFocusSet = set
        openWindow(id: TracexyApp.focusSetEditorWindowID)
    }

    private func navigatorBinding(_ workspace: WorkspaceState) -> Binding<SidebarNavigatorMode> {
        Binding(
            get: { workspace.navigatorMode },
            set: { workspace.navigatorMode = $0 }
        )
    }

    /// Presents an open panel and imports the chosen `.pcap`/`.pcapng` file.
    private func importCapture() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = ["pcap", "pcapng"].compactMap { UTType(filenameExtension: $0) }
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        if panel.runModal() == .OK, let url = panel.url {
            coordinator.importCapture(from: url)
        }
    }

    private func selectionBinding(_ workspace: WorkspaceState) -> Binding<SidebarItem?> {
        Binding(
            get: { workspace.sidebarSelection },
            set: { newValue in
                if let newValue {
                    coordinator.selectSidebarItem(newValue)
                }
            }
        )
    }

    /// Protocol-tinted icon color (Finder-style colored source-list icons).
    private func tint(_ item: SidebarItem) -> Color {
        if let proto = item.protocolFilter {
            return Theme.color(for: proto)
        }
        switch item {
        case .security: return .red
        default: return .secondary
        }
    }

    private func badge(for item: SidebarItem) -> Text? {
        let count: Int = switch item {
        case .sessions: coordinator.visibleSessions.count
        case .security: coordinator.errorCount + coordinator.warningCount
        default:
            if let proto = item.protocolFilter {
                coordinator.count(for: proto)
            } else {
                0
            }
        }
        return count > 0 ? Text(count.formatted()) : nil
    }
}

// MARK: - FocusSetRow

/// A saved focus set in the sidebar: tap to apply its rules, context-menu to
/// edit or delete.
private struct FocusSetRow: View {
    let set: FocusSet
    let coordinator: MainContentCoordinator
    let onEdit: () -> Void

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: set.symbol).foregroundStyle(Color.accentColor)
            VStack(alignment: .leading, spacing: 1) {
                Text(set.name).lineLimit(1)
                Text(set.subtitle)
                    .font(Theme.Typography.micro).foregroundStyle(.tertiary).lineLimit(1)
            }
            Spacer()
        }
        .badge(set.activeRuleCount)
        .contentShape(Rectangle())
        .onTapGesture { coordinator.applyFocusSet(set) }
        .help("Click to apply this focus set")
        .contextMenu {
            Button("Apply", systemImage: "scope") { coordinator.applyFocusSet(set) }
            Button("Edit…", systemImage: "pencil") { onEdit() }
            Divider()
            Button("Delete", systemImage: "trash", role: .destructive) {
                coordinator.deleteFocusSet(set)
            }
        }
    }
}

// MARK: - DomainRow

/// A domain in the sidebar that expands to the server IPs it resolved to.
private struct DomainRow: View {
    // MARK: Internal

    let group: DomainGroup
    let coordinator: MainContentCoordinator
    var forceExpanded = false

    var body: some View {
        DisclosureGroup(isExpanded: expansion) {
            ForEach(group.ips, id: \.self) { ip in
                Label(ip, systemImage: "number")
                    .foregroundStyle(isActiveIP(ip) ? Color.accentColor : .secondary)
                    .fontWeight(isActiveIP(ip) ? .medium : .regular)
                    .lineLimit(1)
                    .contentShape(Rectangle())
                    .onTapGesture { coordinator.selectIP(ip) }
                    .accessibilityAddTraits(.isButton)
                    .accessibilityAddTraits(isActiveIP(ip) ? .isSelected : [])
                    .accessibilityAction { coordinator.selectIP(ip) }
                    .help("Show sessions for \(ip)")
            }
        } label: {
            Label(group.domain, systemImage: "globe")
                .foregroundStyle(isActiveHost ? Color.accentColor : .secondary)
                .fontWeight(isActiveHost ? .medium : .regular)
                .lineLimit(1).badge(group.count)
                .contentShape(Rectangle())
                .onTapGesture { coordinator.selectHost(group.domain) }
                .accessibilityAddTraits(.isButton)
                .accessibilityAddTraits(isActiveHost ? .isSelected : [])
                .accessibilityAction { coordinator.selectHost(group.domain) }
                .help("Show sessions for \(group.domain)")
                .contextMenu { PinHostButton(host: group.domain, coordinator: coordinator) }
        }
    }

    // MARK: Private

    @State private var expanded = false

    private var expansion: Binding<Bool> {
        Binding(get: { forceExpanded || expanded }, set: { expanded = $0 })
    }

    private var isActiveHost: Bool {
        coordinator.activeWorkspace.sidebarSelection == .sessions
            && coordinator.activeWorkspace.hostFilter == group.domain
    }

    private func isActiveIP(_ ip: String) -> Bool {
        coordinator.activeWorkspace.sidebarSelection == .sessions
            && coordinator.activeWorkspace.ipFilter == ip
    }
}

// MARK: - PinHostButton

/// A reusable Pin/Unpin menu item for a host or IP, used across sidebar rows and
/// the session table's context menu.
struct PinHostButton: View {
    let host: String
    let coordinator: MainContentCoordinator

    var body: some View {
        let pinned = coordinator.isHostPinned(host)
        Button(pinned ? "Unpin" : "Pin", systemImage: pinned ? "pin.slash" : "pin") {
            coordinator.togglePinHost(host)
        }
    }
}

// MARK: - AppRow

/// An app in the sidebar that expands to the hosts/IPs it contacted.
private struct AppRow: View {
    // MARK: Internal

    let group: AppGroup
    let coordinator: MainContentCoordinator
    var forceExpanded = false

    var body: some View {
        DisclosureGroup(isExpanded: expansion) {
            ForEach(group.hosts, id: \.self) { host in
                Label(host, systemImage: "arrow.right")
                    .labelStyle(.titleOnly)
                    .foregroundStyle(isActiveHost(host) ? Color.accentColor : .secondary)
                    .fontWeight(isActiveHost(host) ? .medium : .regular)
                    .lineLimit(1)
                    .contentShape(Rectangle())
                    .onTapGesture { coordinator.selectHost(host) }
                    .accessibilityAddTraits(.isButton)
                    .accessibilityAddTraits(isActiveHost(host) ? .isSelected : [])
                    .accessibilityAction { coordinator.selectHost(host) }
                    .help("Show sessions for \(host)")
            }
        } label: {
            HStack(spacing: 6) {
                AppIconView(name: group.app)
                Text(group.app).lineLimit(1)
                    .fontWeight(isActiveApp ? .medium : .regular)
                    .foregroundStyle(isActiveApp ? Color.accentColor : .primary)
            }
            .badge(group.count)
            .contentShape(Rectangle())
            .onTapGesture { coordinator.selectProcess(group.app) }
            .accessibilityAddTraits(.isButton)
            .accessibilityAddTraits(isActiveApp ? .isSelected : [])
            .accessibilityAction { coordinator.selectProcess(group.app) }
            .help("Show sessions from \(group.app)")
        }
    }

    // MARK: Private

    @State private var expanded = false

    private var expansion: Binding<Bool> {
        Binding(get: { forceExpanded || expanded }, set: { expanded = $0 })
    }

    private var isActiveApp: Bool {
        coordinator.activeWorkspace.sidebarSelection == .sessions
            && coordinator.activeWorkspace.processFilter == group.app
    }

    private func isActiveHost(_ host: String) -> Bool {
        coordinator.activeWorkspace.sidebarSelection == .sessions
            && coordinator.activeWorkspace.hostFilter == host
    }
}
