import AppKit
import SwiftUI
import UniformTypeIdentifiers

// MARK: - SidebarView

/// sibling-app-style sidebar: a Browse / Focus / Library navigator segmented control
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
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
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

    @State private var protocolsExpanded = false
    @State private var savedExpanded = false
    @State private var pinnedExpanded = true
    @State private var appsExpanded = true
    @State private var domainsExpanded = false
    @State private var ipsExpanded = false

    // MARK: Focus mode

    private var focusList: some View {
        List {
            Section {
                if coordinator.focusSets.isEmpty {
                    Text("No focus sets yet")
                        .font(Theme.Typography.caption).foregroundStyle(.tertiary)
                } else {
                    ForEach(coordinator.focusSets) { set in
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
        .listStyle(.sidebar)
    }

    // MARK: Library mode

    private var libraryList: some View {
        List {
            Section("Favorites") {
                pinnedDisclosure
                savedDisclosure
            }
        }
        .listStyle(.sidebar)
    }

    private var pinnedDisclosure: some View {
        DisclosureGroup(isExpanded: $pinnedExpanded) {
            if coordinator.pinnedHosts.isEmpty {
                Text("No pinned hosts")
                    .font(Theme.Typography.caption).foregroundStyle(.tertiary)
            } else {
                ForEach(coordinator.pinnedHosts, id: \.self) { host in
                    Label(host, systemImage: "globe")
                        .foregroundStyle(.secondary).lineLimit(1)
                        .contentShape(Rectangle())
                        .onTapGesture { coordinator.selectHost(host) }
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
        DisclosureGroup(isExpanded: $savedExpanded) {
            if coordinator.savedCaptures.isEmpty {
                Text("No saved captures")
                    .font(Theme.Typography.caption).foregroundStyle(.tertiary)
            } else {
                ForEach(coordinator.savedCaptures) { capture in
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
    /// hosts/IPs that app contacted (sibling-app-style).
    private var appsDisclosure: some View {
        DisclosureGroup(isExpanded: $appsExpanded) {
            ForEach(coordinator.appGroups) { group in
                AppRow(group: group, coordinator: coordinator)
            }
        } label: {
            Label("Apps", systemImage: "app.badge").badge(coordinator.appGroups.count)
        }
    }

    /// Domains, each expandable to the server IPs it resolved to (sub-IPs).
    private var domainsDisclosure: some View {
        DisclosureGroup(isExpanded: $domainsExpanded) {
            ForEach(coordinator.domainGroups) { group in
                DomainRow(group: group, coordinator: coordinator)
            }
        } label: {
            Label("Domains", systemImage: "globe").badge(coordinator.domainGroups.count)
        }
    }

    /// Hosts seen only as a bare IP (no domain name resolved).
    private var ipAddressesDisclosure: some View {
        DisclosureGroup(isExpanded: $ipsExpanded) {
            ForEach(coordinator.ipHosts.prefix(20), id: \.name) { host in
                Label(host.name, systemImage: "number")
                    .foregroundStyle(.secondary).lineLimit(1).badge(host.count)
                    .contentShape(Rectangle())
                    .onTapGesture { coordinator.selectIP(host.name) }
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
            Section("Monitor") {
                ForEach(SidebarSection.monitor.items) { item in
                    navRow(item, workspace: workspace)
                }
            }

            // Protocol lenses are secondary: they filter the same list rather than
            // navigating anywhere new, so they stay collapsed until asked for.
            // The cases existed in `SidebarSection` but were never rendered.
            Section {
                DisclosureGroup(isExpanded: $protocolsExpanded) {
                    ForEach(SidebarSection.protocols.items) { item in
                        navRow(item, workspace: workspace)
                    }
                } label: {
                    Label(SidebarSection.protocols.title, systemImage: SidebarSection.protocols.systemImage)
                }
            }

            Section("Sources") {
                appsDisclosure
                domainsDisclosure
                ipAddressesDisclosure
            }
        }
        .listStyle(.sidebar)
    }

    // MARK: Rows / helpers

    private func navRow(_ item: SidebarItem, workspace: WorkspaceState) -> some View {
        let isSelected = workspace.sidebarSelection == item
        return Label {
            Text(item.title)
        } icon: {
            Image(systemName: item.systemImage)
                .foregroundStyle(isSelected ? Color.white : tint(item))
        }
        .badge(badge(for: item))
        .tag(item)
    }

    /// A section header with a trailing action button (the sibling app's "+ Add" pattern).
    private func newFocusSet() {
        coordinator.editingFocusSet = coordinator.draftFocusSet()
        openWindow(id: TracexyApp.focusSetEditorWindowID)
    }

    private func openFocusEditor(_ set: FocusSet) {
        coordinator.editingFocusSet = set
        openWindow(id: TracexyApp.focusSetEditorWindowID)
    }

    private func filterBinding(_ workspace: WorkspaceState) -> Binding<String> {
        Binding(
            get: { workspace.filterText },
            set: { workspace.filterText = $0 }
        )
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
/// edit or delete. Mirrors the sibling app's `FocusSetSidebarRow`.
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

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            ForEach(group.ips, id: \.self) { ip in
                Label(ip, systemImage: "number")
                    .foregroundStyle(.secondary).lineLimit(1)
                    .contentShape(Rectangle())
                    .onTapGesture { coordinator.selectIP(ip) }
            }
        } label: {
            Label(group.domain, systemImage: "globe")
                .foregroundStyle(.secondary).lineLimit(1).badge(group.count)
                .contentShape(Rectangle())
                .onTapGesture { coordinator.selectHost(group.domain) }
                .contextMenu { PinHostButton(host: group.domain, coordinator: coordinator) }
        }
    }

    // MARK: Private

    @State private var expanded = false
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

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            ForEach(group.hosts, id: \.self) { host in
                Label(host, systemImage: "arrow.right")
                    .labelStyle(.titleOnly)
                    .foregroundStyle(.secondary).lineLimit(1)
                    .contentShape(Rectangle())
                    .onTapGesture { coordinator.selectHost(host) }
            }
        } label: {
            HStack(spacing: 6) {
                AppIconView(name: group.app)
                Text(group.app).lineLimit(1)
            }
            .badge(group.count)
            .contentShape(Rectangle())
            .onTapGesture { coordinator.selectProcess(group.app) }
        }
    }

    // MARK: Private

    @State private var expanded = false
}
