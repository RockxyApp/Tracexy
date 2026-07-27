import AppKit
import SwiftUI

// MARK: - SessionCenterView

struct SessionCenterView: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let workspace = coordinator.activeWorkspace
        let sessions = coordinator.visibleSessions
        VStack(spacing: 0) {
            if workspace.isFilterBarVisible {
                SessionFilterBar(coordinator: coordinator)
                // The advanced rule builder reveals just below the category tabs
                // when the footer "Filter" button is toggled on.
                if workspace.isAdvancedFilterVisible {
                    StructuredFilterBar(coordinator: coordinator)
                }
            }
            // Live traffic chart: a modest, collapsible strip above the list — the
            // hero real-time graph, without the old full-height crush. It reads
            // ONLY `throughputSamples`, so its ~1×/sec ticks re-render the strip
            // alone and never re-run this body (which drives the Table).
            LiveTrafficStrip(coordinator: coordinator, isExpanded: liveChartBinding(workspace))
            Divider()
            // List-first (Wireshark/Proxyman): the table is the spine and takes the
            // remaining height.
            //
            // NOTE (reentrancy): the Table stays in its own branch with no
            // GeometryReader — feeding a Table a height derived from its own
            // container re-enters NSTableView layout ("reentrant operation in its
            // NSTableView delegate" → hang/assert under the debugger).
            //
            // When there are no rows, show ONLY the purposeful empty state — not
            // an empty `Table` (its header + ghost row separators would show
            // through an overlay). Safe w.r.t. the live-reload reentrancy note:
            // with zero rows there is nothing for NSTableView to reload, and
            // sessions grow monotonically during capture (one empty→filled flip).
            if sessions.isEmpty {
                emptyState
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Group {
                    if workspace.sessionGrouping == .none {
                        sessionTable(sessions: sessions, workspace: workspace)
                    } else {
                        groupedTable(rows: coordinator.sessionRows, workspace: workspace)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        // The spine of the window takes every point it is offered. Stated here
        // rather than left to whichever child happens to be greedy, so an empty
        // list or a hidden filter bar can never shrink the column.
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: Private

    @ViewBuilder private var emptyState: some View {
        if let error = coordinator.captureError {
            ContentUnavailableView {
                Label("Capture Error", systemImage: "exclamationmark.triangle")
            } description: {
                Text(error)
            }
        } else if coordinator.isCapturing {
            ContentUnavailableView {
                Label("Capturing on \(coordinator.captureInterface)", systemImage: "dot.radiowaves.left.and.right")
            } description: {
                Text("Waiting for packets…")
            }
        } else if coordinator.sessions.isEmpty {
            if coordinator.isViewingSavedCapture {
                ContentUnavailableView {
                    Label("No Sessions", systemImage: "rectangle.stack")
                } description: {
                    Text("This capture contains no sessions.")
                }
            } else {
                firstRunEmptyState
            }
        } else {
            ContentUnavailableView.search
        }
    }

    /// First-run / no-data landing on the Sessions surface: a quiet, actionless
    /// empty state (never a blank table) that points to the toolbar, which
    /// already owns Start/Stop and the interface picker.
    private var firstRunEmptyState: some View {
        ContentUnavailableView {
            Label("No Sessions", systemImage: "network.slash")
        } description: {
            Text("Start a capture from the toolbar to observe network sessions.")
        }
    }

    private func sessionTable(sessions: [SessionSummary], workspace: WorkspaceState) -> some View {
        Table(sessions, selection: Binding(
            get: { workspace.selectedSessionID },
            // Guard the write-back: while a live rebuild replaces the rows,
            // NSTableView re-applies the selection *through this setter from
            // inside its own delegate callback*. Assigning the same value there
            // re-triggers an observable update mid-update — the "reentrant
            // operation in its NSTableView delegate" warning that becomes a hard
            // assert (and a crash under the debugger). No-op when unchanged.
            set: { newValue in
                if workspace.selectedSessionID != newValue {
                    workspace.selectedSessionID = newValue
                }
            }
        )) {
            TableColumn("Time") { session in
                Text(session.startTime, format: .dateTime.hour().minute().second())
                    .font(Theme.Typography.monoSmall)
                    .foregroundStyle(.secondary)
            }
            .width(72)
            TableColumn("Source") { session in
                Text(session.sourceEndpoint).font(Theme.Typography.mono).lineLimit(1)
            }
            .width(min: 110, ideal: 150)
            TableColumn("Destination") { session in
                Text(session.destinationEndpoint).font(Theme.Typography.mono).lineLimit(1)
            }
            .width(min: 110, ideal: 150)
            TableColumn("Host") { session in
                Text(session.host).font(Theme.Typography.body).lineLimit(1)
            }
            .width(min: 120, ideal: 180)
            TableColumn("Client") { session in
                clientCell(session)
            }
            .width(min: 90, ideal: 130)
            TableColumn("Protocol") { session in
                protocolPill(session.primaryProtocol)
            }
            .width(72)
            TableColumn("Length") { session in
                Text(ByteCountFormatter.string(fromByteCount: Int64(session.totalBytes), countStyle: .binary))
                    .font(Theme.Typography.monoSmall)
                    .foregroundStyle(.secondary)
            }
            .width(72)
            TableColumn("") { session in
                Image(systemName: session.status.systemImage)
                    .font(.system(size: Theme.Icon.small))
                    .foregroundStyle(Theme.color(for: session.status))
                    .help(session.status.label)
            }
            .width(20)
            TableColumn("Summary") { session in
                Text(session.infoSummary)
                    .font(Theme.Typography.body)
                    .lineLimit(1)
                    .foregroundStyle(session.status == .error ? Color.red : Color.primary)
            }
            .width(min: 160, ideal: 280)
        }
        .contextMenu(forSelectionType: SessionSummary.ID.self) { ids in
            rowContextMenu(ids: ids, sessions: sessions)
        }
    }

    /// Correlated view: one row per action, its sessions nested beneath.
    ///
    /// Deliberately a separate `Table` from the flat one rather than a
    /// parameterised single table. The flat table carries hard-won guards
    /// against `NSTableView` reentrancy, and grouping changes both its row type
    /// and its selection semantics — folding both into one body risks
    /// destabilising the path that already works.
    private func groupedTable(rows: [SessionRow], workspace: WorkspaceState) -> some View {
        Table(of: SessionRow.self, selection: Binding(
            get: { workspace.selectedSessionID },
            // Selecting an action resolves to its first session, so the
            // inspector and the dock always have a concrete thing to describe.
            // Same no-op guard as the flat table: NSTableView re-applies the
            // selection through this setter from inside its own delegate.
            set: { newValue in
                guard let newValue else {
                    if workspace.selectedSessionID != nil {
                        workspace.selectedSessionID = nil
                    }
                    return
                }
                let resolved = rows.first { $0.id == newValue }?.representativeSessionID ?? newValue
                if workspace.selectedSessionID != resolved {
                    workspace.selectedSessionID = resolved
                }
            }
        )) {
            TableColumn("Time") { (row: SessionRow) in
                Text(row.startTime, format: .dateTime.hour().minute().second())
                    .font(Theme.Typography.monoSmall)
                    .foregroundStyle(.secondary)
            }
            .width(72)
            TableColumn("Source") { (row: SessionRow) in
                Text(row.sourceEndpoint).font(Theme.Typography.mono).lineLimit(1)
            }
            .width(min: 110, ideal: 150)
            TableColumn("Destination") { (row: SessionRow) in
                Text(row.destinationEndpoint).font(Theme.Typography.mono).lineLimit(1)
            }
            .width(min: 110, ideal: 150)
            TableColumn("Host") { (row: SessionRow) in
                actionHostCell(row)
            }
            .width(min: 140, ideal: 220)
            TableColumn("Client") { (row: SessionRow) in
                Text(row.processName ?? "—").font(Theme.Typography.body).lineLimit(1).foregroundStyle(.secondary)
            }
            .width(min: 90, ideal: 130)
            TableColumn("Protocol") { (row: SessionRow) in
                if let proto = row.primaryProtocol {
                    protocolPill(proto)
                }
            }
            .width(72)
            TableColumn("Length") { (row: SessionRow) in
                Text(ByteCountFormatter.string(fromByteCount: Int64(row.totalBytes), countStyle: .binary))
                    .font(Theme.Typography.monoSmall)
                    .foregroundStyle(.secondary)
            }
            .width(72)
            TableColumn("") { (row: SessionRow) in
                Image(systemName: row.status.systemImage)
                    .font(.system(size: Theme.Icon.small))
                    .foregroundStyle(Theme.color(for: row.status))
                    .help(row.status.label)
            }
            .width(20)
            TableColumn("Summary") { (row: SessionRow) in
                Text(row.summary)
                    .font(Theme.Typography.body)
                    .lineLimit(1)
                    .foregroundStyle(row.status == .error ? Color.red : Color.primary)
            }
            .width(min: 160, ideal: 280)
        } rows: {
            ForEach(rows) { row in
                if case .action = row, !row.childRows.isEmpty {
                    DisclosureTableRow(row) {
                        ForEach(row.childRows) { child in
                            TableRow(child)
                        }
                    }
                } else {
                    TableRow(row)
                }
            }
        }
        .contextMenu(forSelectionType: SessionRow.ID.self) { ids in
            groupedRowContextMenu(ids: ids, rows: rows)
        }
    }

    /// The action's name with its confidence, so an inferred grouping never
    /// looks like an observed fact.
    @ViewBuilder
    private func actionHostCell(_ row: SessionRow) -> some View {
        switch row {
        case let .action(activity):
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(activity.title).font(Theme.Typography.body).lineLimit(1).truncationMode(.middle)
                    Text("\(activity.sessions.count) sessions")
                        .font(Theme.Typography.badge)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(Capsule().fill(Color.secondary.opacity(0.15)))
                        .foregroundStyle(.secondary)
                    Text(activity.confidence.title)
                        .font(Theme.Typography.badge)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(Capsule().fill(Theme.color(for: activity.confidence).opacity(0.15)))
                        .foregroundStyle(Theme.color(for: activity.confidence))
                    if activity.isContested {
                        Image(systemName: "questionmark.circle")
                            .font(.system(size: Theme.Icon.small))
                            .foregroundStyle(.orange)
                    }
                }
                // The claim's grounds, on the row that makes the claim. A
                // grouping the user has to open a panel to audit is one they
                // will take on trust — which is exactly what correlation must
                // not be granted.
                Text(evidenceLine(activity))
                    .font(Theme.Typography.micro)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .foregroundStyle(activity.isContested ? Color.orange : Theme.color(for: activity.confidence))
            }
            .help(evidenceLine(activity))
        case let .group(group):
            // Observed, not inferred — so no confidence pill. The count is the
            // whole claim: these sessions literally carry this attribute.
            HStack(spacing: 6) {
                Image(systemName: group.kind == .host ? "globe" : "app.badge")
                    .font(.system(size: Theme.Icon.small))
                    .foregroundStyle(.secondary)
                Text(group.title).font(Theme.Typography.body).lineLimit(1).truncationMode(.middle)
                Text("\(group.sessions.count)")
                    .font(Theme.Typography.badge)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Capsule().fill(Color.secondary.opacity(0.15)))
                    .foregroundStyle(.secondary)
            }
        case let .session(session):
            Text(session.host).font(Theme.Typography.body).lineLimit(1)
        }
    }

    /// Right-click menu for the flat session table. Acts on the row under the
    /// cursor — resolved from the ids the context menu hands us, never the stale
    /// `selectedSessionID` — so a right-click that lands off the current selection
    /// still operates on what the user actually clicked.
    @ViewBuilder
    private func rowContextMenu(ids: Set<SessionSummary.ID>, sessions: [SessionSummary]) -> some View {
        if let session = clickedSession(ids: ids, in: sessions) {
            sessionMenu(session)
        }
    }

    /// Right-click menu for the grouped table. The clicked `SessionRow` is
    /// resolved from the same ids — including nested child rows — so a session,
    /// an action, or a group each gets the menu that is honest for its kind.
    @ViewBuilder
    private func groupedRowContextMenu(ids: Set<SessionRow.ID>, rows: [SessionRow]) -> some View {
        if let row = clickedRow(ids: ids, in: rows) {
            switch row {
            case let .session(session):
                sessionMenu(session)
            case let .action(activity):
                if let first = activity.sessions.first {
                    Button("Inspect First Session", systemImage: "sidebar.right") {
                        coordinator.select(first)
                    }
                }
                // An action spans several conversations, so it has no single
                // hostname to scope by — only its own summary line to copy.
                Button("Copy Summary", systemImage: "doc.on.doc") {
                    copyToPasteboard(row.summary)
                }
            case let .group(group):
                groupMenu(group)
            }
        }
    }

    /// The full menu for one session, shared by both tables.
    @ViewBuilder
    private func sessionMenu(_ session: SessionSummary) -> some View {
        let host = session.host
        let hostValid = isValidHost(host)
        let proto = session.primaryProtocol

        Button("Inspect Session", systemImage: "sidebar.right") { coordinator.select(session) }

        Divider()

        Menu {
            if hostValid {
                Button("Host") { copyToPasteboard(host) }
            }
            Button("Source") { copyToPasteboard(session.sourceEndpoint) }
            Button("Destination") { copyToPasteboard(session.destinationEndpoint) }
            Button("Summary") { copyToPasteboard(session.infoSummary) }
        } label: {
            Label("Copy", systemImage: "doc.on.doc")
        }

        Divider()

        if hostValid {
            Button("Show Sessions for \(host)", systemImage: "line.3.horizontal.decrease.circle") {
                coordinator.selectHost(host)
            }
        }
        if let process = validProcessName(session.processName) {
            Button("Show Sessions for \(process)", systemImage: "app.badge") {
                coordinator.selectProcess(process)
            }
        }

        if hostValid || validProcessName(session.processName) != nil {
            Divider()
        }

        if hostValid {
            Button(
                coordinator.isHostPinned(host) ? "Unpin Host" : "Pin Host",
                systemImage: coordinator.isHostPinned(host) ? "pin.slash" : "pin"
            ) { coordinator.togglePinHost(host) }
            Button(
                coordinator.isHostMuted(host) ? "Unmute Host" : "Mute Host",
                systemImage: coordinator.isHostMuted(host) ? "speaker.wave.2" : "speaker.slash"
            ) { coordinator.toggleMuteHost(host) }
        }
        Button(
            coordinator.isProtocolMuted(proto) ? "Unmute \(proto.label)" : "Mute \(proto.label)",
            systemImage: coordinator.isProtocolMuted(proto) ? "speaker.wave.2" : "speaker.slash"
        ) { coordinator.toggleMuteProtocol(proto) }
    }

    /// The menu for an observed group. Scopes by the group's real attribute — a
    /// host filters by host, a process by process — and never invents an
    /// aggregate endpoint the group does not carry.
    @ViewBuilder
    private func groupMenu(_ group: SessionGroup) -> some View {
        if let first = group.sessions.first {
            Button("Inspect First Session", systemImage: "sidebar.right") {
                coordinator.select(first)
            }
        }
        Button("Copy Group Name", systemImage: "doc.on.doc") {
            copyToPasteboard(group.key)
        }

        Divider()

        switch group.kind {
        case .host:
            let host = group.key
            if isValidHost(host) {
                Button("Show Sessions for \(host)", systemImage: "line.3.horizontal.decrease.circle") {
                    coordinator.selectHost(host)
                }
                Divider()
                Button(
                    coordinator.isHostPinned(host) ? "Unpin Host" : "Pin Host",
                    systemImage: coordinator.isHostPinned(host) ? "pin.slash" : "pin"
                ) { coordinator.togglePinHost(host) }
                Button(
                    coordinator.isHostMuted(host) ? "Unmute Host" : "Mute Host",
                    systemImage: coordinator.isHostMuted(host) ? "speaker.wave.2" : "speaker.slash"
                ) { coordinator.toggleMuteHost(host) }
            }
        case .process:
            Button("Show Sessions for \(group.key)", systemImage: "app.badge") {
                coordinator.selectProcess(group.key)
            }
        }
    }

    @ViewBuilder
    private func clientCell(_ session: SessionSummary) -> some View {
        if let process = session.processName {
            HStack(spacing: 5) {
                AppIconView(name: process, size: 15)
                Text(process).font(Theme.Typography.body).lineLimit(1)
            }
        } else {
            HStack(spacing: 5) {
                Image(systemName: "questionmark.app.dashed")
                    .font(.system(size: Theme.Icon.medium)).foregroundStyle(.tertiary)
                Text("—").font(Theme.Typography.body).foregroundStyle(.secondary)
            }
        }
    }

    private func protocolPill(_ proto: ProtocolKind) -> some View {
        Text(proto.label)
            .font(Theme.Typography.badge)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Theme.color(for: proto).opacity(0.18), in: Capsule())
            .foregroundStyle(Theme.color(for: proto))
    }

    /// The session under the cursor, matched by id rather than read from the
    /// current selection, so the menu never acts on a stale row.
    private func clickedSession(ids: Set<SessionSummary.ID>, in sessions: [SessionSummary]) -> SessionSummary? {
        sessions.first { ids.contains($0.id) }
    }

    /// The row under the cursor, searching top-level rows first and then their
    /// child sessions so a right-click on a disclosed member resolves correctly.
    private func clickedRow(ids: Set<SessionRow.ID>, in rows: [SessionRow]) -> SessionRow? {
        for row in rows {
            if ids.contains(row.id) {
                return row
            }
            if let child = row.childRows.first(where: { ids.contains($0.id) }) {
                return child
            }
        }
        return nil
    }

    /// A host is worth acting on only when it is a real name — a blank host or the
    /// em-dash placeholder must not become a filter, pin, or mute target.
    private func isValidHost(_ host: String) -> Bool {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        return !trimmed.isEmpty && trimmed != "—"
    }

    private func validProcessName(_ processName: String?) -> String? {
        guard let trimmed = processName?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty,
              trimmed != "—" else
        {
            return nil
        }
        return trimmed
    }

    /// Copies exactly the chosen value to the general pasteboard.
    private func copyToPasteboard(_ value: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }

    /// The row's grounds in one line: the evidence summaries, or — when the
    /// address was claimed by more than one name — the competing candidates,
    /// because that ambiguity outranks the reasons for grouping.
    private func evidenceLine(_ activity: Activity) -> String {
        if activity.isContested {
            return "Shared address — also claimed by \(activity.competingNames.joined(separator: ", "))"
        }
        return activity.evidence.map(\.summary).joined(separator: " · ")
    }

    private func liveChartBinding(_ workspace: WorkspaceState) -> Binding<Bool> {
        Binding(
            get: { workspace.isLiveChartExpanded },
            set: { workspace.isLiveChartExpanded = $0 }
        )
    }
}

// MARK: - LiveTrafficStrip

/// A modest, collapsible live-throughput strip above the session table. Isolated
/// so its per-second updates don't re-render the Table's host body.
private struct LiveTrafficStrip: View {
    // MARK: Internal

    let coordinator: MainContentCoordinator

    @Binding var isExpanded: Bool

    var body: some View {
        VStack(spacing: 0) {
            Button {
                withAnimation(.smooth(duration: 0.2)) { isExpanded.toggle() }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "waveform.path.ecg")
                        .font(.system(size: Theme.Icon.small)).foregroundStyle(.secondary)
                    Text("Live Traffic")
                        .font(Theme.Typography.captionEmphasis).foregroundStyle(.secondary)
                    Spacer()
                    Text(currentRate)
                        .font(Theme.Typography.monoSmall)
                        .foregroundStyle(Color.accentColor)
                    Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                        .font(.system(size: Theme.Icon.small)).foregroundStyle(.tertiary)
                }
                .padding(.horizontal, Theme.Metrics.spacingL)
                .padding(.vertical, 5)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if isExpanded {
                ThroughputChart(samples: coordinator.throughputSamples)
                    .frame(height: 104)
                    .padding(.horizontal, Theme.Metrics.spacingL)
                    .padding(.bottom, Theme.Metrics.spacingS)
            }
        }
        .background(.background.secondary)
    }

    // MARK: Private

    private var currentRate: String {
        let bytesPerSecond = coordinator.throughputSamples.last?.bytesPerSecond ?? 0
        return "\(ByteCountFormatter.string(fromByteCount: Int64(bytesPerSecond), countStyle: .binary))/s"
    }
}
