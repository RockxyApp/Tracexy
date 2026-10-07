import AppKit
import SwiftUI

// MARK: - SessionCenterView

struct SessionCenterView: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    let commandDescriptors: [SessionCommandDescriptor]
    let onCommandAction: (SessionCommandKind) -> Void

    var body: some View {
        let workspace = coordinator.activeWorkspace
        let sessions = coordinator.visibleSessions
        sessionContent(sessions: sessions, workspace: workspace)
            .tracexyDenseScrollEdge()
            .tracexySafeAreaBar(edge: .top) {
                sessionControlShelf(
                    workspace,
                    shownCount: sessions.count,
                    shownIDs: coordinator.pinnedSessionIDs.isEmpty ? [] : Set(sessions.map(\.id))
                )
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .onChange(of: visibilityFingerprint(workspace)) { _, _ in
                coordinator.reconcileLiveFollowing(in: workspace)
            }
            .onAppear(perform: loadColumnCustomization)
            .alert(
                "Name \(namingAddress ?? "Address")",
                isPresented: Binding(get: { namingAddress != nil }, set: {
                    if !$0 {
                        namingAddress = nil
                    }
                })
            ) {
                TextField("Name, for example NAS", text: $addressNameDraft)
                Button("Save") {
                    if let address = namingAddress {
                        coordinator.addressNames.setName(addressNameDraft, for: address)
                    }
                    namingAddress = nil
                }
                if let address = namingAddress, coordinator.addressNames.name(for: address) != nil {
                    Button("Remove Name", role: .destructive) {
                        coordinator.addressNames.setName("", for: address)
                        namingAddress = nil
                    }
                }
                Button("Cancel", role: .cancel) { namingAddress = nil }
            } message: {
                Text("Shown in this Project wherever this address is a session’s only name.")
            }
            .onChange(of: coordinator.projectStore.activeProjectID) { _, _ in
                didLoadColumnCustomization = false
                loadColumnCustomization()
            }
            .onChange(of: columnCustomization) { _, customization in
                guard didLoadColumnCustomization,
                      let data = try? JSONEncoder().encode(customization) else
                {
                    return
                }
                coordinator.activeProjectDefaults.set(data, forKey: ProjectScopedSettingsKeys.sessionTableColumns)
            }
    }

    /// A compact, counted inventory of what the file actually contained: how many
    /// link types its frames declared, and the two coverage caveats. Nothing here
    /// interprets a link type, a comment or an option — these are counts only.
    nonisolated static func metadataSummary(_ metadata: CaptureMetadataSummary) -> String {
        var parts: [String] = []
        let linkTypes = metadata.linkTypeCounts.count
        if metadata.linkTypeOverflowFrameCount > 0 {
            parts.append("More than \(linkTypes.formatted()) link types")
        } else if linkTypes > 0 {
            parts.append(linkTypes == 1 ? "1 link type" : "\(linkTypes.formatted()) link types")
        }
        if metadata.untimedFrameCount > 0 {
            parts.append("\(metadata.untimedFrameCount.formatted()) untimed")
        }
        if metadata.undecodableLinkLayerFrameCount > 0 {
            parts.append("\(metadata.undecodableLinkLayerFrameCount.formatted()) undecoded link layer")
        }
        return parts.joined(separator: ", ")
    }

    // MARK: Private

    private struct VisibilityFingerprint: Equatable {
        let sidebarSelection: SidebarItem
        let filterText: String
        let searchField: SessionSearchField
        let isSearchEnabled: Bool
        let categoryFilters: Set<SessionFilterCategory>
        let hostFilter: String?
        let processFilter: String?
        let ipFilter: String?
        let aggregateProtocolFilters: Set<ProtocolKind>
        let aggregateDestinationFilter: String?
        let aggregateRequiresFindings: Bool
        let filterRules: [SessionFilterRule]
    }

    /// Column sort chosen by clicking a header. Empty keeps the engine's stable
    /// capture order (oldest→newest, rows updating in place), which stays the
    /// default so a live list never reshuffles under the cursor unasked.
    @State private var sortOrder: [KeyPathComparator<SessionSummary>] = []
    /// Which columns are shown and in what order; kept per Project.
    @State private var columnCustomization = TableColumnCustomization<SessionSummary>()
    @State private var didLoadColumnCustomization = false
    /// The address being named from the context menu, and the name being typed.
    @State private var namingAddress: String?
    @State private var addressNameDraft = ""

    private var captureImportNotice: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Image(systemName: "tray.and.arrow.down")
                .foregroundStyle(Color.accentColor)
            VStack(alignment: .leading, spacing: 3) {
                Text(coordinator.isCancellingCaptureImport ? "Cancelling import…" : "Importing capture…")
                    .font(Theme.Typography.bodyEmphasis)
                if let name = coordinator.captureImportName {
                    Text(name).font(Theme.Typography.caption).lineLimit(1).truncationMode(.middle)
                }
                if let fraction = coordinator.captureImportFraction {
                    ProgressView(value: fraction)
                        .accessibilityValue(Text(fraction, format: .percent))
                } else {
                    ProgressView().controlSize(.small)
                }
            }
            Spacer(minLength: 0)
            Button("Cancel Import") { coordinator.cancelCaptureImport() }
                .disabled(coordinator.isCancellingCaptureImport)
        }
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingS)
        .background(Color.accentColor.opacity(0.06))
        .accessibilityIdentifier("capture-import-progress")
    }

    private var frameExportNotice: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Image(systemName: "square.and.arrow.up")
                .foregroundStyle(Color.accentColor)
            VStack(alignment: .leading, spacing: 3) {
                Text(coordinator.isCancellingFrameExport ? "Cancelling export…" : "Exporting frames…")
                    .font(Theme.Typography.bodyEmphasis)
                if let name = coordinator.frameExportName {
                    Text(name).font(Theme.Typography.caption).lineLimit(1).truncationMode(.middle)
                }
                if let fraction = coordinator.frameExportFraction {
                    ProgressView(value: fraction)
                        .accessibilityValue(Text(fraction, format: .percent))
                } else {
                    ProgressView().controlSize(.small)
                }
            }
            Spacer(minLength: 0)
            Button("Cancel Export") { coordinator.cancelFrameExport() }
                .disabled(coordinator.isCancellingFrameExport)
        }
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingS)
        .background(Color.accentColor.opacity(0.06))
        .accessibilityIdentifier("frame-export-progress")
    }

    private var savedCaptureSourceNotice: some View {
        HStack(spacing: Theme.Metrics.spacingS) {
            Image(systemName: "doc")
            Text(coordinator.activeSavedCapture?.url.lastPathComponent ?? "Saved capture")
                .lineLimit(1).truncationMode(.middle)
                .help(coordinator.activeSavedCapture?.url.lastPathComponent ?? "Saved capture")
            Spacer(minLength: 0)
            Text("Saved capture")
            if let activity = coordinator.savedCaptureActivity {
                Text("\(activity.totalFrames.formatted()) frames")
                    .monospacedDigit()
            }
            if let metadata = coordinator.savedCaptureMetadata {
                Text(Self.metadataSummary(metadata))
                    .monospacedDigit()
                    .accessibilityIdentifier("saved-capture-metadata")
            }
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingS)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("saved-capture-source")
    }

    private var savedCaptureOpeningNotice: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Image(systemName: "doc.badge.clock")
                .foregroundStyle(Color.accentColor)
            VStack(alignment: .leading, spacing: 3) {
                Text("Opening capture…")
                    .font(Theme.Typography.bodyEmphasis)
                if let fraction = coordinator.savedCaptureOpenFraction {
                    ProgressView(value: fraction)
                        .accessibilityValue(Text(fraction, format: .percent))
                } else {
                    ProgressView()
                        .controlSize(.small)
                }
            }
        }
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingS)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.accentColor.opacity(0.06))
    }

    @ViewBuilder private var emptyState: some View {
        let scope = coordinator.sessionScope(shownCount: 0)
        if let error = coordinator.captureError {
            ContentUnavailableView {
                Label("Capture Error", systemImage: "exclamationmark.triangle")
            } description: {
                Text(error)
            }
        } else if scope.emptyClassification == .allSessionsRemoved {
            ContentUnavailableView {
                Label("All Sessions Removed from View", systemImage: "eye.slash")
            } description: {
                Text("The capture evidence is still intact and can be restored.")
            } actions: {
                scopeRecovery(scope)
            }
        } else if scope.emptyClassification == .hiddenByScope {
            ContentUnavailableView {
                Label("No Matching Sessions", systemImage: "line.3.horizontal.decrease.circle")
            } description: {
                Text("Sessions exist in this capture, but none match the current scope.")
            } actions: {
                scopeRecovery(scope)
            }
        } else if coordinator.isCapturing {
            ContentUnavailableView {
                Label("Capturing on \(coordinator.captureSourceName)", systemImage: "dot.radiowaves.left.and.right")
            } description: {
                Text("Waiting for packets…")
            }
        } else if coordinator.isViewingSavedCapture {
            ContentUnavailableView {
                Label("No Sessions", systemImage: "rectangle.stack")
            } description: {
                Text("This capture contains no sessions.")
            }
        } else {
            firstRunEmptyState
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

    /// The open saved capture's file changed underneath it. Reload re-reads it;
    /// the sessions shown are from the bytes as they were when opened.
    private var changedOnDiskNotice: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Image(systemName: "arrow.clockwise.circle")
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 3) {
                Text("The capture file changed on disk")
                    .font(Theme.Typography.bodyEmphasis)
                Text("Sessions shown are from the file as it was when it was opened. Reload to read the current file.")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
            Button("Reload") { coordinator.reloadActiveSavedCapture() }
                .keyboardShortcut("r", modifiers: .command)
        }
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingS)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.06))
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("capture-changed-on-disk")
    }

    @ViewBuilder
    private func scopeRecovery(_ scope: SessionScopeSummary) -> some View {
        if scope.hasClearableFilters {
            Button(SessionScopeAction.resetTitle) { coordinator.resetSessionFilters() }
                .help(SessionScopeAction.resetHelp)
        }
        if coordinator.isNoiseControlActive {
            Button("Reset Noise Control for Project") { coordinator.clearNoiseControl() }
                .help("Removes this Project’s muted host and protocol rules across its workspaces.")
        }
        if scope.removedCount > 0 {
            Button("Restore Removed Sessions") { coordinator.restoreRemovedSessions() }
        }
    }

    private func sessionControlShelf(_ workspace: WorkspaceState, shownCount: Int, shownIDs: Set<UUID>) -> some View {
        VStack(spacing: Theme.Glass.functionalBarVerticalInset) {
            if workspace.isFilterBarVisible {
                SessionFilterBar(
                    coordinator: coordinator,
                    commandDescriptors: commandDescriptors,
                    onCommandAction: onCommandAction
                )
            }
            if coordinator.sessionScope(shownCount: shownCount).isConstrained || coordinator
                .canReturnToPreviousSessionScope
            {
                SessionScopeNotice(
                    coordinator: coordinator,
                    shownCount: shownCount,
                    showsResetAction: !workspace.isFilterBarVisible && shownCount > 0
                )
                .padding(.horizontal, Theme.Metrics.spacingL)
            }
            let pinned = coordinator.pinnedSessions
            if !pinned.isEmpty {
                PinnedSessionsStrip(coordinator: coordinator, pinned: pinned, shownIDs: shownIDs)
                    .padding(.horizontal, Theme.Metrics.spacingL)
            }
            if coordinator.isViewingSavedCapture {
                savedCaptureSourceNotice
            } else {
                LiveTrafficStrip(coordinator: coordinator, isExpanded: liveChartBinding(workspace))
            }
        }
        .padding(.bottom, Theme.Glass.functionalBarVerticalInset)
    }

    private func sessionContent(sessions: [SessionSummary], workspace: WorkspaceState) -> some View {
        VStack(spacing: 0) {
            if coordinator.isImportingCapture {
                captureImportNotice
                Divider()
            } else if coordinator.isExportingFrames {
                frameExportNotice
                Divider()
            } else if coordinator.isOpeningSavedCapture {
                savedCaptureOpeningNotice
                Divider()
            } else if let unavailable = coordinator.unavailableReferencedCapture {
                unavailableSourceNotice(unavailable)
                Divider()
            } else if coordinator.canReloadActiveSavedCapture {
                changedOnDiskNotice
                Divider()
            } else if let warning = coordinator.savedCaptureWarning {
                savedCaptureWarningNotice(warning)
                Divider()
            }
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
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// A referenced capture whose file is missing or changed. An inline notice
    /// with one recovery action, never an alert (HIG: alerts are not for
    /// information). The Library item and any adopted sessions stay intact.
    private func unavailableSourceNotice(_ capture: SavedCapture) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Image(systemName: "doc.questionmark")
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 3) {
                Text(capture
                    .availability == .missing ? "“\(capture.name)” can’t be found" :
                    "“\(capture.name)” changed on disk")
                    .font(Theme.Typography.bodyEmphasis)
                Text(
                    capture.availability == .missing
                        ? "The original file for this Library item is no longer available on this Mac. Locate it to open the capture."
                        : "The original file for this Library item changed on this Mac. Locate the original, or reload to read the current file."
                )
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .truncationMode(.middle)
            }
            Spacer(minLength: 0)
            if capture.availability == .changed {
                Button("Reload") { coordinator.reloadReferencedCapture(capture) }
            }
            Button("Locate…") { coordinator.locateReferencedCapture(capture) }
        }
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingS)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.06))
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("capture-source-unavailable")
    }

    private func savedCaptureWarningNotice(_ warning: String) -> some View {
        HStack(spacing: Theme.Metrics.spacingS) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.yellow)
            Text(warning)
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingS)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.yellow.opacity(0.06))
    }

    /// The Time cell for a row. A capture file that recorded no time for a frame
    /// leaves the session's start unknown; the cell says so with the standard em
    /// dash rather than showing a substituted instant.
    @ViewBuilder
    private func timeCell(_ startTime: Date?) -> some View {
        if let startTime {
            Text(coordinator.sessionTimeDisplay.format.string(
                for: startTime, captureStart: coordinator.trafficTimeline.firstTimedFrame
            ))
            .font(Theme.Typography.monoSmall)
            .foregroundStyle(.secondary)
        } else {
            Text("—")
                .font(Theme.Typography.monoSmall)
                .foregroundStyle(.tertiary)
                .help("This capture file records no time for these frames.")
        }
    }

    private func sessionTable(sessions: [SessionSummary], workspace: WorkspaceState) -> some View {
        let ordered = sortOrder.isEmpty ? sessions : sessions.sorted(using: sortOrder)
        // Computed once per render, and only when the Timeline column is shown.
        let timelineSpan = columnCustomization[visibility: "timeline"] == .visible
            ? SessionTimelineBar.span(of: sessions)
            : nil
        return Table(ordered, selection: Binding(
            get: { workspace.selectedSessionID },
            // Guard the write-back: while a live rebuild replaces the rows,
            // NSTableView re-applies the selection *through this setter from
            // inside its own delegate callback*. Assigning the same value there
            // re-triggers an observable update mid-update — the "reentrant
            // operation in its NSTableView delegate" warning that becomes a hard
            // assert (and a crash under the debugger). No-op when unchanged.
            set: { newValue in
                if workspace.selectedSessionID != newValue {
                    coordinator.userDidNavigateSessionHistory()
                    workspace.selectedSessionID = newValue
                }
            }
        ), sortOrder: $sortOrder, columnCustomization: $columnCustomization) {
            TableColumn(coordinator.sessionTimeDisplay.format.columnTitle, value: \.sortableStartTime) { session in
                timeCell(session.startTime)
            }
            .width(72)
            .customizationID("time")
            TableColumn("Source", value: \.sourceEndpoint) { session in
                Text(session.sourceEndpoint).font(Theme.Typography.mono).lineLimit(1)
            }
            .width(min: 110, ideal: 150)
            .customizationID("source")
            TableColumn("Destination", value: \.destinationEndpoint) { session in
                Text(session.destinationEndpoint).font(Theme.Typography.mono).lineLimit(1)
            }
            .width(min: 110, ideal: 150)
            .customizationID("destination")
            TableColumn("Host", value: \.host) { session in
                HStack(spacing: Theme.Metrics.spacingS) {
                    SessionTagDots(tags: coordinator.investigationNotes.tags(onSession: session.id))
                    Text(coordinator.addressNames.displayHost(for: session)).font(Theme.Typography.body).lineLimit(1)
                    if coordinator.investigationNotes.hasNote(onSession: session.id) {
                        Image(systemName: "note.text")
                            .font(.system(size: Theme.Icon.small))
                            .foregroundStyle(.secondary)
                            .help("You wrote a note about this session")
                            .accessibilityLabel("Has a note")
                    }
                }
            }
            .width(min: 120, ideal: 180)
            .customizationID("host")
            TableColumn("Client", value: \.sortableProcessName) { session in
                clientCell(session)
            }
            .width(min: 90, ideal: 130)
            .customizationID("client")
            TableColumn("Protocol", value: \.primaryProtocolLabel) { session in
                protocolPill(session.primaryProtocol)
            }
            .width(72)
            .customizationID("protocol")
            TableColumn("Length", value: \.totalBytes) { session in
                Text(ByteUnits.string(Int64(session.totalBytes)))
                    .font(Theme.Typography.monoSmall)
                    .foregroundStyle(.secondary)
            }
            .width(72)
            .customizationID("length")
            TableColumn("", value: \.statusRank) { session in
                Image(systemName: session.status.systemImage)
                    .font(.system(size: Theme.Icon.small))
                    .foregroundStyle(Theme.color(for: session.status))
                    .help(session.status.label)
            }
            .width(20)
            .customizationID("status")
            .disabledCustomizationBehavior(.visibility)
            TableColumn("Summary", value: \.infoSummary) { session in
                Text(session.infoSummary)
                    .font(Theme.Typography.body)
                    .lineLimit(1)
                    .foregroundStyle(session.status == .error ? Color.red : Color.primary)
            }
            .width(min: 160, ideal: 280)
            .customizationID("summary")
            optionalColumns(span: timelineSpan)
        }
        .contextMenu(forSelectionType: SessionSummary.ID.self) { ids in
            rowContextMenu(ids: ids, sessions: sessions)
        }
        .background {
            SessionHistoryScrollObserver(
                revealToken: workspace.sessionRevealToken,
                revealRow: ordered.firstIndex { $0.id == workspace.selectedSessionID }
            ) {
                coordinator.userDidNavigateSessionHistory()
            }
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
                        coordinator.userDidNavigateSessionHistory()
                        workspace.selectedSessionID = nil
                    }
                    return
                }
                let resolved = rows.first { $0.id == newValue }?.representativeSessionID ?? newValue
                if workspace.selectedSessionID != resolved {
                    coordinator.userDidNavigateSessionHistory()
                    workspace.selectedSessionID = resolved
                }
            }
        )) {
            TableColumn(coordinator.sessionTimeDisplay.format.columnTitle) { (row: SessionRow) in
                timeCell(row.startTime)
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
                Text(ByteUnits.string(Int64(row.totalBytes)))
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
        .background {
            SessionHistoryScrollObserver(
                revealToken: workspace.sessionRevealToken,
                revealRow: rows.firstIndex { $0.id == workspace.selectedSessionID }
            ) {
                coordinator.userDidNavigateSessionHistory()
            }
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
                        .tracexyChipStyle(tint: .secondary, isActive: true)
                    Text(activity.confidence.title)
                        .font(Theme.Typography.badge)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .tracexyChipStyle(
                            tint: Theme.color(for: activity.confidence),
                            isActive: true
                        )
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
                    .tracexyChipStyle(tint: .secondary, isActive: true)
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

                Divider()

                Button(
                    "Remove \(activity.sessions.count) Sessions from View",
                    systemImage: "trash",
                    role: .destructive
                ) {
                    coordinator.removeSessionsFromView(Set(activity.sessions.map(\.id)))
                }
            case let .group(group):
                groupMenu(group)
            }
        }
    }

    @ViewBuilder
    private func investigateLikeThisMenu(_ session: SessionSummary) -> some View {
        let available = likeThisTerms(session)
        if !available.isEmpty {
            Menu {
                ForEach(available, id: \.1) { title, term in
                    Button(title) {
                        coordinator.investigateSessions(narrowingWith: term)
                    }
                    .help(term)
                }
            } label: {
                Label("Investigate Sessions Like This", systemImage: "scope")
            }
        }
    }

    /// Name either endpoint's address for this Project. Offered only for endpoints
    /// that are real IP addresses.
    @ViewBuilder
    private func nameAddressMenu(_ session: SessionSummary) -> some View {
        let addresses = [session.sourceEndpointValue?.ip, session.destinationEndpointValue?.ip]
            .compactMap(\.self)
            .filter { IPAddressValue(parsing: $0) != nil }
        if !addresses.isEmpty {
            Menu {
                ForEach(Array(Set(addresses)).sorted(), id: \.self) { address in
                    Button(coordinator.addressNames.name(for: address).map { "\(address) (\($0))…" } ?? "\(address)…") {
                        addressNameDraft = coordinator.addressNames.name(for: address) ?? ""
                        namingAddress = address
                    }
                }
            } label: {
                Label("Name Address", systemImage: "character.cursor.ibeam")
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
            ForEach(SessionExportFormat.allCases) { format in
                Button(format.title) {
                    coordinator.exportSession(session, as: format)
                }
            }
            Divider()
            Button("Export Frames…") {
                coordinator.presentFrameExportPanel(preselectedSessions: [session.id])
            }
            .disabled(!coordinator.canExportFrames)
        } label: {
            Label("Export", systemImage: "square.and.arrow.up")
        }
        .disabled(!coordinator.canExport(session) && !coordinator.canExportFrames)

        Divider()

        Menu {
            if hostValid {
                Button("Host") { copyToPasteboard(host) }
            }
            Button("Source") { copyToPasteboard(session.sourceEndpoint) }
            Button("Destination") { copyToPasteboard(session.destinationEndpoint) }
            Button("Summary") { copyToPasteboard(session.infoSummary) }
            let terms = likeThisTerms(session)
            if !terms.isEmpty {
                Divider()
                Menu("As Session Expression") {
                    ForEach(terms, id: \.term) { title, term in
                        Button(title) { copyToPasteboard(term) }
                            .help(term)
                    }
                }
            }
        } label: {
            Label("Copy", systemImage: "doc.on.doc")
        }

        Divider()

        investigateLikeThisMenu(session)
        SessionTagMenu(coordinator: coordinator, sessionIDs: [session.id])
        nameAddressMenu(session)
        Button(
            coordinator.isSessionPinned(session.id) ? "Unpin Session" : "Pin Session",
            systemImage: coordinator.isSessionPinned(session.id) ? "pin.slash" : "pin"
        ) { coordinator.togglePinSession(session.id) }

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

        Divider()

        Button("Remove from View", systemImage: "trash", role: .destructive) {
            coordinator.removeSessionsFromView(Set([session.id]))
        }
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

        Divider()

        Button(
            "Remove \(group.sessions.count) Sessions from View",
            systemImage: "trash",
            role: .destructive
        ) {
            coordinator.removeSessionsFromView(Set(group.sessions.map(\.id)))
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

    /// "Investigate Sessions Like This": each item narrows the session expression by
    /// one of this session's own facts and applies it. Only facts the session actually
    /// carries are offered, and each becomes a term the parser accepts.
    /// The session-expression terms this session's own facts support, with menu titles.
    private func likeThisTerms(_ session: SessionSummary) -> [(title: String, term: String)] {
        let terms: [(String, String?)] = [
            ("Same Host", SessionExpressionTerm.sameHost(session.host)),
            ("Same Destination Address", SessionExpressionTerm.sameDestinationIP(session.destinationEndpointValue)),
            ("Same Destination Port", SessionExpressionTerm.sameDestinationPort(session.destinationEndpointValue)),
            ("Same Process", SessionExpressionTerm.sameProcess(validProcessName(session.processName))),
            ("Same Protocol", SessionExpressionTerm.sameProtocol(session.primaryProtocol)),
        ]
        return terms.compactMap { title, term in term.map { (title, $0) } }
    }

    /// Columns a user can add from the header's context menu. Each reads a typed
    /// session fact that is already published; none is shown until chosen.
    @TableColumnBuilder<SessionSummary, KeyPathComparator<SessionSummary>>
    private func optionalColumns(span: ClosedRange<Date>?) -> some TableColumnContent<
        SessionSummary,
        KeyPathComparator<SessionSummary>
    > {
        TableColumn("Timeline", value: \.sortableStartTime) { session in
            SessionTimelineBar(session: session, span: span)
        }
        .width(min: 90, ideal: 140)
        .customizationID("timeline")
        .defaultVisibility(.hidden)
        TableColumn("Server Name", value: \.sortableServerName) { session in
            Text(session.sni ?? "—").font(Theme.Typography.mono).lineLimit(1)
                .foregroundStyle(session.sni == nil ? .tertiary : .primary)
        }
        .width(min: 120, ideal: 180)
        .customizationID("serverName")
        .defaultVisibility(.hidden)
        TableColumn("Duration", value: \.sortableDuration) { session in
            Text(session.duration.map { String(format: "%.3f s", $0) } ?? "—")
                .font(Theme.Typography.monoSmall).foregroundStyle(.secondary)
        }
        .width(80)
        .customizationID("duration")
        .defaultVisibility(.hidden)
        TableColumn("Sent", value: \.bytesUp) { session in
            Text(ByteUnits.string(Int64(session.bytesUp)))
                .font(Theme.Typography.monoSmall).foregroundStyle(.secondary)
        }
        .width(72)
        .customizationID("bytesUp")
        .defaultVisibility(.hidden)
        TableColumn("Received", value: \.bytesDown) { session in
            Text(ByteUnits.string(Int64(session.bytesDown)))
                .font(Theme.Typography.monoSmall).foregroundStyle(.secondary)
        }
        .width(72)
        .customizationID("bytesDown")
        .defaultVisibility(.hidden)
        TableColumn("Latency", value: \.sortableLatency) { session in
            Text(session.latencyMilliseconds.map { String(format: "%.1f ms", $0) } ?? "—")
                .font(Theme.Typography.monoSmall).foregroundStyle(.secondary)
        }
        .width(72)
        .customizationID("latency")
        .defaultVisibility(.hidden)
        TableColumn("Protocols") { session in
            Text(session.protocolStack.map(\.label).joined(separator: " "))
                .font(Theme.Typography.monoSmall).foregroundStyle(.secondary).lineLimit(1)
        }
        .width(min: 90, ideal: 130)
        .customizationID("protocolStack")
        .defaultVisibility(.hidden)
        TableColumn("Completeness", value: \.sortableCompleteness) { session in
            SessionCompletenessCell(session: session)
        }
        .width(min: 90, ideal: 110)
        .customizationID("tcpCompleteness")
        .defaultVisibility(.hidden)
    }

    private func loadColumnCustomization() {
        let data = coordinator.activeProjectDefaults.data(forKey: ProjectScopedSettingsKeys.sessionTableColumns)
        let decoder = JSONDecoder()
        let saved = data.flatMap { try? decoder.decode(TableColumnCustomization<SessionSummary>.self, from: $0) }
        columnCustomization = saved ?? TableColumnCustomization<SessionSummary>()
        didLoadColumnCustomization = true
    }

    private func visibilityFingerprint(_ workspace: WorkspaceState) -> VisibilityFingerprint {
        VisibilityFingerprint(
            sidebarSelection: workspace.sidebarSelection,
            filterText: workspace.filterText,
            searchField: workspace.searchField,
            isSearchEnabled: workspace.isSearchEnabled,
            categoryFilters: workspace.categoryFilters,
            hostFilter: workspace.hostFilter,
            processFilter: workspace.processFilter,
            ipFilter: workspace.ipFilter,
            aggregateProtocolFilters: workspace.aggregateProtocolFilters,
            aggregateDestinationFilter: workspace.aggregateDestinationFilter,
            aggregateRequiresFindings: workspace.aggregateRequiresFindings,
            filterRules: workspace.filterRules
        )
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
        return activity.evidence.map(\.summary).joined(separator: "; ")
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
        .tracexyContentSurface(
            in: RoundedRectangle(cornerRadius: Theme.Metrics.cornerRadius, style: .continuous)
        )
        .padding(.horizontal, Theme.Glass.functionalBarHorizontalInset)
    }

    // MARK: Private

    private var currentRate: String {
        let bytesPerSecond = coordinator.throughputSamples.last?.bytesPerSecond ?? 0
        return "\(ByteUnits.string(Int64(bytesPerSecond)))/s"
    }
}
