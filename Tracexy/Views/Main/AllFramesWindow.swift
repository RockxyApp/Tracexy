import AppKit
import SwiftUI

// MARK: - AllFramesWindow

/// View ▸ All Frames: Wireshark's packet list for the whole capture — number, time,
/// source, destination, protocol, length and info for every frame, limited by default
/// to the frames of the sessions in view, with search and Go to Frame. Double-click a
/// frame to open its session and that exact frame in Layers.
struct AllFramesWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    @State var selection: CaptureFrameRow.ID?
    @State var historyRestoreOrdinal: UInt64?
    @State var pendingHistoryRestoreOrdinal: UInt64?
    @State var pendingHistoryBackward: Bool?
    @State var pendingHistoryRequestID: Int?
    @State var goTo = ""
    @State var revealToken = 0
    @State var notice: String?

    @Environment(\.openWindow) var openWindow

    var body: some View {
        @Bindable var state = coordinator.allFrames
        let inView = Set(coordinator.visibleSessions.map(\.id))
        let rows = state.visibleRows(sessionsInView: inView)
        let pinnedRows = state.pinnedFrameRows.values.sorted { $0.ordinal < $1.ordinal }
        let selectedRow = selection.flatMap { ordinal in rows.first { $0.ordinal == ordinal } }
        let canMutateSelectedRow = !state.isLoading
            && !state.isEvaluatingFrameExpression
            && state.error == nil
            && state.list != nil
            && selectedRow != nil
        let commandTarget = selectedRow.flatMap { row in
            row.provenance.timestamp.map { timestamp in
                FrameTimeCommandTarget(
                    reference: .init(sessionID: nil, ordinal: row.ordinal, timestamp: timestamp),
                    projectID: coordinator.projectStore.activeProjectID,
                    captureGeneration: coordinator.startGeneration,
                    captureRow: row
                )
            }
        }
        framesContent(state: state, rows: rows, pinnedRows: pinnedRows)
            .searchable(text: $state.search, placement: .toolbar, prompt: "Info, address or protocol")
            .toolbar {
                ToolbarItem(placement: .navigation) {
                    Toggle("Limit to Sessions in View", isOn: $state.limitToSessionsInView)
                        .toggleStyle(.checkbox)
                        .help(
                            "Show only the frames of the sessions the main window shows, like Wireshark's displayed frames"
                        )
                }
                ToolbarItem(placement: .navigation) {
                    goToField(rows)
                }
                ToolbarItem(placement: .primaryAction) {
                    frameNavigationControls
                }
                ToolbarItem(placement: .primaryAction) {
                    ControlGroup {
                        Button("Previous Frame in Session", systemImage: "chevron.up") {
                            stepInSession(rows, forward: false)
                        }
                        .keyboardShortcut(",", modifiers: .control)
                        Button("Next Frame in Session", systemImage: "chevron.down") {
                            stepInSession(rows, forward: true)
                        }
                        .keyboardShortcut(".", modifiers: .control)
                        Button("First Displayed Frame in Session", systemImage: "arrow.up.to.line") {
                            selectSessionEdge(rows, last: false)
                        }
                        Button("Last Displayed Frame in Session", systemImage: "arrow.down.to.line") {
                            selectSessionEdge(rows, last: true)
                        }
                    }
                    .disabled(selection.flatMap { id in rows.first { $0.id == id }?.sessionID } == nil)
                    .help("Step through or select the first or last displayed frame of the selected frame's session")
                }
                ToolbarItem(placement: .primaryAction) {
                    ControlGroup {
                        Button(
                            selectedRow.map { state.marked.contains($0.id) } == true
                                ? "Unmark Selected Frame" : "Mark Selected Frame",
                            systemImage: selectedRow.map { state.marked.contains($0.id) } == true
                                ? "bookmark.slash" : "bookmark"
                        ) {
                            toggleSelectedMark()
                        }
                        .disabled(!canMutateSelectedRow)
                        .help("Mark or unmark the selected frame that is still visible in the main list")

                        Button(
                            selectedRow.map { state.ignored.contains($0.id) } == true
                                ? "Unignore Selected Frame" : "Ignore Selected Frame",
                            systemImage: selectedRow.map { state.ignored.contains($0.id) } == true ? "eye" : "eye.slash"
                        ) {
                            toggleSelectedIgnore()
                        }
                        .disabled(!canMutateSelectedRow)
                        .help("Ignore or unignore the selected frame that is still visible in the main list")
                    }
                }
                ToolbarItem(placement: .primaryAction) {
                    Toggle("Find in Frames", systemImage: "text.magnifyingglass", isOn: $isFinding)
                        .help("Find text, hex bytes, a regular expression, or a Frame Expression in the capture")
                }
            }
            .tracexyDenseScrollEdge()
            .tracexySafeAreaBar(edge: .top) {
                VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
                    frameExpressionBar(state)
                    if isFinding {
                        FrameFindBar(
                            coordinator: coordinator, selection: selection,
                            onSelect: selectFoundFrame
                        ) { isFinding = false }
                    }
                }
                // The bar spans the window, so its controls need the same inset
                // every other safe-area bar applies. Without it the expression
                // field and Highlight button are drawn hard against the window
                // edge with their leading corners clipped off.
                .padding(.horizontal, Theme.Metrics.spacingL)
                .padding(.vertical, Theme.Metrics.spacingS)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .tracexySafeAreaBar(edge: .bottom) {
                footer(shown: rows.count, rows: rows, state: state)
            }
            .frame(minWidth: 760, minHeight: 360)
            .focusedSceneValue(
                \.frameTimeCommandTarget,
                state.isLoading || state.isEvaluatingFrameExpression || state.list == nil || state.error != nil
                    ? nil : commandTarget
            )
            .onAppear(perform: loadAllFramesAndReceiveSelection)
            .onChange(of: state.externalSelectionRequest) { _, _ in receiveExternalSelectionRequest() }
            .onChange(of: state.isLoading) { _, loading in
                if !loading {
                    state.refreshPinnedFrameRows(from: state.list.map { $0.rows + $0.auxiliaryRows } ?? [])
                    state.refreshFrameColorRules()
                    resolvePendingTableSelection()
                    receiveExternalSelectionRequest()
                }
            }
            .onChange(of: state.frameColorRuleLibrary.rules) { _, _ in state.refreshFrameColorRules() }
            .onChange(of: state.list?.firstRetainedOrdinal) { _, _ in
                state.refreshPinnedFrameRows(from: state.list.map { $0.rows + $0.auxiliaryRows } ?? [])
                state.refreshFrameColorRules()
                resolvePendingTableSelection()
                updateSelectedFrameTimeReference(rows: rows)
            }
            .onChange(of: selection) { previous, current in
                if let current, current != previous {
                    if historyRestoreOrdinal == current {
                        historyRestoreOrdinal = nil
                    } else {
                        if let pendingHistoryRestoreOrdinal,
                           coordinator.allFrames.pendingTableSelection == pendingHistoryRestoreOrdinal
                        {
                            coordinator.allFrames.pendingTableSelection = nil
                        }
                        coordinator.allFrames.recordFrameSelection(current)
                        pendingHistoryRestoreOrdinal = nil
                        pendingHistoryBackward = nil
                        pendingHistoryRequestID = nil
                    }
                }
                updateSelectedFrameTimeReference(rows: rows)
            }
            .onChange(of: coordinator.startGeneration) { _, _ in
                sourceComments.dismiss()
                coordinator.allFrames.clearFrameNavigationHistory()
                state.clearRecentFrameExpressions()
                historyRestoreOrdinal = nil
                pendingHistoryRestoreOrdinal = nil
                pendingHistoryBackward = nil
                pendingHistoryRequestID = nil
                state.externalSelectionRequest = nil
                state.externalSelectionRequestID = nil
                selection = nil
            }
            .onChange(of: state.isEvaluatingFrameExpression) { _, _ in resolveFrameSelections() }
            .onChange(of: state.acceptedFrameExpressionText) { old, new in
                guard old != new, !new.isEmpty, let list = state.list else {
                    return
                }
                coordinator.loadAllFrames(force: true, retainedFrameStartOrdinal: list.firstRetainedOrdinal)
            }
            .onChange(of: coordinator.packetDetailOptions.frameColumns, initial: true) { old, new in
                for index in 0 ..< PacketDetailOptions.maximumFrameColumns {
                    columnCustomization[visibility: "field\(index)"] = index < new.count ? .visible : .hidden
                }
                if old != new {
                    state.clearCaptureTimeReferenceColumnValues()
                    state.clearPinnedFrameColumnValues()
                    coordinator.loadAllFrames(force: true, retainedFrameStartOrdinal: retainedStart(state))
                }
            }
            .onChange(of: coordinator.packetDetailOptions.validateChecksums, initial: true) { _, validate in
                coordinator.allFrames.countsBadChecksums = validate
            }
            .onChange(of: coordinator.sessionTimeDisplay.frameTimeReferences) { old, new in
                let oldCaptureReferences = old.filter { $0.sessionID == nil }.map(\.ordinal)
                let newCaptureReferences = new.filter { $0.sessionID == nil }.map(\.ordinal)
                guard showsCumulativeBytes, oldCaptureReferences != newCaptureReferences, let list = state.list else {
                    return
                }
                coordinator.loadAllFrames(force: true, retainedFrameStartOrdinal: list.firstRetainedOrdinal)
            }
            .onChange(of: showsCumulativeBytes, initial: true) { old, new in
                columnCustomization[visibility: "cumulativeBytes"] = new ? .visible : .hidden
                guard old != new, new, let list = state.list else {
                    return
                }
                coordinator.loadAllFrames(force: true, retainedFrameStartOrdinal: list.firstRetainedOrdinal)
            }
            .onChange(of: state.showsRelativeTCPNumbers) { old, new in
                guard old != new, let list = state.list else {
                    return
                }
                coordinator.loadAllFrames(force: true, retainedFrameStartOrdinal: list.firstRetainedOrdinal)
            }
            .onChange(of: coordinator.projectStore.activeProjectID) { _, _ in
                sourceComments.dismiss()
            }
            .sheet(item: Binding(
                get: { commentingFrame.map(FrameCommentTarget.init) },
                set: { commentingFrame = $0?.id }
            )) { target in
                commentSheet(for: target.id)
            }
            .sheet(item: $sourceComments.target) { target in
                SourceFrameCommentsSheet(ordinal: target.id, presentation: sourceComments.presentation) {
                    sourceComments.dismiss()
                }
            }
            .sheet(isPresented: $isManagingFrameFilters) {
                FrameFilterPresetManagerSheet(
                    library: coordinator.allFrames.frameFilterLibrary,
                    expectedProjectID: presetProjectID
                )
            }
            .sheet(isPresented: $isManagingColorRules) {
                FrameColorRuleManagerSheet(
                    library: coordinator.allFrames.frameColorRuleLibrary,
                    expectedProjectID: colorRuleProjectID
                )
            }
            .sheet(item: $namingAddress) { target in
                FrameAddressNameSheet(
                    address: target.id,
                    addressNames: coordinator.addressNames,
                    projectStore: coordinator.projectStore,
                    expectedProjectID: target.projectID,
                ) {
                    namingAddress = nil
                }
            }
            .alert("Save Frame Filter", isPresented: $isSavingFrameFilter) {
                TextField("Name", text: $newPresetName)
                Button("Cancel", role: .cancel) {}
                Button("Save") {
                    let saved = coordinator.allFrames.frameFilterLibrary.save(
                        name: newPresetName,
                        expression: state.frameExpressionDraft,
                        expectedProjectID: presetProjectID
                    )
                    notice = frameFilterSaveNotice(saved)
                }
            } message: {
                Text("Saved Frame Filters are local to this Project. Saving does not apply the filter.")
            }
            .onChange(of: coordinator.projectStore.activeProjectID) { _, newID in
                state.clearFrameExpression()
                state.clearFrameHighlight()
                state.clearRecentFrameExpressions()
                presetProjectID = newID
                isSavingFrameFilter = false
                isManagingFrameFilters = false
            }
    }

    /// Wireshark's Next/Previous Packet in Conversation: the adjacent frame of the
    /// selected frame's session among the frames the list shows.
    static func adjacentInSession(from selected: UInt64?, forward: Bool, rows: [CaptureFrameRow]) -> UInt64? {
        guard let selected, let session = rows.first(where: { $0.ordinal == selected })?.sessionID else {
            return nil
        }
        let same = rows.filter { $0.sessionID == session }.map(\.ordinal)
        return forward ? same.first { $0 > selected } : same.last { $0 < selected }
    }

    static func columnTitle(_ field: FieldKey) -> String {
        "\(field.proto.label) \(field.name)"
    }

    /// Each shown row's predecessor in this displayed page. A predecessor outside
    /// the retained page is unknown until the same full display scope is scanned.
    ///
    /// The one exception is the row that opens a later page. The scan that built
    /// the page also recorded the frame immediately before it, so that boundary
    /// delta is authoritative rather than guessed. It applies only when the first
    /// shown row really is the page's first retained frame: a filtered page whose
    /// opening frame is hidden, or a pinned row from another page sorted ahead of
    /// it, has some other predecessor and stays unknown.
    static func previousDisplayedFrames(
        _ rows: [CaptureFrameRow],
        retainedOrdinals: Set<UInt64>,
        firstRetainedOrdinal: Int = 1,
        precedingRetainedFrameTimestamp: Date? = nil
    )
        -> [UInt64: FrameTimePredecessor]
    {
        var result: [UInt64: FrameTimePredecessor] = [:]
        result.reserveCapacity(rows.count)
        for (index, row) in rows.enumerated() {
            if index > 0 {
                let previousRow = rows[index - 1]
                result[row.ordinal] = retainedOrdinals.contains(previousRow.ordinal)
                    && retainedOrdinals.contains(row.ordinal)
                    ? previousRow.provenance.timestamp.map(FrameTimePredecessor.timestamp) ?? .unknown
                    : .unknown
            } else if row.ordinal == 1 {
                // Spelled out: a dictionary's subscript setter takes `Value?`, so a
                // bare `.none` is `Optional.none` and removes the key instead of
                // storing the case that says this frame has no predecessor.
                result[row.ordinal] = FrameTimePredecessor.none
            } else if row.ordinal == UInt64(max(1, firstRetainedOrdinal)),
                      retainedOrdinals.contains(row.ordinal),
                      let precedingRetainedFrameTimestamp
            {
                result[row.ordinal] = .timestamp(precedingRetainedFrameTimestamp)
            } else {
                result[row.ordinal] = .unknown
            }
        }
        return result
    }

    /// Resolves the predecessor map for the shown rows from the loaded page,
    /// passing the boundary frame the scan recorded so a later page's first row
    /// shows a real delta instead of an unknown one.
    func previousDisplayedFrames(_ rows: [CaptureFrameRow]) -> [UInt64: FrameTimePredecessor] {
        let page = coordinator.allFrames.list
        return Self.previousDisplayedFrames(
            rows,
            retainedOrdinals: Set(page?.rows.map(\.ordinal) ?? []),
            firstRetainedOrdinal: page?.firstRetainedOrdinal ?? 1,
            precedingRetainedFrameTimestamp: page?.precedingRetainedFrameTimestamp
        )
    }

    func frameRuleColor(_ rgb: UInt32) -> Color {
        Color(
            .sRGB,
            red: Double((rgb >> 16) & 0xFF) / 255,
            green: Double((rgb >> 8) & 0xFF) / 255,
            blue: Double(rgb & 0xFF) / 255,
            opacity: 1
        )
    }

    // MARK: Private

    private struct FrameCommentTarget: Identifiable {
        let id: UInt64
    }

    /// The selected frame's session and its first and last frame in the list, for
    /// Wireshark's related-packet marks.
    private struct RelatedSpan {
        let sessionID: UUID
        let first: UInt64
        let last: UInt64
    }

    /// Hides the Apply as Column slots nobody filled.
    @State private var columnCustomization = TableColumnCustomization<CaptureFrameRow>()
    @State private var showsCumulativeBytes = false

    /// Wireshark's Find Packet bar, shown under the toolbar.
    @State private var isFinding = false
    @State private var commentingFrame: UInt64?
    @State private var commentDraft = ""
    @State private var sourceComments = FrameSourceCommentsPresentationModel()
    @State private var namingAddress: FrameAddressNameTarget?
    @State private var newPresetName = ""
    @State private var presetProjectID: UUID?
    @State private var isSavingFrameFilter = false
    @State private var isManagingFrameFilters = false
    @State private var isManagingColorRules = false
    @State private var colorRuleProjectID: UUID?

    /// View ▸ Zoom's step for the frame list.
    private var zoom: Int {
        coordinator.packetDetailOptions.textZoom
    }

    private func frameExpressionBar(_ state: CaptureFrameListState) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: Theme.Metrics.spacingS) {
                TextField(
                    "Frame Expression", text: Binding(
                        get: { state.frameExpressionDraft },
                        set: { state.updateFrameExpressionDraft($0) }
                    ), prompt: Text("tcp.flags.syn and tcp.flags.ack")
                )
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 460)
                .onSubmit { state.applyFrameExpression() }
                .help(
                    "Filter individual listed frames. Supports frame.len and frame.cap_len comparisons, "
                        + "frame.truncated, tcp.rst, tcp.syn, tcp.port, tcp.srcport, tcp.dstport, "
                        + "tcp.flags.fin/syn/reset/push/ack/urg/ece/cwr, tcp.window_size_value, "
                        + "udp.port, udp.srcport, udp.dstport, sctp.port, sctp.srcport, sctp.dstport, "
                        + "ip.addr, ip.src, "
                        + "ip.dst, ip.id, ip.flags.df, dns.response, dns.rcode, dns.id, dns.flags.truncated, "
                        + "icmp.type/code, icmpv6.type/code, and/or/not."
                )
                FrameExpressionSyntaxStatus(isValid: state.frameExpressionDraftIsValid)
                RecentFrameExpressionsMenu(state: state)
                Menu("Saved Frame Filters") {
                    if coordinator.allFrames.frameFilterLibrary.filters.isEmpty {
                        Text(coordinator.allFrames.frameFilterLibrary
                            .storageAvailable ? "No Saved Frame Filters" : "Saved Filters Unavailable")
                    }
                    ForEach(coordinator.allFrames.frameFilterLibrary.filters) { filter in
                        Button(filter.name) {
                            state.updateFrameExpressionDraft(filter.expression)
                        }
                        .help(filter.expression)
                    }
                    Divider()
                    Button("Save Current Frame Filter…") {
                        presetProjectID = coordinator.projectStore.activeProjectID
                        newPresetName = ""
                        isSavingFrameFilter = true
                    }
                    .disabled(state.frameExpressionDraft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                        || !coordinator.allFrames.frameFilterLibrary.storageAvailable)
                    Button("Manage Saved Frame Filters…") {
                        presetProjectID = coordinator.projectStore.activeProjectID
                        isManagingFrameFilters = true
                    }
                    .disabled(!coordinator.allFrames.frameFilterLibrary.storageAvailable)
                }
                Menu("Coloring Rules") {
                    if state.frameColorRuleLibrary.rules.isEmpty {
                        Text(state.frameColorRuleLibrary.storageAvailable ? "No Coloring Rules" : "Rules Unavailable")
                    }
                    ForEach(state.frameColorRuleLibrary.rules) { rule in
                        Label(rule.name, systemImage: "circle.fill")
                            .foregroundStyle(frameRuleColor(rule.backgroundRGB))
                            .help(rule.expression)
                    }
                    Divider()
                    Button("Manage Coloring Rules…") {
                        colorRuleProjectID = coordinator.projectStore.activeProjectID
                        isManagingColorRules = true
                    }
                    .disabled(!state.frameColorRuleLibrary.storageAvailable)
                }
                Menu("Conversation Colors") {
                    Text(
                        "\(state.temporaryConversationColorSlots.count) of \(CaptureFrameListState.maximumTemporaryConversationColorSlots) temporary slots"
                    )
                    Button("Clear Conversation Colors") { state.clearTemporaryConversationColors() }
                        .disabled(state.temporaryConversationColorSlots.isEmpty)
                }
                .help("Temporary capture-local colors assigned from a frame’s conversation")
                Button("Apply") { state.applyFrameExpression() }
                    .disabled(state.list == nil || state.isLoading)
                Button("Clear") { state.clearFrameExpression() }
                    .disabled(state.frameExpressionDraft.isEmpty && state.acceptedFrameExpression == nil)
                if state.isEvaluatingFrameExpression {
                    ProgressView().controlSize(.small)
                        .accessibilityLabel("Filtering frames")
                }
                if state.isEvaluatingFrameColorRules {
                    ProgressView().controlSize(.small).accessibilityLabel("Evaluating coloring rules")
                }
                Spacer()
                if state.acceptedFrameExpression != nil {
                    Text("Frame filter active")
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                }
            }
            HStack(spacing: Theme.Metrics.spacingS) {
                Button("Highlight") { state.highlightFramesFromDraft() }
                    .disabled(state.list == nil || state.isLoading)
                    .help("Highlight frames matching the draft without filtering the packet list")
                if state.highlightedFrameExpression != nil {
                    Text("Highlight: \(state.highlightedFrameExpressionText)")
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .frame(maxWidth: 360, alignment: .leading)
                        .help("Temporary highlight for frames in the retained page")
                    Button("Clear Highlight") { state.clearFrameHighlight() }
                    if state.isEvaluatingFrameHighlight {
                        ProgressView().controlSize(.small)
                            .accessibilityLabel("Evaluating frame highlights")
                    } else if state.highlightedFrameUnknownCount > 0 {
                        Text("\(state.highlightedFrameUnknownCount) unknown on page")
                            .font(Theme.Typography.caption)
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Text("Highlights apply to the retained page only")
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            if let error = state.frameExpressionError {
                Text("Draft — Character \(error.position): \(error.reason)")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.red)
                    .accessibilityLabel(
                        "Frame Expression draft syntax error at character \(error.position): \(error.reason)"
                    )
            }
        }
        .controlSize(.small)
    }

    /// Wireshark's Conversation Filter and Colorize Conversation for the frame's session.
    @ViewBuilder
    private func conversationMenus(_ row: CaptureFrameRow) -> some View {
        if let session = coordinator.sessions.first(where: { $0.id == row.sessionID }) {
            Menu("Conversation Filter") {
                ForEach(ConversationFilter.options(for: session)) { option in
                    Button(option.title) {
                        coordinator.filterSessions(with: option.term, combination: .selected, applying: true)
                    }
                }
            }
            SessionTagMenu(coordinator: coordinator, sessionIDs: [session.id])
        }
    }

    @ViewBuilder
    private func removeColumnMenu(_ fields: [FieldKey]) -> some View {
        if !fields.isEmpty {
            Menu("Remove Column") {
                ForEach(fields, id: \.self) { field in
                    Button(Self.columnTitle(field)) {
                        coordinator.packetDetailOptions.toggleFrameColumn(field)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func captureTimeReferenceMenu(_ row: CaptureFrameRow) -> some View {
        if coordinator.sessionTimeDisplay.isCaptureTimeReference(ordinal: row.ordinal),
           let timestamp = row.provenance.timestamp
        {
            Button("Clear Time Reference") {
                let reference = FrameTimeReference(sessionID: nil, ordinal: row.ordinal, timestamp: timestamp)
                coordinator.sessionTimeDisplay.toggleTimeReference(reference)
                coordinator.allFrames.removeCaptureTimeReferenceRow(row.ordinal)
                coordinator.sessionTimeDisplay.selectedFrame = reference
            }
        } else if let timestamp = row.provenance.timestamp {
            Button("Set as Time Reference") {
                let reference = FrameTimeReference(sessionID: nil, ordinal: row.ordinal, timestamp: timestamp)
                if coordinator.sessionTimeDisplay.toggleTimeReference(reference) {
                    coordinator.allFrames.retainCaptureTimeReferenceRow(row)
                }
            }
            .disabled(!coordinator.sessionTimeDisplay.canAddTimeReference(at: row.ordinal))
        }
    }

    private func frameAddressNameMenu(_ row: CaptureFrameRow) -> some View {
        FrameAddressNameMenu(
            row: row, addressNames: coordinator.addressNames,
            target: $namingAddress, projectStore: coordinator.projectStore
        )
    }

    @ViewBuilder
    private func frameSourceMetadataMenu(_ row: CaptureFrameRow) -> some View {
        SourceFrameCommentMenuItem(row: row, coordinator: coordinator, presentation: sourceComments)
        frameAddressNameMenu(row)
    }

    private func table(_ rows: [CaptureFrameRow]) -> some View {
        let name = coordinator.packetDetailOptions.resolvesNetworkAddresses ? coordinator
            .resolvedFrameAddressName : { $0 }
        let previous = previousDisplayedFrames(rows)
        let captureStart = coordinator.allFrames.list?.captureStartTimestamp
        let format = coordinator.sessionTimeDisplay.frameFormat
        let captureReferences = coordinator.sessionTimeDisplay.captureReferences()
        let related = Self.relatedSpan(of: selection, in: rows)
        let time = { (row: CaptureFrameRow) in
            FrameTimeFormat.text(
                // A whole capture's list has no session start: its origin is the capture's first frame.
                format == .sinceSessionStart ? .sinceCaptureStart : format,
                timestamp: row.provenance.timestamp,
                ordinal: row.ordinal,
                previous: previous[row.ordinal] ?? .unknown,
                previousCaptured: row.previousCapturedFrame,
                sessionStart: nil,
                captureStart: captureStart,
                precision: coordinator.sessionTimeDisplay.framePrecision,
                references: captureReferences
            )
        }
        let fields = coordinator.packetDetailOptions.frameColumns
        return Table(rows, selection: interactiveFrameSelection, columnCustomization: $columnCustomization) {
            TableColumn("No.") { row in
                colorizedCell(row) {
                    HStack(spacing: 4) {
                        if let related, row.id != selection, row.sessionID == related.sessionID {
                            AllFramesRelatedFrameGlyph(ordinal: row.ordinal, first: related.first, last: related.last)
                        }
                        temporaryConversationColorGlyph(row)
                        frameColorRuleGlyph(row)
                        frameHighlightGlyph(row)
                        if coordinator.allFrames.marked.contains(row.id) {
                            Image(systemName: "bookmark.fill")
                                .foregroundStyle(Color.accentColor)
                                .accessibilityLabel("Marked")
                        }
                        Text(row.ordinal.formatted()).monospacedDigit()
                            .fontWeight(coordinator.allFrames.marked.contains(row.id) ? .semibold : .regular)
                    }
                }
            }
            .width(min: 56, ideal: 72)
            frameTimeColumn(format: format, time: time)
            TableColumn("Source") { row in
                colorizedCell(row) {
                    Text(name(row.source)).font(Theme.Typography.zoomed(.callout, zoom: zoom, monospaced: true))
                        .lineLimit(1).truncationMode(.middle).help(row.source)
                }
            }
            .width(min: 100, ideal: 130)
            TableColumn("Destination") { row in
                colorizedCell(row) {
                    Text(name(row.destination)).font(Theme.Typography.zoomed(.callout, zoom: zoom, monospaced: true))
                        .lineLimit(1).truncationMode(.middle).help(row.destination)
                }
            }
            .width(min: 100, ideal: 130)
            TableColumn("Protocol") { row in
                colorizedCell(row) { Text(row.protocolName).lineLimit(1) }
            }
            .width(min: 60, ideal: 72)
            captureDirectionColumn()
            TableColumn("Length") { row in
                colorizedCell(row) { Text(row.length.formatted()).monospacedDigit() }
            }
            .width(min: 52, ideal: 64)
            frameCumulativeBytesColumn()
            Group {
                fieldColumn(0, fields)
                fieldColumn(1, fields)
                fieldColumn(2, fields)
                fieldColumn(3, fields)
            }
            frameInfoColumn()
        }
        .font(Theme.Typography.zoomed(.body, zoom: zoom))
        .contextMenu(forSelectionType: CaptureFrameRow.ID.self) { ids in
            if let row = rows.first(where: { $0.id == ids.first }) {
                Button("Open Session and Frame") { open(row) }
                    .disabled(row.sessionID == nil)
                decodeAsMenu(row)
                Divider()
                Button(coordinator.allFrames.marked.contains(row.id) ? "Unmark Frame" : "Mark Frame") {
                    coordinator.allFrames.toggleMark(row.id, sessionID: row.sessionID)
                }
                PinnedFrameRowMenu(row: row, state: coordinator.allFrames)
                captureTimeReferenceMenu(row)
                frameSourceMetadataMenu(row)
                Button(coordinator.allFrames
                    .frameComments[row.id] == nil ? "Add Frame Comment…" : "Edit Frame Comment…")
                {
                    commentDraft = coordinator.allFrames.frameComments[row.id] ?? ""
                    commentingFrame = row.id
                }
                Button(coordinator.allFrames.ignored.contains(row.id) ? "Unignore Frame" : "Ignore Frame") {
                    coordinator.allFrames.toggleIgnore(row.id)
                }
                if !coordinator.allFrames.marked.isEmpty {
                    Button("Unmark All") { coordinator.allFrames.marked = [] }
                }
                if !coordinator.allFrames.ignored.isEmpty {
                    Button("Unignore All") { coordinator.allFrames.ignored = [] }
                }
                if let sessionID = row.sessionID {
                    let colorSlot = coordinator.allFrames.temporaryConversationColorSlots[sessionID]
                    Button(colorSlot == nil ? "Color This Conversation" : "Clear Conversation Color") {
                        coordinator.allFrames.toggleTemporaryConversationColor(sessionID: sessionID)
                    }
                    .disabled(
                        colorSlot == nil
                            && coordinator.allFrames.temporaryConversationColorSlots.count
                            >= CaptureFrameListState.maximumTemporaryConversationColorSlots
                    )
                    .help(
                        "Temporary color applies to this conversation in the current capture and overrides saved coloring rules."
                    )
                }
                Divider()
                Button("Export This Frame’s Dissection…") {
                    DissectionExportController.shared.export(
                        from: coordinator,
                        frameSelection: FrameOrdinalSelection(intervals: [.init(first: row.id, last: row.id)])
                    )
                }
                .disabled(!coordinator.canExportFrames || DissectionExportController.shared.isExporting)
                .help("Export the selected capture frame as text, CSV, or JSON")
                Button("Export This Frame…", systemImage: "square.and.arrow.up") {
                    coordinator.presentFrameExportPanel(preselectedFrameOrdinals: [row.id])
                }
                .disabled(!coordinator.canExportFrames)
                .help("Export only this frame's captured bytes to a new PCAP or PCAPNG file")
                printFrameMenu(row)
                Divider()
                conversationMenus(row)
                removeColumnMenu(fields)
                copyMenu(
                    for: row,
                    values: [
                        String(row.ordinal), time(row), name(row.source), name(row.destination),
                        row.protocolName, String(row.length),
                    ] + (showsCumulativeBytes ? [row.cumulativeCapturedBytes?.formatted() ?? ""] : [])
                        + row.columnValues + [row.info],
                    rowIndex: row.ordinal
                )
            }
        } primaryAction: { ids in
            if let row = rows.first(where: { $0.id == ids.first }) {
                open(row)
            }
        }
        .background {
            SessionHistoryScrollObserver(
                revealToken: revealToken,
                revealRow: rows.firstIndex { $0.id == selection }
            ) {}
        }
    }

    private func printFrameMenu(_ row: CaptureFrameRow) -> some View {
        let frame = FrameOrdinalSelection(intervals: [.init(first: row.id, last: row.id)])
        return Menu("Print This Frame") {
            Button("Summary…") {
                DissectionExportController.shared.printDissections(
                    from: coordinator, frameSelection: frame, layout: .summary
                )
            }
            Button("Dissection…") {
                DissectionExportController.shared.printDissections(from: coordinator, frameSelection: frame)
            }
            Button("Captured Bytes…") {
                DissectionExportController.shared.printDissections(
                    from: coordinator, frameSelection: frame, layout: .bytes
                )
            }
        }
        .disabled(!coordinator.canExportFrames || DissectionExportController.shared.isPrinting)
    }

    private func goToField(_ rows: [CaptureFrameRow]) -> some View {
        HStack(spacing: Theme.Metrics.spacingS) {
            TextField("Go to Frame", text: $goTo, prompt: Text("Frame number"))
                .frame(width: 100)
                .textFieldStyle(.roundedBorder)
                .help("Type a frame number and press Return")
                .onSubmit { goToFrame(rows) }
            Button("Go") { goToFrame(rows) }
                .disabled(goTo.trimmingCharacters(in: .whitespaces).isEmpty)
                .help("Select and scroll to that frame, as Wireshark's Go to Packet")
        }
        .controlSize(.small)
    }

    private func loading(_ state: CaptureFrameListState) -> some View {
        VStack(spacing: Theme.Metrics.spacingM) {
            if let fraction = state.fraction {
                ProgressView(value: fraction)
                    .frame(maxWidth: 320)
                    .accessibilityLabel("Listing frames")
            } else {
                ProgressView().controlSize(.small)
            }
            Text("Listing every frame of the capture…")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
            Button("Cancel") { state.cancel(clearList: false) }
                .controlSize(.small)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// The bulk mark and ignore commands as one menu rather than four buttons.
    /// Laid out side by side they did not fit the window's own default width:
    /// every label truncated ("Mark All Di…", "Unignore D…"), which leaves a
    /// control whose text no longer says what pressing it does.
    @ViewBuilder
    private func markActionsMenu(rows: [CaptureFrameRow], state: CaptureFrameListState) -> some View {
        let hasMarked = rows.contains { state.marked.contains($0.id) }
        let hasIgnored = rows.contains { state.ignored.contains($0.id) }
        Menu("Marks") {
            Button("Mark All Displayed") { state.markDisplayed(rows) }
                .disabled(rows.isEmpty)
            Button("Unmark All Displayed") { state.unmarkDisplayed(rows) }
                .disabled(!hasMarked)
            Divider()
            Button("Ignore All Displayed") { state.ignoreDisplayed(rows) }
                .disabled(rows.isEmpty)
            Button("Unignore Displayed") { state.unignoreDisplayed(rows) }
                .disabled(!hasIgnored)
        }
        .fixedSize()
        // A menu whose every item is unavailable stays openable unless the menu
        // itself is disabled, which reads as a working control that does nothing.
        // With no rows there is nothing any of these commands can act on, and
        // the marked and ignored checks are drawn from those same rows.
        .disabled(rows.isEmpty)
        .help("Mark, unmark, ignore or unignore every frame displayed in this list")
    }

    /// The export and print commands as one menu, for the same reason. With a
    /// Frame Expression applied this group grows to five controls, so the row
    /// was at its worst exactly when the expression tools were in use.
    @ViewBuilder
    private func exportActionsMenu(state: CaptureFrameListState) -> some View {
        let matching = state.acceptedFrameExpression
        let canExport = coordinator.canExportFrames
        Menu("Export") {
            Button("Export Marked…") {
                coordinator.presentFrameExportPanel(prefersMarkedFrames: true)
            }
            .disabled(state.marked.isEmpty || !canExport)
            if matching != nil {
                Divider()
                Button("Export Matching Frames…") {
                    coordinator.presentFrameExportPanel(prefersAppliedFrameExpression: true)
                }
                .disabled(!canExport)
                Button("Export Matching Dissections…") {
                    DissectionExportController.shared.export(from: coordinator, frameExpression: matching)
                }
                .disabled(!canExport || DissectionExportController.shared.isExporting)
                Menu("Print Matching Packet Views…") {
                    Button("Summaries…") {
                        DissectionExportController.shared.printDissections(
                            from: coordinator, frameExpression: matching, layout: .summary
                        )
                    }
                    Button("Dissections…") {
                        DissectionExportController.shared.printDissections(
                            from: coordinator, frameExpression: matching
                        )
                    }
                    Button("Captured Bytes…") {
                        DissectionExportController.shared.printDissections(
                            from: coordinator, frameExpression: matching, layout: .bytes
                        )
                    }
                }
                .disabled(!canExport || DissectionExportController.shared.isPrinting)
            }
        }
        .fixedSize()
        .disabled(!canExport || (state.marked.isEmpty && matching == nil))
        .help("Export the marked frames, or everything matching the applied Frame Expression")
    }

    private func footer(shown: Int, rows: [CaptureFrameRow], state: CaptureFrameListState) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            HStack(spacing: Theme.Metrics.spacingM) {
                CaptureFrameListSummaryView(shown: shown, state: state, notice: notice)
                Spacer(minLength: Theme.Metrics.spacingS)
                if let coverage = state.captureExpressionCoverage {
                    if let previous = coverage.previousMatchOrdinal {
                        Button("Previous Matching Page") { loadPage(containing: previous) }
                    }
                    if let next = coverage.nextMatchOrdinal {
                        Button("Next Matching Page") { loadPage(containing: next) }
                    }
                }
            }
            HStack(spacing: Theme.Metrics.spacingM) {
                Spacer()
                if let list = state.list, list.omittedFrameCount > 0 {
                    Button("Previous Page") {
                        let pageSize = CaptureFrameListScanner.Configuration.defaultMaxRetainedFrames
                        coordinator.loadAllFrames(
                            force: true, retainedFrameStartOrdinal: max(1, list.firstRetainedOrdinal - pageSize)
                        )
                    }
                    .disabled(list.firstRetainedOrdinal <= 1 || state.isLoading)
                    Button("Next Page") {
                        let pageSize = CaptureFrameListScanner.Configuration.defaultMaxRetainedFrames
                        coordinator.loadAllFrames(
                            force: true, retainedFrameStartOrdinal: list.firstRetainedOrdinal + pageSize
                        )
                    }
                    .disabled(list.firstRetainedOrdinal + list.rows.count > list.scannedFrameCount || state.isLoading)
                }
                if !state.marked.isEmpty || !state.ignored.isEmpty {
                    Text("\(state.marked.count.formatted()) marked, \(state.ignored.count.formatted()) ignored")
                        .monospacedDigit()
                }
                relativeTCPNumbersToggle(state: state)
                Toggle("Cumulative Bytes", isOn: $showsCumulativeBytes)
                    .toggleStyle(.checkbox)
                    .disabled(state.list == nil || state.isLoading || state.error != nil)
                    .help(
                        "Show captured-byte totals from the capture start or latest capture-wide time reference; hidden frames still count"
                    )
                let captureReferences = coordinator.sessionTimeDisplay.captureReferences()
                if !captureReferences.isEmpty {
                    Menu("Time References (\(captureReferences.count.formatted()))") {
                        Button("Previous Time Reference") { jumpToTimeReference(forward: false) }
                        Button("Next Time Reference") { jumpToTimeReference(forward: true) }
                        Divider()
                        Button("Clear Time References") {
                            coordinator.sessionTimeDisplay.clearCaptureTimeReferences()
                            state.clearCaptureTimeReferenceRows()
                        }
                    }
                }
                Button("Previous Mark") { jumpToMark(forward: false) }
                    .disabled(state.marked.isEmpty)
                    .help("Select the previous marked frame")
                Button("Next Mark") { jumpToMark(forward: true) }
                    .disabled(state.marked.isEmpty)
                    .help("Select the next marked frame")
                if let problems = state.list?.problemCount(countingBadChecksums: state.countsBadChecksums),
                   problems > 0 || state.showsDecodeProblemsOnly
                {
                    Toggle(
                        (state.list?.omittedFrameCount ?? 0) > 0
                            ? "Only Decode Problems (\(problems.formatted()) on page)"
                            : "Only Decode Problems (\(problems.formatted()))",
                        isOn: Binding(
                            get: { state.showsDecodeProblemsOnly },
                            set: { state.showsDecodeProblemsOnly = $0 }
                        )
                    )
                    .toggleStyle(.checkbox)
                    .help(state.countsBadChecksums
                        ? "Show only malformed frames, frames the snapshot length cut short, and frames with a wrong checksum"
                        : "Show only malformed frames and frames the snapshot length cut short")
                }
                Toggle("Show Ignored", isOn: Binding(get: { state.showsIgnored }, set: { state.showsIgnored = $0 }))
                    .toggleStyle(.checkbox)
                    .disabled(state.ignored.isEmpty)
                    .help("Show ignored frames, dimmed and struck through")
                markActionsMenu(rows: rows, state: state)
                exportActionsMenu(state: state)
                Button("Rescan") { rescan(coordinator, state) }
                    .disabled(state.isLoading || coordinator.allFramesUnavailableReason != nil)
            }
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    private func frameListContent(
        rows: [CaptureFrameRow], pinnedRows: [CaptureFrameRow], state: CaptureFrameListState
    )
        -> some View
    {
        FrameListPinnedContent(pinnedRows: pinnedRows, state: state, onGoTo: selectFoundFrame) {
            if rows.isEmpty {
                NoFramesMatchView(state: state)
            } else {
                table(rows)
            }
        }
    }

    private func commentSheet(for ordinal: UInt64) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            Text("Comment on Frame \(ordinal.formatted())")
                .font(Theme.Typography.bodyEmphasis)
            TextEditor(text: $commentDraft)
                .font(Theme.Typography.body)
                .frame(minWidth: 360, minHeight: 120)
                .border(Color(nsColor: .separatorColor))
                .accessibilityLabel("Frame comment")
            Text(
                "Written into the frame when you export frames as PCAPNG with your notes, as Wireshark saves packet comments."
            )
            .font(Theme.Typography.caption)
            .foregroundStyle(.secondary)
            HStack {
                if coordinator.allFrames.frameComments[ordinal] != nil {
                    Button("Delete Comment", role: .destructive) {
                        coordinator.allFrames.frameComments[ordinal] = nil
                        commentingFrame = nil
                    }
                }
                Spacer()
                Button("Cancel", role: .cancel) { commentingFrame = nil }
                    .keyboardShortcut(.cancelAction)
                Button("Save") {
                    let text = commentDraft.trimmingCharacters(in: .whitespacesAndNewlines)
                    coordinator.allFrames.frameComments[ordinal] = text.isEmpty ? nil : text
                    commentingFrame = nil
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(Theme.Metrics.spacingL)
    }

    private static func relatedSpan(of selection: UInt64?, in rows: [CaptureFrameRow]) -> RelatedSpan? {
        guard let selection, let session = rows.first(where: { $0.id == selection })?.sessionID else {
            return nil
        }
        let ordinals = rows.lazy.filter { $0.sessionID == session }.map(\.ordinal)
        guard let first = ordinals.min(), let last = ordinals.max() else {
            return nil
        }
        return RelatedSpan(sessionID: session, first: first, last: last)
    }

    private func fieldColumn(_ index: Int, _ fields: [FieldKey]) -> some TableColumnContent<CaptureFrameRow, Never> {
        TableColumn(fields.indices.contains(index) ? Self.columnTitle(fields[index]) : "") { row in
            let value = row.columnValues.indices.contains(index) ? row.columnValues[index] : ""
            colorizedCell(row) { Text(value).lineLimit(1).truncationMode(.tail).help(value) }
        }
        .width(min: 60, ideal: 120)
        .customizationID("field\(index)")
        .disabledCustomizationBehavior(.all)
    }

    private func frameInfoColumn() -> some TableColumnContent<CaptureFrameRow, Never> {
        TableColumn("Info") { row in
            colorizedCell(row) {
                HStack(spacing: Theme.Metrics.spacingS) {
                    if let stop = row.decodeStop {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                            .help(stop.explanation)
                            .accessibilityLabel(stop.explanation)
                    } else if row.hasBadChecksum, coordinator.allFrames.countsBadChecksums {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                            .help(
                                "A checksum in this frame is wrong. Frames sent from this Mac are often captured before the network card fills checksums in."
                            )
                            .accessibilityLabel("Wrong checksum")
                    }
                    Text(row.info).lineLimit(1).truncationMode(.tail)
                        .strikethrough(coordinator.allFrames.ignored.contains(row.id))
                    if let comment = coordinator.allFrames.frameComments[row.id] {
                        Image(systemName: "text.bubble.fill")
                            .foregroundStyle(Color.accentColor)
                            .help(comment)
                            .accessibilityLabel("Your comment: \(comment)")
                    } else if row.hasComment {
                        Image(systemName: "text.bubble")
                            .foregroundStyle(.secondary)
                            .help("This frame carries a comment in the capture file")
                            .accessibilityLabel("Has comment")
                    }
                }
            }
        }
        .width(min: 200, ideal: 380)
    }

    private func updateSelectedFrameTimeReference(rows: [CaptureFrameRow]) {
        if let selection, let row = rows.first(where: { $0.id == selection }),
           let timestamp = row.provenance.timestamp
        {
            coordinator.sessionTimeDisplay.selectedFrame = FrameTimeReference(
                sessionID: nil, ordinal: row.ordinal, timestamp: timestamp
            )
        } else if coordinator.sessionTimeDisplay.selectedFrame?.sessionID == nil {
            coordinator.sessionTimeDisplay.selectedFrame = nil
        }
    }

    private func jumpToMark(forward: Bool) {
        let state = coordinator.allFrames
        guard let next = state.adjacentMarkAcrossCapture(from: selection, forward: forward) else {
            return
        }
        cancelExternalSelectionForManualSelection()
        let rows = state.visibleRows(sessionsInView: Set(coordinator.visibleSessions.map(\.id)))
        if rows.contains(where: { $0.ordinal == next }) {
            selection = next
            revealToken &+= 1
            notice = nil
        } else if state.list?.rows.contains(where: { $0.ordinal == next }) == true {
            notice = String(localized: "Frame \(next.formatted()) is hidden by the current filters.")
        } else if let list = state.list, next <= UInt64(list.scannedFrameCount) {
            let pageSize = CaptureFrameListScanner.Configuration.defaultMaxRetainedFrames
            let start = ((Int(next) - 1) / pageSize) * pageSize + 1
            coordinator.loadAllFrames(force: true, retainedFrameStartOrdinal: start)
            state.pendingTableSelection = next
            notice = nil
        } else {
            // The mark survives a rescan but the list does not, so the page that
            // holds this frame cannot be resolved yet. Say so rather than letting
            // an enabled button do nothing.
            notice = String(localized: "Frame \(next.formatted()) can’t be shown until the list is rescanned.")
        }
    }

    private func jumpToTimeReference(forward: Bool) {
        let references = coordinator.sessionTimeDisplay.captureReferences()
        guard !references.isEmpty else {
            return
        }
        let next = if let selection {
            if forward {
                references.first { $0.ordinal > selection }
            } else {
                references.last { $0.ordinal < selection }
            }
        } else if forward {
            references.first
        } else {
            references.last
        }
        guard let next else {
            notice = forward
                ? String(localized: "There is no later time reference.")
                : String(localized: "There is no earlier time reference.")
            return
        }
        cancelExternalSelectionForManualSelection()
        selection = next.ordinal
        revealToken &+= 1
        notice = nil
    }

    private func open(_ row: CaptureFrameRow) {
        if coordinator.revealFrame(row) {
            notice = nil
        } else if row.sessionID == nil {
            Task {
                switch await coordinator.inspectOrphanFrameBytes(row) {
                case let .unavailable(error):
                    notice = error
                case .ready:
                    openWindow(id: TracexyApp.packetBytesWindowID)
                    notice = nil
                case .superseded:
                    break
                }
            }
        } else {
            notice = String(localized: "Frame \(row.ordinal.formatted())'s session is not in view in the main window.")
        }
    }
}

// MARK: - Page retention

/// The page a reload should come back to: the one the window is showing, or the
/// first page before anything has been listed. A forced rescan that drops this
/// throws the user back to frame 1 from wherever they were reading.
private func retainedStart(_ state: CaptureFrameListState) -> Int {
    state.list?.firstRetainedOrdinal ?? 1
}

/// Re-lists the frames the window is showing, on the page it is showing. A forced
/// rescan that drops the page throws the user back to frame 1 from wherever they
/// were reading.
@MainActor
private func rescan(_ coordinator: MainContentCoordinator, _ state: CaptureFrameListState) {
    coordinator.loadAllFrames(force: true, retainedFrameStartOrdinal: retainedStart(state))
}

/// Confirms or explains a Frame Filter save, localized like every other notice.
private func frameFilterSaveNotice(_ saved: Bool) -> String {
    saved
        ? String(localized: "Frame filter saved to this Project.")
        : String(localized: "Could not save this Frame Filter. Choose a valid name and expression.")
}

// MARK: - Frame-list content

/// `body` is one long modifier chain. Leaving the list's six states inline put
/// the whole chain past what the type checker will solve on the toolchain CI
/// builds with, so they are a separate expression here.
extension AllFramesWindow {
    @ViewBuilder
    func framesContent(
        state: CaptureFrameListState,
        rows: [CaptureFrameRow],
        pinnedRows: [CaptureFrameRow]
    )
        -> some View
    {
        if state.isLoading {
            FrameListPinnedContent(pinnedRows: pinnedRows, state: state, onGoTo: selectFoundFrame) {
                loading(state)
            }
        } else if let error = state.error {
            ContentUnavailableView {
                Label("Frames Unavailable", systemImage: "list.number")
            } description: {
                Text(error)
            } actions: {
                Button("Try Again") { coordinator.loadAllFrames(force: true) }
            }
        } else if state.list == nil {
            ContentUnavailableView {
                Label("No Frames Listed", systemImage: "list.number")
            } actions: {
                Button("List Frames") { coordinator.loadAllFrames(force: true) }
            }
        } else if state.isEvaluatingFrameExpression {
            FrameListPinnedContent(pinnedRows: pinnedRows, state: state, onGoTo: selectFoundFrame) {
                ProgressView("Filtering frames…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        } else if rows.isEmpty, pinnedRows.isEmpty {
            NoFramesMatchView(state: state)
        } else {
            frameListContent(rows: rows, pinnedRows: pinnedRows, state: state)
        }
    }
}
