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

    var body: some View {
        @Bindable var state = coordinator.allFrames
        let inView = Set(coordinator.visibleSessions.map(\.id))
        let rows = state.visibleRows(sessionsInView: inView)
        Group {
            if state.isLoading {
                loading(state)
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
            } else if rows.isEmpty {
                ContentUnavailableView(
                    "No Frames Match",
                    systemImage: "line.3.horizontal.decrease.circle",
                    description: Text(state.limitToSessionsInView
                        ? "No frame of the sessions in view matches. Turn off Limit to Sessions in View to see every frame."
                        : "No frame matches the search.")
                )
            } else {
                table(rows)
            }
        }
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
                ControlGroup {
                    Button("Previous Frame in Session", systemImage: "chevron.up") {
                        stepInSession(rows, forward: false)
                    }
                    .keyboardShortcut(",", modifiers: .control)
                    Button("Next Frame in Session", systemImage: "chevron.down") { stepInSession(rows, forward: true) }
                        .keyboardShortcut(".", modifiers: .control)
                }
                .disabled(selection.flatMap { id in rows.first { $0.id == id }?.sessionID } == nil)
                .help("Previous or next frame of the selected frame's session (Control-comma, Control-period)")
            }
            ToolbarItem(placement: .primaryAction) {
                Toggle("Find in Frames", systemImage: "text.magnifyingglass", isOn: $isFinding)
                    .help("Find a string, hex bytes or a regular expression in the frames' bytes or details")
            }
        }
        .tracexySafeAreaBar(edge: .top) {
            if isFinding {
                FrameFindBar(
                    coordinator: coordinator, rows: rows, selection: $selection, revealToken: $revealToken
                ) { isFinding = false }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) {
            footer(shown: rows.count, state: state)
        }
        .frame(minWidth: 760, minHeight: 360)
        .onAppear { coordinator.loadAllFrames() }
        .onChange(of: coordinator.packetDetailOptions.frameColumns, initial: true) { old, new in
            for index in 0 ..< PacketDetailOptions.maximumFrameColumns {
                columnCustomization[visibility: "field\(index)"] = index < new.count ? .visible : .hidden
            }
            if old != new {
                coordinator.loadAllFrames(force: true)
            }
        }
        .onChange(of: coordinator.packetDetailOptions.validateChecksums, initial: true) { _, validate in
            coordinator.allFrames.countsBadChecksums = validate
        }
        .sheet(item: Binding(
            get: { commentingFrame.map(FrameCommentTarget.init) },
            set: { commentingFrame = $0?.id }
        )) { target in
            commentSheet(for: target.id)
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

    @State private var selection: CaptureFrameRow.ID?
    /// Hides the Apply as Column slots nobody filled.
    @State private var columnCustomization = TableColumnCustomization<CaptureFrameRow>()

    @State private var goTo = ""
    @State private var revealToken = 0
    /// Wireshark's Find Packet bar, shown under the toolbar.
    @State private var isFinding = false
    @State private var notice: String?
    @State private var commentingFrame: UInt64?
    @State private var commentDraft = ""

    /// View ▸ Zoom's step for the frame list.
    private var zoom: Int {
        coordinator.packetDetailOptions.textZoom
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

    /// Marks a frame of the selected frame's session, as Wireshark's related-packet
    /// column does: where the session starts and ends, and every frame between.
    private func relatedGlyph(_ ordinal: UInt64, span: RelatedSpan) -> some View {
        let (symbol, label): (String, String) = if ordinal == span.first {
            ("arrow.down.to.line", String(localized: "First frame of the selected frame's session"))
        } else if ordinal == span.last {
            ("arrow.up.to.line", String(localized: "Last frame of the selected frame's session"))
        } else {
            ("link", String(localized: "Same session as the selected frame"))
        }
        return Image(systemName: symbol)
            .font(.system(size: Theme.Icon.small))
            .foregroundStyle(.secondary)
            .help(label)
            .accessibilityLabel(label)
    }

    private func table(_ rows: [CaptureFrameRow]) -> some View {
        let name = coordinator.packetDetailOptions.resolvesNetworkAddresses
            ? FrameAddressNames.resolver(sessions: coordinator.presentedSessions, book: coordinator.addressNames)
            : { $0 }
        let previous = Self.previousTimestamps(rows)
        let captureStart = coordinator.allFrames.list?.rows.first?.provenance.timestamp
        let format = coordinator.sessionTimeDisplay.frameFormat
        let related = Self.relatedSpan(of: selection, in: rows)
        let time = { (row: CaptureFrameRow) in
            FrameTimeFormat.text(
                // A whole capture's list has no session start: its origin is the capture's first frame.
                format == .sinceSessionStart ? .sinceCaptureStart : format,
                timestamp: row.provenance.timestamp,
                ordinal: row.ordinal,
                previous: previous[row.ordinal] ?? nil,
                sessionStart: nil,
                captureStart: captureStart,
                reference: nil
            )
        }
        let fields = coordinator.packetDetailOptions.frameColumns
        return Table(rows, selection: $selection, columnCustomization: $columnCustomization) {
            TableColumn("No.") { row in
                HStack(spacing: 4) {
                    if let related, row.id != selection, row.sessionID == related.sessionID {
                        relatedGlyph(row.ordinal, span: related)
                    }
                    if coordinator.allFrames.marked.contains(row.id) {
                        Image(systemName: "bookmark.fill")
                            .foregroundStyle(Color.accentColor)
                            .accessibilityLabel("Marked")
                    }
                    Text(row.ordinal.formatted()).monospacedDigit()
                        .fontWeight(coordinator.allFrames.marked.contains(row.id) ? .semibold : .regular)
                }
                .foregroundStyle(coordinator.allFrames.ignored.contains(row.id) ? .tertiary : .primary)
            }
            .width(min: 56, ideal: 72)
            TableColumn(format == .sinceSessionStart ? String(localized: "Time") : format.columnTitle) { row in
                Text(time(row)).monospacedDigit()
            }
            .width(min: 90, ideal: 110)
            TableColumn("Source") { row in
                Text(name(row.source)).font(Theme.Typography.zoomed(.callout, zoom: zoom, monospaced: true))
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(row.source)
            }
            .width(min: 100, ideal: 130)
            TableColumn("Destination") { row in
                Text(name(row.destination)).font(Theme.Typography.zoomed(.callout, zoom: zoom, monospaced: true))
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(row.destination)
            }
            .width(min: 100, ideal: 130)
            TableColumn("Protocol") { row in
                Text(row.protocolName).lineLimit(1)
            }
            .width(min: 60, ideal: 72)
            TableColumn("Length") { row in
                Text(row.length.formatted()).monospacedDigit()
            }
            .width(min: 52, ideal: 64)
            Group {
                fieldColumn(0, fields)
                fieldColumn(1, fields)
                fieldColumn(2, fields)
                fieldColumn(3, fields)
            }
            TableColumn("Info") { row in
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
                        .foregroundStyle(coordinator.allFrames.ignored.contains(row.id) ? .tertiary : .primary)
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
            .width(min: 200, ideal: 380)
        }
        .font(Theme.Typography.zoomed(.body, zoom: zoom))
        .contextMenu(forSelectionType: CaptureFrameRow.ID.self) { ids in
            if let row = rows.first(where: { $0.id == ids.first }) {
                Button("Open Session and Frame") { open(row) }
                    .disabled(row.sessionID == nil)
                Divider()
                Button(coordinator.allFrames.marked.contains(row.id) ? "Unmark Frame" : "Mark Frame") {
                    coordinator.allFrames.toggleMark(row.id)
                }
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
                Divider()
                conversationMenus(row)
                removeColumnMenu(fields)
                Menu("Copy") {
                    ForEach(FrameSummaryCopy.Format.allCases) { copyFormat in
                        Button(copyFormat.title) {
                            copySummary(
                                [
                                    String(row.ordinal), time(row), name(row.source), name(row.destination),
                                    row.protocolName, String(row.length),
                                ] + row.columnValues + [row.info],
                                format: copyFormat,
                                rowIndex: rows.firstIndex { $0.id == row.id } ?? 0
                            )
                        }
                    }
                }
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

    private func footer(shown: Int, state: CaptureFrameListState) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            if let notice {
                Text(notice)
            } else if let list = state.list {
                Text(list.omittedFrameCount > 0
                    ? "Showing \(shown.formatted()) of the first \(list.rows.count.formatted()) of \(list.scannedFrameCount.formatted()) frames"
                    : "Showing \(shown.formatted()) of \(list.scannedFrameCount.formatted()) frames")
            }
            Spacer()
            if !state.marked.isEmpty || !state.ignored.isEmpty {
                Text("\(state.marked.count.formatted()) marked, \(state.ignored.count.formatted()) ignored")
                    .monospacedDigit()
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
                Toggle("Only Decode Problems (\(problems.formatted()))", isOn: Binding(
                    get: { state.showsDecodeProblemsOnly },
                    set: { state.showsDecodeProblemsOnly = $0 }
                ))
                .toggleStyle(.checkbox)
                .help(state.countsBadChecksums
                    ? "Show only malformed frames, frames the snapshot length cut short, and frames with a wrong checksum"
                    : "Show only malformed frames and frames the snapshot length cut short")
            }
            Toggle("Show Ignored", isOn: Binding(get: { state.showsIgnored }, set: { state.showsIgnored = $0 }))
                .toggleStyle(.checkbox)
                .disabled(state.ignored.isEmpty)
                .help("Show ignored frames, dimmed and struck through")
            Button("Export Marked…") {
                coordinator.presentFrameExportPanel(prefersMarkedFrames: true)
            }
            .disabled(state.marked.isEmpty || !coordinator.canExportFrames)
            .help("Export only the marked frames as PCAPNG or PCAP")
            Button("Rescan") { coordinator.loadAllFrames(force: true) }
                .disabled(state.isLoading || coordinator.allFramesUnavailableReason != nil)
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
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

    /// Each shown row's predecessor in the list, for the delta format.
    private static func previousTimestamps(_ rows: [CaptureFrameRow]) -> [UInt64: Date?] {
        var result: [UInt64: Date?] = [:]
        result.reserveCapacity(rows.count)
        var previous: Date?
        for row in rows {
            result[row.ordinal] = previous
            previous = row.provenance.timestamp
        }
        return result
    }

    /// An Apply as Column slot: the field's values in each frame, hidden while unused.
    private func fieldColumn(_ index: Int, _ fields: [FieldKey]) -> some TableColumnContent<CaptureFrameRow, Never> {
        TableColumn(fields.indices.contains(index) ? Self.columnTitle(fields[index]) : "") { row in
            let value = row.columnValues.indices.contains(index) ? row.columnValues[index] : ""
            Text(value).lineLimit(1).truncationMode(.tail).help(value)
        }
        .width(min: 60, ideal: 120)
        .customizationID("field\(index)")
        .disabledCustomizationBehavior(.all)
    }

    /// Copy ▸ Summary as Text / CSV / YAML / HTML: the row's columns as shown.
    private func copySummary(_ values: [String], format: FrameSummaryCopy.Format, rowIndex: Int) {
        let copied = FrameSummaryCopy.copy(
            values, format: format, rowIndex: rowIndex,
            captureName: coordinator.savedCaptureEvidenceURL?.path ?? String(localized: "live capture")
        )
        NSPasteboard.general.clearContents()
        if let html = copied.html {
            NSPasteboard.general.setString(html, forType: .html)
        }
        NSPasteboard.general.setString(copied.text, forType: .string)
    }

    private func goToFrame(_ rows: [CaptureFrameRow]) {
        guard let number = UInt64(goTo.trimmingCharacters(in: .whitespaces)) else {
            notice = String(localized: "Type a frame number.")
            return
        }
        if rows.contains(where: { $0.ordinal == number }) {
            selection = number
            revealToken &+= 1
            notice = nil
        } else {
            notice = String(localized: "Frame \(number.formatted()) is not in this list.")
        }
    }

    private func stepInSession(_ rows: [CaptureFrameRow], forward: Bool) {
        guard let next = Self.adjacentInSession(from: selection, forward: forward, rows: rows) else {
            notice = forward
                ? String(localized: "This is the session's last frame in the list.")
                : String(localized: "This is the session's first frame in the list.")
            return
        }
        notice = nil
        selection = next
        revealToken &+= 1
    }

    private func jumpToMark(forward: Bool) {
        let rows = coordinator.allFrames.visibleRows(sessionsInView: Set(coordinator.visibleSessions.map(\.id)))
        guard let next = coordinator.allFrames.adjacentMark(from: selection, in: rows, forward: forward) else {
            return
        }
        selection = next
        revealToken &+= 1
    }

    private func open(_ row: CaptureFrameRow) {
        if coordinator.revealFrame(row) {
            notice = nil
        } else {
            notice = row.sessionID == nil
                ? String(localized: "Frame \(row.ordinal.formatted()) belongs to no session.")
                : String(localized: "Frame \(row.ordinal.formatted())'s session is not in view in the main window.")
        }
    }
}
