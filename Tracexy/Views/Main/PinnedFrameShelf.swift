import SwiftUI

// MARK: - FrameListPinnedContent

struct FrameListPinnedContent<Content: View>: View {
    let pinnedRows: [CaptureFrameRow]
    @Bindable var state: CaptureFrameListState

    let onGoTo: (UInt64) -> Void
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            if !pinnedRows.isEmpty {
                PinnedFrameShelf(rows: pinnedRows, state: state, onGoTo: onGoTo)
            }
            content
        }
    }
}

// MARK: - PinnedFrameShelf

struct PinnedFrameShelf: View {
    // MARK: Internal

    let rows: [CaptureFrameRow]
    @Bindable var state: CaptureFrameListState

    let onGoTo: (UInt64) -> Void

    var body: some View {
        GroupBox("Pinned Frames — \(rows.count.formatted()) of \(CaptureFrameListState.maximumPinnedFrameRows)") {
            ScrollView(.horizontal) {
                HStack(spacing: Theme.Metrics.spacingS) {
                    ForEach(rows, id: \.id) { row in
                        pinnedRow(row)
                    }
                }
            }
            .scrollIndicators(.automatic)
        }
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.top, Theme.Metrics.spacingS)
    }

    // MARK: Private

    private func pinnedRow(_ row: CaptureFrameRow) -> some View {
        PinnedFrameRowCard(row: row, state: state, onGoTo: onGoTo)
    }
}

// MARK: - PinnedFrameRowCard

private struct PinnedFrameRowCard: View {
    // MARK: Internal

    let row: CaptureFrameRow
    @Bindable var state: CaptureFrameListState

    let onGoTo: (UInt64) -> Void

    var body: some View {
        HStack(spacing: Theme.Metrics.spacingS) {
            packetButton
            unpinButton
            moreActions
        }
        .padding(Theme.Metrics.spacingS)
        .background(Color(nsColor: .controlBackgroundColor), in: shape)
        .overlay {
            shape.strokeBorder(Color.primary.opacity(Theme.Glass.contentStrokeOpacity), lineWidth: 0.5)
        }
    }

    // MARK: Private

    private var canNavigate: Bool {
        !state.isLoading && !state.isEvaluatingFrameExpression
    }

    private var shape: RoundedRectangle {
        RoundedRectangle(cornerRadius: Theme.Metrics.cornerRadius)
    }

    private var packetButton: some View {
        Button {
            onGoTo(row.ordinal)
        } label: {
            VStack(alignment: .leading, spacing: 3) {
                Text("Frame \(row.ordinal.formatted()) · \(row.protocolName)")
                    .font(Theme.Typography.captionMedium)
                Text("\(row.source) → \(row.destination)")
                    .font(Theme.Typography.caption)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help("\(row.source) → \(row.destination)")
                Text(row.info)
                    .font(Theme.Typography.caption)
                    .lineLimit(1)
            }
            .frame(width: 250, alignment: .leading)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(!canNavigate)
        .accessibilityLabel("Go to pinned frame \(row.ordinal.formatted())")
        .help(canNavigate ? "Go to Frame \(row.ordinal.formatted())" : "Wait for the frame list scan to finish")
    }

    private var unpinButton: some View {
        Button("Unpin Row", systemImage: "pin.slash") {
            state.unpinFrameRow(row.ordinal)
        }
        .labelStyle(.iconOnly)
        .help("Unpin Frame \(row.ordinal.formatted())")
    }

    private var moreActions: some View {
        Menu {
            PinnedFrameRowContextMenu(row: row, state: state, canNavigate: canNavigate, onGoTo: onGoTo)
        } label: {
            Image(systemName: "ellipsis.circle")
        }
        .menuStyle(.borderlessButton)
        .help("More actions for Frame \(row.ordinal.formatted())")
    }
}

// MARK: - PinnedFrameRowContextMenu

private struct PinnedFrameRowContextMenu: View {
    let row: CaptureFrameRow
    @Bindable var state: CaptureFrameListState

    let canNavigate: Bool
    let onGoTo: (UInt64) -> Void

    var body: some View {
        Button("Go to Packet") { onGoTo(row.ordinal) }
            .disabled(!canNavigate)
        Button("Unpin Row") { state.unpinFrameRow(row.ordinal) }
        Button("Unpin All Rows") { state.unpinAllFrameRows() }
    }
}

// MARK: - PinnedFrameRowMenu

struct PinnedFrameRowMenu: View {
    let row: CaptureFrameRow

    @Bindable var state: CaptureFrameListState

    var body: some View {
        let isPinned = state.pinnedFrameRows[row.id] != nil
        Button(
            isPinned ? "Unpin Row from Top" : "Pin Row to Top",
            systemImage: isPinned ? "pin.slash" : "pin"
        ) {
            state.togglePinnedFrameRow(row)
        }
        .disabled(!isPinned && state.pinnedFrameRows.count >= CaptureFrameListState.maximumPinnedFrameRows)
        .help("Keep this frame in the separate pinned strip across pages and filters")
    }
}

// MARK: - NoFramesMatchView

struct NoFramesMatchView: View {
    let state: CaptureFrameListState

    var body: some View {
        ContentUnavailableView {
            Label("No Frames Match", systemImage: "line.3.horizontal.decrease.circle")
        } description: {
            Text(state.acceptedFrameExpression != nil
                ? "No listed frame matches the Frame Expression in the current scope. Unknown frames are excluded and counted below."
                : state.limitToSessionsInView
                ? "No frame of the sessions in view matches. Other active filters still apply."
                : "No frame matches the current filters.")
        } actions: {
            if state.limitToSessionsInView {
                Button("Show Frames Outside Sessions in View", systemImage: "rectangle.expand.vertical") {
                    state.showFramesOutsideSessionsInView()
                }
                Text("Search, expression and other active filters still apply.")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
