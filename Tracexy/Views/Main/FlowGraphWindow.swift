import AppKit
import SwiftUI
import UniformTypeIdentifiers

// MARK: - FlowGraphWindow

/// Statistics ▸ Flow Graph: the capture-wide sequence diagram — one lane per
/// address, one arrow per frame, the frame's Info beside it — for the frames the All
/// Frames list shows. Double-click an arrow to open its session and frame; Export
/// as ASCII writes the diagram as text, as Wireshark's dialog does.
struct FlowGraphWindow: View {
    // MARK: Internal

    static let laneWidth: CGFloat = 150
    static let rowHeight: CGFloat = 22
    static let timeWidth: CGFloat = 90

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        @Bindable var frames = coordinator.allFrames
        let inView = Set(coordinator.visibleSessions.map(\.id))
        let visible = frames.visibleRows(sessionsInView: inView)
        let graph = CaptureFlowGraph(rows: frames.flowCallID
            .map { SIPCallFlow.rows(callID: $0, in: visible) } ?? visible)
        Group {
            if frames.isLoading {
                ProgressView("Listing frames…")
                    .controlSize(.small)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let error = frames.error {
                ContentUnavailableView(
                    "Flow Graph Unavailable",
                    systemImage: "arrow.left.arrow.right",
                    description: Text(error)
                )
            } else if graph.isEmpty {
                ContentUnavailableView(
                    "No Frames to Draw",
                    systemImage: "arrow.left.arrow.right",
                    description: Text("No frame between two addresses matches the sessions in view and the search.")
                )
            } else {
                diagram(graph)
            }
        }
        .searchable(text: $frames.search, placement: .toolbar, prompt: "Info, address or protocol")
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Toggle("Limit to Sessions in View", isOn: $frames.limitToSessionsInView)
                    .toggleStyle(.checkbox)
                    .help("Draw only the frames of the sessions the main window shows")
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .top) {
            if let callID = frames.flowCallID {
                HStack(spacing: Theme.Metrics.spacingM) {
                    Text("Call \(callID)").lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Button("Show All Frames") { frames.flowCallID = nil }
                }
                .font(Theme.Typography.caption)
                .controlSize(.small)
                .padding(.horizontal, Theme.Metrics.spacingL)
                .padding(.vertical, Theme.Metrics.spacingS)
            }
        }
        .tracexySafeAreaBar(edge: .bottom) {
            footer(graph)
        }
        .frame(minWidth: 720, minHeight: 360)
        .onAppear { coordinator.loadAllFrames() }
    }

    static func draw(
        _ arrow: CaptureFlowGraph.Arrow,
        laneCount: Int,
        in context: GraphicsContext,
        size: CGSize
    ) {
        let centre = { (lane: Int) -> CGFloat in CGFloat(lane) * laneWidth + laneWidth / 2 }
        for lane in 0 ..< laneCount {
            var line = Path()
            line.move(to: CGPoint(x: centre(lane), y: 0))
            line.addLine(to: CGPoint(x: centre(lane), y: size.height))
            context.stroke(line, with: .color(.secondary.opacity(0.35)), lineWidth: 1)
        }
        let y = size.height / 2
        let from = centre(arrow.from)
        let to = centre(arrow.to)
        var shaft = Path()
        if arrow.from == arrow.to {
            shaft.addEllipse(in: CGRect(x: from - 6, y: y - 6, width: 12, height: 12))
            context.stroke(shaft, with: .color(.accentColor), lineWidth: 1.5)
            return
        }
        shaft.move(to: CGPoint(x: from, y: y))
        shaft.addLine(to: CGPoint(x: to, y: y))
        context.stroke(shaft, with: .color(.accentColor), lineWidth: 1.5)
        let direction: CGFloat = to > from ? -1 : 1
        var head = Path()
        head.move(to: CGPoint(x: to, y: y))
        head.addLine(to: CGPoint(x: to + direction * 7, y: y - 4))
        head.addLine(to: CGPoint(x: to + direction * 7, y: y + 4))
        head.closeSubpath()
        context.fill(head, with: .color(.accentColor))
    }

    // MARK: Private

    @State private var selection: UInt64?
    @State private var notice: String?

    private func diagram(_ graph: CaptureFlowGraph) -> some View {
        let origin = graph.arrows.first?.timestamp
        let canvasWidth = CGFloat(graph.lanes.count) * Self.laneWidth
        return ScrollView([.vertical, .horizontal]) {
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 0) {
                    Text("Time")
                        .font(Theme.Typography.captionMedium)
                        .frame(width: Self.timeWidth, alignment: .leading)
                    ForEach(Array(graph.lanes.enumerated()), id: \.offset) { _, lane in
                        Text(lane)
                            .font(Theme.Typography.monoSmall)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .frame(width: Self.laneWidth)
                            .help(lane)
                    }
                    Text("Info")
                        .font(Theme.Typography.captionMedium)
                        .padding(.leading, Theme.Metrics.spacingM)
                }
                .padding(.vertical, Theme.Metrics.spacingS)
                Divider()
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(graph.arrows) { arrow in
                        row(arrow, laneCount: graph.lanes.count, canvasWidth: canvasWidth, origin: origin)
                    }
                }
            }
            .padding(.horizontal, Theme.Metrics.spacingL)
        }
    }

    private func row(
        _ arrow: CaptureFlowGraph.Arrow,
        laneCount: Int,
        canvasWidth: CGFloat,
        origin: Date?
    )
        -> some View
    {
        HStack(spacing: 0) {
            Text(arrow.timestamp.flatMap { stamp in
                origin.map { String(format: "%.6f", stamp.timeIntervalSince($0)) }
            } ?? "—")
                .font(Theme.Typography.monoSmall)
                .foregroundStyle(.secondary)
                .frame(width: Self.timeWidth, alignment: .leading)
            Canvas { context, size in
                Self.draw(arrow, laneCount: laneCount, in: context, size: size)
            }
            .frame(width: canvasWidth, height: Self.rowHeight)
            .accessibilityHidden(true)
            Text(arrow.label)
                .font(Theme.Typography.monoSmall)
                .lineLimit(1)
                .padding(.leading, Theme.Metrics.spacingM)
                .fixedSize()
        }
        .frame(height: Self.rowHeight)
        .background(selection == arrow.ordinal ? Color.accentColor.opacity(0.18) : Color.clear)
        .contentShape(Rectangle())
        .onTapGesture(count: 2) { open(arrow) }
        .onTapGesture { selection = arrow.ordinal }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Frame \(arrow.ordinal): \(arrow.row.source) to \(arrow.row.destination), \(arrow.label)")
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { open(arrow) }
        .help("Frame \(arrow.ordinal.formatted()) — double-click to open its session and frame")
    }

    private func footer(_ graph: CaptureFlowGraph) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            if let notice {
                Text(notice)
            } else {
                Text(graph.omittedCount > 0
                    ? "\(graph.arrows.count.formatted()) frames between \(graph.lanes.count.formatted()) addresses; \(graph.omittedCount.formatted()) more not drawn"
                    : "\(graph.arrows.count.formatted()) frames between \(graph.lanes.count.formatted()) addresses")
            }
            Spacer()
            Menu("Save As") {
                ForEach(StatisticsImageFormat.allCases) { format in
                    Button(format.menuTitle) { saveImage(graph, format: format) }
                }
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .disabled(graph.isEmpty)
            .help(
                "Save the diagram as a PDF (every frame, one page per \(FlowGraphPage.rowsPerPage) frames) or a PNG image"
            )
            Button("Copy as ASCII") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(graph.ascii(), forType: .string)
            }
            .disabled(graph.isEmpty)
            Button("Export as ASCII…") { export(graph) }
                .disabled(graph.isEmpty)
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    private func open(_ arrow: CaptureFlowGraph.Arrow) {
        selection = arrow.ordinal
        notice = coordinator.revealFrame(arrow.row)
            ? nil
            : String(localized: "Frame \(arrow.ordinal.formatted())'s session is not in view in the main window.")
    }

    private func saveImage(_ graph: CaptureFlowGraph, format: StatisticsImageFormat) {
        let origin = graph.arrows.first?.timestamp
        switch format {
        case .pdf:
            let pages = stride(from: 0, to: graph.arrows.count, by: FlowGraphPage.rowsPerPage).map { start in
                let slice = Array(graph.arrows[start ..< min(start + FlowGraphPage.rowsPerPage, graph.arrows.count)])
                return AnyView(FlowGraphPage(lanes: graph.lanes, arrows: slice, origin: origin))
            }
            notice = StatisticsExport.savePDF(
                pages: pages, pageSize: FlowGraphPage.size(lanes: graph.lanes.count, rows: FlowGraphPage.rowsPerPage),
                suggestedName: "Flow Graph.pdf"
            )
        case .png:
            let arrows = Array(graph.arrows.prefix(FlowGraphPage.maxImageRows))
            notice = StatisticsExport.saveImage(
                FlowGraphPage(lanes: graph.lanes, arrows: arrows, origin: origin),
                size: FlowGraphPage.size(lanes: graph.lanes.count, rows: arrows.count),
                format: .png, suggestedName: "Flow Graph.png"
            )
            if notice == nil, graph.arrows.count > arrows.count {
                notice = String(localized: """
                The image shows the first \(arrows.count.formatted()) frames; the PDF has all \(graph.arrows.count
                    .formatted()).
                """)
            }
        }
    }

    private func export(_ graph: CaptureFlowGraph) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "flow-graph.txt"
        panel.allowedContentTypes = [.plainText]
        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }
        do {
            try Data(graph.ascii().utf8).write(to: url, options: .atomic)
        } catch {
            notice = String(localized: "Couldn’t save the flow graph: \(error.localizedDescription)")
        }
    }
}

// MARK: - FlowGraphPage

/// One printed page of the flow graph: the address lanes, then up to
/// ``rowsPerPage`` arrows with their time and Info — what Save As writes.
struct FlowGraphPage: View {
    static let rowsPerPage = 40
    /// A PNG stays a reasonable size at this many rows.
    static let maxImageRows = 300
    static let infoWidth: CGFloat = 420
    static let margin: CGFloat = 24
    static let headerHeight: CGFloat = 32

    let lanes: [String]
    let arrows: [CaptureFlowGraph.Arrow]
    let origin: Date?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 0) {
                Text("Time").font(Theme.Typography.microEmphasis)
                    .frame(width: FlowGraphWindow.timeWidth, alignment: .leading)
                ForEach(Array(lanes.enumerated()), id: \.offset) { _, lane in
                    Text(lane).font(Theme.Typography.monoMicro).lineLimit(1).truncationMode(.middle)
                        .frame(width: FlowGraphWindow.laneWidth)
                }
                Text("Info").font(Theme.Typography.microEmphasis).padding(.leading, 8)
            }
            .frame(height: Self.headerHeight)
            Divider()
            ForEach(arrows) { arrow in
                HStack(spacing: 0) {
                    Text(arrow.timestamp.flatMap { stamp in
                        origin.map { String(format: "%.6f", stamp.timeIntervalSince($0)) }
                    } ?? "—")
                        .font(Theme.Typography.monoMicro)
                        .foregroundStyle(.secondary)
                        .frame(width: FlowGraphWindow.timeWidth, alignment: .leading)
                    Canvas { context, size in
                        FlowGraphWindow.draw(arrow, laneCount: lanes.count, in: context, size: size)
                    }
                    .frame(width: CGFloat(lanes.count) * FlowGraphWindow.laneWidth, height: FlowGraphWindow.rowHeight)
                    Text(arrow.label).font(Theme.Typography.monoMicro).lineLimit(1)
                        .frame(width: Self.infoWidth, alignment: .leading)
                        .padding(.leading, 8)
                }
                .frame(height: FlowGraphWindow.rowHeight)
            }
        }
        .padding(Self.margin)
    }

    static func size(lanes: Int, rows: Int) -> CGSize {
        CGSize(
            width: FlowGraphWindow.timeWidth + CGFloat(lanes) * FlowGraphWindow.laneWidth + infoWidth + 8 + margin * 2,
            height: headerHeight + 1 + CGFloat(max(rows, 1)) * FlowGraphWindow.rowHeight + margin * 2
        )
    }
}
