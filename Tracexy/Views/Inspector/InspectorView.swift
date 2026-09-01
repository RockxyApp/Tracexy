import AppKit
import SwiftUI

// MARK: - InspectorView

struct InspectorView: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let workspace = coordinator.activeWorkspace
        let session = coordinator.selectedSession
        // Progressive disclosure: only the facets relevant to this session are
        // shown, and the active tab falls back to Timeline if the persisted
        // selection is hidden for the newly-selected session.
        let visibleTabs = session.map { resolvedVisibleTabs(for: $0) } ?? []
        let activeTab = visibleTabs.contains(workspace.inspectorTab) ? workspace.inspectorTab : .timeline
        VStack(spacing: 0) {
            if let session {
                inspectorChrome(
                    workspace: workspace,
                    visibleTabs: visibleTabs,
                    activeTab: activeTab,
                    session: session
                )
            }
            Group {
                if let session {
                    if activeTab == .layers {
                        layersInspector(session)
                    } else {
                        ScrollView {
                            content(tab: activeTab, session: session)
                                .padding(Theme.Metrics.spacingL)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                } else {
                    ContentUnavailableView("No Session Selected", systemImage: "rectangle.dashed")
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            .tracexyDenseScrollEdge()
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        // Claim the full width here, on the pane itself.
        //
        // This used to happen by accident: a header row sat above both branches
        // and its trailing `Spacer` made the VStack greedy. Removing the header
        // took the greed with it, so with nothing selected the pane sized to the
        // intrinsic width of `ContentUnavailableView` — and because it is one
        // half of the enclosing `VSplitView`, it dragged the session table and
        // the whole centre column down to that width with it.
        //
        // Layout intent belongs where it is meant, not as a side effect of a
        // spacer inside a subview that may or may not be rendered.
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Session evidence inspector")
        .onAppear {
            coordinator.loadSelectedSavedCaptureEvidence()
        }
        .onChange(of: workspace.selectedSessionID) {
            selectedRange = nil
            coordinator.loadSelectedSavedCaptureEvidence()
            // Reconcile the persisted tab so the picker never shows a hidden facet.
            if let session = coordinator.selectedSession,
               !resolvedVisibleTabs(for: session).contains(workspace.inspectorTab)
            {
                workspace.inspectorTab = .timeline
            }
        }
    }

    // MARK: Private

    @State private var fieldQuery = ""
    @State private var selectedRange: Range<Int>?
    @State private var followStreamDisplayMode: FollowStreamDisplayMode = .text

    private var selectedEvidence: SessionEvidenceSelection? {
        guard let selection = coordinator.evidenceProjection.selection,
              selection.sessionID == coordinator.activeWorkspace.selectedSessionID else
        {
            return nil
        }
        return selection
    }

    private var selectedCitedFrame: SelectedFrameEvidence? {
        guard case let .loaded(evidence) = coordinator.citedFrame.state,
              evidence.sessionID == coordinator.activeWorkspace.selectedSessionID else
        {
            return nil
        }
        return evidence
    }

    private var citedFrameStateIsActive: Bool {
        if case .idle = coordinator.citedFrame.state {
            return false
        }
        return true
    }

    private var citedFrameScopeRow: some View {
        HStack(spacing: Theme.Metrics.spacingS) {
            Image(systemName: "scope")
                .foregroundStyle(.secondary)
            switch coordinator.citedFrame.state {
            case .idle:
                EmptyView()
            case .unavailable:
                Text("Exact cited frame unavailable")
            case let .loading(provenance):
                ProgressView()
                    .controlSize(.mini)
                Text("Loading cited frame \(provenance.ordinal.rawValue.formatted())…")
            case let .loaded(evidence):
                Text("Cited frame \(evidence.provenance.ordinal.rawValue.formatted())")
                    .font(Theme.Typography.captionMedium)
                Text("· \(evidence.bytes.count.formatted()) captured bytes")
                    .foregroundStyle(.secondary)
            case let .failed(message):
                Text(message)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: Theme.Metrics.spacingM)
            Button("Clear Citation") {
                coordinator.cancelCitedFrame()
            }
            .controlSize(.small)
        }
        .font(Theme.Typography.caption)
        .padding(.horizontal, Theme.Metrics.spacingM)
        .padding(.vertical, 5)
        .background(.quaternary.opacity(0.35))
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Cited frame scope")
    }

    /// Decode-tree filtering is a compact Layers utility, not another full-width
    /// sticky row. Keeping it inside the tab chrome preserves the scarce vertical
    /// viewport when an exact citation also needs its own visible scope row.
    private var layerFilterControl: some View {
        HStack(spacing: 5) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary).font(.system(size: Theme.Icon.small))
            TextField("Filter key or value", text: $fieldQuery)
                .textFieldStyle(.plain)
                .font(Theme.Typography.caption)
                .accessibilityLabel("Filter decoded fields")
            if !fieldQuery.isEmpty {
                Button { fieldQuery = "" } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain).foregroundStyle(.secondary)
                    .accessibilityLabel("Clear field filter")
                    .help("Clear the field filter")
            }
        }
        .padding(.horizontal, 8).padding(.vertical, 5)
        .tracexyContentSurface(in: Capsule(style: .continuous))
        .frame(minWidth: 180, idealWidth: 240, maxWidth: 280)
    }

    private var followStreamLoading: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            if let fraction = coordinator.followStreamFraction {
                ProgressView(value: fraction)
                    .accessibilityLabel("Following TCP stream")
                    .accessibilityValue(fraction.formatted(.percent.precision(.fractionLength(0))))
            } else {
                ProgressView()
                    .controlSize(.small)
            }
            HStack {
                if let progress = coordinator.followStreamProgress {
                    Text(
                        "Scanned \(progress.bytesConsumed.formatted()) of "
                            + "\(progress.totalBytes.formatted()) bytes"
                    )
                    .font(Theme.Typography.monoSmall)
                    .foregroundStyle(.secondary)
                } else {
                    Text("Preparing stable local source…")
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Cancel") {
                    coordinator.cancelFollowStream(clearResult: true)
                }
                .controlSize(.small)
            }
        }
        .padding(Theme.Metrics.spacingM)
        .tracexyContentSurface(
            in: RoundedRectangle(cornerRadius: Theme.Metrics.cornerRadius, style: .continuous)
        )
    }

    /// The bottom inspector hosts AppKit-backed split content. Native
    /// `safeAreaBar` allows that content to continue underneath the bar, but
    /// nested split scroll views do not consume the propagated inset and their
    /// scrollbars end up behind the chrome. Keep this header in normal layout so
    /// the decode and hex panes begin strictly below it.
    private func inspectorChrome(
        workspace: WorkspaceState,
        visibleTabs: [InspectorTab],
        activeTab: InspectorTab,
        session: SessionSummary
    )
        -> some View
    {
        VStack(spacing: 0) {
            tabStrip(
                workspace: workspace,
                visibleTabs: visibleTabs,
                activeTab: activeTab,
                session: session
            )
            if activeTab != .evidence, citedFrameStateIsActive {
                citedFrameScopeRow
            }
            Divider()
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    /// What the pane is currently describing, stated at the right of the tab row.
    ///
    /// The scope pill is the important half: when the selection resolves to a
    /// correlated action, the timeline below spans *four conversations*, and
    /// without saying so the pane would look like it was mis-reporting a single
    /// session's duration.
    @ViewBuilder
    private func scopeLabel(_ session: SessionSummary) -> some View {
        let activity = coordinator.activity(containing: session)
        HStack(spacing: 6) {
            if let process = session.processName {
                Text(process)
                    .font(Theme.Typography.bodyEmphasis)
                Image(systemName: "arrow.right")
                    .font(.system(size: Theme.Icon.small))
                    .foregroundStyle(.secondary)
            }
            Text(activity?.title ?? session.host)
                .font(Theme.Typography.bodyEmphasis)
                .lineLimit(1)
                .truncationMode(.middle)
            if let activity, activity.sessions.count > 1 {
                Text("whole action")
                    .font(Theme.Typography.microMedium)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 2)
                    .tracexyChipStyle(tint: .accentColor, isActive: true)
            }
        }
    }

    /// Wireshark-style linked view: a selectable decode tree paired with a hex pane,
    /// where selecting a field/layer highlights its bytes. The evidence inspector
    /// is the wide bottom dock, so the tree and hex sit **side by side** and use
    /// the horizontal space deliberately.
    @ViewBuilder
    private func layersInspector(_ session: SessionSummary) -> some View {
        let sourceLayers = selectedCitedFrame?.layers ?? session.decodedLayers
        let layers = filterLayers(sourceLayers, query: fieldQuery)
        if case .loading = coordinator.citedFrame.state {
            ProgressView("Loading cited frame…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if case .unavailable = coordinator.citedFrame.state {
            placeholder("This observation has no exact source locator. No replacement frame was loaded.")
                .padding(Theme.Metrics.spacingL)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else if case let .failed(message) = coordinator.citedFrame.state {
            placeholder(message)
                .padding(Theme.Metrics.spacingL)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else if sourceLayers.isEmpty {
            placeholder("No decode available for this session.")
                .padding(Theme.Metrics.spacingL)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else if layers.isEmpty {
            placeholder("No inspector fields match “\(fieldQuery)”.")
                .padding(Theme.Metrics.spacingL)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else {
            HSplitView {
                layerTree(layers)
                hexPane(session)
            }
        }
    }

    private func layerTree(_ layers: [DecodedLayer]) -> some View {
        ScrollView {
            DecodedLayerTree(layers: layers, selectedRange: selectedRange) { range in
                selectedRange = (range == selectedRange) ? nil : range
            }
            .padding(Theme.Metrics.spacingL)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder
    private func hexPane(_ session: SessionSummary) -> some View {
        let bytes = evidenceBytes(for: session)
        if !bytes.isEmpty {
            ScrollView {
                HexDumpView(bytes: bytes, highlight: selectedRange)
                    .padding(Theme.Metrics.spacingL)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(minWidth: 280)
        } else if coordinator.isLoadingSelectedSessionEvidence {
            ProgressView("Loading selected evidence…")
                .frame(minWidth: 280, maxWidth: .infinity, maxHeight: .infinity)
        } else if let error = coordinator.selectedSessionEvidenceError {
            placeholder(error)
                .padding(Theme.Metrics.spacingL)
                .frame(minWidth: 280, maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else {
            placeholder("No packet bytes are available for this session.")
                .padding(Theme.Metrics.spacingL)
                .frame(minWidth: 280, maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
    }

    /// Named tabs, not icons.
    ///
    /// The evidence facets are close enough in kind (Layers · Requests · Payload
    /// · Hex are all "the bytes, at four zoom levels") that a glyph cannot
    /// separate them — an icon-only strip made the user click to find out which
    /// was which. Words cost a few points of height and remove the guessing.
    private func tabStrip(
        workspace: WorkspaceState,
        visibleTabs: [InspectorTab],
        activeTab: InspectorTab,
        session: SessionSummary
    )
        -> some View
    {
        // Tabs and the optional Layers filter always share one horizontally
        // scrollable row. The scope stays visible at the trailing edge, so even
        // compact panes add no extra sticky row above an exact citation.
        HStack(spacing: Theme.Metrics.spacingM) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 2) {
                    tabButtons(workspace: workspace, visibleTabs: visibleTabs, activeTab: activeTab)
                    if activeTab == .layers {
                        layerFilterControl
                            .padding(.leading, Theme.Metrics.spacingS)
                    }
                }
            }
            .layoutPriority(1)
            scopeLabel(session)
                .frame(minWidth: 140, idealWidth: 240, maxWidth: 320, alignment: .trailing)
        }
        .padding(.horizontal, Theme.Metrics.spacingM)
        .padding(.vertical, 6)
    }

    private func tabButtons(
        workspace: WorkspaceState,
        visibleTabs: [InspectorTab],
        activeTab: InspectorTab
    )
        -> some View
    {
        ForEach(visibleTabs) { tab in
            Button {
                workspace.inspectorTab = tab
            } label: {
                Text(tab.title)
                    .font(tab == activeTab ? Theme.Typography.bodyEmphasis : Theme.Typography.body)
                    .padding(.horizontal, 9)
                    .padding(.vertical, 4)
                    .tracexyChipStyle(tint: .accentColor, isActive: tab == activeTab)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityAddTraits(tab == activeTab ? .isSelected : [])
            .help(tab.title)
        }
    }

    @ViewBuilder
    private func content(tab: InspectorTab, session: SessionSummary) -> some View {
        switch tab {
        case .layers: EmptyView() // routed to layersInspector (linked tree + hex)
        case .timeline: timeline(session)
        case .evidence: sessionEvidence(session)
        case .stream: followStream(session)
        case .requests: requests(session)
        case .payload: payload(session)
        case .hex: rawEvidence(session)
        }
    }

    // MARK: Connection and TLS evidence

    @ViewBuilder
    private func sessionEvidence(_ session: SessionSummary) -> some View {
        if let selection = selectedEvidence {
            SessionEvidenceTimelineView(
                selection: selection,
                selectedFrameOrdinal: selectedCitedFrame?.provenance.ordinal,
                isLoadingFrame: {
                    if case .loading = coordinator.citedFrame.state {
                        return true
                    }
                    return false
                }(),
                frameError: {
                    if case let .failed(message) = coordinator.citedFrame.state {
                        return message
                    }
                    return nil
                }(),
                frameUnavailable: {
                    if case .unavailable = coordinator.citedFrame.state {
                        return true
                    }
                    return false
                }(),
                inspectFrame: { provenance in
                    coordinator.inspectCitedFrame(sessionID: session.id, provenance: provenance)
                    coordinator.activeWorkspace.inspectorTab = .layers
                    selectedRange = nil
                }
            )
        } else if coordinator.evidenceProjection.task != nil {
            ProgressView("Preparing retained evidence…")
        } else {
            placeholder("No retained connection or direct-frame TLS evidence is available for this session.")
        }
    }

    // MARK: Follow Stream

    /// Explicit, local-only TCP stream reconstruction. Merely selecting the tab
    /// never scans a capture or retains application bytes; the button is the user
    /// action that activates the bounded coordinator workflow.
    private func followStream(_ session: SessionSummary) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            HStack(alignment: .center, spacing: Theme.Metrics.spacingM) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Follow TCP Stream")
                        .font(Theme.Typography.bodyEmphasis)
                    Text("Reads this local capture on demand. Nothing is sent or exported.")
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: Theme.Metrics.spacingM)
                Picker("Display", selection: $followStreamDisplayMode) {
                    ForEach(FollowStreamDisplayMode.allCases) { mode in
                        Text(mode.title).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 132)
            }

            Label(
                "Application data can contain credentials or personal information. Review it locally before copying.",
                systemImage: "hand.raised"
            )
            .font(Theme.Typography.caption)
            .foregroundStyle(.secondary)

            if coordinator.isLoadingFollowStream {
                followStreamLoading
            } else if let error = coordinator.followStreamError {
                followStreamEmptyState(message: error, session: session)
            } else if let result = coordinator.followStreamResult,
                      SessionBuilder.sessionID(for: result.tuple) == session.id
            {
                followStreamResult(result)
            } else {
                followStreamEmptyState(
                    message: coordinator.followStreamUnavailableReason
                        ?? "Reconstruct both TCP directions from the stable capture source.",
                    session: session
                )
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Follow TCP Stream")
    }

    private func followStreamEmptyState(message: String, session _: SessionSummary) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            Text(message)
                .font(Theme.Typography.body)
                .foregroundStyle(.secondary)
            Button("Follow Stream") {
                coordinator.followSelectedTCPStream()
            }
            .controlSize(.small)
            .disabled(coordinator.followStreamUnavailableReason != nil)
            .help(coordinator.followStreamUnavailableReason ?? "Reconstruct this TCP stream")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(Theme.Metrics.spacingM)
        .tracexyContentSurface(
            in: RoundedRectangle(cornerRadius: Theme.Metrics.cornerRadius, style: .continuous)
        )
    }

    private func followStreamResult(_ result: FollowStreamResult) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            HStack(spacing: Theme.Metrics.spacingL) {
                field("Matched Frames", result.matchedFrameCount.formatted())
                field("Scanned Frames", result.scannedFrameCount.formatted())
                field("Source", followStreamCompleteness(result.completeness))
                Spacer(minLength: Theme.Metrics.spacingM)
                Button("Refresh") {
                    coordinator.followSelectedTCPStream()
                }
                .controlSize(.small)
                .disabled(coordinator.followStreamUnavailableReason != nil)
            }

            let limitations = result.limitations.presentationLabels
            if !limitations.isEmpty {
                VStack(alignment: .leading, spacing: 5) {
                    Text("Observed limitations")
                        .font(Theme.Typography.captionMedium)
                        .foregroundStyle(.secondary)
                    ForEach(limitations, id: \.self) { limitation in
                        Label(limitation, systemImage: "info.circle")
                            .font(Theme.Typography.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }

            ViewThatFits(in: .horizontal) {
                HStack(alignment: .top, spacing: Theme.Metrics.spacingM) {
                    followStreamDirection(
                        result.aToB,
                        title: "\(result.tuple.a.display) → \(result.tuple.b.display)"
                    )
                    followStreamDirection(
                        result.bToA,
                        title: "\(result.tuple.b.display) → \(result.tuple.a.display)"
                    )
                }
                VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
                    followStreamDirection(
                        result.aToB,
                        title: "\(result.tuple.a.display) → \(result.tuple.b.display)"
                    )
                    followStreamDirection(
                        result.bToA,
                        title: "\(result.tuple.b.display) → \(result.tuple.a.display)"
                    )
                }
            }
        }
    }

    private func followStreamDirection(
        _ snapshot: FollowStreamDirectionSnapshot,
        title: String
    )
        -> some View
    {
        let presentation = FollowStreamDirectionPresentation(
            snapshot: snapshot,
            mode: followStreamDisplayMode
        )
        return GroupBox {
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
                HStack {
                    Text("\(snapshot.retainedByteCount.formatted()) retained bytes")
                    if snapshot.observedOmittedByteCount > 0 {
                        Text("· \(snapshot.observedOmittedByteCount.formatted()) omitted by reader bounds")
                    }
                    if presentation.viewOmittedByteCount > 0 {
                        Text("· \(presentation.viewOmittedByteCount.formatted()) not shown")
                    }
                }
                .font(Theme.Typography.micro)
                .foregroundStyle(.secondary)

                if presentation.body.isEmpty {
                    placeholder("No application bytes were retained in this direction.")
                } else {
                    Text(presentation.body)
                        .font(Theme.Typography.monoSmall)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Text(title)
                .font(Theme.Typography.captionMedium)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .frame(minWidth: 280, maxWidth: .infinity, alignment: .topLeading)
    }

    // MARK: Requests

    /// The application-layer exchanges this session carried, one row each.
    ///
    /// Read off the decode — a request the decoder did not produce is not listed,
    /// because an empty-but-present row is a claim the bytes do not support.
    @ViewBuilder
    private func requests(_ session: SessionSummary) -> some View {
        let exchanges = applicationLayers(session.decodedLayers)
        if exchanges.isEmpty {
            placeholder("No application-layer exchange was decoded for this session.")
        } else {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(exchanges.enumerated()), id: \.offset) { index, layer in
                    HStack(alignment: .top, spacing: Theme.Metrics.spacingM) {
                        Text(layer.proto.label)
                            .font(Theme.Typography.badge)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Theme.color(for: layer.proto).opacity(0.18), in: Capsule())
                            .foregroundStyle(Theme.color(for: layer.proto))
                            .frame(width: 62, alignment: .leading)
                        Text(layer.summary.isEmpty ? layer.title : layer.summary)
                            .font(Theme.Typography.caption)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                        Spacer(minLength: 0)
                    }
                    .padding(.vertical, 5)
                    if index < exchanges.count - 1 {
                        Divider()
                    }
                }
            }
        }
    }

    // MARK: Payload

    /// The representative packet's bytes rendered as text, with non-printable
    /// bytes shown as `.` — the middle zoom level between a decode tree and raw
    /// hex, and the fastest way to confirm what a body actually was.
    @ViewBuilder
    private func payload(_ session: SessionSummary) -> some View {
        let text = printablePayload(evidenceBytes(for: session))
        if case .loading = coordinator.citedFrame.state {
            ProgressView("Loading cited frame…")
        } else if case .unavailable = coordinator.citedFrame.state {
            placeholder("This observation has no exact source locator. No replacement frame was loaded.")
        } else if case let .failed(message) = coordinator.citedFrame.state {
            placeholder(message)
        } else if coordinator.isLoadingSelectedSessionEvidence {
            ProgressView("Loading selected evidence…")
        } else if let error = coordinator.selectedSessionEvidenceError {
            placeholder(error)
        } else if text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            placeholder("This packet carries no printable payload.")
        } else {
            Text(text)
                .font(Theme.Typography.monoSmall)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder
    private func rawEvidence(_ session: SessionSummary) -> some View {
        let bytes = evidenceBytes(for: session)
        if case .loading = coordinator.citedFrame.state {
            ProgressView("Loading cited frame…")
        } else if case .unavailable = coordinator.citedFrame.state {
            placeholder("This observation has no exact source locator. No replacement frame was loaded.")
        } else if case let .failed(message) = coordinator.citedFrame.state {
            placeholder(message)
        } else if !bytes.isEmpty {
            HexDumpView(bytes: bytes, highlight: nil)
        } else if coordinator.isLoadingSelectedSessionEvidence {
            ProgressView("Loading selected evidence…")
        } else if let error = coordinator.selectedSessionEvidenceError {
            placeholder(error)
        } else {
            placeholder("No packet bytes are available for this session.")
        }
    }

    // MARK: Timing

    /// The Timing facet: an honest phase-bar over the session's real `duration`,
    /// split into a leading Handshake/TTFB segment and a Transfer segment when a
    /// measured latency exists (otherwise a single Duration bar). Wide, time-based
    /// content — the bottom dock has the width, so the legend lays out on one line.
    private func timeline(_ session: SessionSummary) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            if let activity = coordinator.activity(containing: session), activity.sessions.count > 1 {
                CorrelatedActionTimeline(activity: activity, selectedID: session.id)
            } else {
                // A lone conversation has no cross-protocol axis to draw, so it
                // falls back to the honest phase split of its own duration.
                let phases = timingPhases(session)
                field("Total Duration", String(format: "%.3f s", session.duration))
                timingBar(phases, compact: false)
                if session.latencyMilliseconds == nil {
                    placeholder("No handshake / TTFB latency was measured for this session.")
                }
            }
        }
    }

    /// Renders the proportional bar plus a wrapping-safe legend (one row per phase
    /// with a color swatch + ms label). `compact` gives the thin Summary-embedded
    /// variant with a stacked legend; the full-size variant uses the bottom dock's
    /// width for a single-line legend.
    @ViewBuilder
    private func timingBar(_ phases: [TimingPhase], compact: Bool) -> some View {
        let total = max(phases.reduce(0) { $0 + $1.milliseconds }, 0.0001)
        VStack(alignment: .leading, spacing: compact ? Theme.Metrics.spacingS : Theme.Metrics.spacingM) {
            GeometryReader { geo in
                HStack(spacing: phases.count > 1 ? 1 : 0) {
                    ForEach(phases) { phase in
                        phase.color
                            .frame(width: max(
                                geo.size.width * phase.milliseconds / total,
                                phase.milliseconds > 0 ? 2 : 0
                            ))
                    }
                    Spacer(minLength: 0)
                }
            }
            .frame(height: compact ? 8 : 18)
            .clipShape(RoundedRectangle(cornerRadius: compact ? 4 : 5))
            timingLegend(phases, wide: !compact)
        }
    }

    @ViewBuilder
    private func timingLegend(_ phases: [TimingPhase], wide: Bool) -> some View {
        if wide {
            HStack(spacing: Theme.Metrics.spacingL) {
                ForEach(phases) { phase in
                    timingLegendRow(phase, fill: false)
                }
                Spacer(minLength: 0)
            }
        } else {
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
                ForEach(phases) { phase in
                    timingLegendRow(phase, fill: true)
                }
            }
        }
    }

    private func timingLegendRow(_ phase: TimingPhase, fill: Bool) -> some View {
        HStack(spacing: 6) {
            RoundedRectangle(cornerRadius: 2).fill(phase.color).frame(width: 10, height: 10)
            Text(phase.name).font(Theme.Typography.caption)
            if fill {
                Spacer(minLength: 8)
            }
            Text(phase.msLabel).font(Theme.Typography.monoSmall).foregroundStyle(.secondary)
        }
    }

    private func placeholder(_ text: String) -> some View {
        Text(text).font(Theme.Typography.body).foregroundStyle(.secondary)
    }

    private func field(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(label).font(Theme.Typography.captionMedium).foregroundStyle(.secondary)
            Text(value).font(Theme.Typography.mono).textSelection(.enabled)
        }
    }

    private func followStreamCompleteness(_ completeness: FollowStreamCompleteness) -> String {
        switch completeness {
        case .complete: "Complete file"
        case .incompleteTruncatedTail: "Truncated tail"
        }
    }

    /// Application-layer layers, flattened out of the decode tree in order.
    private func applicationLayers(_ layers: [DecodedLayer]) -> [DecodedLayer] {
        var found: [DecodedLayer] = []
        for layer in layers {
            let isApplication: Set<ProtocolKind> = [.http, .http2, .dns, .websocket, .quic, .stun]
            if isApplication.contains(layer.proto) {
                found.append(layer)
            }
            found.append(contentsOf: applicationLayers(layer.children))
        }
        return found
    }

    private func printablePayload(_ bytes: [UInt8]) -> String {
        String(bytes.map { byte in
            if byte == 0x0A || byte == 0x0D || byte == 0x09 {
                return Character(UnicodeScalar(byte))
            }
            return byte >= 0x20 && byte < 0x7F ? Character(UnicodeScalar(byte)) : "."
        })
    }

    /// Builds the timing phases from the fields `SessionSummary` carries **today**:
    /// the measured latency (Handshake / TTFB) and the remainder (Transfer). No
    /// phase is fabricated — if there is no latency we show a single Duration bar.
    ///
    /// Forward-compat seam: when a future `SessionSummary` gains a typed array of
    /// decoded phases (DNS · TCP handshake · TLS handshake · TTFB · Transfer), map
    /// each element to a `TimingPhase` here and the bar/legend render unchanged.
    private func timingPhases(_ session: SessionSummary) -> [TimingPhase] {
        // TODO: decoders (Core/) will populate real DNS/TCP/TLS phases later; until
        // then this is a two-segment latency/transfer split from real fields only.
        let totalMs = max(session.duration * 1_000, 0)
        guard let latency = session.latencyMilliseconds, latency >= 0, latency <= totalMs else {
            return [TimingPhase(
                name: "Duration",
                milliseconds: totalMs,
                color: Theme.color(for: session.primaryProtocol)
            )]
        }
        return [
            TimingPhase(
                name: "Handshake / TTFB",
                milliseconds: latency,
                color: Theme.latencyColor(milliseconds: latency)
            ),
            TimingPhase(
                name: "Transfer",
                milliseconds: max(totalMs - latency, 0),
                color: Theme.color(for: session.primaryProtocol)
            ),
        ]
    }

    // Plain-language verdict for the top of the Summary tab, e.g.
    // "TLS to api.example.com · 142 ms · 2 protocols · OK".

    private func resolvedVisibleTabs(for session: SessionSummary) -> [InspectorTab] {
        let hasEvidence = selectedEvidence.map { selection in
            !selection.isEmpty
                || selection.connectionCoverage.omittedSummaryCount > 0
                || selection.connectionCoverage.countersOverflowed
                || selection.tlsCoverage.capacityReached
                || selection.tlsCoverage.countersOverflowed
                || selection.tlsCoverage.omittedObservationCount > 0
                || selection.tlsCoverage.excludedReassembledRecordCount > 0
        } ?? false
        var tabs = InspectorTab.visibleTabs(for: session, hasSessionEvidence: hasEvidence)
        if citedFrameStateIsActive, !tabs.contains(.layers), let evidenceIndex = tabs.firstIndex(of: .evidence) {
            tabs.insert(.layers, at: tabs.index(after: evidenceIndex))
        }
        return tabs
    }

    private func evidenceBytes(for session: SessionSummary) -> [UInt8] {
        selectedCitedFrame?.bytes ?? coordinator.evidenceBytes(for: session)
    }

    /// Prunes the decode tree to layers/fields matching the field-filter query.
    private func filterLayers(_ layers: [DecodedLayer], query: String) -> [DecodedLayer] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else {
            return layers
        }
        return layers.compactMap { layer in
            if layer.title.lowercased().contains(q) || layer.summary.lowercased().contains(q) {
                return layer
            }
            let fields = layer.fields.filter {
                $0.name.lowercased().contains(q) || $0.value.lowercased().contains(q)
            }
            let children = filterLayers(layer.children, query: q)
            if fields.isEmpty, children.isEmpty {
                return nil
            }
            return DecodedLayer(
                proto: layer.proto, title: layer.title, summary: layer.summary,
                fields: fields, children: children
            )
        }
    }
}

// MARK: - TimingPhase

/// One segment of the Inspector's Timing phase-bar. Local to the view for now:
/// today it models the measured latency/transfer split, but its shape (a named,
/// timed, colored span) is exactly what a future decoded DNS/TCP/TLS/TTFB phase
/// array would map onto, so the bar and legend need no change when that lands.
private struct TimingPhase: Identifiable {
    let name: String
    let milliseconds: Double
    let color: Color

    var id: String {
        name
    }

    /// Human ms label; sub-millisecond spans keep two decimals so they don't read
    /// as "0 ms".
    var msLabel: String {
        milliseconds >= 1 || milliseconds == 0
            ? String(format: "%.0f ms", milliseconds)
            : String(format: "%.2f ms", milliseconds)
    }
}

// MARK: - CorrelatedActionTimeline

/// Every session of a correlated action on one shared, labelled time axis.
///
/// This is what the width of a bottom dock is actually for, and it is the thing a
/// packet analyser cannot draw: its engine relates frames within one conversation
/// and one protocol, so the DNS lookup, the connect, the handshake and the
/// request are four unrelated objects with no common axis to place them on.
///
/// The axis is the point. Bars without ticks show *ordering*; bars against a
/// measured scale show *cost*, which is the question — which step took the time —
/// that made the user open the pane.
private struct CorrelatedActionTimeline: View {
    // MARK: Internal

    let activity: Activity
    let selectedID: SessionSummary.ID

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            header
            VStack(spacing: 3) {
                ForEach(activity.sessions) { member in
                    row(member)
                }
            }
            .background(alignment: .leading) { gridlines }
            axis
            if let note = dominantPhaseNote {
                Text(note)
                    .font(Theme.Typography.micro)
                    .foregroundStyle(.orange)
            }
        }
    }

    // MARK: Private

    /// Width of the leading label gutter — the protocol and its subtitle — kept
    /// constant so every bar shares one origin.
    private static let labelWidth: CGFloat = 96
    /// Ticks drawn across the plot, including both ends.
    private static let tickCount = 5

    private var spanMilliseconds: Double {
        max(activity.duration * 1_000, 0.0001)
    }

    /// "142 ms to first byte · 296 ms complete" — the two numbers the action is
    /// judged on. The first is stated only when something measured a latency.
    private var headerDetail: String {
        let complete = "\(Self.ms(spanMilliseconds)) complete"
        guard let ttfb = firstByteMilliseconds else {
            return complete
        }
        return "\(Self.ms(ttfb)) to first byte · \(complete)"
    }

    private var firstByteMilliseconds: Double? {
        activity.sessions.compactMap(\.latencyMilliseconds).max()
    }

    /// The one-line reading of the chart: which step dominated the wait.
    ///
    /// Stated only when a step actually dominates — below a third of the time to
    /// first byte there is no single culprit, and naming one anyway would be the
    /// chart drawing a conclusion the numbers don't support.
    private var dominantPhaseNote: String? {
        guard let ttfb = firstByteMilliseconds, ttfb > 0 else {
            return nil
        }
        guard let worst = activity.sessions.max(by: { $0.duration < $1.duration }) else {
            return nil
        }
        let share = worst.duration * 1_000 / ttfb
        guard share >= 0.33, share <= 1 else {
            return nil
        }
        let name = worst.primaryProtocol == .tls ? "TLS handshake" : worst.primaryProtocol.label
        return "\(name) is \(Int((share * 100).rounded()))% of time-to-first-byte"
    }

    private var header: some View {
        SectionHeader("Correlated Action Timeline", detail: headerDetail)
    }

    private var gridlines: some View {
        GeometryReader { geo in
            let plot = max(geo.size.width - Self.labelWidth, 1)
            ForEach(0 ..< Self.tickCount, id: \.self) { tick in
                Rectangle()
                    .fill(Color.primary.opacity(0.07))
                    .frame(width: 1)
                    .offset(x: Self.labelWidth + plot * CGFloat(tick) / CGFloat(Self.tickCount - 1))
            }
        }
    }

    private var axis: some View {
        HStack(spacing: 0) {
            Color.clear.frame(width: Self.labelWidth)
            GeometryReader { geo in
                ForEach(0 ..< Self.tickCount, id: \.self) { tick in
                    let fraction = Double(tick) / Double(Self.tickCount - 1)
                    Text(Self.ms(spanMilliseconds * fraction))
                        .font(Theme.Typography.micro)
                        .monospacedDigit()
                        .foregroundStyle(.tertiary)
                        .fixedSize()
                        // Both ends hug the plot; interior ticks centre on the line.
                        .alignmentGuide(.leading) { dimension in
                            switch tick {
                            case 0: 0
                            case Self.tickCount - 1: dimension.width
                            default: dimension.width / 2
                            }
                        }
                        .offset(x: geo.size.width * fraction)
                }
            }
            .frame(height: 12)
        }
    }

    private func row(_ member: SessionSummary) -> some View {
        let proto = member.primaryProtocol
        let tint = Theme.color(for: proto)
        let isSelected = member.id == selectedID
        return HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 0) {
                Text(proto.label)
                    .font(Theme.Typography.captionEmphasis)
                    .foregroundStyle(tint)
                Text(Self.subtitle(for: member))
                    .font(Theme.Typography.micro)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            .frame(width: Self.labelWidth, alignment: .leading)
            .padding(.trailing, Theme.Metrics.spacingM)

            GeometryReader { geo in
                let offset = member.startTime.timeIntervalSince(activity.startTime) * 1_000 / spanMilliseconds
                let fraction = member.duration * 1_000 / spanMilliseconds
                let width = max(geo.size.width * fraction, 3)
                let label = Self.ms(member.duration * 1_000)
                // The duration sits inside the bar when it fits, and trails it
                // when it doesn't — so a short DNS lookup still shows its number.
                let fitsInside = width > 46
                HStack(spacing: 5) {
                    RoundedRectangle(cornerRadius: 3)
                        .fill(tint.opacity(isSelected ? 1 : 0.75))
                        .frame(width: width)
                        .overlay(alignment: .trailing) {
                            if fitsInside {
                                Text(label)
                                    .font(Theme.Typography.microMedium)
                                    .monospacedDigit()
                                    .foregroundStyle(.white)
                                    .padding(.trailing, 6)
                            }
                        }
                    if !fitsInside {
                        Text(label)
                            .font(Theme.Typography.micro)
                            .monospacedDigit()
                            .foregroundStyle(.secondary)
                            .fixedSize()
                    }
                }
                .offset(x: geo.size.width * max(offset, 0))
            }
            .frame(height: 14)
        }
        .frame(height: 26)
    }

    /// What this step was actually talking to, so the row identifies itself
    /// without the user cross-referencing the session list.
    private static func subtitle(for member: SessionSummary) -> String {
        if let query = member.dnsQuery, !query.isEmpty {
            return query
        }
        if let sni = member.sni, !sni.isEmpty {
            return sni
        }
        return member.destinationEndpoint
    }

    private static func ms(_ value: Double) -> String {
        value >= 1_000
            ? String(format: "%.2f s", value / 1_000)
            : String(format: "%.0f ms", value)
    }
}

// MARK: - DecodedLayerTree

/// A selectable decode tree (Eth → IP → TCP → TLS → handshake). Tapping a layer
/// header or a field reports its byte range so the hex pane can highlight it.
private struct DecodedLayerTree: View {
    // MARK: Internal

    let layers: [DecodedLayer]
    let selectedRange: Range<Int>?
    let onSelect: (Range<Int>?) -> Void
    var depth = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(layers) { layer in
                VStack(alignment: .leading, spacing: 2) {
                    layerHeader(layer)
                    ForEach(Array(layer.fields.enumerated()), id: \.offset) { _, decodedField in
                        fieldRow(decodedField)
                    }
                    if !layer.children.isEmpty {
                        DecodedLayerTree(
                            layers: layer.children, selectedRange: selectedRange, onSelect: onSelect,
                            depth: depth + 1
                        )
                        .padding(.leading, 14)
                    }
                }
            }
        }
    }

    // MARK: Private

    private func layerHeader(_ layer: DecodedLayer) -> some View {
        HStack(spacing: 6) {
            Image(systemName: "chevron.down").font(.system(size: Theme.Icon.small)).foregroundStyle(.secondary)
            Text(layer.title).font(Theme.Typography.bodyMedium)
                .foregroundStyle(Theme.color(for: layer.proto))
            if !layer.summary.isEmpty {
                Text(layer.summary).font(Theme.Typography.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 1).padding(.horizontal, 4)
        .background(rowBackground(layer.byteRange), in: RoundedRectangle(cornerRadius: 4))
        .contentShape(Rectangle())
        // Tap still selects the byte range for the hex pane; the context menu is
        // an additive right-click affordance and leaves that behavior untouched.
        .onTapGesture { onSelect(layer.byteRange) }
        .contextMenu {
            Button("Copy Layer Summary", systemImage: "doc.on.doc") {
                copy(DecodedClipboardText.layerSummary(layer))
            }
        }
    }

    private func fieldRow(_ field: DecodedField) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text(field.name).font(Theme.Typography.caption).foregroundStyle(.secondary)
                .frame(width: 96, alignment: .leading)
            Text(field.value).font(Theme.Typography.monoSmall)
            Spacer(minLength: 0)
        }
        .padding(.leading, 15).padding(.trailing, 4).padding(.vertical, 1)
        .background(rowBackground(field.byteRange), in: RoundedRectangle(cornerRadius: 4))
        .contentShape(Rectangle())
        .onTapGesture { onSelect(field.byteRange) }
        .contextMenu {
            Button("Copy Value", systemImage: "doc.on.doc") {
                copy(DecodedClipboardText.value(field))
            }
            Button("Copy Field Name", systemImage: "textformat") {
                copy(DecodedClipboardText.name(field))
            }
            Button("Copy \u{201C}Name: Value\u{201D}", systemImage: "text.append") {
                copy(DecodedClipboardText.nameValue(field))
            }
        }
    }

    private func rowBackground(_ range: Range<Int>?) -> Color {
        guard let range, range == selectedRange else {
            return .clear
        }
        return Color.accentColor.opacity(0.18)
    }

    /// The only side effect of the copy actions: the text formatting itself lives
    /// in the pure ``DecodedClipboardText`` so it stays independently testable.
    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

// MARK: - HexDumpView

/// A read-only hex + ASCII dump (offset · 16 bytes · ASCII), Wireshark-style,
/// over the representative packet's real captured bytes. Bytes inside `highlight`
/// are tinted to mirror the field selected in the decode tree.
private struct HexDumpView: View {
    // MARK: Internal

    let bytes: [UInt8]
    var highlight: Range<Int>?

    var body: some View {
        // One Text(AttributedString) per row (not ~32 views) — keeps the hex pane
        // light enough to stay smooth while a capture is updating.
        VStack(alignment: .leading, spacing: 2) {
            ForEach(rowStarts, id: \.self) { start in
                Text(row(start: start))
                    .font(Theme.Typography.monoSmall)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .textSelection(.enabled)
    }

    // MARK: Private

    private var rowStarts: [Int] {
        Array(stride(from: 0, to: bytes.count, by: 16))
    }

    private func row(start: Int) -> AttributedString {
        var line = attributed(String(format: "%04X   ", start), color: .secondary)
        for col in 0 ..< 16 {
            let index = start + col
            if index < bytes.count {
                line += attributed(String(format: "%02X ", bytes[index]), highlighted: isHighlighted(index))
            } else {
                line += attributed("   ")
            }
            if col == 7 {
                line += attributed(" ")
            }
        }
        line += attributed("  ")
        for col in 0 ..< 16 {
            let index = start + col
            if index < bytes.count {
                line += attributed(
                    String(asciiChar(bytes[index])), color: .secondary, highlighted: isHighlighted(index)
                )
            } else {
                line += attributed(" ")
            }
        }
        return line
    }

    private func attributed(_ string: String, color: Color? = nil, highlighted: Bool = false) -> AttributedString {
        var piece = AttributedString(string)
        if let color {
            piece.foregroundColor = color
        }
        if highlighted {
            piece.backgroundColor = Color.accentColor.opacity(0.35)
        }
        return piece
    }

    private func isHighlighted(_ index: Int) -> Bool {
        guard let highlight else {
            return false
        }
        return highlight.contains(index)
    }

    private func asciiChar(_ byte: UInt8) -> Character {
        byte >= 0x20 && byte < 0x7F ? Character(UnicodeScalar(byte)) : "."
    }
}
