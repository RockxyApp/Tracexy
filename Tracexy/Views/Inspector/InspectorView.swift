import AppKit
import SwiftUI

// MARK: - InspectorView

struct InspectorView: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var allowsDetaching = true

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
            if let session {
                inspectorFooter(session: session, activeTab: activeTab)
            }
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

    /// A session duration, or "Unknown" when the capture file left one of its
    /// frames untimed. Never a formatted `0 s`, which would read as a measurement.
    static func durationLabel(_ duration: TimeInterval?) -> String {
        guard let duration else {
            return "Unknown"
        }
        return String(format: "%.3f s", duration)
    }

    // MARK: Private

    @State private var fieldQuery = ""
    @State private var selectedRange: Range<Int>?
    /// Bumped when a click in the bytes picks a field, so the tree scrolls to it
    /// (a click in the tree itself leaves the tree where it is).
    @State private var byteRevealToken = 0
    @State private var hoveredByte: Int?
    /// Decode-tree layers folded shut, by title, for the whole inspector.
    @State private var collapsedLayers: Set<String> = []
    /// The decode tree takes the arrow keys once a row in it is clicked.
    @FocusState private var isLayerTreeFocused: Bool
    @Environment(\.openWindow) private var openWindow

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

    /// The bytes panes' Show as, kept per Project.
    private var dumpStyleBinding: Binding<ByteDumpStyle> {
        Binding(
            get: { coordinator.packetDetailOptions.byteDumpStyle },
            set: { coordinator.packetDetailOptions.byteDumpStyle = $0 }
        )
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
                    .accessibilityIdentifier("evidence.citedFrameLoaded")
                Text("\(evidence.bytes.count.formatted()) bytes captured")
                    .foregroundStyle(.secondary)
            case let .failed(message):
                Text(message)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: Theme.Metrics.spacingM)
            Button("Clear Citation") {
                coordinator.clearCitedFrameAndReturn()
            }
            .controlSize(.small)
            .help("Clear this citation and return to the facet it interrupted")
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

    private var footerDivider: some View {
        Divider()
            .frame(height: 18)
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
        VStack(spacing: Theme.Glass.functionalBarVerticalInset) {
            sessionIdentityBar(session)
                .tracexyGlassEffect(
                    in: RoundedRectangle(
                        cornerRadius: Theme.Glass.functionalBarCornerRadius,
                        style: .continuous
                    )
                )
            InspectorFacetBar(
                workspace: workspace,
                visibleTabs: visibleTabs,
                activeTab: activeTab
            ) {
                layerFilterControl
            }
            .tracexyContentSurface(
                in: RoundedRectangle(
                    cornerRadius: Theme.Metrics.cornerRadius,
                    style: .continuous
                )
            )
            if activeTab != .evidence, citedFrameStateIsActive {
                citedFrameScopeRow
                    .clipShape(RoundedRectangle(cornerRadius: Theme.Metrics.cornerRadius, style: .continuous))
            }
        }
        .padding(.horizontal, Theme.Glass.functionalBarHorizontalInset)
        .padding(.vertical, Theme.Glass.functionalBarVerticalInset)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .windowBackgroundColor))
        .overlay(alignment: .bottom) { Divider() }
    }

    /// A protocol-neutral selected-session identity bar. It describes only
    /// identity Tracexy actually observed: health, protocol, process/host and
    /// endpoints. A URL is never synthesized for DNS, TLS or transport sessions.
    private func sessionIdentityBar(_ session: SessionSummary) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            ViewThatFits(in: .horizontal) {
                sessionIdentityContent(session, showsEndpoints: true)
                sessionIdentityContent(session, showsEndpoints: false)
            }
            .layoutPriority(1)

            Spacer(minLength: Theme.Metrics.spacingM)

            activityScopeBadge(session)

            if allowsDetaching {
                Button {
                    openWindow(id: TracexyApp.sessionInspectorWindowID)
                } label: {
                    Image(systemName: "macwindow.on.rectangle")
                        .font(.system(size: Theme.Icon.large))
                }
                .buttonStyle(.borderless)
                .help("Open Session Inspector in a new window")
                .accessibilityLabel("Open Session Inspector in a new window")
            }
        }
        .padding(.horizontal, Theme.Metrics.spacingM)
        .padding(.vertical, 7)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func sessionIdentityContent(_ session: SessionSummary, showsEndpoints: Bool) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Label(session.status.label, systemImage: session.status.systemImage)
                .font(Theme.Typography.badge)
                .padding(.horizontal, 7)
                .padding(.vertical, 3)
                .tracexyChipStyle(tint: Theme.color(for: session.status), isActive: true)

            Text(session.primaryProtocol.label)
                .font(Theme.Typography.badge)
                .padding(.horizontal, 7)
                .padding(.vertical, 3)
                .tracexyChipStyle(tint: Theme.color(for: session.primaryProtocol), isActive: true)

            if let process = session.processName {
                Text(process)
                    .font(Theme.Typography.bodyMedium)
                    .lineLimit(1)
                Image(systemName: "arrow.right")
                    .font(.system(size: Theme.Icon.small))
                    .foregroundStyle(.secondary)
            }

            Text(selectedIdentity(for: session))
                .font(Theme.Typography.mono)
                .foregroundStyle(Color.cyan)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)

            if showsEndpoints {
                Spacer(minLength: Theme.Metrics.spacingM)
                Text("\(session.sourceEndpoint) → \(session.destinationEndpoint)")
                    .font(Theme.Typography.monoSmall)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
            }
        }
        .fixedSize(horizontal: true, vertical: false)
    }

    /// The evidence pane owns a small, read-only footer of its own. Logical
    /// regions are divided inside one rounded surface; no nested glass cards are
    /// introduced and no capture/filter command moves into this status area.
    private func inspectorFooter(session: SessionSummary, activeTab: InspectorTab) -> some View {
        WorkspaceFooterBar(surface: .workspace) {
            HStack(spacing: Theme.Metrics.spacingM) {
                Label("Selected", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(Color.accentColor)
                    .font(Theme.Typography.chromeAction)
                footerDivider
                Text(activeTab.title)
                    .font(Theme.Typography.chromeAction)
                footerDivider
                Text(session.protocolStack.map(\.label).joined(separator: " › "))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                Spacer(minLength: Theme.Metrics.spacingL)
                Text(
                    "\(ByteUnits.string(Int64(session.totalBytes))) total"
                )
                .font(Theme.Typography.chromeSecondary)
                .foregroundStyle(.secondary)
                footerDivider
                Text(Self.durationLabel(session.duration))
                    .font(Theme.Typography.chromeSecondary.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, Theme.Metrics.spacingL)
        }
    }

    @ViewBuilder
    private func activityScopeBadge(_ session: SessionSummary) -> some View {
        let activity = coordinator.activity(containing: session)
        if let activity, activity.sessions.count > 1 {
            Label("Whole action", systemImage: "rectangle.3.group")
                .font(Theme.Typography.microMedium)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
                .padding(.horizontal, 7)
                .padding(.vertical, 2)
                .tracexyChipStyle(tint: .accentColor, isActive: true)
                .help("This inspector summarizes all \(activity.sessions.count) sessions in the correlated action")
        }
    }

    /// Wireshark-style linked view: a selectable decode tree paired with a hex pane,
    /// where selecting a field/layer highlights its bytes. The evidence inspector
    /// is the wide bottom dock, so the tree and hex sit **side by side** and use
    /// the horizontal space deliberately.
    @ViewBuilder
    private func layersInspector(_ session: SessionSummary) -> some View {
        let decoded = inspectedLayers(session)
        // An installed locator (none by default) adds where the addresses are.
        let sourceLayers = decoded.isEmpty
            ? decoded : decoded + (AddressLocators.installed?.inspectorLayers(for: session) ?? [])
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
            .environment(\.packetTextZoom, coordinator.packetDetailOptions.textZoom)
            .environment(\.byteDumpStyle, coordinator.packetDetailOptions.byteDumpStyle)
        }
    }

    private func layerTree(_ layers: [DecodedLayer]) -> some View {
        ScrollViewReader { proxy in
            ScrollView {
                DecodedLayerTree(
                    layers: layers, selectedRange: selectedRange, collapsed: $collapsedLayers,
                    onSelect: { range in
                        isLayerTreeFocused = true
                        selectedRange = (range == selectedRange) ? nil : range
                    },
                    onFilter: { coordinator.filterSessions(with: $0, combination: $1, applying: $2) },
                    columnOptions: coordinator.packetDetailOptions
                )
                .padding(Theme.Metrics.spacingL)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .focusable()
            .focused($isLayerTreeFocused)
            .focusEffectDisabled()
            .onKeyPress(keys: [.upArrow, .downArrow, .leftArrow, .rightArrow]) { press in
                navigate(press, layers: layers)
            }
            .onChange(of: byteRevealToken) {
                if let selectedRange {
                    proxy.scrollTo(DecodedLayerTree.rowID(selectedRange), anchor: .center)
                }
            }
        }
    }

    @ViewBuilder
    private func hexPane(_ session: SessionSummary) -> some View {
        let bytes = evidenceBytes(for: session)
        if !bytes.isEmpty {
            ScrollView {
                PacketBytesPane(
                    bytes: bytes, highlight: selectedRange, onShowBytes: { showBytes($0, of: session) },
                    layers: inspectedLayers(session),
                    onSelectRange: { range in
                        // Unfold the layers above the picked field so the tree can show it.
                        if let owner = DecodedByteMap.owner(ofByte: range.lowerBound, in: inspectedLayers(session)) {
                            collapsedLayers.subtract(owner.path)
                        }
                        selectedRange = range
                        byteRevealToken &+= 1
                    },
                    onHoverByte: { hoveredByte = $0 },
                    dumpStyle: dumpStyleBinding
                )
                .padding(Theme.Metrics.spacingL)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .overlay(alignment: .bottom) {
                // Shown only while the pointer is on a byte, over the dump's bottom
                // edge, so it takes no room from the rows and stays in view as they scroll.
                if let hoveredByte {
                    Text(DecodedByteMap.pointerText(
                        forByte: hoveredByte, in: inspectedLayers(session)
                    ))
                    .font(Theme.Typography.caption)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, Theme.Metrics.spacingL)
                    .padding(.vertical, Theme.Metrics.spacingS)
                    .background(.bar)
                    .allowsHitTesting(false)
                }
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

    @ViewBuilder
    private func content(tab: InspectorTab, session: SessionSummary) -> some View {
        switch tab {
        case .layers: EmptyView() // routed to layersInspector (linked tree + hex)
        case .timeline: timeline(session)
        case .evidence: sessionEvidence(session)
        case .ladder:
            if let selection = selectedEvidence {
                SessionLadderView(ladder: SessionLadder.build(selection)) { provenance in
                    coordinator.inspectCitedFrame(sessionID: session.id, provenance: provenance)
                    selectedRange = nil
                }
            } else {
                placeholder("No retained evidence to draw for this session.")
            }
        case .frames: SessionFramesFacetView(
                coordinator: coordinator,
                session: session,
                selectedOrdinal: selectedCitedFrame?.provenance.ordinal.rawValue
            )
        case .stream: FollowConversationView(coordinator: coordinator, session: session)
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
                // The coordinator owns the move to Layers and remembers the facet
                // it interrupted; the view only clears its own byte selection.
                inspectFrame: { provenance in
                    coordinator.inspectCitedFrame(sessionID: session.id, provenance: provenance)
                    selectedRange = nil
                }
            )
        } else if coordinator.evidenceProjection.task != nil {
            ProgressView("Preparing retained evidence…")
        } else {
            placeholder("No retained connection or direct-frame TLS evidence is available for this session.")
        }
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
            PacketBytesPane(bytes: bytes, onShowBytes: { showBytes($0, of: session) }, dumpStyle: dumpStyleBinding)
                .environment(\.packetTextZoom, coordinator.packetDetailOptions.textZoom)
                .environment(\.byteDumpStyle, coordinator.packetDetailOptions.byteDumpStyle)
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
                field("Total Duration", Self.durationLabel(session.duration))
                timingBar(phases, compact: false)
                if session.hasUnknownTiming {
                    placeholder(
                        "This capture file records no time for some of this session’s frames, "
                            + "so its duration and latency can’t be measured."
                    )
                } else if session.latencyMilliseconds == nil {
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

    /// ↑ ↓ ← → and ⌘← ⌘→ in the decode tree (``DecodeTreeNavigation``).
    private func navigate(_ press: KeyPress, layers: [DecodedLayer]) -> KeyPress.Result {
        let command = press.modifiers.contains(.command)
        let key: DecodeTreeNavigation.Key = switch press.key {
        case .upArrow: .up
        case .downArrow: .down
        case .leftArrow: command ? .collapseAll : .left
        default: command ? .expandAll : .right
        }
        guard let outcome = DecodeTreeNavigation.press(
            key, layers: layers, selection: selectedRange, collapsed: collapsedLayers
        ) else {
            return .ignored
        }
        collapsedLayers = outcome.collapsed
        selectedRange = outcome.selection
        byteRevealToken &+= 1
        return .handled
    }

    /// The frame's decode tree as shown: the cited frame's, else the session's
    /// representative packet's, with checksum notes when View ▸ Validate Checksums is on.
    private func inspectedLayers(_ session: SessionSummary) -> [DecodedLayer] {
        let layers = selectedCitedFrame?.layers ?? session.decodedLayers
        guard coordinator.packetDetailOptions.validateChecksums else {
            return layers
        }
        return ChecksumValidation.annotate(layers, bytes: evidenceBytes(for: session))
    }

    private func selectedIdentity(for session: SessionSummary) -> String {
        if let query = session.dnsQuery, !query.isEmpty {
            return query
        }
        if let sni = session.sni, !sni.isEmpty {
            return sni
        }
        return session.host
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
        // Unknown timing has no measured phase or zero-duration legend.
        guard let duration = session.duration else {
            return []
        }
        let totalMs = max(duration * 1_000, 0)
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
        var tabs = InspectorTab.visibleTabs(
            for: session, hasSessionEvidence: hasEvidence, hasFrameSource: coordinator.hasSessionFrameSource
        )
        if citedFrameStateIsActive, !tabs.contains(.layers), let evidenceIndex = tabs.firstIndex(of: .evidence) {
            tabs.insert(.layers, at: tabs.index(after: evidenceIndex))
        }
        return tabs
    }

    /// Show Packet Bytes on a frame's (or a selected field's) bytes.
    private func showBytes(_ bytes: [UInt8], of session: SessionSummary) {
        let frame = selectedCitedFrame.map { String(localized: "Frame \($0.provenance.ordinal.rawValue.formatted())") }
        coordinator.packetBytesInspection.show(PacketBytesSubject(
            title: [frame, session.host].compactMap(\.self).joined(separator: " — "),
            bytes: bytes
        ))
        openWindow(id: TracexyApp.packetBytesWindowID)
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
            if hasKnownSpan {
                VStack(spacing: 3) {
                    ForEach(activity.sessions) { member in
                        row(member)
                    }
                }
                .background(alignment: .leading) { gridlines }
                axis
            }
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

    /// The plotted span. An action whose members include unknown timing has no span
    /// to divide by; the tiny floor keeps the geometry total rather than trapping,
    /// and ``hasKnownSpan`` is what decides whether the chart is shown at all.
    private var spanMilliseconds: Double {
        max((activity.duration ?? 0) * 1_000, 0.0001)
    }

    /// Whether every member of the action is timed, so a correlated timeline is a
    /// truthful drawing rather than one composed from partial instants.
    private var hasKnownSpan: Bool {
        activity.duration != nil && activity.startTime != nil
    }

    /// "First byte after 142 ms, complete after 296 ms" — the two numbers the action is
    /// judged on. The first is stated only when something measured a latency.
    private var headerDetail: String {
        guard hasKnownSpan else {
            return "Duration unknown — some frames have no capture time"
        }
        guard let ttfb = firstByteMilliseconds else {
            return String(localized: "Complete after \(Self.ms(spanMilliseconds))")
        }
        return String(localized: "First byte after \(Self.ms(ttfb)), complete after \(Self.ms(spanMilliseconds))")
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
        guard hasKnownSpan, let ttfb = firstByteMilliseconds, ttfb > 0 else {
            return nil
        }
        guard let worst = activity.sessions.max(by: { ($0.duration ?? 0) < ($1.duration ?? 0) }),
              let worstDuration = worst.duration else
        {
            return nil
        }
        let share = worstDuration * 1_000 / ttfb
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
                // Both coordinates come from real instants or they are not drawn:
                // an unknown member start/duration collapses to a zero-offset,
                // minimum-width bar labelled "—" rather than a plotted guess.
                let offset = Self.offsetFraction(
                    member: member, origin: activity.startTime, spanMilliseconds: spanMilliseconds
                )
                let fraction = (member.duration ?? 0) * 1_000 / spanMilliseconds
                let width = max(geo.size.width * fraction, 3)
                let label = member.duration.map { Self.ms($0 * 1_000) } ?? "—"
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

    /// Where a member's bar starts, as a fraction of the action's span. `0` when
    /// either the member's start or the action's origin is unknown — no instant is
    /// substituted to place it somewhere plausible.
    private static func offsetFraction(
        member: SessionSummary,
        origin: Date?,
        spanMilliseconds: Double
    )
        -> Double
    {
        guard let start = member.startTime, let origin else {
            return 0
        }
        return start.timeIntervalSince(origin) * 1_000 / spanMilliseconds
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
