import SwiftUI

// MARK: - SessionFramesFacetView

/// The Frames facet of the bottom evidence inspector: every frame of the
/// selected session, listed in capture order from a bounded on-demand rescan of
/// the stable source. A native `Table` (sortable headers, alternating rows,
/// ↑/↓ selection) whose row activation loads that exact frame into Layers/Hex
/// through the guarded cited-frame path. The list retains references only —
/// never bytes — and says when it is a bounded prefix of the session.
struct SessionFramesFacetView: View {
    // MARK: Internal

    let coordinator: MainContentCoordinator
    let session: SessionSummary
    let selectedOrdinal: UInt64?
    let onFrameTimeSelection: (FrameTimeReference?) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            header
            if coordinator.isLoadingSessionFrames {
                loading
            } else if let error = coordinator.sessionFramesError {
                emptyState(error)
            } else if let result = coordinator.sessionFramesResult, result.sessionID == session.id {
                if result.frames.isEmpty {
                    emptyState("No frames of this session were found in the capture source.")
                } else {
                    table(result)
                    footer(result)
                }
            } else {
                emptyState(coordinator
                    .sessionFramesUnavailableReason ?? "List the frames of this session from the capture source.")
            }
        }
        .onAppear { coordinator.loadSelectedSessionFrames() }
        .onChange(of: session.id) { _, _ in coordinator.loadSelectedSessionFrames() }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Frames")
        .accessibilityIdentifier("session-frames-facet")
    }

    static func flagsText(_ flags: TCPFlags) -> String {
        let names: [(TCPFlags, String)] = [
            (.syn, "SYN"), (.ack, "ACK"), (.fin, "FIN"), (.rst, "RST"),
            (.psh, "PSH"), (.urg, "URG"), (.ece, "ECE"), (.cwr, "CWR"),
        ]
        return names.filter { flags.contains($0.0) }.map(\.1).joined(separator: ",")
    }

    // MARK: Private

    @State private var selection: UInt64?
    @State private var sortOrder: [KeyPathComparator<SessionFrameReference>] = [KeyPathComparator(\.ordinal)]

    /// Interface names by pcapng interface id, only when the file declares more
    /// than one — a single interface (or a classic pcap) adds nothing per row.
    private var interfaceNames: [Int: String]? {
        guard let properties = coordinator.savedCaptureProperties,
              case .pcapng = properties.container,
              properties.interfaceCount > 1 else
        {
            return nil
        }
        return properties.allInterfaces.reduce(into: [:]) { names, interface in
            names[interface.id.interfaceID] = names[interface.id.interfaceID] ?? interface.displayName
        }
    }

    private var summaryColumn: some TableColumnContent<SessionFrameReference, Never> {
        TableColumn("Summary") { frame in
            HStack(spacing: Theme.Metrics.spacingS) {
                Text(frame.summary).lineLimit(1).truncationMode(.tail)
                if frame.hasComment {
                    Image(systemName: "text.bubble")
                        .foregroundStyle(.secondary)
                        .help("This frame carries a comment in the capture file (shown in Get Info)")
                        .accessibilityLabel("Has comment")
                }
            }
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: Theme.Metrics.spacingM) {
            VStack(alignment: .leading, spacing: 3) {
                Text("Frames of This Session")
                    .font(Theme.Typography.bodyEmphasis)
                Text("Rescanned on demand from the local capture source. Select a row to load that exact frame.")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
                if coordinator.sessionTimeDisplay.referenceLimitReached
                    || coordinator.sessionTimeDisplay.frameTimeReferences.count
                    >= SessionTimeDisplay.maximumTimeReferences
                {
                    Label(
                        "Time reference limit reached (\(SessionTimeDisplay.maximumTimeReferences)). Remove one to add another.",
                        systemImage: "exclamationmark.triangle.fill"
                    )
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.orange)
                    .accessibilityLabel("Time reference limit reached. Remove one reference to add another.")
                }
            }
            Spacer(minLength: Theme.Metrics.spacingM)
            if coordinator.isLoadingSessionFrames {
                Button("Cancel") { coordinator.cancelSessionFrames(clearResult: false) }
                    .controlSize(.small)
            } else {
                Button("Rescan") { coordinator.loadSelectedSessionFrames(force: true) }
                    .controlSize(.small)
                    .disabled(coordinator.sessionFramesUnavailableReason != nil)
            }
        }
    }

    private var loading: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            if let fraction = coordinator.sessionFramesFraction {
                ProgressView(value: fraction)
                    .accessibilityLabel("Listing frames")
                    .accessibilityValue(fraction.formatted(.percent.precision(.fractionLength(0))))
            } else {
                ProgressView().controlSize(.small)
            }
            if let progress = coordinator.sessionFramesProgress {
                Text("Scanned \(progress.bytesConsumed.formatted()) of \(progress.totalBytes.formatted()) bytes")
                    .font(Theme.Typography.monoSmall)
                    .foregroundStyle(.secondary)
            } else {
                Text("Preparing stable local source…")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func emptyState(_ message: String) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            Text(message)
                .font(Theme.Typography.body)
                .foregroundStyle(.secondary)
            Button("List Frames") { coordinator.loadSelectedSessionFrames(force: true) }
                .controlSize(.small)
                .disabled(coordinator.sessionFramesUnavailableReason != nil)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func table(_ result: SessionFramesResult) -> some View {
        let previousDisplayedFrames = coordinator.sessionTimeDisplay.frameFormat == .sincePreviousFrame
            ? Self.previousDisplayedFrames(in: result.frames) : [:]
        let sessionStart = result.frames.min { $0.ordinal < $1.ordinal }?.provenance.timestamp
        let frameReferences = coordinator.sessionTimeDisplay.references(forSession: session.id)
        return Group {
            if let interfaceNames {
                Table(result.frames, selection: $selection, sortOrder: $sortOrder) {
                    leadingColumns(
                        previousDisplayedFrames: previousDisplayedFrames,
                        sessionStart: sessionStart,
                        frameReferences: frameReferences
                    )
                    TableColumn("Interface", value: \SessionFrameReference.interfaceID) { frame in
                        Text(interfaceNames[frame.interfaceID] ?? "Interface \(frame.interfaceID)")
                            .lineLimit(1)
                            .truncationMode(.tail)
                    }
                    .width(min: 80, ideal: 110)
                    summaryColumn
                }
            } else {
                Table(result.frames, selection: $selection, sortOrder: $sortOrder) {
                    leadingColumns(
                        previousDisplayedFrames: previousDisplayedFrames,
                        sessionStart: sessionStart,
                        frameReferences: frameReferences
                    )
                    summaryColumn
                }
            }
        }
        .alternatingRowBackgrounds()
        .contextMenu(forSelectionType: UInt64.self) { ordinals in
            if let ordinal = ordinals.first, let frame = result.frames.first(where: { $0.ordinal == ordinal }),
               let timestamp = frame.provenance.timestamp
            {
                let reference = FrameTimeReference(sessionID: session.id, ordinal: ordinal, timestamp: timestamp)
                if coordinator.sessionTimeDisplay.isSessionTimeReference(sessionID: session.id, ordinal: ordinal) {
                    Button("Clear Time Reference") {
                        coordinator.sessionTimeDisplay.toggleTimeReference(reference)
                    }
                } else if coordinator.sessionTimeDisplay.isCaptureTimeReference(ordinal: ordinal) {
                    Button("Clear Capture Time Reference") {
                        coordinator.sessionTimeDisplay.toggleTimeReference(
                            .init(sessionID: nil, ordinal: ordinal, timestamp: timestamp)
                        )
                        coordinator.allFrames.removeCaptureTimeReferenceRow(ordinal)
                    }
                } else {
                    Button("Set as Time Reference") {
                        coordinator.sessionTimeDisplay.toggleTimeReference(reference)
                    }
                    .disabled(coordinator.sessionTimeDisplay.frameTimeReferences.count
                        >= SessionTimeDisplay.maximumTimeReferences)
                    .help("Up to \(SessionTimeDisplay.maximumTimeReferences) temporary references per capture")
                }
            }
        }
        .onChange(of: selection) { _, ordinal in
            let frame = ordinal.flatMap { ordinal in result.frames.first { $0.ordinal == ordinal } }
            onFrameTimeSelection(frame.flatMap { frame in
                frame.provenance.timestamp.map {
                    FrameTimeReference(sessionID: session.id, ordinal: frame.ordinal, timestamp: $0)
                }
            })
            // Re-showing the already cited frame's row (on return to this facet) is
            // not a new choice: loading it again would bounce the inspector straight
            // back to Layers and make this facet unreachable while a citation is up.
            guard let ordinal, ordinal != selectedOrdinal, let frame else {
                return
            }
            coordinator.inspectSessionFrame(frame)
        }
        .onAppear {
            if let selectedOrdinal, result.frames.contains(where: { $0.ordinal == selectedOrdinal }) {
                selection = selectedOrdinal
            }
        }
        .frame(minHeight: 160)
        .accessibilityIdentifier("session-frames-table")
    }

    private func footer(_ result: SessionFramesResult) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            if result.omittedFrameCount > 0 {
                Label(
                    "Showing the first \(result.frames.count.formatted()) of \(result.matchedFrameCount.formatted()) frames",
                    systemImage: "exclamationmark.circle"
                )
            } else {
                Text(
                    "\(result.matchedFrameCount.formatted()) frames of \(result.scannedFrameCount.formatted()) scanned"
                )
            }
            if case .incompleteTruncatedTail = result.completeness {
                Label("Capture ends mid-record", systemImage: "scissors")
            }
            Spacer(minLength: 0)
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .accessibilityIdentifier("session-frames-footer")
    }

    private static func lengthText(_ frame: SessionFrameReference) -> String {
        let original = frame.provenance.originalLength
        let captured = frame.provenance.capturedLength
        return captured < original ? "\(captured.formatted())/\(original.formatted())" : original.formatted()
    }

    private static func directionText(_ direction: SessionFrameDirection) -> String {
        switch direction {
        case .clientToServer: "Client → Server"
        case .serverToClient: "Server → Client"
        case .unknown: "Unknown"
        }
    }

    private static func directionSymbol(_ direction: SessionFrameDirection) -> String {
        switch direction {
        case .clientToServer: "arrow.up.right"
        case .serverToClient: "arrow.down.left"
        case .unknown: "questionmark"
        }
    }

    private static func previousDisplayedFrames(
        in frames: [SessionFrameReference]
    )
        -> [UInt64: FrameTimePredecessor]
    {
        let ordered = frames.sorted { $0.ordinal < $1.ordinal }
        var result: [UInt64: FrameTimePredecessor] = [:]
        for (index, frame) in ordered.enumerated() {
            if index > 0 {
                result[frame.ordinal] = ordered[index - 1]
                    .provenance.timestamp.map(FrameTimePredecessor.timestamp) ?? .unknown
            } else {
                result[frame.ordinal] = FrameTimePredecessor.none
            }
        }
        return result
    }

    /// Column groups, not views: SwiftFormat rewrites `Group` inside a
    /// `@ViewBuilder` body, so the builder is named explicitly.
    @TableColumnBuilder<SessionFrameReference, KeyPathComparator<SessionFrameReference>>
    private func leadingColumns(
        previousDisplayedFrames: [UInt64: FrameTimePredecessor],
        sessionStart: Date?,
        frameReferences: [FrameTimeReference]
    )
        -> some TableColumnContent<
            SessionFrameReference,
            KeyPathComparator<SessionFrameReference>
        >
    {
        TableColumn("No.", value: \SessionFrameReference.ordinal) { frame in
            Text(frame.ordinal.formatted()).monospacedDigit()
        }
        .width(min: 56, ideal: 72)
        TableColumn(coordinator.sessionTimeDisplay.frameFormat.columnTitle) { frame in
            let time = timeText(
                frame, previousDisplayedFrames: previousDisplayedFrames,
                sessionStart: sessionStart, frameReferences: frameReferences
            )
            let isReference = coordinator.sessionTimeDisplay
                .isTimeReference(sessionID: session.id, ordinal: frame.ordinal)
            Text(time)
                .monospacedDigit()
                .accessibilityLabel(isReference ? "Time reference" : time)
                .fontWeight(isReference ? .semibold : .regular)
        }
        .width(min: 84, ideal: 110)
        TableColumn("Direction") { frame in
            Label(Self.directionText(frame.direction), systemImage: Self.directionSymbol(frame.direction))
                .labelStyle(.titleAndIcon)
        }
        .width(min: 90, ideal: 120)
        TableColumn("Length", value: \SessionFrameReference.provenance.originalLength) { frame in
            Text(Self.lengthText(frame)).monospacedDigit()
        }
        .width(min: 64, ideal: 88)
        TableColumn("Flags") { frame in
            Text(frame.tcpFlags.map(Self.flagsText) ?? "")
                .font(Theme.Typography.monoSmall)
        }
        .width(min: 70, ideal: 96)
    }

    private func timeText(
        _ frame: SessionFrameReference,
        previousDisplayedFrames: [UInt64: FrameTimePredecessor],
        sessionStart: Date?,
        frameReferences: [FrameTimeReference]
    )
        -> String
    {
        FrameTimeFormat.text(
            coordinator.sessionTimeDisplay.frameFormat,
            timestamp: frame.provenance.timestamp,
            ordinal: frame.ordinal,
            previous: previousDisplayedFrames[frame.ordinal] ?? .unknown,
            previousCaptured: frame.previousCapturedFrame,
            sessionStart: sessionStart,
            captureStart: coordinator.trafficTimeline.captureStartFrame,
            precision: coordinator.sessionTimeDisplay.framePrecision,
            references: frameReferences,
            sessionID: session.id
        )
    }
}
