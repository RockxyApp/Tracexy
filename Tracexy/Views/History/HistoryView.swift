import SwiftUI

// MARK: - HistoryCaptureSurfaceState

/// Pure capture-list state resolution. Loading, empty, failure and unavailable
/// are deliberately disjoint so the view never infers History state from the
/// current live capture's sessions.
nonisolated enum HistoryCaptureSurfaceState: Equatable {
    case unavailable(String)
    case loading
    case failed(String)
    case empty
    case content

    // MARK: Internal

    static func resolve(
        availability: HistoryAvailability,
        captureCount: Int,
        unavailableReason: String?
    )
        -> HistoryCaptureSurfaceState
    {
        switch availability {
        case .unavailable:
            .unavailable(unavailableReason ?? "Local History storage could not be opened.")
        case .idle,
             .loading:
            .loading
        case let .failed(message):
            .failed(message)
        case .loaded:
            captureCount == 0 ? .empty : .content
        }
    }
}

// MARK: - HistorySessionSurfaceState

/// Pure state for the selected capture's session pane.
nonisolated enum HistorySessionSurfaceState: Equatable {
    case noSelection
    case loading
    case failed(String)
    case empty
    case content

    // MARK: Internal

    static func resolve(
        selectedCaptureID: UUID?,
        availability: HistoryAvailability,
        sessionCount: Int
    )
        -> HistorySessionSurfaceState
    {
        guard selectedCaptureID != nil else {
            return .noSelection
        }
        switch availability {
        case .idle,
             .loading:
            return .loading
        case let .failed(message):
            return .failed(message)
        case .unavailable:
            return .failed("Local History storage is unavailable.")
        case .loaded:
            return sessionCount == 0 ? .empty : .content
        }
    }
}

// MARK: - HistoryView

/// Local, terminal capture History. This surface reads only bounded neutral
/// records from `SessionStore`; it never borrows the active capture table,
/// throughput strip, inspector selection or raw evidence.
struct HistoryView: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        Group {
            if let historyError = coordinator.historyError,
               captureState == .content
            {
                VStack(spacing: 0) {
                    recoverableNotice(historyError)
                    captureContent
                }
            } else {
                captureContent
            }
        }
        .tracexyDenseScrollEdge()
        .tracexySafeAreaBar(edge: .top) { header }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .task {
            if case .idle = coordinator.historyAvailability {
                coordinator.refreshHistory()
            }
        }
        .onChange(of: coordinator.historyCaptures.map(\.id), initial: true) { _, ids in
            guard coordinator.selectedHistoryCaptureID == nil, let first = ids.first else {
                return
            }
            coordinator.selectHistoryCapture(first)
        }
        .confirmationDialog(
            "Clear all local History?",
            isPresented: $showsClearConfirmation,
            titleVisibility: .visible
        ) {
            Button("Clear History", role: .destructive) {
                coordinator.clearAllHistory()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "This removes every persisted History summary. Current capture data and saved capture files are unchanged."
            )
        }
    }

    // MARK: Private

    @State private var showsClearConfirmation = false

    private var captureState: HistoryCaptureSurfaceState {
        HistoryCaptureSurfaceState.resolve(
            availability: coordinator.historyAvailability,
            captureCount: coordinator.historyCaptures.count,
            unavailableReason: coordinator.historyError
        )
    }

    private var sessionState: HistorySessionSurfaceState {
        HistorySessionSurfaceState.resolve(
            selectedCaptureID: coordinator.selectedHistoryCaptureID,
            availability: coordinator.historySessionsAvailability,
            sessionCount: coordinator.historySessions.count
        )
    }

    private var captureSelection: Binding<UUID?> {
        Binding(
            get: { coordinator.selectedHistoryCaptureID },
            set: { coordinator.selectHistoryCapture($0) }
        )
    }

    private var header: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            VStack(alignment: .leading, spacing: 2) {
                Text("History")
                    .font(Theme.Typography.title)
                Text("Terminal capture summaries stored locally")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Refresh", systemImage: "arrow.clockwise") {
                coordinator.refreshHistory()
            }
            .help("Reload local History")
            Button("Clear…", systemImage: "trash", role: .destructive) {
                showsClearConfirmation = true
            }
            .disabled(coordinator.historyCaptures.isEmpty)
            .help("Clear all local History summaries")
        }
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    @ViewBuilder private var captureContent: some View {
        switch captureState {
        case let .unavailable(message):
            unavailableView(message)
        case .loading:
            loadingView("Loading History…")
        case let .failed(message):
            failureView(title: "Couldn’t Load History", message: message) {
                coordinator.retryHistory()
            }
        case .empty:
            ContentUnavailableView {
                Label("No Capture History", systemImage: "clock.arrow.circlepath")
            } description: {
                Text("Stop a live capture or open a saved capture to add a local summary here.")
            } actions: {
                Button("Refresh") { coordinator.refreshHistory() }
            }
        case .content:
            historySplit
        }
    }

    private var historySplit: some View {
        HSplitView {
            captureList
                .frame(minWidth: 250, idealWidth: 300, maxWidth: 380)
            sessionContent
                .frame(minWidth: 560, maxWidth: .infinity, maxHeight: .infinity)
        }
        // HSplitView hosts AppKit children that do not consume the safe-area bar
        // inset. Preserve the visual underlap while keeping the first/last data
        // rows reachable instead of hiding them under functional chrome.
        .tracexyChromeContentClearance(edge: .top, length: 12)
        .tracexyChromeContentClearance(
            edge: .bottom,
            length: Theme.Metrics.footerBarHeight + Theme.Glass.functionalBarVerticalInset * 2
        )
    }

    private var captureList: some View {
        VStack(spacing: 0) {
            HStack {
                Text("CAPTURES")
                    .font(Theme.Typography.sectionHeader)
                    .foregroundStyle(.secondary)
                Spacer()
                Text(loadedCount(coordinator.historyCaptures.count, hasMore: coordinator.historyCaptureCursor != nil))
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, Theme.Metrics.spacingM)
            .padding(.vertical, Theme.Metrics.spacingS)

            List(selection: captureSelection) {
                ForEach(coordinator.historyCaptures) { capture in
                    HistoryCaptureRow(capture: capture)
                        .tag(capture.id)
                }
                if coordinator.historyCaptureCursor != nil {
                    Button("Load More", systemImage: "arrow.down.circle") {
                        coordinator.loadMoreHistoryCaptures()
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(Color.accentColor)
                }
            }
            .listStyle(.inset)
            .scrollContentBackground(.hidden)
        }
        .background(Color(nsColor: .controlBackgroundColor))
    }

    @ViewBuilder private var sessionContent: some View {
        switch sessionState {
        case .noSelection:
            ContentUnavailableView {
                Label("Select a Capture", systemImage: "sidebar.left")
            } description: {
                Text("Choose a local History entry to inspect its persisted sessions.")
            }
        case .loading:
            loadingView("Loading Sessions…")
        case let .failed(message):
            failureView(title: "Couldn’t Load Sessions", message: message) {
                if let captureID = coordinator.selectedHistoryCaptureID {
                    coordinator.selectHistoryCapture(captureID)
                }
            }
        case .empty:
            ContentUnavailableView {
                Label("No Sessions", systemImage: "rectangle.stack")
            } description: {
                Text("This capture ended without a persisted session summary.")
            }
        case .content:
            sessionTable
        }
    }

    private var sessionTable: some View {
        VStack(spacing: 0) {
            selectedCaptureHeader
            Divider()
            Table(coordinator.historySessions) {
                TableColumn("Time") { session in
                    Text(date(session.startTime), format: .dateTime.hour().minute().second())
                        .font(Theme.Typography.caption.monospacedDigit())
                }
                .width(min: 76, ideal: 88)
                TableColumn("Process") { session in
                    Text(session.processName ?? "—").lineLimit(1)
                }
                .width(min: 86, ideal: 120)
                TableColumn("Host") { session in
                    Text(session.host).lineLimit(1)
                }
                .width(min: 130, ideal: 200)
                TableColumn("Stack") { session in
                    Text(session.protocols.map { $0.uppercased() }.joined(separator: " · "))
                        .font(Theme.Typography.caption)
                        .lineLimit(1)
                }
                .width(min: 100, ideal: 150)
                TableColumn("Status") { session in
                    Label(statusTitle(session.status), systemImage: statusSymbol(session.status))
                        .foregroundStyle(statusColor(session.status))
                        .labelStyle(.titleAndIcon)
                }
                .width(min: 78, ideal: 90)
                TableColumn("Duration") { session in
                    Text(duration(session.duration))
                        .font(Theme.Typography.caption.monospacedDigit())
                }
                .width(min: 72, ideal: 82)
                TableColumn("Bytes") { session in
                    Text(bytes(session.bytesUp + session.bytesDown))
                        .font(Theme.Typography.caption.monospacedDigit())
                }
                .width(min: 74, ideal: 92)
            }
            if coordinator.historySessionCursor != nil {
                Divider()
                Button("Load More Sessions", systemImage: "arrow.down.circle") {
                    coordinator.loadMoreHistorySessions()
                }
                .buttonStyle(.plain)
                .foregroundStyle(Color.accentColor)
                .padding(Theme.Metrics.spacingS)
            }
        }
    }

    private var selectedCaptureHeader: some View {
        let selected = coordinator.historyCaptures.first { $0.id == coordinator.selectedHistoryCaptureID }
        return HStack(spacing: Theme.Metrics.spacingS) {
            Image(systemName: selected?.record.sourceKind == .live ? "dot.radiowaves.left.and.right" : "doc")
                .foregroundStyle(Color.accentColor)
            Text(selected.map { captureDate($0.record) } ?? "Capture")
                .font(Theme.Typography.bodyEmphasis)
            if selected?.record.completeness == .incomplete {
                Label("Incomplete", systemImage: "exclamationmark.triangle.fill")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.orange)
            }
            Spacer()
            Text(loadedCount(coordinator.historySessions.count, hasMore: coordinator.historySessionCursor != nil))
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, Theme.Metrics.spacingM)
        .frame(height: 38)
        .tracexyGlassEffect(
            in: RoundedRectangle(
                cornerRadius: Theme.Glass.functionalBarCornerRadius,
                style: .continuous
            )
        )
        .padding(.horizontal, Theme.Glass.functionalBarHorizontalInset)
        .padding(.vertical, Theme.Glass.functionalBarVerticalInset)
    }

    private func unavailableView(_ message: String) -> some View {
        ContentUnavailableView {
            Label("History Unavailable", systemImage: "externaldrive.badge.xmark")
        } description: {
            Text(message)
        }
    }

    private func loadingView(_ title: String) -> some View {
        VStack(spacing: Theme.Metrics.spacingM) {
            ProgressView()
            Text(title).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func failureView(title: String, message: String, retry: @escaping () -> Void) -> some View {
        ContentUnavailableView {
            Label(title, systemImage: "exclamationmark.triangle")
        } description: {
            Text(message)
        } actions: {
            Button("Try Again", action: retry)
        }
    }

    private func recoverableNotice(_ message: String) -> some View {
        HStack(spacing: Theme.Metrics.spacingS) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            Text(message).font(Theme.Typography.caption).lineLimit(2)
            Spacer()
            Button("Dismiss") { coordinator.historyError = nil }
                .buttonStyle(.plain)
        }
        .padding(.horizontal, Theme.Metrics.spacingM)
        .padding(.vertical, Theme.Metrics.spacingS)
        .background(Color.orange.opacity(0.08))
    }

    private func captureDate(_ record: HistoryCaptureRecord) -> String {
        Date(timeIntervalSince1970: record.endedAt).formatted(date: .abbreviated, time: .shortened)
    }

    private func date(_ value: Double) -> Date {
        Date(timeIntervalSince1970: value)
    }

    private func duration(_ value: Double) -> String {
        if value < 1 {
            return "\(Int((value * 1_000).rounded())) ms"
        }
        return value.formatted(.number.precision(.fractionLength(1))) + " s"
    }

    private func bytes(_ value: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: value, countStyle: .binary)
    }

    private func loadedCount(_ count: Int, hasMore: Bool) -> String {
        "\(count.formatted())\(hasMore ? "+" : "")"
    }

    private func statusTitle(_ status: HistorySessionStatus) -> String {
        switch status {
        case .ok: "OK"
        case .warning: "Warning"
        case .error: "Error"
        }
    }

    private func statusSymbol(_ status: HistorySessionStatus) -> String {
        switch status {
        case .ok: "checkmark.circle.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .error: "xmark.octagon.fill"
        }
    }

    private func statusColor(_ status: HistorySessionStatus) -> Color {
        switch status {
        case .ok: .green
        case .warning: .orange
        case .error: .red
        }
    }
}

// MARK: - HistoryCaptureRow

private struct HistoryCaptureRow: View {
    let capture: HistoryStoredCapture

    var body: some View {
        HStack(alignment: .top, spacing: Theme.Metrics.spacingS) {
            Image(systemName: capture.record.sourceKind == .live ? "dot.radiowaves.left.and.right" : "doc")
                .foregroundStyle(capture.record.completeness == .complete ? Color.accentColor : .orange)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 3) {
                Text(
                    Date(timeIntervalSince1970: capture.record.endedAt),
                    format: .dateTime.month().day().hour().minute()
                )
                .font(Theme.Typography.navigationMedium)
                HStack(spacing: 5) {
                    Text(capture.record.sourceKind == .live ? "Live" : "Saved")
                    Text("·")
                    Text(capture.sessionCount == 1 ? "1 session" : "\(capture.sessionCount.formatted()) sessions")
                }
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
            if capture.record.completeness == .incomplete {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .help("Capture summary is incomplete")
            }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
    }
}
