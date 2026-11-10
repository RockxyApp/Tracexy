import AppKit
import SwiftUI

// MARK: - ServiceResponseTimeWindow

/// Statistics ▸ Service Response Time. Every protocol is rescanned across the stable
/// capture, independently of All Frames paging.
struct ServiceResponseTimeWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        @Bindable var frames = coordinator.allFrames
        let rows = scannedRows
        let omittedCorrelations = scannedOmittedCorrelations
        let echo = service.isEcho ? echoScanResult : nil
        scanContent(rows, echo: echo)
            .toolbar {
                ToolbarItem(placement: .navigation) {
                    Toggle("Limit to Sessions in View", isOn: $frames.limitToSessionsInView)
                        .toggleStyle(.checkbox)
                        .help("Count only the frames of the sessions the main window shows")
                }
            }
            .tracexyDenseScrollEdge()
            // Expanded before the bar is attached: a bar attached first is
            // sized together with the content and the pair is then centred, so
            // the picker floated below the titlebar in the empty state.
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .tracexySafeAreaBar(edge: .top) {
                HStack {
                    Picker("Service", selection: $service) {
                        ForEach(ServiceResponseTime.Service.allCases) { Text($0.title).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .fixedSize()
                    .help("Which protocol's requests and replies to time")
                    Spacer(minLength: 0)
                }
                .controlSize(.small)
                .padding(.horizontal, Theme.Metrics.spacingL)
                .padding(.vertical, Theme.Metrics.spacingS)
            }
            .tracexySafeAreaBar(edge: .bottom) {
                footer(rows, echo: echo, omittedCorrelations: omittedCorrelations)
            }
            .frame(minWidth: 640, minHeight: 320)
            .onAppear { coordinator.loadAllFrames() }
            .task(id: scanKey) { await runScan() }
    }

    // MARK: Private

    @State private var service = ServiceResponseTime.Service.smb2
    @State private var notice: String?
    @State private var smb2ScanResult: ServiceResponseTime.StreamingSMB2Accumulator.Result?
    @State private var correlatedScanResult: ServiceResponseTime.StreamingAccumulator.Result?
    @State private var echoScanResult: EchoResponseTime?
    @State private var smb2ScanError: String?
    @State private var smb2ScanIsLoading = false
    @State private var smb2ScanRequestID = 0
    @State private var scanWasCancelled = false
    @State private var rescanToken = 0
    @State private var scanTask: Task<Void, Never>?

    private var captureIsLive: Bool {
        coordinator.isCapturing || coordinator.isStarting
    }

    /// The scan is keyed on the capture's identity, not on the live session list:
    /// keying on `visibleSessions` restarted (and first cleared) a whole-capture
    /// scan for every session a live capture folded, so the window never settled.
    /// While the capture is live the scoped key is frozen and Rescan is the way to
    /// take in newer sessions.
    private var scanKey: String {
        let frames = coordinator.allFrames
        let scope: String = if !frames.limitToSessionsInView {
            "all-sessions"
        } else if captureIsLive {
            "sessions-in-view-live"
        } else {
            coordinator.visibleSessions.map(\.id.uuidString).sorted().joined(separator: ",")
        }
        let availability = coordinator.allFramesUnavailableReason ?? "available"
        return "\(service.rawValue)|\(coordinator.projectStore.activeProjectID.uuidString)|\(coordinator.startGeneration)|\(availability)|\(frames.limitToSessionsInView)|\(scope)|\(rescanToken)"
    }

    private var scannedRows: [ServiceResponseTime.Row] {
        switch service {
        case .smb2: smb2ScanResult?.rows ?? []
        case .ldap,
             .kerberos: correlatedScanResult?.rows ?? []
        case .icmp,
             .icmpv6: []
        }
    }

    private var scannedOmittedCorrelations: Int {
        switch service {
        case .smb2: smb2ScanResult?.omittedRequests ?? 0
        case .ldap,
             .kerberos: correlatedScanResult?.omittedCorrelations ?? 0
        case .icmp,
             .icmpv6: 0
        }
    }

    @ViewBuilder
    private func scanContent(_ rows: [ServiceResponseTime.Row], echo: EchoResponseTime?) -> some View {
        if smb2ScanIsLoading {
            VStack(spacing: Theme.Metrics.spacingM) {
                ProgressView("Scanning capture for response times…")
                    .controlSize(.small)
                Button("Cancel", role: .cancel) { cancelScan() }
                    .keyboardShortcut(.cancelAction)
                    .controlSize(.small)
                    .accessibilityIdentifier("serviceResponseTime.cancel")
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let smb2ScanError {
            ContentUnavailableView(
                "Service Response Time Unavailable", systemImage: "stopwatch", description: Text(smb2ScanError)
            )
        } else if scanWasCancelled {
            ContentUnavailableView(
                "Scan Cancelled",
                systemImage: "stopwatch",
                description: Text("This scan stopped before it finished. Rescan to time these replies.")
            )
        } else if let echo, echo.requests > 0 {
            echoSummary(echo)
        } else if rows.isEmpty {
            ContentUnavailableView(
                "No Paired Replies",
                systemImage: "stopwatch",
                description: Text(service.isEcho
                    ? "No \(service.title) echo request is in this capture scope."
                    : "No \(service.title) reply in this capture scope could be paired with its request.")
            )
        } else {
            table(rows)
        }
    }

    private func table(_ rows: [ServiceResponseTime.Row]) -> some View {
        Table(rows) {
            TableColumn("Index") { row in
                Text(String(row.index)).monospacedDigit()
            }
            .width(min: 40, ideal: 44)
            TableColumn(service.procedureTitle) { row in
                Text(row.procedure).lineLimit(1)
            }
            .width(min: 110, ideal: 150)
            TableColumn("Calls") { row in
                Text(row.calls.formatted()).monospacedDigit()
            }
            .width(min: 40, ideal: 48)
            TableColumn("Min SRT") { row in
                Text(ServiceResponseTime.seconds(row.minimum)).monospacedDigit()
            }
            .width(min: 70, ideal: 84)
            TableColumn("Max SRT") { row in
                Text(ServiceResponseTime.seconds(row.maximum)).monospacedDigit()
            }
            .width(min: 70, ideal: 84)
            TableColumn("Avg SRT") { row in
                Text(ServiceResponseTime.seconds(row.average)).monospacedDigit()
            }
            .width(min: 70, ideal: 84)
            TableColumn("Sum SRT") { row in
                Text(ServiceResponseTime.seconds(row.sum)).monospacedDigit()
            }
            .width(min: 70, ideal: 84)
        }
    }

    /// tshark's two ICMP lines as labelled values.
    private func echoSummary(_ echo: EchoResponseTime) -> some View {
        let ms = EchoResponseTime.milliseconds
        let items: [(String, String)] = [
            (String(localized: "Requests"), echo.requests.formatted()),
            (String(localized: "Replies"), echo.replies.formatted()),
            (String(localized: "Lost"), "\(echo.lost.formatted()) (\(String(format: "%.1f", echo.lossPercent))%)"),
            (String(localized: "Minimum"), "\(ms(echo.minimum)) ms"),
            (String(localized: "Maximum"), "\(ms(echo.maximum)) ms"),
            (String(localized: "Mean"), "\(ms(echo.mean)) ms"),
            (String(localized: "Median"), "\(ms(echo.median)) ms"),
            (String(localized: "Standard deviation"), "\(ms(echo.standardDeviation)) ms"),
            (
                String(localized: "Fastest reply"),
                echo.minimumFrame.map { String(localized: "Frame \($0.formatted())") } ?? "—"
            ),
            (
                String(localized: "Slowest reply"),
                echo.maximumFrame.map { String(localized: "Frame \($0.formatted())") } ?? "—"
            ),
        ]
        return Form {
            ForEach(items, id: \.0) { label, value in
                LabeledContent(label) {
                    Text(value).monospacedDigit().textSelection(.enabled)
                }
            }
        }
        .formStyle(.grouped)
    }

    private func footer(
        _ rows: [ServiceResponseTime.Row], echo: EchoResponseTime?, omittedCorrelations: Int
    )
        -> some View
    {
        let calls = echo?.replies ?? rows.reduce(0) { $0 + $1.calls }
        let csv = echo?.csv ?? ServiceResponseTime.csv(service, rows, omittedRequests: omittedCorrelations)
        let isEmpty = (echo.map { $0.requests == 0 } ?? rows.isEmpty) && omittedCorrelations == 0
        var summary = omittedCorrelations > 0
            ? String(localized: "\(omittedCorrelations.formatted()) correlations omitted at the 200,000-record limit")
            : calls == 1 ? String(localized: "1 reply timed") : String(localized: "\(calls.formatted()) replies timed")
        if captureIsLive {
            summary += String(localized: "; the capture is still running — rescan to include newer frames")
        }
        return HStack(spacing: Theme.Metrics.spacingM) {
            Text(notice ?? summary)
                .lineLimit(1)
            Spacer()
            Button("Copy as CSV") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(csv, forType: .string)
            }
            .disabled(isEmpty)
            Button("Save as CSV…") {
                notice = StatisticsExport.saveText(csv, suggestedName: "\(service.title) SRT.csv")
            }
            .disabled(isEmpty)
            Button("Rescan") { rescanToken &+= 1 }
                .disabled(smb2ScanIsLoading)
                .accessibilityIdentifier("serviceResponseTime.rescan")
                .help("Scan the capture again, taking in everything captured since the last scan")
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    /// Runs the scan as a task this view can cancel from the Cancel button, while
    /// still cancelling with the surrounding `.task` when the key changes.
    @MainActor
    private func runScan() async {
        let task = Task { @MainActor in await loadCaptureWideSRT() }
        scanTask = task
        await withTaskCancellationHandler {
            await task.value
        } onCancel: {
            task.cancel()
        }
        if scanTask == task {
            scanTask = nil
        }
    }

    @MainActor
    private func cancelScan() {
        scanTask?.cancel()
        scanTask = nil
        scanWasCancelled = true
        smb2ScanIsLoading = false
        smb2ScanRequestID &+= 1
    }

    @MainActor
    private func loadCaptureWideSRT() async {
        smb2ScanRequestID &+= 1
        let requestID = smb2ScanRequestID
        let requestedService = service
        scanWasCancelled = false
        echoScanResult = nil
        smb2ScanResult = nil
        correlatedScanResult = nil
        smb2ScanError = nil
        smb2ScanIsLoading = true
        defer {
            if requestID == smb2ScanRequestID {
                smb2ScanIsLoading = false
            }
        }
        let frames = coordinator.allFrames
        let sessionScope = frames.limitToSessionsInView ? Set(coordinator.visibleSessions.map(\.id)) : nil
        do {
            if requestedService.isEcho {
                let result = try await coordinator.scanEchoResponseTime(
                    ipv6: requestedService == .icmpv6,
                    sessionsInScope: sessionScope
                )
                guard requestID == smb2ScanRequestID else {
                    return
                }
                echoScanResult = result
            } else if requestedService == .smb2 {
                let result = try await coordinator.scanSMB2ServiceResponseTime(sessionsInScope: sessionScope)
                guard requestID == smb2ScanRequestID else {
                    return
                }
                smb2ScanResult = result
            } else {
                let result = try await coordinator.scanServiceResponseTime(
                    requestedService,
                    sessionsInScope: sessionScope
                )
                guard requestID == smb2ScanRequestID else {
                    return
                }
                correlatedScanResult = result
            }
        } catch is CancellationError {
            if requestID == smb2ScanRequestID {
                scanWasCancelled = true
            }
            return
        } catch {
            if requestID == smb2ScanRequestID {
                smb2ScanError = error.localizedDescription
            }
        }
    }
}
