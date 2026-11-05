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
        let smb2Result = smb2ScanResult
        let rows: [ServiceResponseTime.Row] = switch service {
        case .smb2: smb2Result?.rows ?? []
        case .ldap,
             .kerberos: correlatedScanResult?.rows ?? []
        case .icmp,
             .icmpv6: []
        }
        let omittedCorrelations = switch service {
        case .smb2: smb2Result?.omittedRequests ?? 0
        case .ldap,
             .kerberos: correlatedScanResult?.omittedCorrelations ?? 0
        case .icmp,
             .icmpv6: 0
        }
        let echo = service.isEcho ? echoScanResult : nil
        Group {
            if smb2ScanIsLoading {
                ProgressView("Scanning capture for response times…")
                    .controlSize(.small)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let smb2ScanError {
                ContentUnavailableView(
                    "Service Response Time Unavailable", systemImage: "stopwatch", description: Text(smb2ScanError)
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
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Toggle("Limit to Sessions in View", isOn: $frames.limitToSessionsInView)
                    .toggleStyle(.checkbox)
                    .help("Count only the frames of the sessions the main window shows")
            }
        }
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
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) {
            footer(rows, echo: echo, omittedCorrelations: omittedCorrelations)
        }
        .frame(minWidth: 640, minHeight: 320)
        .onAppear { coordinator.loadAllFrames() }
        .task(id: scanKey) { await loadCaptureWideSRT() }
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

    private var scanKey: String {
        let frames = coordinator.allFrames
        let scope = frames.limitToSessionsInView
            ? coordinator.visibleSessions.map(\.id.uuidString).sorted().joined(separator: ",")
            : "all-sessions"
        let availability = coordinator.allFramesUnavailableReason ?? "available"
        return "\(service.rawValue)|\(coordinator.projectStore.activeProjectID.uuidString)|\(coordinator.startGeneration)|\(availability)|\(frames.limitToSessionsInView)|\(scope)"
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
        let summary = omittedCorrelations > 0
            ? String(localized: "\(omittedCorrelations.formatted()) correlations omitted at the 200,000-record limit")
            : calls == 1 ? String(localized: "1 reply timed") : String(localized: "\(calls.formatted()) replies timed")
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
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    @MainActor
    private func loadCaptureWideSRT() async {
        smb2ScanRequestID &+= 1
        let requestID = smb2ScanRequestID
        let requestedService = service
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
            return
        } catch {
            if requestID == smb2ScanRequestID {
                smb2ScanError = error.localizedDescription
            }
        }
    }
}
