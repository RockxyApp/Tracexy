import AppKit
import SwiftUI

// MARK: - ServiceResponseTimeWindow

/// Statistics ▸ Service Response Time: Wireshark's SRT tables for SMB2, LDAP and
/// Kerberos over the frames the All Frames list shows — each procedure's paired
/// replies and their minimum, maximum, mean and total time.
struct ServiceResponseTimeWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        @Bindable var frames = coordinator.allFrames
        let inView = Set(coordinator.visibleSessions.map(\.id))
        let visible = frames.visibleRows(sessionsInView: inView)
        let rows = ServiceResponseTime.table(service, rows: visible)
        let echo = service.isEcho ? EchoResponseTime(rows: visible, ipv6: service == .icmpv6) : nil
        Group {
            if frames.isLoading {
                ProgressView("Listing frames…")
                    .controlSize(.small)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let error = frames.error {
                ContentUnavailableView(
                    "Service Response Time Unavailable", systemImage: "stopwatch", description: Text(error)
                )
            } else if let echo, echo.requests > 0 {
                echoSummary(echo)
            } else if rows.isEmpty {
                ContentUnavailableView(
                    "No Paired Replies",
                    systemImage: "stopwatch",
                    description: Text(service.isEcho
                        ? "No \(service.title) echo request is in view."
                        : "No \(service.title) reply in view could be paired with its request.")
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
        .tracexySafeAreaBar(edge: .bottom) { footer(rows, echo: echo) }
        .frame(minWidth: 640, minHeight: 320)
        .onAppear { coordinator.loadAllFrames() }
    }

    // MARK: Private

    @State private var service = ServiceResponseTime.Service.smb2
    @State private var notice: String?

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

    private func footer(_ rows: [ServiceResponseTime.Row], echo: EchoResponseTime?) -> some View {
        let calls = echo?.replies ?? rows.reduce(0) { $0 + $1.calls }
        let csv = echo?.csv ?? ServiceResponseTime.csv(service, rows)
        let isEmpty = echo.map { $0.requests == 0 } ?? rows.isEmpty
        return HStack(spacing: Theme.Metrics.spacingM) {
            Text(notice ?? (calls == 1 ? String(localized: "1 reply timed") : String(
                localized: "\(calls.formatted()) replies timed"
            )))
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
}
