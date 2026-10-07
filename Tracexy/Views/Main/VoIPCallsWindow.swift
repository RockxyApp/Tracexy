import AppKit
import SwiftUI

// MARK: - VoIPCallsWindow

/// Statistics ▸ VoIP Calls: every SIP call in the frames in view — who called whom,
/// when, for how long and how it ended — as Wireshark's Telephony ▸ VoIP Calls.
struct VoIPCallsWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        @Bindable var frames = coordinator.allFrames
        let inView = Set(coordinator.visibleSessions.map(\.id))
        let rows = frames.visibleRows(sessionsInView: inView)
        let calls = SIPCalls.calls(rows: rows)
        let origin = rows.lazy.compactMap(\.provenance.timestamp).first
        Group {
            if frames.isLoading {
                ProgressView("Listing frames…")
                    .controlSize(.small)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let error = frames.error {
                ContentUnavailableView("VoIP Calls Unavailable", systemImage: "phone", description: Text(error))
            } else if calls.isEmpty {
                ContentUnavailableView(
                    "No Calls",
                    systemImage: "phone",
                    description: Text("No SIP INVITE was read in the frames in view.")
                )
            } else {
                table(calls, rows: rows, origin: origin)
            }
        }
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Toggle("Limit to Sessions in View", isOn: $frames.limitToSessionsInView)
                    .toggleStyle(.checkbox)
                    .help("Count only the frames of the sessions the main window shows")
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) {
            footer(calls)
        }
        .frame(minWidth: 700, minHeight: 300)
        .onAppear { coordinator.loadAllFrames() }
    }

    // MARK: Private

    @Environment(\.openWindow) private var openWindow
    @State private var selection: SIPCallRow.ID?
    @State private var notice: String?

    private func table(_ calls: [SIPCallRow], rows: [CaptureFrameRow], origin: Date?) -> some View {
        Table(calls, selection: $selection) {
            TableColumn("Start") { call in
                Text(call.start.flatMap { start in origin.map { start.timeIntervalSince($0) } }
                    .map { "\($0.formatted(.number.precision(.fractionLength(3)))) s" } ?? "—")
                    .monospacedDigit()
            }
            .width(min: 60, ideal: 80)
            TableColumn("Duration") { call in
                Text(call.duration.map { "\($0.formatted(.number.precision(.fractionLength(1)))) s" } ?? "—")
                    .monospacedDigit()
            }
            .width(min: 60, ideal: 70)
            TableColumn("From") { call in
                Text(call.from).lineLimit(1).truncationMode(.middle).help(call.from)
            }
            .width(min: 120, ideal: 170)
            TableColumn("To") { call in
                Text(call.to).lineLimit(1).truncationMode(.middle).help(call.to)
            }
            .width(min: 120, ideal: 170)
            TableColumn("State") { call in
                Text(call.state.title)
                    .foregroundStyle(stateColor(call.state))
            }
            .width(min: 80, ideal: 110)
            TableColumn("Messages") { call in
                Text(call.messages.formatted()).monospacedDigit()
            }
            .width(min: 50, ideal: 64)
        }
        .contextMenu(forSelectionType: SIPCallRow.ID.self) { ids in
            if let call = calls.first(where: { ids.contains($0.id) }) {
                Button("Show Sessions") { coordinator.showSessions(narrowingWith: call.term) }
                Button("Flow Sequence") { showFlow(call) }
                Button("Open First Frame") {
                    if let frame = rows.first(where: { $0.ordinal == call.firstFrame }) {
                        notice = coordinator.revealFrame(frame)
                            ? nil : String(localized: "That frame's session is not in the main window's list.")
                    }
                }
                Divider()
                Button("Copy Call-ID") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(call.callID, forType: .string)
                }
            }
        } primaryAction: { ids in
            if let call = calls.first(where: { ids.contains($0.id) }) {
                coordinator.showSessions(narrowingWith: call.term)
            }
        }
    }

    private func footer(_ calls: [SIPCallRow]) -> some View {
        let selected = calls.first { $0.id == selection }
        return HStack(spacing: Theme.Metrics.spacingM) {
            Text(notice ??
                (calls
                    .count == 1 ? String(localized: "1 call") : String(localized: "\(calls.count.formatted()) calls")))
                .lineLimit(1)
            Spacer()
            Button("Flow Sequence") {
                if let selected {
                    showFlow(selected)
                }
            }
            .disabled(selected == nil)
            Button("Show Sessions") {
                if let selected {
                    coordinator.showSessions(narrowingWith: selected.term)
                }
            }
            .disabled(selected == nil)
            .keyboardShortcut(.defaultAction)
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    /// Wireshark's Flow Sequence: the Flow Graph limited to this call's messages and media.
    private func showFlow(_ call: SIPCallRow) {
        coordinator.allFrames.flowCallID = call.callID
        openWindow(id: TracexyApp.flowGraphWindowID)
    }

    private func stateColor(_ state: SIPCallState) -> Color {
        switch state {
        case .rejected: .orange
        case .setup,
             .ringing: .secondary
        default: .primary
        }
    }
}
