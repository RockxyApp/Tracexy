import AppKit
import SwiftUI

// MARK: - IPStatisticsWindow

/// Statistics ▸ IP Statistics: Wireshark's IPv4 and IPv6 Statistics trees — All
/// Addresses, IP Protocol Types, Source and Destination Addresses, Destinations and
/// Ports, Source TTLs (Source Hop Limits) — over the frames the All Frames list shows.
struct IPStatisticsWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        @Bindable var frames = coordinator.allFrames
        let inView = Set(coordinator.visibleSessions.map(\.id))
        let roots = IPStatistics.tree(tree, ipv6: isIPv6, rows: frames.visibleRows(sessionsInView: inView))
        Group {
            if frames.isLoading {
                ProgressView("Listing frames…")
                    .controlSize(.small)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let error = frames.error {
                ContentUnavailableView(
                    "IP Statistics Unavailable",
                    systemImage: "point.3.connected.trianglepath.dotted",
                    description: Text(error)
                )
            } else if roots.isEmpty {
                ContentUnavailableView(
                    isIPv6 ? "No IPv6 Packets" : "No IPv4 Packets",
                    systemImage: "point.3.connected.trianglepath.dotted",
                    description: Text("No frame in view carries this IP version.")
                )
            } else {
                StatsTreeTable(roots: roots)
                    .id("\(isIPv6)-\(tree.rawValue)")
            }
        }
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Toggle("Limit to Sessions in View", isOn: $frames.limitToSessionsInView)
                    .toggleStyle(.checkbox)
                    .help("Count only the frames of the sessions the main window shows")
            }
        }
        .tracexySafeAreaBar(edge: .top) { choosers }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) { footer(roots) }
        .frame(minWidth: 640, minHeight: 360)
        .onAppear { coordinator.loadAllFrames() }
    }

    // MARK: Private

    @State private var isIPv6 = false
    @State private var tree = IPStatistics.Tree.allAddresses
    @State private var notice: String?

    /// IPv4 or IPv6, and which tree — Wireshark's two Statistics submenus in one bar.
    private var choosers: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Picker("Version", selection: $isIPv6) {
                Text("IPv4").tag(false)
                Text("IPv6").tag(true)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            .help("IPv4 or IPv6 packets")
            Picker("Statistics", selection: $tree) {
                ForEach(IPStatistics.Tree.allCases) { tree in
                    Text(tree.title(ipv6: isIPv6)).tag(tree)
                }
            }
            .labelsHidden()
            .fixedSize()
            .help("Which of Wireshark's IP statistics trees to show")
            Spacer(minLength: 0)
        }
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingS)
    }

    private func footer(_ roots: [StatsTreeNode]) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Text(notice ?? summary(roots)).lineLimit(1)
            Spacer()
            Button("Copy as CSV") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(StatsTreeNode.csv(roots), forType: .string)
            }
            .disabled(roots.isEmpty)
            Button("Save as CSV…") {
                notice = StatisticsExport.saveText(
                    StatsTreeNode.csv(roots),
                    suggestedName: "\(isIPv6 ? "IPv6" : "IPv4") \(tree.title(ipv6: isIPv6)).csv"
                )
            }
            .disabled(roots.isEmpty)
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    /// The packets the tree counts: its root's count, or the source branch's.
    private func summary(_ roots: [StatsTreeNode]) -> String {
        guard let first = roots.first else {
            return ""
        }
        return first
            .count == 1 ? String(localized: "1 packet") : String(localized: "\(first.count.formatted()) packets")
    }
}
