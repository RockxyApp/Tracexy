import AppKit
import SwiftUI

// MARK: - StatsTreeWindow

/// A Wireshark statistics tree (Statistics ▸ DNS, ▸ SIP) over the frames the All
/// Frames list shows, as an outline with count, average, minimum and maximum, every
/// row expanded as Wireshark shows its trees. Copy or save it as CSV.
struct StatsTreeWindow: View {
    // MARK: Internal

    /// What one statistics window reads and says.
    struct Content {
        let unavailableTitle: LocalizedStringKey
        let emptyTitle: LocalizedStringKey
        let emptyDescription: LocalizedStringKey
        let systemImage: String
        let csvName: String
        let tree: ([CaptureFrameRow]) -> [StatsTreeNode]
        /// The footer's total, from the tree's first row.
        let total: (StatsTreeNode) -> String
    }

    @Bindable var coordinator: MainContentCoordinator

    let content: Content

    var body: some View {
        @Bindable var frames = coordinator.allFrames
        let inView = Set(coordinator.visibleSessions.map(\.id))
        let tree = content.tree(frames.visibleRows(sessionsInView: inView))
        Group {
            if frames.isLoading {
                ProgressView("Listing frames…")
                    .controlSize(.small)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let error = frames.error {
                ContentUnavailableView(
                    content.unavailableTitle,
                    systemImage: content.systemImage,
                    description: Text(error)
                )
            } else if tree.isEmpty {
                ContentUnavailableView(
                    content.emptyTitle, systemImage: content.systemImage, description: Text(content.emptyDescription)
                )
            } else {
                StatsTreeTable(roots: tree)
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
            footer(tree)
        }
        .frame(minWidth: 640, minHeight: 360)
        .onAppear { coordinator.loadAllFrames() }
    }

    // MARK: Private

    @State private var notice: String?

    private func footer(_ tree: [StatsTreeNode]) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            if let notice {
                Text(notice).lineLimit(1)
            } else if let total = tree.first {
                Text(content.total(total))
            }
            Spacer()
            Button("Copy as CSV") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(StatsTreeNode.csv(tree), forType: .string)
            }
            .disabled(tree.isEmpty)
            Button("Save as CSV…") {
                notice = StatisticsExport.saveText(StatsTreeNode.csv(tree), suggestedName: content.csvName)
            }
            .disabled(tree.isEmpty)
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }
}
