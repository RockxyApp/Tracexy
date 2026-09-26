import SwiftUI

// MARK: - SIPStatisticsWindow

/// Statistics ▸ SIP: Wireshark's SIP Statistics — messages, resent messages, status
/// codes, request methods and call setup time.
struct SIPStatisticsWindow: View {
    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        StatsTreeWindow(coordinator: coordinator, content: StatsTreeWindow.Content(
            unavailableTitle: "SIP Statistics Unavailable",
            emptyTitle: "No SIP Messages",
            emptyDescription: "No SIP request or response was read in the frames in view.",
            systemImage: "phone",
            csvName: "SIP Statistics.csv",
            tree: { SIPStatistics.tree(rows: $0) },
            total: {
                $0
                    .count == 1 ? String(localized: "1 SIP message") :
                    String(localized: "\($0.count.formatted()) SIP messages")
            }
        ))
    }
}
