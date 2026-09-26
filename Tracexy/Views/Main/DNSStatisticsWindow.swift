import SwiftUI

// MARK: - DNSStatisticsWindow

/// Statistics ▸ DNS: Wireshark's DNS statistics tree — packet types, query and
/// answer types, classes, response codes, opcodes, sizes, name and section
/// statistics and response times.
struct DNSStatisticsWindow: View {
    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        StatsTreeWindow(coordinator: coordinator, content: StatsTreeWindow.Content(
            unavailableTitle: "DNS Statistics Unavailable",
            emptyTitle: "No DNS Messages",
            emptyDescription: "No DNS query or response was read in the frames in view.",
            systemImage: "globe",
            csvName: "DNS Statistics.csv",
            tree: { DNSStatistics.tree(rows: $0) },
            total: {
                $0
                    .count == 1 ? String(localized: "1 DNS message") :
                    String(localized: "\($0.count.formatted()) DNS messages")
            }
        ))
    }
}
