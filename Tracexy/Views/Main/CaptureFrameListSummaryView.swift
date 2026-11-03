import SwiftUI

// MARK: - CaptureFrameListSummaryView

struct CaptureFrameListSummaryView: View {
    let shown: Int
    let state: CaptureFrameListState
    let notice: String?

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            if let notice {
                Text(notice)
            } else if let list = state.list {
                let pinnedFromOtherPages = state.captureTimeReferenceRows.keys
                    .filter { ordinal in !list.rows.contains { $0.id == ordinal } }.count
                if list.omittedFrameCount > 0 {
                    let last = list.rows.last?.ordinal ?? UInt64(list.firstRetainedOrdinal)
                    Text(
                        "Showing \(shown.formatted()) of frames \(list.firstRetainedOrdinal.formatted())–\(last.formatted()), \(list.scannedFrameCount.formatted()) scanned"
                    )
                } else {
                    Text("Showing \(shown.formatted()) of \(list.scannedFrameCount.formatted()) frames")
                }
                if pinnedFromOtherPages > 0 {
                    Text("Includes \(pinnedFromOtherPages.formatted()) time reference(s) from other pages")
                }
            }
            if let coverage = state.captureExpressionCoverage, state.acceptedFrameExpression != nil {
                let scope = state.list?.completeness == .complete
                    ? String(localized: "in capture")
                    : String(localized: "in complete frames; truncated tail")
                Text("\(coverage.matchingCount.formatted()) match Frame Expression \(scope)")
                if coverage.unknownCount > 0 {
                    Text("\(coverage.unknownCount.formatted()) unknown \(scope)")
                        .help("These frames could not be decoded enough to decide the Frame Expression.")
                }
            } else if state.acceptedFrameExpression != nil, state.frameExpressionUnknownCount > 0 {
                Text(
                    "\(state.frameExpressionUnknownCount.formatted()) \(state.frameExpressionUnknownCount == 1 ? "frame" : "frames") unknown to filter"
                )
                .help(
                    "These retained frames were truncated or could not be decoded enough to decide the Frame Expression; they are not shown as matches."
                )
            }
        }
        .lineLimit(1)
    }
}
