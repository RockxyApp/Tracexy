import SwiftUI

// MARK: - SessionResponseTimeView

/// The measured response times for the selected session: one row per interval, each
/// ending in the two frames that bound it.
///
/// It sits near the top of the Details column, because "how long did that take"
/// is among the first questions about a session. Every word and number comes from
/// ``SessionResponseTimes`` so the claims are testable without a window; this view
/// renders rows, values and the frame route only.
struct SessionResponseTimeView: View {
    // MARK: Internal

    let responseTimes: SessionResponseTimes
    let inspectFrame: (SessionFrameProvenance) -> Void

    var body: some View {
        if !responseTimes.isEmpty {
            ContextInspectorTable(title: "Response Times") {
                ForEach(Array(responseTimes.rows.enumerated()), id: \.element.id) { index, row in
                    if index > 0 {
                        Divider()
                    }
                    ContextInspectorFullRow {
                        rowView(row)
                    }
                }
                if let caveat = responseTimes.caveat {
                    Divider()
                    ContextInspectorFullRow {
                        Label(caveat, systemImage: "info.circle")
                            .font(Theme.Typography.micro)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
        }
    }

    // MARK: Private

    private func rowView(_ row: SessionResponseTimeRow) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: Theme.Metrics.spacingM) {
            Text(row.label)
                .font(Theme.Typography.caption)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)

            Text(row.value)
                .font(Theme.Typography.monoSmall)
                .monospacedDigit()

            citation(row)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(row.label), \(row.value)")
    }

    /// The row's route into the evidence: the two frames that bound the interval, in
    /// the same menu shape the evidence rows use.
    @ViewBuilder
    private func citation(_ row: SessionResponseTimeRow) -> some View {
        if row.provenance.count == 1, let frame = row.provenance.first {
            Button("Frame \(frame.ordinal.rawValue.formatted())") {
                inspectFrame(frame)
            }
            .controlSize(.small)
        } else if !row.provenance.isEmpty {
            Menu("Frames") {
                ForEach(Array(row.provenance.enumerated()), id: \.offset) { _, frame in
                    Button(
                        frame.locator == nil
                            ? "Frame \(frame.ordinal.rawValue.formatted()) — unavailable"
                            : "Frame \(frame.ordinal.rawValue.formatted())"
                    ) {
                        inspectFrame(frame)
                    }
                }
            }
            .controlSize(.small)
            .fixedSize()
        }
    }
}
