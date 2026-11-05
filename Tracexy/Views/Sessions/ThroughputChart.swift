import Charts
import SwiftUI

// MARK: - ThroughputChart

/// The pure live throughput plot (bytes/sec) — an area+line Swift Chart with no
/// header or card, so it can be embedded anywhere (Overview card, Sessions
/// live strip, or a footer sparkline). Reads only `samples`, so its ~1×/sec
/// updates never re-run a host view that also drives the NSTableView.
struct ThroughputChart: View {
    let samples: [ThroughputSample]
    var showYAxis = true

    var body: some View {
        Chart(Array(samples.enumerated()), id: \.offset) { index, sample in
            AreaMark(x: .value("t", index), y: .value("B/s", sample.bytesPerSecond))
                .interpolationMethod(.catmullRom)
                .foregroundStyle(.linearGradient(
                    colors: [Color.accentColor.opacity(0.35), Color.accentColor.opacity(0.02)],
                    startPoint: .top, endPoint: .bottom
                ))
            LineMark(x: .value("t", index), y: .value("B/s", sample.bytesPerSecond))
                .interpolationMethod(.catmullRom)
                .foregroundStyle(Color.accentColor)
                .lineStyle(StrokeStyle(lineWidth: 1.5))
        }
        .chartXAxis(.hidden)
        .chartXScale(domain: 0 ... Double(max(samples.count - 1, 1)))
        .chartYAxis {
            if showYAxis {
                AxisMarks(position: .leading, values: .automatic(desiredCount: 3)) { value in
                    AxisGridLine().foregroundStyle(.quaternary)
                    AxisValueLabel {
                        if let bytes = value.as(Double.self) {
                            Text(ByteUnits.string(Int64(bytes)))
                                .font(Theme.Typography.micro)
                        }
                    }
                }
            }
        }
    }
}
