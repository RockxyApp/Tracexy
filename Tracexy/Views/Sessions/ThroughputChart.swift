import Charts
import SwiftUI

// MARK: - ThroughputChart

/// The pure live throughput plot (bytes/sec) — an area+line Swift Chart with no
/// header or card, so it can be embedded anywhere (Overview card, Sessions
/// live strip, or a footer sparkline). Reads only `samples`, so its ~1×/sec
/// updates never re-run a host view that also drives the NSTableView.
struct ThroughputChart: View {
    // MARK: Internal

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
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Throughput chart. Bytes per second over the recent capture window.")
        .accessibilityValue(Self.accessibilityValue(for: samples))
    }

    /// Spoken summary of the plot: VoiceOver cannot read the marks, so the
    /// current rate, the peak and the range carry the same reading the shape does.
    static func accessibilityValue(for samples: [ThroughputSample]) -> String {
        let rates = samples.map(\.bytesPerSecond)
        guard let low = rates.min(), let high = rates.max(), let current = rates.last else {
            return "No throughput samples yet"
        }
        let sampleWord = samples.count == 1 ? "sample" : "samples"
        return "\(samples.count.formatted()) \(sampleWord). "
            + "Now \(Self.rate(current)). Peak \(Self.rate(high)). "
            + "Range \(Self.rate(low)) to \(Self.rate(high))."
    }

    // MARK: Private

    private static func rate(_ bytesPerSecond: Double) -> String {
        let clamped = bytesPerSecond.rounded()
        let bytes = Int64(exactly: clamped.isFinite ? max(clamped, 0) : 0) ?? Int64.max
        return "\(ByteUnits.string(bytes)) per second"
    }
}
