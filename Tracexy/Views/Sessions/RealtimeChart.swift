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
                            Text(ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .binary))
                                .font(Theme.Typography.micro)
                        }
                    }
                }
            }
        }
    }
}

// MARK: - RealtimeChart

/// A live throughput chart (bytes/sec) with a labeled header + card — used on the
/// Overview surface. The always-on real-time graph.
struct RealtimeChart: View {
    // MARK: Internal

    let samples: [ThroughputSample]

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Image(systemName: "waveform.path.ecg")
                    .font(.system(size: Theme.Icon.small)).foregroundStyle(.secondary)
                Text("Throughput").font(Theme.Typography.badge).foregroundStyle(.secondary)
                Spacer()
                Text(currentRate)
                    .font(Theme.Typography.monoSmall)
                    .foregroundStyle(Color.accentColor)
            }
            chart
        }
        .padding(8)
        .tracexyContentSurface(
            in: RoundedRectangle(cornerRadius: Theme.Metrics.cornerRadius, style: .continuous)
        )
    }

    // MARK: Private

    private var currentRate: String {
        let bps = samples.last?.bytesPerSecond ?? 0
        return "\(ByteCountFormatter.string(fromByteCount: Int64(bps), countStyle: .binary))/s"
    }

    @ViewBuilder private var chart: some View {
        if samples.isEmpty {
            RoundedRectangle(cornerRadius: 4)
                .fill(.quaternary.opacity(0.4))
                .overlay {
                    Text("Waiting for traffic…")
                        .font(Theme.Typography.micro).foregroundStyle(.tertiary)
                }
        } else {
            ThroughputChart(samples: samples)
        }
    }
}
