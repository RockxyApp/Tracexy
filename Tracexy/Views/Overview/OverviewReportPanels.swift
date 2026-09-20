import Charts
import SwiftUI

// MARK: - OverviewPanel

/// The bordered panel every report component sits in: a headline, one short
/// caption, and the content. Two text levels, nothing more.
struct OverviewPanel<Content: View, Accessory: View>: View {
    // MARK: Lifecycle

    init(
        _ title: String,
        caption: String,
        @ViewBuilder content: () -> Content,
        @ViewBuilder accessory: () -> Accessory = { EmptyView() }
    ) {
        self.title = title
        self.caption = caption
        self.content = content()
        self.accessory = accessory()
    }

    // MARK: Internal

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(Theme.Typography.surfaceTitle)
                    Text(caption).font(Theme.Typography.caption).foregroundStyle(.secondary)
                }
                Spacer(minLength: Theme.Metrics.spacingM)
                accessory
            }
            content
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .padding(Theme.Metrics.spacingL + 4)
        .tracexyContentSurface(
            in: RoundedRectangle(cornerRadius: Theme.Metrics.cornerRadius + 4, style: .continuous)
        )
    }

    // MARK: Private

    private let title: String
    private let caption: String
    private let content: Content
    private let accessory: Accessory
}

// MARK: - OverviewProtocolShare

/// One protocol's slice of the scoped session bytes.
struct OverviewProtocolShare: Identifiable, Equatable {
    let id: String
    let title: String
    let bytes: Int
    let fraction: Double
    let color: Color
    /// `nil` for the folded remainder row.
    let kind: ProtocolKind?
}

// MARK: - OverviewProtocolChart

/// A compact horizontal bar chart of session bytes by innermost protocol. Bars
/// are the byte share; each is a drill-in.
struct OverviewProtocolChart: View {
    let rows: [OverviewProtocolShare]
    let onSelect: (ProtocolKind) -> Void

    var body: some View {
        Chart(rows) { row in
            BarMark(
                x: .value("Bytes", row.bytes),
                y: .value("Protocol", row.title)
            )
            .foregroundStyle(row.color.gradient)
            .cornerRadius(3)
            .annotation(position: .trailing, spacing: 6) {
                Text(row.fraction.formatted(.percent.precision(.fractionLength(0))))
                    .font(Theme.Typography.micro)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
        }
        .chartXAxis(.hidden)
        .chartXScale(domain: 0 ... Double(max(1, rows.map(\.bytes).max() ?? 1)) * 1.22)
        .chartYAxis {
            AxisMarks(preset: .aligned, position: .leading) { _ in
                AxisValueLabel()
                    .font(Theme.Typography.caption)
            }
        }
        .chartOverlay { proxy in
            GeometryReader { geometry in
                Rectangle()
                    .fill(.clear)
                    .contentShape(Rectangle())
                    .onTapGesture { location in
                        guard let plotFrame = proxy.plotFrame else {
                            return
                        }
                        let plot = geometry[plotFrame]
                        guard let title = proxy.value(atY: location.y - plot.minY, as: String.self),
                              let kind = rows.first(where: { $0.title == title })?.kind else
                        {
                            return
                        }
                        onSelect(kind)
                    }
            }
        }
        .accessibilityLabel("Session bytes by protocol")
        .accessibilityValue(rows.map { "\($0.title) \($0.fraction.formatted(.percent.precision(.fractionLength(0))))" }
            .joined(separator: ", "))
    }
}

// MARK: - OverviewSeverityChart

/// Findings in scope by severity, as three bars in the severity colours.
struct OverviewSeverityChart: View {
    struct Row: Identifiable {
        let severity: Finding.Severity
        let title: String
        let count: Int

        var id: String {
            title
        }
    }

    let rows: [Row]

    var body: some View {
        Chart(rows) { row in
            BarMark(
                x: .value("Findings", row.count),
                y: .value("Severity", row.title)
            )
            .foregroundStyle(row.severity.tint.gradient)
            .cornerRadius(3)
            .annotation(position: .trailing, spacing: 6) {
                Text(row.count.formatted())
                    .font(Theme.Typography.micro)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
        }
        .chartXAxis(.hidden)
        .chartXScale(domain: 0 ... Double(max(1, rows.map(\.count).max() ?? 1)) * 1.22)
        .chartYAxis {
            AxisMarks(preset: .aligned, position: .leading) { _ in
                AxisValueLabel()
                    .font(Theme.Typography.caption)
            }
        }
        .accessibilityLabel("Findings by severity")
        .accessibilityValue(rows.map { "\($0.title) \($0.count)" }.joined(separator: ", "))
    }
}

// MARK: - OverviewSessionStartChart

/// Sessions that began in each slice of the capture clock, on the same axis as
/// the traffic chart above it, so bursts of new conversations line up with
/// bursts of bytes.
struct OverviewSessionStartChart: View {
    struct Column: Identifiable {
        let date: Date
        let count: Int

        var id: Date {
            date
        }
    }

    let columns: [Column]
    let width: TimeInterval

    var body: some View {
        Chart(columns) { column in
            BarMark(
                x: .value("Time", column.date, unit: .second),
                y: .value("Sessions", column.count),
                width: .automatic
            )
            .foregroundStyle(Color.accentColor.gradient)
        }
        .chartXAxis {
            AxisMarks(values: .automatic(desiredCount: 2)) { value in
                AxisValueLabel {
                    if let date = value.as(Date.self) {
                        Text(width >= 60
                            ? date.formatted(.dateTime.hour().minute())
                            : date.formatted(.dateTime.hour().minute().second()))
                            .font(Theme.Typography.micro)
                    }
                }
                .foregroundStyle(.tertiary)
            }
        }
        .chartYAxis {
            AxisMarks(position: .leading, values: .automatic(desiredCount: 2)) { value in
                AxisGridLine().foregroundStyle(.quaternary)
                AxisValueLabel {
                    if let count = value.as(Int.self) {
                        Text(count.formatted()).font(Theme.Typography.micro)
                    }
                }
                .foregroundStyle(.tertiary)
            }
        }
        .accessibilityLabel("Sessions started over time")
        .accessibilityValue("\(columns.reduce(0) { $0 + $1.count }) sessions across \(columns.count) slices")
    }
}

// MARK: - OverviewTalkerTable

/// A native report table of the parties carrying the most bytes in scope.
/// Double-clicking a row narrows the session list to exactly that row.
struct OverviewTalkerTable: View {
    // MARK: Internal

    enum Kind {
        case hosts
        case apps
    }

    let kind: Kind
    let rows: [TrafficRankingEntry]
    let scopedBytes: Int
    let onOpen: (TrafficRankingEntry) -> Void

    var body: some View {
        Table(rows, selection: $selection) {
            TableColumn(kind == .apps ? "App" : "Host") { row in
                HStack(spacing: Theme.Metrics.spacingM) {
                    if kind == .apps {
                        AppIconView(name: row.name, size: 16)
                            .accessibilityHidden(true)
                    }
                    Text(row.name)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            .width(min: 120, ideal: 200)
            TableColumn("Sessions") { row in
                numeric(row.sessionCount.formatted())
            }
            .width(min: 56, ideal: 64)
            TableColumn("Sent") { row in
                numeric(Self.bytes(row.sentBytes))
            }
            .width(min: 62, ideal: 70)
            TableColumn("Received") { row in
                numeric(Self.bytes(row.receivedBytes))
            }
            .width(min: 62, ideal: 70)
            TableColumn("Total") { row in
                numeric(Self.bytes(row.totalBytes))
            }
            .width(min: 62, ideal: 70)
            TableColumn("Share") { row in
                shareCell(row)
            }
            .width(min: 96, ideal: 130)
        }
        .tableStyle(.bordered)
        .frame(height: Self.rowHeight * CGFloat(rows.count) + Self.headerHeight)
        .contextMenu(forSelectionType: TrafficRankingEntry.ID.self) { ids in
            if let row = rows.first(where: { ids.contains($0.id) }) {
                Button("Show Sessions") { onOpen(row) }
            }
        } primaryAction: { ids in
            if let row = rows.first(where: { ids.contains($0.id) }) {
                onOpen(row)
            }
        }
        .accessibilityLabel(kind == .apps ? "Top apps" : "Top hosts")
        .accessibilityValue(rows.prefix(3).map {
            "\($0.name) \(Self.percent(scopedBytes > 0 ? Double($0.totalBytes) / Double(scopedBytes) : 0))"
        }.joined(separator: ", "))
    }

    // MARK: Private

    /// Bordered rows measure 24pt plus a hairline; the header 28pt. A little
    /// slack keeps the table from growing its own scroll bar.
    private static let rowHeight: CGFloat = 24
    private static let headerHeight: CGFloat = 36

    @State private var selection: TrafficRankingEntry.ID?

    private var leadingBytes: Int {
        max(1, rows.map(\.totalBytes).max() ?? 1)
    }

    /// The row's bytes against the leader, split into client-sent and
    /// server-received, with its share of the scope — the ranking read at a
    /// glance inside the table.
    private func shareCell(_ row: TrafficRankingEntry) -> some View {
        let leading = Double(leadingBytes)
        let share = scopedBytes > 0 ? Double(row.totalBytes) / Double(scopedBytes) : 0
        return HStack(spacing: Theme.Metrics.spacingM) {
            OverviewDirectionBar(
                sentFraction: Double(row.sentBytes) / leading,
                receivedFraction: Double(row.receivedBytes) / leading
            )
            Text(Self.percent(share))
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .monospacedDigit()
                .frame(width: 36, alignment: .trailing)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(Self.percent(share)) of scope")
    }

    private func numeric(_ text: String) -> some View {
        Text(text)
            .monospacedDigit()
            .frame(maxWidth: .infinity, alignment: .trailing)
    }

    private static func bytes(_ count: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(count), countStyle: .binary)
    }

    private static func percent(_ fraction: Double) -> String {
        let clamped = min(max(fraction, 0), 1)
        if clamped > 0, clamped < 0.01 {
            return "<1%"
        }
        return clamped.formatted(.percent.precision(.fractionLength(0)))
    }
}

// MARK: - OverviewFactTable

/// A compact two-column report table for facts that are not a ranking —
/// storage, provenance, coverage.
struct OverviewFactTable: View {
    struct Row: Identifiable {
        let label: String
        let value: String
        var tint: Color = .primary

        var id: String {
            label
        }
    }

    let rows: [Row]

    var body: some View {
        VStack(spacing: 0) {
            ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                HStack(alignment: .firstTextBaseline) {
                    Text(row.label)
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                    Spacer(minLength: Theme.Metrics.spacingM)
                    Text(row.value)
                        .font(Theme.Typography.caption)
                        .foregroundStyle(row.tint)
                        .monospacedDigit()
                        .multilineTextAlignment(.trailing)
                }
                .padding(.vertical, Theme.Metrics.controlSpacing)
                .padding(.horizontal, Theme.Metrics.spacingM)
                .background(index.isMultiple(of: 2) ? Color.primary.opacity(0.03) : .clear)
                .accessibilityElement(children: .combine)
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: Theme.Metrics.pillCornerRadius, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: Theme.Metrics.pillCornerRadius, style: .continuous)
                .stroke(.primary.opacity(Theme.Glass.neutralStrokeOpacity), lineWidth: 1)
        }
    }
}
