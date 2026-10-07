import Foundation

// This file owns every user-visible word and number for the TCP health charts,
// exactly as `SessionResponseTimes` owns the response-time rows: the view below it
// draws marks and axes only, so the claims stay testable without a window. It reads
// the series `TCPStreamHealth` derived and adds no point, unit, threshold, severity
// or cause of its own.
//
// Three rules, and they are the contract for adding a chart or a line:
// 1. A label names *what was measured between frames*, never a judgement about it.
//    There is no "slow", no "congested", no target line and no colour that means bad.
// 2. A direction is named by the endpoint the frames came from — never "client",
//    "server", "up" or "down", which the passive fold does not know.
// 3. What the chart does *not* cover is stated once, beneath it, in at most two
//    lines: where the retained run ends, and what is known about fidelity.

// MARK: - SessionStreamChartLine

/// One line ready to draw: the phrase naming it, the canonical direction it is about,
/// and the points in capture order.
nonisolated struct SessionStreamChartLine: Identifiable, Hashable, Sendable {
    // MARK: Lifecycle

    init(series: TCPStreamSeries, tuple: FiveTuple) {
        id = series.id
        role = series.role
        direction = series.direction
        label = Self.phrase(for: series.role, tuple: tuple, direction: series.direction)
        points = series.points
    }

    // MARK: Internal

    let id: Int
    let role: TCPStreamSeriesRole
    let direction: ConnectionDirection
    /// What this line is, naming its direction by the endpoint the frames came from.
    let label: String
    let points: [TCPStreamPoint]

    /// The phrase naming one line. Observation-only by construction: each says what
    /// the frames showed, never why.
    static func phrase(
        for role: TCPStreamSeriesRole,
        tuple: FiveTuple,
        direction: ConnectionDirection
    )
        -> String
    {
        let endpoint = direction == .aToB ? tuple.a.display : tuple.b.display
        return switch role {
        case .roundTrip,
             .sequenceReached,
             .throughput: "Sent by \(endpoint)"
        case .sequenceAcknowledged: "Acknowledged to \(endpoint)"
        case .receiveWindowOffered: "Offered to \(endpoint)"
        case .bytesInFlight: "Unacknowledged from \(endpoint)"
        }
    }
}

// MARK: - SessionStreamChart

/// One chart the user can select: its title, the caption naming the vertical axis,
/// its lines, and the one line of prose — if any — that only this chart needs.
nonisolated struct SessionStreamChart: Identifiable, Hashable, Sendable {
    let kind: TCPStreamSeriesKind
    /// The picker segment and the chart's own name.
    let title: String
    /// What the vertical axis measures, stated once under the chart.
    let axisCaption: String
    let lines: [SessionStreamChartLine]
    /// A caveat true of this chart alone (today: an unscaled receive window).
    let caveat: String?

    var id: Int {
        kind.rawValue
    }

    /// The picker segment title for a chart. Two words at most: the segment strip has
    /// to stay readable in a narrow inspector column.
    static func name(for kind: TCPStreamSeriesKind) -> String {
        switch kind {
        case .sequence: "Sequence"
        case .throughput: "Throughput"
        case .roundTrip: "Round Trip"
        case .receiveWindow: "Window"
        }
    }

    /// What the vertical axis measures. It names the unit *and* the reference point,
    /// because a relative sequence number means nothing without saying what it is
    /// relative to.
    static func caption(for kind: TCPStreamSeriesKind) -> String {
        switch kind {
        case .sequence: "Bytes past each direction's first observed sequence number"
        case .throughput: "Wire bytes per second"
        case .roundTrip: "Seconds from a segment to the acknowledgement covering it"
        case .receiveWindow: "Bytes"
        }
    }
}

// MARK: - SessionStreamHealth

/// The TCP health panel for one selected session: its charts in a fixed order plus
/// the coverage lines that apply to all of them.
nonisolated struct SessionStreamHealth: Hashable, Sendable {
    // MARK: Lifecycle

    /// Project one derived health value into charts. The input is expected to be the
    /// projection's own deterministic order; this initializer preserves it and
    /// re-derives nothing.
    init(health: TCPStreamHealth) {
        charts = health.availableKinds.map { kind in
            SessionStreamChart(
                kind: kind,
                title: SessionStreamChart.name(for: kind),
                axisCaption: SessionStreamChart.caption(for: kind),
                lines: health.series(for: kind).map { SessionStreamChartLine(series: $0, tuple: health.tuple) },
                caveat: Self.caveat(for: kind, coverage: health.coverage)
            )
        }
        caveats = Self.caveats(for: health.coverage)
    }

    private init(charts: [SessionStreamChart], caveats: [String]) {
        self.charts = charts
        self.caveats = caveats
    }

    // MARK: Internal

    /// Nothing to draw: a session with no retained TCP segments at all.
    static let empty = SessionStreamHealth(charts: [], caveats: [])

    let charts: [SessionStreamChart]
    /// At most two lines, in this order: where the retained run ends, then what is
    /// known about the fidelity of the frames inside it.
    let caveats: [String]

    var isEmpty: Bool {
        charts.isEmpty
    }

    /// The panel-wide coverage lines. The first says what run of frames the charts are
    /// drawn from, and appears only when the run ended before the session did. The
    /// second states fidelity with strict precedence — retained segments that could not
    /// be plotted at all outrank a reported loss, which outranks a short capture, which
    /// outranks unknown loss — and a capture with none of those says nothing rather
    /// than promising completeness.
    static func caveats(for coverage: TCPStreamCoverage) -> [String] {
        var lines: [String] = []
        if coverage.isTruncated, let first = coverage.firstOrdinal, let last = coverage.lastOrdinal {
            lines.append(
                "These charts cover frames \(first.formatted()) to \(last.formatted()) of this session; "
                    + "\(coverage.omittedSegmentCount.formatted()) later segments were not retained."
            )
        }
        if coverage.untimedSegmentCount > 0 {
            lines.append(
                "\(coverage.untimedSegmentCount.formatted()) retained segments carried no capture time "
                    + "and are not plotted."
            )
        } else if coverage.lossKnowledge == .lossReported {
            lines.append(
                "Capture loss was reported for this session, so segments may be missing between "
                    + "the points drawn here."
            )
        } else if coverage.snapLengthTruncationObserved {
            lines.append(
                "At least one segment was captured shorter than it was sent, so a payload length "
                    + "here may be below what crossed the wire."
            )
        } else if coverage.lossKnowledge == .unknown {
            lines.append(
                "This capture reports nothing about dropped frames, so completeness between "
                    + "these points is unknown."
            )
        }
        return Array(lines.prefix(2))
    }

    /// The caveat only one chart needs. Today that is the receive window, whose values
    /// can be understated by up to 2^14 when the frames never showed the scale.
    static func caveat(for kind: TCPStreamSeriesKind, coverage: TCPStreamCoverage) -> String? {
        guard kind == .receiveWindow, coverage.windowScaling == .notObserved else {
            return nil
        }
        return "No SYN carrying a window scale was retained for one side, so these are the raw "
            + "advertised values and the real window may be larger."
    }

    /// The shared formatter for one plotted value, chosen by its role so the same
    /// number never reads in two units.
    static func valueLabel(_ value: Double, role: TCPStreamSeriesRole) -> String {
        switch role {
        case .sequenceReached,
             .sequenceAcknowledged,
             .receiveWindowOffered,
             .bytesInFlight:
            ByteUnits.string(Int64(max(0, value.rounded())))
        case .throughput:
            "\(ByteUnits.string(Int64(max(0, value.rounded()))))/s"
        case .roundTrip:
            SessionResponseTimes.durationLabel(value)
        }
    }

    /// The chart matching a remembered selection, or the first one. A session whose
    /// previously-selected chart has nothing to draw falls back rather than blanking.
    func chart(for kind: TCPStreamSeriesKind?) -> SessionStreamChart? {
        guard let kind, let match = charts.first(where: { $0.kind == kind }) else {
            return charts.first
        }
        return match
    }
}
