import Foundation

// This file owns every user-visible word and number for the response-time surface:
// the views below it render rows and buttons only, so the claims stay testable
// without a window. It reads the
// measurements `SessionTimingAssessor` produced and adds no interval, threshold,
// severity or cause of its own.
//
// Three rules, and they are the contract for adding a row:
// 1. A row names *what was measured between two frames*, never a judgement about it.
//    There is no "slow", no colour and no target — a passive capture cannot support one.
// 2. The interval is stated once, in the unit that reads naturally at its scale, and
//    the two frames that bound it are always reachable.
// 3. Capture-loss knowledge is stated once beneath the rows, never hedged into each
//    value.

// MARK: - SessionResponseTimeRow

/// One measured interval, ready to render: the phrase naming it, the formatted value,
/// the two frames that bound it, and a stable identity for `ForEach`.
nonisolated struct SessionResponseTimeRow: Identifiable, Hashable, Sendable {
    let id: UUID
    /// What was measured, as a short noun phrase. Never a verdict.
    let label: String
    /// The interval, formatted at the scale it reads best.
    let value: String
    /// The two bounding frames, oldest first, for the row's inspect route.
    let provenance: [SessionFrameProvenance]
}

// MARK: - SessionResponseTimes

/// The response-time panel for one selected session: its rows in capture order plus the
/// single coverage line, if any, that applies to all of them.
nonisolated struct SessionResponseTimes: Hashable, Sendable {
    // MARK: Lifecycle

    /// Project the measurements belonging to one session. The input is expected to be
    /// the snapshot's own deterministic order; this initializer preserves it and
    /// re-derives nothing.
    init(measurements: [SessionTimingMeasurement]) {
        rows = measurements.map { measurement in
            SessionResponseTimeRow(
                id: measurement.id,
                label: Self.label(for: measurement.kind),
                value: Self.durationLabel(measurement.elapsed),
                provenance: [measurement.start.provenance, measurement.end.provenance]
            )
        }
        // Strict precedence, and stated once: a reported loss outranks unknown loss,
        // and a capture with neither says nothing rather than promising completeness.
        if measurements.contains(where: { $0.lossKnowledge == .lossReported }) {
            caveat = "Capture loss was reported for this session, so an interval "
                + "measured across the missing frames may be longer than the exchange was."
        } else if measurements.contains(where: { $0.lossKnowledge == .unknown }) {
            caveat = "This capture reports nothing about dropped frames, so completeness "
                + "between the two cited frames is unknown."
        } else {
            caveat = nil
        }
    }

    // MARK: Internal

    let rows: [SessionResponseTimeRow]
    /// The one coverage line for the whole panel, or `nil` when there is nothing true
    /// to add.
    let caveat: String?

    var isEmpty: Bool {
        rows.isEmpty
    }

    /// The phrase naming one measured interval. Observation-only by construction: each
    /// says what the frames showed, never why.
    static func label(for kind: SessionTimingMeasurementKind) -> String {
        switch kind {
        case .tcpHandshakeReply: "Connection attempt answered"
        case .tcpHandshakeCompletion: "Handshake completed"
        case .applicationResponse: "First reply after the request"
        case .tlsHandshakeReply: "TLS hello answered"
        case .dnsResponse: "DNS query answered"
        }
    }

    /// The shared formatter for every measured interval: sub-millisecond intervals keep
    /// two decimals so a loopback exchange is not rendered as "0 ms", and anything a
    /// second or longer reads in seconds.
    static func durationLabel(_ elapsed: TimeInterval) -> String {
        let value = max(0, elapsed)
        if value >= 1 {
            return String(format: "%.2f s", value)
        }
        let milliseconds = value * 1_000
        if milliseconds < 1 {
            return String(format: "%.2f ms", milliseconds)
        }
        if milliseconds < 10 {
            return String(format: "%.1f ms", milliseconds)
        }
        return "\(Int(milliseconds.rounded())) ms"
    }
}

// MARK: - SessionResponseTimeDistributionRow

/// One row of the capture-scope response-time table: the kind, how many intervals were
/// measured in the visible scope, the fastest, median and slowest of them, and the
/// session the slowest belongs to so the row can end in a Tracexy action.
nonisolated struct SessionResponseTimeDistributionRow: Identifiable, Hashable, Sendable {
    // MARK: Lifecycle

    init(distribution: SessionTimingDistribution) {
        kind = distribution.kind
        label = SessionResponseTimes.label(for: distribution.kind)
        count = distribution.count
        fastest = SessionResponseTimes.durationLabel(distribution.fastest)
        median = SessionResponseTimes.durationLabel(distribution.median)
        slowest = SessionResponseTimes.durationLabel(distribution.slowest)
        slowestSessionID = distribution.slowestSessionID
    }

    // MARK: Internal

    let kind: SessionTimingMeasurementKind
    let label: String
    let count: Int
    let fastest: String
    let median: String
    let slowest: String
    let slowestSessionID: UUID

    var id: Int {
        kind.rank
    }

    /// "12 measured" — the count is a fact about this scope, so it is spelled out once
    /// in the row rather than repeated in a header.
    var countLabel: String {
        "\(count.formatted()) measured"
    }
}
