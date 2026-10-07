import SwiftUI

// MARK: - SessionTimelineBar

/// One session's span drawn against the span of the sessions in view, so the table
/// shows *when* each conversation happened. Drawn only from the session's own
/// capture-timed start and duration: an untimed session draws nothing, never a
/// guessed position, and a session shorter than a pixel still gets a visible tick.
struct SessionTimelineBar: View {
    // MARK: Internal

    let session: SessionSummary
    let span: ClosedRange<Date>?

    var body: some View {
        GeometryReader { proxy in
            if let fraction {
                let width = proxy.size.width
                let start = width * fraction.lowerBound
                let length = max(2, width * (fraction.upperBound - fraction.lowerBound))
                ZStack(alignment: .leading) {
                    Capsule()
                        .fill(.quaternary)
                        .frame(height: 4)
                    Capsule()
                        .fill(Theme.color(for: session.primaryProtocol))
                        .frame(width: min(length, width - start), height: 6)
                        .offset(x: start)
                }
                .frame(maxHeight: .infinity)
            }
        }
        .accessibilityElement()
        .accessibilityLabel("Timeline")
        .accessibilityValue(accessibilityValue)
        .help(accessibilityValue)
    }

    /// The earliest start to the latest end among `sessions`, from known times only.
    static func span(of sessions: [SessionSummary]) -> ClosedRange<Date>? {
        var lower: Date?
        var upper: Date?
        for session in sessions {
            guard let start = session.startTime else {
                continue
            }
            let end = start.addingTimeInterval(max(0, session.duration ?? 0))
            lower = min(lower ?? start, start)
            upper = max(upper ?? end, end)
        }
        guard let lower, let upper else {
            return nil
        }
        return lower ... upper
    }

    /// This session's start and end as fractions of `span`, or `nil` when it cannot
    /// be placed.
    static func fraction(of session: SessionSummary, in span: ClosedRange<Date>?) -> ClosedRange<Double>? {
        guard let span, let start = session.startTime else {
            return nil
        }
        let total = span.upperBound.timeIntervalSince(span.lowerBound)
        guard total > 0 else {
            return 0 ... 1
        }
        let from = start.timeIntervalSince(span.lowerBound) / total
        let to = (start.timeIntervalSince(span.lowerBound) + max(0, session.duration ?? 0)) / total
        return min(max(from, 0), 1) ... min(max(to, from), 1)
    }

    // MARK: Private

    private var fraction: ClosedRange<Double>? {
        Self.fraction(of: session, in: span)
    }

    private var accessibilityValue: String {
        guard let span, let start = session.startTime else {
            return "No capture time"
        }
        let offset = start.timeIntervalSince(span.lowerBound)
        let duration = session.duration.map { String(format: "%.3f s", $0) } ?? "unknown duration"
        return String(format: "Starts %.3f s into the view, lasting ", offset) + duration
    }
}

// MARK: - SessionCompletenessCell

/// The optional Completeness column: Wireshark's stage string for a TCP session
/// (R·F·D·A·S·S), with the plain label and the number in its help text.
struct SessionCompletenessCell: View {
    let session: SessionSummary

    var body: some View {
        if session.protocolStack.contains(.tcp) {
            let completeness = session.tcpCompleteness
            Text(completeness.stageString)
                .font(Theme.Typography.monoSmall)
                .foregroundStyle(completeness.isComplete ? .primary : .secondary)
                .help("\(completeness.label) — tcp.completeness == \(completeness.rawValue)")
                .accessibilityLabel(completeness.label)
        } else {
            Text("—").font(Theme.Typography.monoSmall).foregroundStyle(.tertiary)
        }
    }
}
