import Foundation

// MARK: - FrameTimeFormat

/// View ▸ Frame Time: how frame lists show each frame's capture time — Wireshark's
/// Time Display Formats for session-scoped and capture-wide frame lists.
nonisolated enum FrameTimeFormat: String, CaseIterable, Identifiable, Sendable {
    /// Seconds since the session's first listed frame (the default).
    case sinceSessionStart
    /// Seconds since the first captured frame's timestamp.
    case sinceCaptureStart
    /// Seconds since the frame listed before it (Wireshark's "since previous displayed").
    case sincePreviousFrame
    /// Seconds since the immediately preceding packet in capture order.
    case sincePreviousCapturedFrame
    /// Local date and time of day at the selected precision.
    case timeOfDay
    /// UTC date and time of day at the selected precision.
    case utc
    /// Seconds since 1970-01-01 UTC.
    case epoch

    // MARK: Internal

    var id: String {
        rawValue
    }

    var menuTitle: String {
        switch self {
        case .sinceSessionStart: String(localized: "Seconds Since Session Start")
        case .sinceCaptureStart: String(localized: "Seconds Since Capture Start")
        case .sincePreviousFrame: String(localized: "Seconds Since Previous Displayed Frame")
        case .sincePreviousCapturedFrame: String(localized: "Seconds Since Previous Captured Frame")
        case .timeOfDay: String(localized: "Date and Time of Day")
        case .utc: String(localized: "UTC Date and Time of Day")
        case .epoch: String(localized: "Seconds Since 1970 (Epoch)")
        }
    }

    var columnTitle: String {
        switch self {
        case .sinceSessionStart: String(localized: "Time")
        case .sinceCaptureStart: String(localized: "Since Start")
        case .sincePreviousFrame: String(localized: "Since Previous Displayed")
        case .sincePreviousCapturedFrame: String(localized: "Since Previous Captured")
        case .timeOfDay: String(localized: "Time of Day")
        case .utc: String(localized: "UTC")
        case .epoch: String(localized: "Epoch")
        }
    }

    /// The text for one frame. The latest preceding applicable reference restarts
    /// since-start formats; each reference row reads `*REF*`. An untimed frame or
    /// unknown predecessor is an em dash, never zero.
    static func text(
        _ format: FrameTimeFormat,
        timestamp: Date?,
        ordinal: UInt64,
        previous: FrameTimePredecessor = .unknown,
        previousCaptured: FrameTimePredecessor = .unknown,
        sessionStart: Date?,
        captureStart: Date?,
        precision: FrameTimePrecision = .microseconds,
        references: [FrameTimeReference] = [],
        sessionID: UUID? = nil
    )
        -> String
    {
        let scopedReferences = sessionID.map { id in
            references.filter { $0.sessionID == nil || $0.sessionID == id }
        } ?? references.filter { $0.sessionID == nil }
        if scopedReferences.contains(where: { $0.ordinal == ordinal }) {
            return "*REF*"
        }
        guard let timestamp else {
            return "—"
        }
        let precedingReference = scopedReferences.filter { $0.ordinal < ordinal }.max { $0.ordinal < $1.ordinal }
        let origin: Date? = if let precedingReference {
            precedingReference.timestamp
        } else {
            switch format {
            case .sinceSessionStart: sessionStart
            case .sinceCaptureStart: captureStart
            default: nil
            }
        }
        switch format {
        case .sinceSessionStart,
             .sinceCaptureStart:
            guard let origin else {
                return "—"
            }
            return seconds(timestamp.timeIntervalSince(origin), precision: precision)
        case .sincePreviousFrame:
            return delta(timestamp, from: previous, precision: precision)
        case .sincePreviousCapturedFrame:
            return delta(timestamp, from: previousCaptured, precision: precision)
        case .timeOfDay:
            return calendarText(timestamp, formatter: localFormatter, precision: precision)
        case .utc:
            return calendarText(timestamp, formatter: utcFormatter, precision: precision)
        case .epoch:
            return seconds(timestamp.timeIntervalSince1970, precision: precision)
        }
    }

    // MARK: Private

    private static let localFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter
    }()

    private static let utcFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter
    }()

    private static func delta(
        _ timestamp: Date,
        from predecessor: FrameTimePredecessor,
        precision: FrameTimePrecision
    )
        -> String
    {
        switch predecessor {
        case .none: seconds(0, precision: precision)
        case let .timestamp(previous): seconds(timestamp.timeIntervalSince(previous), precision: precision)
        case .unknown: "—"
        }
    }

    private static func seconds(_ interval: TimeInterval, precision: FrameTimePrecision) -> String {
        let ticks = roundedTicks(interval, precision: precision)
        let magnitude = ticks.magnitude
        let divisor = UInt64(precision.scale)
        let whole = magnitude / divisor
        let fraction = magnitude % divisor
        let sign = ticks < 0 ? "-" : ""
        guard precision.fractionalDigits > 0 else {
            return "\(sign)\(whole)"
        }
        return "\(sign)\(whole).\(fractionText(fraction, precision: precision))"
    }

    private static func calendarText(
        _ timestamp: Date,
        formatter: DateFormatter,
        precision: FrameTimePrecision
    )
        -> String
    {
        let ticks = roundedTicks(timestamp.timeIntervalSince1970, precision: precision)
        let divisor = precision.scale
        var wholeSeconds = ticks / divisor
        var fraction = ticks % divisor
        if fraction < 0 {
            wholeSeconds -= 1
            fraction += divisor
        }
        let date = Date(timeIntervalSince1970: Double(wholeSeconds))
        let base = formatter.string(from: date)
        guard precision.fractionalDigits > 0 else {
            return base
        }
        return base + "." + fractionText(UInt64(fraction), precision: precision)
    }

    private static func roundedTicks(_ interval: TimeInterval, precision: FrameTimePrecision) -> Int64 {
        let scaled = interval * Double(precision.scale)
        if scaled >= Double(Int64.max) {
            return .max
        }
        if scaled <= Double(Int64.min) {
            return .min
        }
        return Int64(scaled.rounded(.toNearestOrAwayFromZero))
    }

    private static func fractionText(_ fraction: UInt64, precision: FrameTimePrecision) -> String {
        let text = String(fraction)
        return String(repeating: "0", count: max(0, precision.fractionalDigits - text.count)) + text
    }
}

// MARK: - FrameTimePrecision

/// Presentation precision only. Tracexy does not infer source-clock accuracy.
nonisolated enum FrameTimePrecision: String, CaseIterable, Identifiable, Sendable {
    case seconds
    case milliseconds
    case microseconds

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .seconds: String(localized: "Seconds")
        case .milliseconds: String(localized: "Milliseconds")
        case .microseconds: String(localized: "Microseconds")
        }
    }

    var fractionalDigits: Int {
        switch self {
        case .seconds: 0
        case .milliseconds: 3
        case .microseconds: 6
        }
    }

    var scale: Int64 {
        switch self {
        case .seconds: 1
        case .milliseconds: 1_000
        case .microseconds: 1_000_000
        }
    }
}

// MARK: - FrameTimeReference

/// A temporary time origin selected in a session or capture frame list. Its
/// optional session scope and capture ordinal identify the packet it references.
nonisolated struct FrameTimeReference: Equatable, Sendable {
    /// `nil` identifies a capture-wide reference; otherwise it belongs to one
    /// session frame list while retaining its original capture ordinal.
    let sessionID: UUID?
    let ordinal: UInt64
    let timestamp: Date
}
