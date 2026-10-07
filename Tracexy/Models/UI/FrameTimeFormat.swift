import Foundation

// MARK: - FrameTimeFormat

/// View ▸ Frame Time: how frame lists show each frame's capture time — Wireshark's
/// Time Display Formats, re-expressed for a session's frames.
nonisolated enum FrameTimeFormat: String, CaseIterable, Identifiable, Sendable {
    /// Seconds since the session's first listed frame (the default).
    case sinceSessionStart
    /// Seconds since the capture's first timed frame.
    case sinceCaptureStart
    /// Seconds since the frame listed before it (Wireshark's "since previous displayed").
    case sincePreviousFrame
    /// Local date and time of day, to the microsecond.
    case timeOfDay
    /// UTC date and time of day, to the microsecond.
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
        case .sincePreviousFrame: String(localized: "Seconds Since Previous Frame")
        case .timeOfDay: String(localized: "Date and Time of Day")
        case .utc: String(localized: "UTC Date and Time of Day")
        case .epoch: String(localized: "Seconds Since 1970 (Epoch)")
        }
    }

    var columnTitle: String {
        switch self {
        case .sinceSessionStart: String(localized: "Time")
        case .sinceCaptureStart: String(localized: "Since Start")
        case .sincePreviousFrame: String(localized: "Delta")
        case .timeOfDay: String(localized: "Time of Day")
        case .utc: String(localized: "UTC")
        case .epoch: String(localized: "Epoch")
        }
    }

    /// The text for one frame. `previous` is the frame listed just before it; the
    /// reference, when it belongs to the same list, restarts the relative formats
    /// from itself for every later frame and reads `*REF*` on its own row — as
    /// Wireshark's time reference does. An untimed frame is an em dash, never zero.
    static func text(
        _ format: FrameTimeFormat,
        timestamp: Date?,
        ordinal: UInt64,
        previous: Date?,
        sessionStart: Date?,
        captureStart: Date?,
        reference: FrameTimeReference?
    )
        -> String
    {
        if let reference, reference.ordinal == ordinal {
            return "*REF*"
        }
        guard let timestamp else {
            return "—"
        }
        let origin: Date? = if let reference, reference.ordinal < ordinal {
            reference.timestamp
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
            return seconds(timestamp.timeIntervalSince(origin))
        case .sincePreviousFrame:
            guard let previous else {
                return seconds(0)
            }
            return seconds(timestamp.timeIntervalSince(previous))
        case .timeOfDay:
            return localFormatter.string(from: timestamp)
        case .utc:
            return utcFormatter.string(from: timestamp)
        case .epoch:
            return String(format: "%.6f", timestamp.timeIntervalSince1970)
        }
    }

    // MARK: Private

    private static let localFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSSSSS"
        return formatter
    }()

    private static let utcFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSSSSS"
        return formatter
    }()

    /// Seconds with microseconds, independent of the locale's decimal separator so
    /// times line up with tshark output and paste into logs unchanged.
    private static func seconds(_ interval: TimeInterval) -> String {
        String(format: "%.6f", interval)
    }
}

// MARK: - FrameTimeReference

/// The frame the investigator marked as time zero (Wireshark's ⌘T `*REF*`). It
/// belongs to one session's frame list of one capture source and means nothing
/// outside it.
nonisolated struct FrameTimeReference: Equatable, Sendable {
    let sessionID: UUID
    let ordinal: UInt64
    let timestamp: Date
}
