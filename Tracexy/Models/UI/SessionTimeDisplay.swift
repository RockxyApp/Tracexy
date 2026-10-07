import Foundation
import Observation

// MARK: - SessionTimeFormat

/// How the Sessions table shows when each session started.
nonisolated enum SessionTimeFormat: String, CaseIterable, Identifiable, Sendable {
    /// Local time of day, as the rest of macOS shows it.
    case timeOfDay
    /// Coordinated Universal Time, for lining up with server logs.
    case utc
    /// Seconds since the capture's first timed frame.
    case sinceCaptureStart

    // MARK: Internal

    var id: String {
        rawValue
    }

    var menuTitle: String {
        switch self {
        case .timeOfDay: "Time of Day"
        case .utc: "Time of Day (UTC)"
        case .sinceCaptureStart: "Seconds Since Capture Start"
        }
    }

    var columnTitle: String {
        switch self {
        case .timeOfDay: "Time"
        case .utc: "UTC"
        case .sinceCaptureStart: "Since Start"
        }
    }

    /// `date` in this format. Seconds since start need the capture's first timed
    /// frame; without one the time of day is shown instead of an invented origin.
    func string(for date: Date, captureStart: Date?) -> String {
        switch self {
        case .timeOfDay:
            return date.formatted(.dateTime.hour().minute().second())
        case .utc:
            return Self.utcFormatter.string(from: date)
        case .sinceCaptureStart:
            guard let captureStart else {
                return date.formatted(.dateTime.hour().minute().second())
            }
            return String(format: "%.3f", max(0, date.timeIntervalSince(captureStart)))
        }
    }

    // MARK: Private

    private static let utcFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "HH:mm:ss"
        return formatter
    }()
}

// MARK: - SessionTimeDisplay

/// View ▸ Session Time: the active Project's choice, written through to its suite.
@MainActor
@Observable
final class SessionTimeDisplay {
    // MARK: Internal

    /// The frame marked as time zero; capture-local, never persisted.
    var frameReference: FrameTimeReference?
    /// The frame last chosen in a frame list — what ⌘T marks.
    var selectedFrame: FrameTimeReference?

    var format: SessionTimeFormat = .timeOfDay {
        didSet {
            defaults?.set(format.rawValue, forKey: ProjectScopedSettingsKeys.sessionTimeFormat)
        }
    }

    /// View ▸ Frame Time: how frame lists show each frame's time.
    var frameFormat: FrameTimeFormat = .sinceSessionStart {
        didSet {
            defaults?.set(frameFormat.rawValue, forKey: ProjectScopedSettingsKeys.frameTimeFormat)
        }
    }

    var selectedFrameIsReference: Bool {
        selectedFrame != nil && frameReference == selectedFrame
    }

    /// ⌘T: mark the chosen frame as time zero, or clear it when it already is.
    func toggleReferenceOnSelectedFrame() {
        guard let selectedFrame else {
            return
        }
        frameReference = frameReference == selectedFrame ? nil : selectedFrame
    }

    func bind(to defaults: UserDefaults) {
        self.defaults = nil
        format = defaults.string(forKey: ProjectScopedSettingsKeys.sessionTimeFormat)
            .flatMap(SessionTimeFormat.init(rawValue:)) ?? .timeOfDay
        frameFormat = defaults.string(forKey: ProjectScopedSettingsKeys.frameTimeFormat)
            .flatMap(FrameTimeFormat.init(rawValue:)) ?? .sinceSessionStart
        frameReference = nil
        self.defaults = defaults
    }

    // MARK: Private

    @ObservationIgnored private var defaults: UserDefaults?
}
