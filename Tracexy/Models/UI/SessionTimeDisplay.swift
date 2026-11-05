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

    /// `date` in this format. Seconds since start need the first captured frame's
    /// timestamp; when it is unknown, show an em dash rather than a false origin.
    func string(for date: Date, captureStart: Date?) -> String {
        switch self {
        case .timeOfDay:
            return date.formatted(.dateTime.hour().minute().second())
        case .utc:
            return Self.utcFormatter.string(from: date)
        case .sinceCaptureStart:
            guard let captureStart else {
                return "—"
            }
            return String(format: "%.3f", date.timeIntervalSince(captureStart))
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

    static let maximumTimeReferences = 16

    /// Temporary, capture-local time references, bounded and never persisted.
    private(set) var frameTimeReferences: [FrameTimeReference] = []
    private(set) var referenceLimitReached = false
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

    var framePrecision: FrameTimePrecision = .microseconds {
        didSet {
            defaults?.set(framePrecision.rawValue, forKey: ProjectScopedSettingsKeys.frameTimePrecision)
        }
    }

    var selectedFrameIsReference: Bool {
        selectedFrame.map { reference in
            if let sessionID = reference.sessionID {
                return isTimeReference(sessionID: sessionID, ordinal: reference.ordinal)
            }
            return isCaptureTimeReference(ordinal: reference.ordinal)
        } == true
    }

    func references(forSession sessionID: UUID) -> [FrameTimeReference] {
        frameTimeReferences.filter { $0.sessionID == nil || $0.sessionID == sessionID }
            .sorted { $0.ordinal < $1.ordinal }
    }

    func captureReferences() -> [FrameTimeReference] {
        frameTimeReferences.filter { $0.sessionID == nil }.sorted { $0.ordinal < $1.ordinal }
    }

    func remapReferences(using transform: (FrameTimeReference) -> FrameTimeReference?) {
        frameTimeReferences = frameTimeReferences.compactMap(transform)
        selectedFrame = selectedFrame.flatMap(transform)
    }

    func isCaptureTimeReference(ordinal: UInt64) -> Bool {
        frameTimeReferences.contains { $0.sessionID == nil && $0.ordinal == ordinal }
    }

    func isSessionTimeReference(sessionID: UUID, ordinal: UInt64) -> Bool {
        frameTimeReferences.contains { $0.sessionID == sessionID && $0.ordinal == ordinal }
    }

    func isTimeReference(sessionID: UUID, ordinal: UInt64) -> Bool {
        frameTimeReferences.contains {
            $0.ordinal == ordinal && ($0.sessionID == nil || $0.sessionID == sessionID)
        }
    }

    /// Re-scoping an existing packet reference does not consume another slot.
    func canAddTimeReference(at ordinal: UInt64) -> Bool {
        frameTimeReferences.count < Self.maximumTimeReferences
            || frameTimeReferences.contains { $0.ordinal == ordinal }
    }

    /// Add or remove a timed frame reference. `false` means the bounded list is full.
    @discardableResult
    func toggleTimeReference(_ reference: FrameTimeReference) -> Bool {
        selectedFrame = reference
        if let index = frameTimeReferences.firstIndex(where: {
            $0.sessionID == reference.sessionID && $0.ordinal == reference.ordinal
        }) {
            frameTimeReferences.remove(at: index)
            referenceLimitReached = false
            return true
        }
        // The same capture packet has one time-reference identity. Selecting it
        // from the other list promotes or narrows its scope instead of duplicating it.
        if let index = frameTimeReferences.firstIndex(where: { $0.ordinal == reference.ordinal }) {
            frameTimeReferences.remove(at: index)
        }
        guard frameTimeReferences.count < Self.maximumTimeReferences else {
            referenceLimitReached = true
            return false
        }
        frameTimeReferences.append(reference)
        frameTimeReferences
            .sort {
                $0.ordinal == $1.ordinal
                    ? ($0.sessionID?.uuidString ?? "") < ($1.sessionID?.uuidString ?? "")
                    : $0.ordinal < $1.ordinal
            }
        referenceLimitReached = false
        return true
    }

    /// ⌘T: toggle the chosen frame as one of the active time references.
    func toggleReferenceOnSelectedFrame() {
        guard let selectedFrame else {
            return
        }
        if frameTimeReferences.contains(where: {
            $0.sessionID == selectedFrame.sessionID && $0.ordinal == selectedFrame.ordinal
        }) {
            toggleTimeReference(selectedFrame)
            return
        }
        if selectedFrame.sessionID != nil,
           let captureReference = frameTimeReferences.first(where: {
               $0.sessionID == nil && $0.ordinal == selectedFrame.ordinal
           })
        {
            toggleTimeReference(captureReference)
            return
        }
        toggleTimeReference(selectedFrame)
    }

    func clearTimeReferences() {
        frameTimeReferences = []
        referenceLimitReached = false
    }

    func clearCaptureTimeReferences() {
        frameTimeReferences.removeAll { $0.sessionID == nil }
        referenceLimitReached = false
    }

    func bind(to defaults: UserDefaults) {
        self.defaults = nil
        format = defaults.string(forKey: ProjectScopedSettingsKeys.sessionTimeFormat)
            .flatMap(SessionTimeFormat.init(rawValue:)) ?? .timeOfDay
        frameFormat = defaults.string(forKey: ProjectScopedSettingsKeys.frameTimeFormat)
            .flatMap(FrameTimeFormat.init(rawValue:)) ?? .sinceSessionStart
        framePrecision = defaults.string(forKey: ProjectScopedSettingsKeys.frameTimePrecision)
            .flatMap(FrameTimePrecision.init(rawValue:)) ?? .microseconds
        clearTimeReferences()
        selectedFrame = nil
        self.defaults = defaults
    }

    // MARK: Private

    @ObservationIgnored private var defaults: UserDefaults?
}
