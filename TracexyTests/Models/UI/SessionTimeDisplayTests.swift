import Foundation
import Testing
@testable import Tracexy

/// View ▸ Session Time: three formats, an honest fallback when a capture has no
/// timed frame, and a per-Project choice that survives rebinding.
@MainActor
struct SessionTimeDisplayTests {
    @Test
    func formatsReadAsNamed() {
        let start = Date(timeIntervalSince1970: 1_800_000_000) // 2027-01-15T08:00:00Z
        let later = start.addingTimeInterval(83.4567)
        #expect(SessionTimeFormat.utc.string(for: later, captureStart: start) == "08:01:23")
        #expect(SessionTimeFormat.sinceCaptureStart.string(for: later, captureStart: start) == "83.457")
        #expect(SessionTimeFormat.sinceCaptureStart.string(for: start, captureStart: start) == "0.000")
        // No timed frame to count from: the time of day, never an invented origin.
        #expect(
            SessionTimeFormat.sinceCaptureStart.string(for: later, captureStart: nil)
                == SessionTimeFormat.timeOfDay.string(for: later, captureStart: nil)
        )
        #expect(SessionTimeFormat.allCases.map(\.columnTitle) == ["Time", "UTC", "Since Start"])
    }

    @Test
    func choiceIsKeptPerProjectSuite() throws {
        let first = "session-time-a-\(UUID().uuidString)"
        let second = "session-time-b-\(UUID().uuidString)"
        let defaultsA = try #require(UserDefaults(suiteName: first))
        let defaultsB = try #require(UserDefaults(suiteName: second))
        defer {
            TestPreferences.remove(first)
            TestPreferences.remove(second)
        }
        let display = SessionTimeDisplay()
        display.bind(to: defaultsA)
        #expect(display.format == .timeOfDay)
        display.format = .utc
        display.bind(to: defaultsB)
        #expect(display.format == .timeOfDay)
        // Binding never writes the incoming Project's value into the other suite.
        #expect(defaultsB.string(forKey: ProjectScopedSettingsKeys.sessionTimeFormat) == nil)
        display.bind(to: defaultsA)
        #expect(display.format == .utc)
    }
}
