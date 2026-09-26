import Foundation
import Testing
@testable import Tracexy

/// View ▸ Frame Time and the ⌘T time reference, as Wireshark's time display formats.
struct FrameTimeFormatTests {
    // MARK: Internal

    @Test
    func relativeAndAbsoluteFormats() {
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        let frame = start.addingTimeInterval(1.5)
        #expect(text(.sinceSessionStart, frame, sessionStart: start) == "1.500000")
        #expect(text(.sinceCaptureStart, frame, captureStart: start.addingTimeInterval(-1)) == "2.500000")
        #expect(text(.sincePreviousFrame, frame, previous: start.addingTimeInterval(1.25)) == "0.250000")
        #expect(text(.sincePreviousFrame, frame) == "0.000000", "the first listed frame has no predecessor")
        #expect(text(.epoch, frame) == "1700000001.500000")
        #expect(text(.utc, frame) == "2023-11-14 22:13:21.500000")
        #expect(text(.sinceSessionStart, nil, sessionStart: start) == "—", "an untimed frame is never zero")
    }

    @Test
    func aReferenceRestartsLaterFramesAndReadsREF() {
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        let session = UUID()
        let reference = FrameTimeReference(sessionID: session, ordinal: 5, timestamp: start.addingTimeInterval(2))
        #expect(text(
            .sinceSessionStart,
            start.addingTimeInterval(2),
            ordinal: 5,
            sessionStart: start,
            reference: reference
        )
            == "*REF*")
        #expect(text(
            .sinceSessionStart,
            start.addingTimeInterval(3),
            ordinal: 7,
            sessionStart: start,
            reference: reference
        )
            == "1.000000")
        #expect(
            text(.sinceSessionStart, start.addingTimeInterval(1), ordinal: 3, sessionStart: start, reference: reference)
                == "1.000000",
            "earlier frames keep their own origin"
        )
        #expect(text(.utc, start, ordinal: 5, reference: reference) == "*REF*")
    }

    @MainActor
    @Test
    func commandTTogglesTheChosenFrame() {
        let display = SessionTimeDisplay()
        let frame = FrameTimeReference(sessionID: UUID(), ordinal: 9, timestamp: Date())
        display.toggleReferenceOnSelectedFrame()
        #expect(display.frameReference == nil, "nothing chosen, nothing marked")
        display.selectedFrame = frame
        display.toggleReferenceOnSelectedFrame()
        #expect(display.frameReference == frame)
        display.toggleReferenceOnSelectedFrame()
        #expect(display.frameReference == nil)
    }

    // MARK: Private

    private func text(
        _ format: FrameTimeFormat,
        _ timestamp: Date?,
        ordinal: UInt64 = 1,
        previous: Date? = nil,
        sessionStart: Date? = nil,
        captureStart: Date? = nil,
        reference: FrameTimeReference? = nil
    )
        -> String
    {
        FrameTimeFormat.text(
            format, timestamp: timestamp, ordinal: ordinal, previous: previous,
            sessionStart: sessionStart, captureStart: captureStart, reference: reference
        )
    }
}
