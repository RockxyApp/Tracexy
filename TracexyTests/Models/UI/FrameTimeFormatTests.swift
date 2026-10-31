import Foundation
import Testing
@testable import Tracexy

/// View ▸ Frame Time and the ⌘T time reference, as Wireshark's time display formats.
struct FrameTimeFormatTests {
    // MARK: Internal

    @Test
    func focusedTimeReferenceTargetsAreBoundToProjectCaptureAndSession() {
        let projectID = UUID()
        let sessionID = UUID()
        let reference = FrameTimeReference(sessionID: sessionID, ordinal: 4, timestamp: Date())
        let sessionTarget = FrameTimeCommandTarget(
            reference: reference,
            projectID: projectID,
            captureGeneration: 12,
            captureRow: nil
        )
        #expect(sessionTarget.isCurrent(projectID: projectID, captureGeneration: 12, sessionID: sessionID))
        #expect(!sessionTarget.isCurrent(projectID: UUID(), captureGeneration: 12, sessionID: sessionID))
        #expect(!sessionTarget.isCurrent(projectID: projectID, captureGeneration: 13, sessionID: sessionID))
        #expect(!sessionTarget.isCurrent(projectID: projectID, captureGeneration: 12, sessionID: UUID()))

        let captureTarget = FrameTimeCommandTarget(
            reference: .init(sessionID: nil, ordinal: 4, timestamp: reference.timestamp),
            projectID: projectID,
            captureGeneration: 12,
            captureRow: nil
        )
        #expect(captureTarget.isCurrent(projectID: projectID, captureGeneration: 12, sessionID: nil))
        #expect(captureTarget.isCurrent(projectID: projectID, captureGeneration: 12, sessionID: sessionID))
    }

    @Test
    func relativeAndAbsoluteFormats() {
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        let frame = start.addingTimeInterval(1.5)
        #expect(text(.sinceSessionStart, frame, sessionStart: start) == "1.500000")
        #expect(text(.sinceCaptureStart, frame, captureStart: start.addingTimeInterval(-1)) == "2.500000")
        #expect(text(.sincePreviousFrame, frame, previous: .timestamp(start.addingTimeInterval(1.25))) == "0.250000")
        #expect(text(.sincePreviousFrame, frame, previous: .none) == "0.000000")
        #expect(text(.sincePreviousFrame, frame) == "—", "an unknown predecessor is not zero")
        #expect(text(
            .sincePreviousCapturedFrame,
            frame,
            previousCaptured: .timestamp(start.addingTimeInterval(1))
        ) == "0.500000")
        #expect(text(.sincePreviousCapturedFrame, frame, previousCaptured: .unknown) == "—")
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
            references: [reference],
            sessionID: session
        )
            == "*REF*")
        #expect(text(
            .sinceSessionStart,
            start.addingTimeInterval(3),
            ordinal: 7,
            sessionStart: start,
            references: [reference],
            sessionID: session
        )
            == "1.000000")
        #expect(
            text(
                .sinceSessionStart, start.addingTimeInterval(1), ordinal: 3, sessionStart: start,
                references: [reference], sessionID: session
            )
                == "1.000000",
            "earlier frames keep their own origin"
        )
        #expect(text(.utc, start, ordinal: 5, references: [reference], sessionID: session) == "*REF*")
    }

    @Test
    func multipleReferencesUseNearestEarlierCaptureOrdinalAndStaySessionScoped() {
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        let session = UUID()
        let otherSession = UUID()
        let references = [
            FrameTimeReference(sessionID: session, ordinal: 7, timestamp: start.addingTimeInterval(1)),
            FrameTimeReference(sessionID: session, ordinal: 3, timestamp: start.addingTimeInterval(2)),
            FrameTimeReference(sessionID: otherSession, ordinal: 6, timestamp: start.addingTimeInterval(4)),
        ]
        #expect(text(
            .sinceSessionStart,
            start.addingTimeInterval(1),
            ordinal: 2,
            sessionStart: start,
            references: references,
            sessionID: session
        ) == "1.000000")
        #expect(text(
            .sinceSessionStart,
            start.addingTimeInterval(4),
            ordinal: 5,
            sessionStart: start,
            references: references,
            sessionID: session
        ) == "2.000000")
        #expect(text(
            .sinceSessionStart,
            start.addingTimeInterval(1),
            ordinal: 7,
            sessionStart: start,
            references: references,
            sessionID: session
        ) == "*REF*")
        #expect(text(
            .sinceSessionStart,
            start.addingTimeInterval(6),
            ordinal: 8,
            sessionStart: start,
            references: references,
            sessionID: session
        ) == "5.000000")
        #expect(text(
            .sinceSessionStart,
            start.addingTimeInterval(6),
            ordinal: 6,
            sessionStart: start,
            references: references,
            sessionID: session
        ) == "4.000000")
    }

    @Test
    func captureWideReferenceAppliesAcrossSessionsButSessionReferenceDoesNotLeakToAllFrames() {
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        let session = UUID()
        let otherSession = UUID()
        let captureReference = FrameTimeReference(
            sessionID: nil, ordinal: 4, timestamp: start.addingTimeInterval(2)
        )
        #expect(text(
            .sinceCaptureStart, start.addingTimeInterval(5), ordinal: 5,
            captureStart: start, references: [captureReference], sessionID: session
        ) == "3.000000")
        #expect(text(
            .sinceCaptureStart, start.addingTimeInterval(2), ordinal: 4,
            captureStart: start, references: [captureReference], sessionID: otherSession
        ) == "*REF*")

        let sessionReference = FrameTimeReference(
            sessionID: otherSession, ordinal: 2, timestamp: start.addingTimeInterval(1)
        )
        #expect(text(
            .sinceCaptureStart, start.addingTimeInterval(3), ordinal: 3,
            captureStart: start, references: [sessionReference]
        ) == "3.000000")
    }

    @MainActor
    @Test
    func commandTTogglesTheChosenFrame() {
        let display = SessionTimeDisplay()
        let frame = FrameTimeReference(sessionID: UUID(), ordinal: 9, timestamp: Date())
        display.toggleReferenceOnSelectedFrame()
        #expect(display.frameTimeReferences.isEmpty, "nothing chosen, nothing marked")
        display.selectedFrame = frame
        display.toggleReferenceOnSelectedFrame()
        #expect(display.frameTimeReferences == [frame])
        #expect(display.selectedFrameIsReference)
        display.toggleReferenceOnSelectedFrame()
        #expect(display.frameTimeReferences.isEmpty)
        #expect(!display.selectedFrameIsReference)
    }

    @MainActor
    @Test
    func timeReferencesAreBoundedSortedAndClearedOnProjectBinding() throws {
        let suiteName = "FrameTimeDisplayTests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let display = SessionTimeDisplay()
        display.bind(to: defaults)
        let persistedSettings = defaults.persistentDomain(forName: suiteName) ?? [:]
        let session = UUID()
        for ordinal in stride(from: SessionTimeDisplay.maximumTimeReferences, through: 1, by: -1) {
            let reference = FrameTimeReference(
                sessionID: session, ordinal: UInt64(ordinal), timestamp: Date(timeIntervalSince1970: Double(ordinal))
            )
            #expect(display.toggleTimeReference(reference))
        }
        #expect(display.references(forSession: session).map(\.ordinal)
            == (1 ... UInt64(SessionTimeDisplay.maximumTimeReferences)).map { $0 })
        let extra = FrameTimeReference(sessionID: session, ordinal: 99, timestamp: Date())
        #expect(!display.toggleTimeReference(extra))
        #expect(!display.canAddTimeReference(at: extra.ordinal))
        #expect(display.canAddTimeReference(at: 1), "re-scoping a referenced packet does not use another slot")
        #expect(display.referenceLimitReached)
        #expect(display.toggleTimeReference(display.frameTimeReferences[0]))
        #expect(!display.referenceLimitReached)
        #expect(display.frameTimeReferences.count == SessionTimeDisplay.maximumTimeReferences - 1)
        let currentSettings = defaults.persistentDomain(forName: suiteName) ?? [:]
        #expect(NSDictionary(dictionary: currentSettings).isEqual(NSDictionary(dictionary: persistedSettings)))
        display.bind(to: defaults)
        #expect(display.frameTimeReferences.isEmpty)
        #expect(display.selectedFrame == nil)
    }

    @MainActor
    @Test
    func captureReferencesShareTheCapAndCanBeClearedWithoutRemovingSessionReferences() {
        let display = SessionTimeDisplay()
        let sessionID = UUID()
        let sessionReference = FrameTimeReference(sessionID: sessionID, ordinal: 3, timestamp: Date())
        let captureReference = FrameTimeReference(sessionID: nil, ordinal: 9, timestamp: Date())
        #expect(display.toggleTimeReference(sessionReference))
        #expect(display.toggleTimeReference(captureReference))
        #expect(display.references(forSession: sessionID).map(\.ordinal) == [3, 9])
        #expect(display.captureReferences() == [captureReference])
        #expect(display.isTimeReference(sessionID: sessionID, ordinal: 9))
        display.clearCaptureTimeReferences()
        #expect(display.frameTimeReferences == [sessionReference])
        #expect(display.captureReferences().isEmpty)

        let promoted = FrameTimeReference(sessionID: nil, ordinal: 3, timestamp: sessionReference.timestamp)
        #expect(display.toggleTimeReference(promoted))
        #expect(display.frameTimeReferences == [promoted])
    }

    // MARK: Private

    private func text(
        _ format: FrameTimeFormat,
        _ timestamp: Date?,
        ordinal: UInt64 = 1,
        previous: FrameTimePredecessor = .unknown,
        previousCaptured: FrameTimePredecessor = .unknown,
        sessionStart: Date? = nil,
        captureStart: Date? = nil,
        references: [FrameTimeReference] = [],
        sessionID: UUID? = nil
    )
        -> String
    {
        FrameTimeFormat.text(
            format, timestamp: timestamp, ordinal: ordinal, previous: previous, previousCaptured: previousCaptured,
            sessionStart: sessionStart, captureStart: captureStart, references: references, sessionID: sessionID
        )
    }
}
