import Foundation
import Testing
@testable import Tracexy

@Suite("History surface truth and footer copy")
struct HistoryViewModelTests {
    @Test("Capture state keeps unavailable loading failure empty and content distinct")
    func captureStateResolution() {
        #expect(HistoryCaptureSurfaceState.resolve(
            availability: .unavailable,
            captureCount: 0,
            unavailableReason: "disk unavailable"
        ) == .unavailable("disk unavailable"))
        #expect(HistoryCaptureSurfaceState.resolve(
            availability: .loading,
            captureCount: 0,
            unavailableReason: nil
        ) == .loading)
        #expect(HistoryCaptureSurfaceState.resolve(
            availability: .failed("corrupt"),
            captureCount: 0,
            unavailableReason: nil
        ) == .failed("corrupt"))
        #expect(HistoryCaptureSurfaceState.resolve(
            availability: .loaded,
            captureCount: 0,
            unavailableReason: nil
        ) == .empty)
        #expect(HistoryCaptureSurfaceState.resolve(
            availability: .loaded,
            captureCount: 1,
            unavailableReason: nil
        ) == .content)
    }

    @Test("Session state never mistakes no selection or an empty capture for loading")
    func sessionStateResolution() {
        #expect(HistorySessionSurfaceState.resolve(
            selectedCaptureID: nil,
            availability: .loaded,
            sessionCount: 10
        ) == .noSelection)
        let captureID = UUID()
        #expect(HistorySessionSurfaceState.resolve(
            selectedCaptureID: captureID,
            availability: .loading,
            sessionCount: 0
        ) == .loading)
        #expect(HistorySessionSurfaceState.resolve(
            selectedCaptureID: captureID,
            availability: .loaded,
            sessionCount: 0
        ) == .empty)
        #expect(HistorySessionSurfaceState.resolve(
            selectedCaptureID: captureID,
            availability: .loaded,
            sessionCount: 1
        ) == .content)
    }

    @Test("Footer marks bounded subtotals when more keyset pages exist")
    func footerBoundedTotals() {
        #expect(HistoryFooterModel.statusText(
            captureCount: 0,
            sessionCount: 0,
            hasMore: false
        ) == "Local History · No captures")
        #expect(HistoryFooterModel.statusText(
            captureCount: 1,
            sessionCount: 1,
            hasMore: false
        ) == "1 capture · 1 persisted session")
        #expect(HistoryFooterModel.statusText(
            captureCount: 100,
            sessionCount: 900,
            hasMore: true
        ) == "100+ captures · 900+ persisted sessions")
    }
}
