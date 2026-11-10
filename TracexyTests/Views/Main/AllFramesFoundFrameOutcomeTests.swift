import Foundation
import Testing
@testable import Tracexy

/// Go to Packet on a frame named elsewhere — the pinned shelf or a find result —
/// must reach a reported outcome in every list state, so an enabled action never
/// looks inert and the view never claims a verdict the list cannot support.
@MainActor
struct AllFramesFoundFrameOutcomeTests {
    @Test
    func everyListStateReachesAReportedOutcome() {
        // On the page and passing the filters: select it outright.
        #expect(AllFramesWindow.foundFrameOutcome(
            ordinal: 7, isVisible: true, isRetained: true, scannedFrameCount: 100
        ) == .select)

        // Retained but filtered out: say so rather than selecting nothing.
        #expect(AllFramesWindow.foundFrameOutcome(
            ordinal: 7, isVisible: false, isRetained: true, scannedFrameCount: 100
        ) == .hiddenByFilters)

        // Within the scan but on another page: page to it.
        #expect(AllFramesWindow.foundFrameOutcome(
            ordinal: 7, isVisible: false, isRetained: false, scannedFrameCount: 100
        ) == .loadPage)

        // The last scanned ordinal is inside the capture, not past it.
        #expect(AllFramesWindow.foundFrameOutcome(
            ordinal: 100, isVisible: false, isRetained: false, scannedFrameCount: 100
        ) == .loadPage)

        // One past the scan is the first ordinal this capture cannot hold.
        #expect(AllFramesWindow.foundFrameOutcome(
            ordinal: 101, isVisible: false, isRetained: false, scannedFrameCount: 100
        ) == .outsideCapture)

        // No list yet — find searches the capture, so it can name a frame while
        // the window still offers List Frames. Nothing has placed this ordinal,
        // so it is listed optimistically instead of being declared outside a
        // capture whose extent is unknown.
        #expect(AllFramesWindow.foundFrameOutcome(
            ordinal: 7, isVisible: false, isRetained: false, scannedFrameCount: nil
        ) == .loadPageBeforeAnyScan)

        // An empty scan still has a known extent, so it can refuse honestly.
        #expect(AllFramesWindow.foundFrameOutcome(
            ordinal: 1, isVisible: false, isRetained: false, scannedFrameCount: 0
        ) == .outsideCapture)

        // Visibility wins over every later branch: a visible row is never
        // reported as filtered, paged or absent.
        #expect(AllFramesWindow.foundFrameOutcome(
            ordinal: 500, isVisible: true, isRetained: false, scannedFrameCount: nil
        ) == .select)
    }
}
