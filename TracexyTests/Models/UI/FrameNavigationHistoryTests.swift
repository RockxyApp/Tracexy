import Foundation
import Testing
@testable import Tracexy

struct FrameNavigationHistoryTests {
    @MainActor
    @Test
    func backForwardAndNewSelectionBranchFromTheCurrentPosition() {
        let state = CaptureFrameListState()
        state.recordFrameSelection(10)
        state.recordFrameSelection(10)
        state.recordFrameSelection(20)
        state.recordFrameSelection(30)

        #expect(state.frameNavigationHistory == [10, 20, 30])
        #expect(state.canNavigateFrameHistoryBackward)
        #expect(!state.canNavigateFrameHistoryForward)
        #expect(state.frameHistoryDestination(backward: true) == 20)
        #expect(state.moveFrameHistoryCursor(backward: true, to: 20))
        #expect(state.frameHistoryDestination(backward: false) == 30)
        #expect(state.moveFrameHistoryCursor(backward: false, to: 30))

        #expect(state.moveFrameHistoryCursor(backward: true, to: 20))
        state.recordFrameSelection(40)
        #expect(state.frameNavigationHistory == [10, 20, 40])
        #expect(!state.canNavigateFrameHistoryForward)
        #expect(!state.moveFrameHistoryCursor(backward: false, to: 30))
    }

    @MainActor
    @Test
    func historyIsBoundedAndCaptureResetClearsIt() {
        let state = CaptureFrameListState()
        for ordinal in 1 ... CaptureFrameListState.maximumFrameNavigationHistoryCount + 3 {
            state.recordFrameSelection(UInt64(ordinal))
        }

        let newestOrdinal = UInt64(CaptureFrameListState.maximumFrameNavigationHistoryCount + 3)
        #expect(state.frameNavigationHistory.count == CaptureFrameListState.maximumFrameNavigationHistoryCount)
        #expect(state.frameNavigationHistory.first == 4)
        #expect(state.frameNavigationHistory.last == newestOrdinal)
        #expect(state.frameHistoryDestination(backward: true) == newestOrdinal - 1)

        state.cancel(clearList: true)
        #expect(state.frameNavigationHistory.isEmpty)
        #expect(state.frameNavigationHistoryIndex == nil)
        #expect(!state.canNavigateFrameHistoryBackward)
        #expect(!state.canNavigateFrameHistoryForward)
    }
}
