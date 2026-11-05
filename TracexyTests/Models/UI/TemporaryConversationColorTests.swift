import Foundation
import Testing
@testable import Tracexy

@MainActor
@Suite("Temporary conversation colors")
struct TemporaryConversationColorTests {
    @Test
    func paletteIsDistinctAndMeetsTheSavedRuleContrastThreshold() {
        let backgrounds = TemporaryConversationColorPalette.backgroundRGB
        #expect(backgrounds.count == CaptureFrameListState.maximumTemporaryConversationColorSlots)
        #expect(Set(backgrounds).count == backgrounds.count)
        for (slot, background) in backgrounds.enumerated() {
            #expect(FrameColorRuleLibrary.isValid(FrameColorRule(
                name: "Temporary slot \(slot + 1)", expression: "tcp.syn",
                foregroundRGB: TemporaryConversationColorPalette.foregroundRGB,
                backgroundRGB: background
            )))
        }
    }

    @Test
    func assignsDistinctBoundedSlotsAndReusesClearedSlots() throws {
        let state = CaptureFrameListState()
        let sessions = (0 ..< CaptureFrameListState.maximumTemporaryConversationColorSlots + 1).map { _ in UUID() }
        let newSessionID = try #require(sessions.last)

        for (slot, sessionID) in sessions.dropLast().enumerated() {
            #expect(state.toggleTemporaryConversationColor(sessionID: sessionID))
            #expect(state.temporaryConversationColorSlots[sessionID] == slot)
        }
        #expect(!state.toggleTemporaryConversationColor(sessionID: newSessionID))
        #expect(state.temporaryConversationColorSlots.count == CaptureFrameListState
            .maximumTemporaryConversationColorSlots)

        let removed = sessions[2]
        #expect(state.toggleTemporaryConversationColor(sessionID: removed))
        #expect(state.toggleTemporaryConversationColor(sessionID: newSessionID))
        #expect(state.temporaryConversationColorSlots[newSessionID] == 2)
    }

    @Test
    func sessionlessRowsCannotBeColoredAndCaptureResetClearsSlots() {
        let state = CaptureFrameListState()
        let sessionID = UUID()
        #expect(!state.toggleTemporaryConversationColor(sessionID: nil))
        #expect(state.toggleTemporaryConversationColor(sessionID: sessionID))

        state.cancel(clearList: false)
        #expect(state.temporaryConversationColorSlots[sessionID] == 0)

        state.cancel(clearList: true)

        #expect(state.temporaryConversationColorSlots.isEmpty)
    }
}
