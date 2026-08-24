import Testing
@testable import Tracexy

@Suite("Sidebar capture auto-expansion")
struct SidebarCaptureAutoExpansionTests {
    @Test("First decoded session expands capture-derived groups once")
    func firstSessionExpandsOnce() {
        var state = SidebarCaptureAutoExpansionState()

        let empty = state.observe(hasCaptureData: false)
        let firstSession = state.observe(hasCaptureData: true)
        let secondSession = state.observe(hasCaptureData: true)
        let laterSessions = state.observe(hasCaptureData: true)

        #expect(!empty)
        #expect(firstSession)
        #expect(!secondSession)
        #expect(!laterSessions)
    }

    @Test("Empty capture boundary re-arms auto-expansion")
    func captureBoundaryRearmsExpansion() {
        var state = SidebarCaptureAutoExpansionState()

        let firstCapture = state.observe(hasCaptureData: true)
        let reset = state.observe(hasCaptureData: false)
        let nextCapture = state.observe(hasCaptureData: true)

        #expect(firstCapture)
        #expect(!reset)
        #expect(nextCapture)
    }
}
