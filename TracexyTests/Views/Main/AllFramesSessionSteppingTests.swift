import Foundation
import Testing
@testable import Tracexy

/// Wireshark's Next/Previous Packet in Conversation (⌃. / ⌃,) in View ▸
/// All Frames steps between the frames of the selected frame's session the list shows.
@MainActor
struct AllFramesSessionSteppingTests {
    @Test
    func stepsWithinTheSelectedSession() {
        let first = UUID()
        let second = UUID()
        let rows = [(1, first), (2, second), (3, first), (5, nil), (8, first)].map { ordinal, session in
            CaptureFrameRow(
                provenance: SessionFrameProvenance(
                    ordinal: FrameOrdinal(rawValue: UInt64(ordinal)), timestamp: nil, capturedLength: 0,
                    originalLength: 0, linkType: LinkType.ethernet
                ),
                source: "", destination: "", protocolName: "", info: "", sessionID: session, interfaceID: 0,
                hasComment: false
            )
        }
        #expect(AllFramesWindow.adjacentInSession(from: 1, forward: true, rows: rows) == 3)
        #expect(AllFramesWindow.adjacentInSession(from: 3, forward: true, rows: rows) == 8)
        #expect(AllFramesWindow.adjacentInSession(from: 8, forward: true, rows: rows) == nil)
        #expect(AllFramesWindow.adjacentInSession(from: 8, forward: false, rows: rows) == 3)
        #expect(AllFramesWindow.adjacentInSession(from: 2, forward: true, rows: rows) == nil)
        // A frame that belongs to no session has none to step through.
        #expect(AllFramesWindow.adjacentInSession(from: 5, forward: true, rows: rows) == nil)
        #expect(AllFramesWindow.adjacentInSession(from: nil, forward: true, rows: rows) == nil)
    }
}
