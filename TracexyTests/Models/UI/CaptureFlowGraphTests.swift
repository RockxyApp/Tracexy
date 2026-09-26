import Foundation
import Testing
@testable import Tracexy

/// Statistics ▸ Flow Graph: lanes in order of first appearance, one arrow per frame,
/// bounded lanes, and the ASCII export.
struct CaptureFlowGraphTests {
    // MARK: Internal

    @Test
    func lanesAndArrowsFollowTheFrames() {
        let rows = [
            Self.row(1, "10.0.0.5", "192.0.2.1", info: "SYN"),
            Self.row(2, "192.0.2.1", "10.0.0.5", info: "SYN, ACK"),
            Self.row(3, "10.0.0.5", "198.51.100.9", info: "Query"),
            Self.row(4, "02:00:00:00:00:01", "—", info: "no destination"),
        ]
        let graph = CaptureFlowGraph(rows: rows)
        #expect(graph.lanes == ["10.0.0.5", "192.0.2.1", "198.51.100.9"])
        #expect(graph.arrows.map(\.from) == [0, 1, 0])
        #expect(graph.arrows.map(\.to) == [1, 0, 2])
        let ascii = graph.ascii()
        #expect(ascii.hasPrefix("Time         [0] 10.0.0.5  [1] 192.0.2.1  [2] 198.51.100.9\n"))
        #expect(ascii.contains("0.000000     [0] ──▶ [1]  TCP SYN"))
        #expect(ascii.contains("[0] ◀── [1]  TCP SYN, ACK"))
    }

    @Test
    func lanesAreBounded() {
        let rows = (0 ..< 20).map { index in Self.row(UInt64(index + 1), "10.0.0.\(index)", "192.0.2.1", info: "x") }
        let graph = CaptureFlowGraph(rows: rows)
        #expect(graph.lanes.count == CaptureFlowGraph.maxLanes)
        #expect(graph.arrows.count == CaptureFlowGraph.maxLanes - 1)
        #expect(graph.omittedCount == 20 - graph.arrows.count)
    }

    // MARK: Private

    private static func row(
        _ ordinal: UInt64,
        _ source: String,
        _ destination: String,
        info: String
    )
        -> CaptureFrameRow
    {
        CaptureFrameRow(
            provenance: SessionFrameProvenance(
                ordinal: FrameOrdinal(ordinal),
                timestamp: Date(timeIntervalSince1970: 1_700_000_000 + Double(ordinal - 1)),
                capturedLength: 60,
                originalLength: 60,
                linkType: LinkType.ethernet
            ),
            source: source,
            destination: destination,
            protocolName: "TCP",
            info: info,
            sessionID: nil,
            interfaceID: 0,
            hasComment: false
        )
    }
}
