import Foundation
import Testing
@testable import Tracexy

/// The first row of a later All Frames page has a real predecessor: the scan that
/// built the page recorded the frame immediately before it. Every other way a row
/// can open a page leaves the delta unknown rather than borrowing that timestamp.
@MainActor
struct AllFramesPageBoundaryDeltaTests {
    // MARK: Internal

    @Test
    func aLaterPageOpensWithTheScannedPrecedingFrame() {
        let rows = Self.rows(ordinals: [4, 5, 6])
        let retained = Set(rows.map(\.ordinal))

        let predecessors = AllFramesWindow.previousDisplayedFrames(
            rows,
            retainedOrdinals: retained,
            firstRetainedOrdinal: 4,
            precedingRetainedFrameTimestamp: Self.boundary
        )

        #expect(predecessors[4] == FrameTimePredecessor.timestamp(Self.boundary))
        // Rows after the first still derive from the row shown above them.
        #expect(predecessors[5] == FrameTimePredecessor.timestamp(Self.timestamp(for: 4)))
        #expect(predecessors[6] == FrameTimePredecessor.timestamp(Self.timestamp(for: 5)))
    }

    @Test
    func theFirstFrameOfTheCaptureHasNoPredecessor() {
        let rows = Self.rows(ordinals: [1, 2])
        let predecessors = AllFramesWindow.previousDisplayedFrames(
            rows,
            retainedOrdinals: Set(rows.map(\.ordinal)),
            firstRetainedOrdinal: 1,
            precedingRetainedFrameTimestamp: nil
        )

        #expect(predecessors[1] == FrameTimePredecessor.none)
    }

    @Test
    func aHiddenPageOpeningFrameLeavesTheDeltaUnknown() {
        // A filter removed ordinal 4, so the frame above ordinal 5 is not the one
        // the scan recorded and no delta can be claimed.
        let rows = Self.rows(ordinals: [5, 6])
        let predecessors = AllFramesWindow.previousDisplayedFrames(
            rows,
            retainedOrdinals: Set(rows.map(\.ordinal)),
            firstRetainedOrdinal: 4,
            precedingRetainedFrameTimestamp: Self.boundary
        )

        #expect(predecessors[5] == FrameTimePredecessor.unknown)
    }

    @Test
    func aPinnedRowFromAnotherPageLeavesTheDeltaUnknown() {
        // Ordinal 2 is pinned from an earlier page and sorts ahead of this page,
        // so it is not retained here and the recorded boundary is not its own.
        let rows = Self.rows(ordinals: [2, 4, 5])
        let predecessors = AllFramesWindow.previousDisplayedFrames(
            rows,
            retainedOrdinals: Set([4, 5]),
            firstRetainedOrdinal: 4,
            precedingRetainedFrameTimestamp: Self.boundary
        )

        #expect(predecessors[2] == FrameTimePredecessor.unknown)
        // The genuine page opener is no longer first, so it falls back too.
        #expect(predecessors[4] == FrameTimePredecessor.unknown)
    }

    @Test
    func aMissingBoundaryTimestampStaysUnknown() {
        let rows = Self.rows(ordinals: [4, 5])
        let predecessors = AllFramesWindow.previousDisplayedFrames(
            rows,
            retainedOrdinals: Set(rows.map(\.ordinal)),
            firstRetainedOrdinal: 4,
            precedingRetainedFrameTimestamp: nil
        )

        #expect(predecessors[4] == FrameTimePredecessor.unknown)
    }

    @Test
    func callersThatPassNoBoundaryKeepTheEarlierBehavior() {
        let rows = Self.rows(ordinals: [4, 5])
        let predecessors = AllFramesWindow.previousDisplayedFrames(
            rows, retainedOrdinals: Set(rows.map(\.ordinal))
        )

        #expect(predecessors[4] == FrameTimePredecessor.unknown)
    }

    // MARK: Private

    private static let origin = Date(timeIntervalSince1970: 1_700_000_000)

    private static let boundary = Date(timeIntervalSince1970: 1_700_000_003)

    private static func timestamp(for ordinal: UInt64) -> Date {
        origin.addingTimeInterval(TimeInterval(ordinal))
    }

    private static func rows(ordinals: [UInt64]) -> [CaptureFrameRow] {
        ordinals.map { ordinal in
            CaptureFrameRow(
                provenance: SessionFrameProvenance(
                    ordinal: FrameOrdinal(rawValue: ordinal),
                    timestamp: timestamp(for: ordinal),
                    capturedLength: 0,
                    originalLength: 0,
                    linkType: LinkType.ethernet
                ),
                source: "", destination: "", protocolName: "", info: "", sessionID: nil, interfaceID: 0,
                hasComment: false
            )
        }
    }
}
