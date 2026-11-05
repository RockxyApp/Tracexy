import Foundation
import Testing
@testable import Tracexy

/// Marks and ignores in View ▸ All Frames, and exporting exactly the marked frames
/// (Wireshark's "Marked packets only").
struct MarkedFramesExportTests {
    // MARK: Internal

    @Test
    func exportsExactlyTheMarkedFrames() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("marked-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let source = directory.appendingPathComponent("conv.pcap")
        let frames = ReplayCorpus.conversationCapturedFrames()
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: source)
        let output = directory.appendingPathComponent("marked.pcapng")

        let summary = try CaptureFrameExporter.export(
            from: source, scope: .frames([1, 3, 5]), options: FrameExportOptions(), to: output
        )
        #expect(summary.writtenFrameCount == 3)
        let reloaded = try SavedCaptureStreamLoader(contentsOf: output).load()
        #expect(reloaded.properties.totalFrames == 3)
        if WiresharkOracle.isAvailable {
            let original = try WiresharkOracle.tsharkFields(source, fields: ["frame.len"]).map { $0.first ?? "" }
            let exported = try WiresharkOracle.tsharkFields(output, fields: ["frame.len"]).map { $0.first ?? "" }
            #expect(exported == [original[0], original[2], original[4]])
        }
    }

    @Test
    func frameCommentsAreWrittenOnTheirFrames() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("commented-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let source = directory.appendingPathComponent("conv.pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: ReplayCorpus.conversationCapturedFrames(), to: source)
        let output = directory.appendingPathComponent("commented.pcapng")
        var options = FrameExportOptions()
        options.frameComments = [2: "server answered here"]
        _ = try CaptureFrameExporter.export(from: source, scope: .wholeCapture, options: options, to: output)
        if WiresharkOracle.isAvailable {
            let rows = try WiresharkOracle.tsharkFields(output, fields: ["frame.number", "frame.comment"])
            #expect(rows.first { $0.first == "2" }?.last == "server answered here")
            #expect(rows.filter { ($0.last ?? "").isEmpty == false }.count == 1)
        }
    }

    @MainActor
    @Test
    func marksIgnoresAndNavigation() throws {
        let state = CaptureFrameListState()
        let markedSessionID = UUID()
        state.toggleMark(2)
        state.toggleMark(7, sessionID: markedSessionID)
        state.toggleIgnore(3)
        let rows = (1 ... 8).map { Self.row($0) }
        state.list = try CaptureFrameList(
            identity: Self.identity(), rows: rows, scannedFrameCount: 8, completeness: .complete
        )
        state.limitToSessionsInView = false
        #expect(state.visibleRows(sessionsInView: []).map(\.id) == [1, 2, 4, 5, 6, 7, 8])
        state.showsIgnored = true
        #expect(state.visibleRows(sessionsInView: []).count == 8)
        #expect(state.adjacentMark(from: nil, in: rows, forward: true) == 2)
        #expect(state.adjacentMark(from: 2, in: rows, forward: true) == 7)
        #expect(state.adjacentMark(from: 7, in: rows, forward: true) == 2, "wraps")
        #expect(state.adjacentMark(from: 2, in: rows, forward: false) == 7, "wraps backwards")
        #expect(state.adjacentMarkAcrossCapture(from: 2, forward: true) == 7)
        #expect(state.adjacentMarkAcrossCapture(from: 7, forward: true) == 2)
        state.toggleMark(2)
        #expect(state.marked == [7])
        state.frameComments[7] = "reviewed"
        state.pendingTableSelection = 7
        state.cancel(clearList: true, clearAnnotations: false)
        #expect(state.list == nil)
        #expect(state.pendingTableSelection == nil)
        #expect(state.marked == [7] && state.ignored == [3])
        #expect(state.markedSessionIDs[7] == markedSessionID)
        #expect(state.frameComments[7] == "reviewed")
        state.cancel(clearList: true)
        #expect(state.marked.isEmpty && state.ignored.isEmpty)
        #expect(state.markedSessionIDs.isEmpty)
        #expect(state.frameComments.isEmpty)
    }

    @MainActor
    @Test
    func ignoreDisplayedUsesOnlyRowsCurrentlyShown() throws {
        let state = CaptureFrameListState()
        state.list = try CaptureFrameList(
            identity: Self.identity(), rows: (1 ... 8).map { Self.row($0) },
            scannedFrameCount: 8, completeness: .complete
        )
        state.limitToSessionsInView = false
        state.toggleIgnore(3)
        state.search = "frame 4"

        let displayed = state.visibleRows(sessionsInView: [])
        #expect(displayed.map(\.id) == [4])
        state.ignoreDisplayed(displayed)

        #expect(state.ignored == [3, 4])
        #expect(state.visibleRows(sessionsInView: []).isEmpty)
        state.showsIgnored = true
        #expect(state.visibleRows(sessionsInView: []).map(\.id) == [4])
    }

    @MainActor
    @Test
    func unignoreDisplayedRestoresOnlyIgnoredRowsActuallyShown() throws {
        let state = CaptureFrameListState()
        let rows = (1 ... 8).map { Self.row($0) }
        let offPageReference = Self.row(8)
        state.list = try CaptureFrameList(
            identity: Self.identity(), rows: rows, scannedFrameCount: 8, completeness: .complete
        )
        state.limitToSessionsInView = false
        state.ignored = [4, 5, 7, 8]
        state.search = "frame 4"
        state.retainCaptureTimeReferenceRow(offPageReference)

        // Without Show Ignored, frame 4 is hidden; the pinned reference row 8 is
        // still displayed and is therefore in the action's exact scope.
        let referenceOnly = state.visibleRows(sessionsInView: [])
        #expect(referenceOnly.map(\.id) == [8])
        state.unignoreDisplayed(referenceOnly)
        state.unignoreDisplayed(referenceOnly)
        #expect(state.ignored == [4, 5, 7])

        state.showsIgnored = true
        let withIgnoredDisplayed = state.visibleRows(sessionsInView: [])
        #expect(withIgnoredDisplayed.map(\.id) == [4, 8])
        state.unignoreDisplayed(withIgnoredDisplayed)
        #expect(state.ignored == [5, 7])
        #expect(state.visibleRows(sessionsInView: []).map(\.id) == [4, 8])
    }

    @MainActor
    @Test
    func markDisplayedAddsOnlyVisibleRowsAndPreservesExistingMarks() throws {
        let state = CaptureFrameListState()
        let priorSessionID = UUID()
        let visibleSessionID = UUID()
        let rows = (1 ... 8).map { ordinal in
            Self.row(ordinal, sessionID: ordinal == 4 ? visibleSessionID : nil)
        }
        state.list = try CaptureFrameList(
            identity: Self.identity(), rows: rows, scannedFrameCount: 8, completeness: .complete
        )
        state.limitToSessionsInView = false
        state.toggleMark(7, sessionID: priorSessionID)
        state.ignored = [3]
        state.retainCaptureTimeReferenceRow(rows[7])
        state.search = "frame 4"

        let displayed = state.visibleRows(sessionsInView: [])
        #expect(displayed.map(\.id) == [4, 8], "a pinned reference row is part of the visible result")
        state.markDisplayed(displayed)
        state.markDisplayed(displayed)
        #expect(state.marked == [4, 7, 8])
        #expect(state.markedSessionIDs[4] == visibleSessionID)
        #expect(state.markedSessionIDs[7] == priorSessionID)
        #expect(state.markedSessionIDs[8] == nil)

        state.search = "frame 5"
        let noSessionRow = state.visibleRows(sessionsInView: [])
        #expect(noSessionRow.map(\.id) == [5, 8])
        state.markDisplayed(noSessionRow)
        #expect(state.marked == [4, 5, 7, 8])
        #expect(state.markedSessionIDs[5] == nil)
        #expect(state.markedSessionIDs[4] == visibleSessionID)
        #expect(state.markedSessionIDs[7] == priorSessionID)

        state.search = "frame 4"
        let displayedMarks = state.visibleRows(sessionsInView: [])
        state.unmarkDisplayed(displayedMarks)
        state.unmarkDisplayed(displayedMarks)
        #expect(state.marked == [5, 7])
        #expect(state.markedSessionIDs[4] == nil)
        #expect(state.markedSessionIDs[8] == nil)
        #expect(state.markedSessionIDs[7] == priorSessionID)
    }

    // MARK: Private

    private static func row(_ ordinal: Int, sessionID: UUID? = nil) -> CaptureFrameRow {
        CaptureFrameRow(
            provenance: SessionFrameProvenance(
                ordinal: FrameOrdinal(UInt64(ordinal)), timestamp: nil, capturedLength: 60, originalLength: 60,
                linkType: LinkType.ethernet
            ),
            source: "192.0.2.1", destination: "192.0.2.2", protocolName: "TCP",
            info: "Frame \(ordinal)", sessionID: sessionID,
            interfaceID: 0, hasComment: false
        )
    }

    private static func identity() throws -> PcapFileIdentity {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("identity-\(UUID().uuidString)")
        try Data([0]).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        return PcapFileIdentity.snapshot(of: handle)
    }
}
