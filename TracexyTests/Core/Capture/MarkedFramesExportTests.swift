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
        state.toggleMark(2)
        state.toggleMark(7)
        state.toggleIgnore(3)
        let rows = (1 ... 8).map(Self.row)
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
        state.toggleMark(2)
        #expect(state.marked == [7])
        state.cancel(clearList: true)
        #expect(state.marked.isEmpty && state.ignored.isEmpty)
    }

    // MARK: Private

    private static func row(_ ordinal: Int) -> CaptureFrameRow {
        CaptureFrameRow(
            provenance: SessionFrameProvenance(
                ordinal: FrameOrdinal(UInt64(ordinal)), timestamp: nil, capturedLength: 60, originalLength: 60,
                linkType: LinkType.ethernet
            ),
            source: "192.0.2.1", destination: "192.0.2.2", protocolName: "TCP", info: "", sessionID: nil,
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
