import Foundation
import Testing
@testable import Tracexy

/// View ▸ All Frames: every frame of a stable capture, in order, with its session,
/// bounded, identity-checked and agreeing with tshark on the columns it shares.
struct CaptureFrameListScannerTests {
    // MARK: Internal

    @Test
    func listsEveryFrameWithItsSession() throws {
        try withCapture { url, frames in
            let identity = try Self.identity(url)
            let list = try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID())
                .scan()
            #expect(list.rows.count == frames.count)
            #expect(list.scannedFrameCount == frames.count)
            #expect(list.rows.map(\.ordinal) == Array(1 ... UInt64(frames.count)))
            #expect(list.completeness == .complete)

            let loaded = try SavedCaptureStreamLoader(contentsOf: url).load()
            let sessionIDs = Set(loaded.sessions.map(\.id))
            #expect(list.rows.compactMap(\.sessionID).allSatisfy(sessionIDs.contains))

            if WiresharkOracle.isAvailable {
                let rows = try WiresharkOracle.tsharkFields(
                    url,
                    fields: ["frame.number", "ip.src", "ipv6.src", "frame.len"]
                )
                for (row, oracle) in zip(list.rows, rows) {
                    let source = oracle[1].isEmpty ? oracle[2] : oracle[1]
                    if !source.isEmpty {
                        #expect(row.source == source, "frame \(row.ordinal)")
                    }
                    #expect(String(row.length) == oracle[3], "frame \(row.ordinal)")
                }
            }
        }
    }

    @Test
    func boundedAndRefusesAChangedFile() throws {
        try withCapture { url, frames in
            let identity = try Self.identity(url)
            let bounded = try CaptureFrameListScanner(
                contentsOf: url, expectedIdentity: identity, sourceToken: UUID(),
                configuration: .init(maxRetainedFrames: 3)
            ).scan()
            #expect(bounded.rows.count == 3)
            #expect(bounded.omittedFrameCount == frames.count - 3)

            let handle = try FileHandle(forWritingTo: url)
            try handle.seekToEnd()
            try handle.write(contentsOf: Data([0, 0, 0, 0]))
            try handle.close()
            #expect(throws: FollowStreamError.self) {
                _ = try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID())
            }
        }
    }

    // MARK: Private

    private static func identity(_ url: URL) throws -> PcapFileIdentity {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        return PcapFileIdentity.snapshot(of: handle)
    }

    private func withCapture(_ body: (URL, [CapturedFrame]) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("all-frames-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("conv.pcap")
        let frames = ReplayCorpus.conversationCapturedFrames()
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        try body(url, frames)
    }
}
