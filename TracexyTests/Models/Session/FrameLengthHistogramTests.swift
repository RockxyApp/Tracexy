import Foundation
import Testing
@testable import Tracexy

/// Statistics ▸ Packet Lengths: Wireshark's length ranges per session, added exactly.
struct FrameLengthHistogramTests {
    @Test
    func rangesMatchWiresharkBoundaries() {
        var histogram = FrameLengthHistogram()
        for length in [0, 19, 20, 39, 40, 79, 80, 1_279, 1_280, 5_119, 5_120, 9_000] {
            histogram.record(length)
        }
        #expect(histogram.buckets.map(\.count) == [2, 2, 2, 1, 0, 0, 1, 1, 1, 2])
        #expect(histogram.buckets[9].minimum == 5_120)
        #expect(histogram.buckets[9].maximum == 9_000)
        #expect(FrameLengthHistogram.label(ofBucket: 0) == "0–19")
        #expect(FrameLengthHistogram.label(ofBucket: 9) == "5120 and greater")
        #expect(histogram.total.count == 12)
    }

    @Test
    func histogramsAddExactly() {
        var one = FrameLengthHistogram()
        one.record(60)
        var two = FrameLengthHistogram()
        two.record(70)
        two.record(1_500)
        one.add(two)
        #expect(one.buckets[2].count == 2)
        #expect(one.buckets[2].average == 65)
        #expect(one.total.minimum == 60)
        #expect(one.total.maximum == 1_500)
    }

    @Test
    func theFoldMatchesTsharkPacketLengths() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("plen-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("conv.pcap")
        let frames = ReplayCorpus.conversationCapturedFrames()
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        let loaded = try SavedCaptureStreamLoader(contentsOf: url).load()
        var histogram = FrameLengthHistogram()
        for session in loaded.sessions {
            histogram.add(session.frameLengths)
        }
        #expect(histogram.total.count == frames.count)
        if WiresharkOracle.isAvailable {
            let lengths = try WiresharkOracle.tsharkFields(url, fields: ["frame.len"])
                .compactMap { $0.first.flatMap(Int.init) }
            var expected = FrameLengthHistogram()
            lengths.forEach { expected.record($0) }
            #expect(histogram == expected)
        }
    }
}
