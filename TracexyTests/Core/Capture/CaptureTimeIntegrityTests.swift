import Foundation
import Testing
@testable import Tracexy

@Suite("Capture time integrity")
struct CaptureTimeIntegrityTests {
    @Test("PCAPNG preserves explicit interface direction without inventing capture time")
    func packetDirectionRoundTrip() throws {
        let time = Date(timeIntervalSince1970: 42)
        let frames = [
            CapturedFrame(bytes: [1], timestamp: time, originalLength: 1, direction: .inbound),
            CapturedFrame(bytes: [2], timestamp: time, originalLength: 1, direction: .outbound),
            CapturedFrame(bytes: [3], timestamp: nil, originalLength: 1),
        ]
        let data = try PcapngWriter.data(defaultLinkType: 1, frames: frames)
        let reread = try PcapngReader.read(Array(data)).frames
        #expect(reread.map(\.direction) == [.inbound, .outbound, .unknown])
        #expect(reread.map(\.timestamp) == [time, time, nil])
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".pcapng")
        try data.write(to: file, options: .atomic)
        defer { try? FileManager.default.removeItem(at: file) }
        let stream = try CaptureStreamReader(contentsOf: file)
        var streamed: [CaptureDirection] = []
        read: while true {
            switch try stream.next() {
            case let .frame(event): streamed.append(event.reference.direction)
            case .end: break read
            }
        }
        #expect(streamed == [.inbound, .outbound, .unknown])
        let source = try CaptureStreamReader(contentsOf: file)
        guard case let .frame(first) = try source.next() else {
            Issue.record("Missing first directed frame")
            return
        }
        var rewritten = PcapngBlockWriter.sectionHeader(comment: nil)
        rewritten += PcapngBlockWriter.interfaceDescription(linkType: 1, name: nil, fileName: "source.pcapng")
        rewritten += try PcapngBlockWriter.enhancedPacket(first, interfaceID: 0, time: time)
        #expect(try PcapngReader.read(Array(rewritten)).frames.map(\.direction) == [.inbound])
        #expect(!PcapWriter.canRepresent(frames: [frames[0]]))
        #expect(throws: SessionExportError.self) {
            _ = try PcapWriter.data(linkType: 1, frames: [frames[0]])
        }
        #expect(throws: SessionExportError.self) {
            _ = try PcapngWriter.data(defaultLinkType: 1, frames: [
                CapturedFrame(bytes: [4], timestamp: nil, originalLength: 1, direction: .inbound),
            ])
        }
    }

    @Test(
        "Unrepresentable instants fail without clamping or trapping",
        arguments: [-1.0, Double.nan, Double.infinity, Double.greatestFiniteMagnitude, Double(UInt64.max)]
    )
    func unrepresentableTimes(interval: Double) {
        let frame = CapturedFrame(bytes: [0], timestamp: Date(timeIntervalSince1970: interval), originalLength: 1)
        #expect(throws: SessionExportError.self) { try PcapWriter.data(linkType: 1, frames: [frame]) }
        #expect(throws: SessionExportError.self) { try PcapngWriter.data(defaultLinkType: 1, frames: [frame]) }
        #expect(!PcapWriter.canRepresent(frames: [frame]))
    }

    @Test("A real epoch stays known and the wider PCAPNG counter stays usable")
    func representableTimes() throws {
        #expect(try CaptureTimestampEncoding.microseconds(Date(timeIntervalSince1970: 0)) == 0)
        #expect(try CaptureTimestampEncoding.classic(Date(timeIntervalSince1970: 0)).seconds == 0)
        let wider = Date(timeIntervalSince1970: Double(UInt32.max) + 1)
        #expect(throws: SessionExportError.self) { try CaptureTimestampEncoding.classic(wider) }
        #expect(try CaptureTimestampEncoding.microseconds(wider) == 4_294_967_296_000_000)
    }

    @Test("An SPB snap length does not constrain a later larger timed packet")
    func mixedTimingInterfaceLengths() throws {
        let frames = [
            CapturedFrame(bytes: Array(repeating: 1, count: 14), timestamp: nil, originalLength: 54),
            CapturedFrame(
                bytes: Array(repeating: 2, count: 60),
                timestamp: Date(timeIntervalSince1970: 5),
                originalLength: 60
            ),
        ]
        let data = try PcapngWriter.data(defaultLinkType: 1, frames: frames)
        let buffer = PacketBuffer(Array(data))
        var offset = 0
        var snapLengths: [UInt32] = []
        var timedPackets = 0
        while offset < data.count {
            let type = try buffer.u32le(offset)
            let length = try Int(buffer.u32le(offset + 4))
            try #require(length >= 12)
            if type == 1 {
                try snapLengths.append(buffer.u32le(offset + 12))
            } else if type == 6 {
                let interfaceID = try Int(buffer.u32le(offset + 8))
                let captured = try buffer.u32le(offset + 20)
                #expect(interfaceID == 1)
                #expect(try #require(snapLengths.last) >= captured)
                timedPackets += 1
            }
            offset += length
        }
        #expect(snapLengths == [14, PcapWriter.snapLength])
        #expect(timedPackets == 1)
    }

    @Test("A wide finite timestamp range widens buckets before narrowing indices")
    func wideTimeRange() {
        var accumulator = CaptureActivityAccumulator()
        for value in [0.0, 0.000001, 1.0e19] {
            accumulator.add(timestamp: Date(timeIntervalSince1970: value), originalLength: 20)
        }
        let activity = accumulator.activity()
        #expect(activity.totalFrames == 3)
        #expect(activity.totalBytes == 60)
        #expect(activity.buckets.count <= CaptureActivityBuilder.defaultBucketCap)
        #expect(activity.buckets.reduce(0) { $0 + $1.frameCount } == 3)
    }

    @Test("Earlier frames rebase the bounded chart without inventing offsets")
    func earlierFramesRebase() {
        var accumulator = CaptureActivityAccumulator()
        for value in [100.0, 110, 90, 95] {
            accumulator.add(timestamp: Date(timeIntervalSince1970: value), originalLength: 20)
        }
        let activity = accumulator.activity()
        #expect(activity.timedSpan == 20)
        #expect(activity.buckets.count == 1)
        #expect(activity.buckets.first?.startOffset == 0)
        #expect(activity.buckets.first?.frameCount == 4)
        #expect(activity.buckets.first?.byteCount == 80)
        #expect(activity.bucketWidth >= activity.timedSpan)
    }
}
