import Foundation
import Testing
@testable import Tracexy

/// RTP ▸ Stream Analysis: per packet, the delta since the previous in-order packet,
/// RFC 3550 jitter, skew and bandwidth over the last second, with a status for a
/// sequence gap; its largest delta, largest and mean jitter equal the RTP Streams row,
/// which matches `tshark -z rtp,streams`.
struct RTPStreamAnalysisTests {
    // MARK: Internal

    @Test
    func packetsReadAsWiresharksAnalysis() throws {
        // PCMU at 8 kHz: 160 samples every 20 ms. Packet 4 is lost; packet 6 arrives 5 ms late.
        let schedule: [(sequence: UInt16, milliseconds: Double)] = [
            (1, 0),
            (2, 20),
            (3, 40),
            (5, 80),
            (6, 105),
            (7, 120)
        ]
        let frames = schedule.map { sequence, milliseconds in
            (milliseconds, PacketBuilder.ethernetIPv4(
                proto: 17, src: "192.0.2.10", dst: "198.51.100.7",
                payload: PacketBuilder.udp(srcPort: 40_000, dstPort: 40_002, payload: [
                    sequence == 1 ? 0x80 : 0x80, sequence == 1 ? 0x80 : 0x00, UInt8(sequence >> 8),
                    UInt8(sequence & 0xFF),
                ] + Self.be32(UInt32(sequence - 1) * 160) + Self.be32(0x11111111) + [UInt8](
                    repeating: 0xFF,
                    count: 160
                ))
            ))
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("rtpa-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames.map { milliseconds, bytes in
            CapturedFrame(
                bytes: bytes, timestamp: Date(timeIntervalSince1970: 1_800_000_000 + milliseconds / 1_000),
                originalLength: bytes.count
            )
        }, to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let rows = try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID()).scan()
            .rows
        let stream = try #require(RTPStreams.streams(rows: rows).first)
        let analysis = RTPStreamAnalysis(stream: stream, rows: rows)
        let format = { (value: Double) in String(format: "%.3f", value) }
        #expect(analysis.packets.map(\.sequence) == [1, 2, 3, 5, 6, 7])
        #expect(analysis.packets.map { format($0.time) } == [
            "0.000",
            "20.000",
            "40.000",
            "80.000",
            "105.000",
            "120.000"
        ])
        #expect(analysis.packets.map { format($0.delta) } == [
            "0.000",
            "20.000",
            "20.000",
            "40.000",
            "25.000",
            "15.000"
        ])
        // The jitter recurrence J += (|D| − J) / 16: 5 ms late, then 5 ms early.
        #expect(analysis.packets.map { format($0.jitter) } == ["0.000", "0.000", "0.000", "0.000", "0.312", "0.605"])
        #expect(analysis.packets.map { format($0.skew) } == ["0.000", "0.000", "0.000", "0.000", "-5.000", "0.000"])
        #expect(analysis.packets.map(\.isMarker) == [true, false, false, false, false, false])
        #expect(analysis.packets.map(\.status) == [nil, nil, nil, "Wrong sequence number", nil, nil])
        // 200 bytes a packet (172 of RTP + 28 of IP and UDP) in the last second.
        #expect(analysis.packets.map { String(format: "%.1f", $0.bandwidth) } == [
            "1.6",
            "3.2",
            "4.8",
            "6.4",
            "8.0",
            "9.6"
        ])
        #expect(analysis.expected == 7)
        #expect(analysis.lost == 1)
        #expect(analysis.sequenceErrors == 1)
        #expect(format(analysis.maxDelta) == format(stream.maxDelta))
        #expect(format(analysis.maxJitter) == format(stream.jitter?.max ?? -1))
        #expect(format(analysis.meanJitter) == format(stream.jitter?.mean ?? -1))
        #expect(analysis.maxDeltaFrame == 4)
        #expect(analysis.csv.hasPrefix(
            "Source,Destination,Packet,Sequence,Delta (ms),Jitter (ms),Skew,Bandwidth,Marker,Status\r\n"
                + "192.0.2.10:40000,198.51.100.7:40002,1,1,0.000"
        ))
    }

    /// A sender whose clock runs 1 % slow: 20 ms of timestamp arrives every 20.2 ms, so
    /// Wireshark's least-squares fit reads −10 ms of drift and 7,842 Hz (−0.99 %).
    @Test
    func driftIsFittedAsWiresharkFitsIt() throws {
        let frames = (0 ..< 50).map { index in
            PacketBuilder.ethernetIPv4(
                proto: 17, src: "192.0.2.10", dst: "198.51.100.7",
                payload: PacketBuilder.udp(srcPort: 40_000, dstPort: 40_002, payload: [
                    0x80, 0x00, UInt8(index >> 8), UInt8(index & 0xFF),
                ] + Self.be32(UInt32(index) * 160) + Self.be32(0x11111111) + [UInt8](repeating: 0xFF, count: 160))
            )
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("drift-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames.enumerated().map {
            CapturedFrame(
                bytes: $0.element, timestamp: Date(timeIntervalSince1970: 1_800_000_000 + Double($0.offset) * 0.0202),
                originalLength: $0.element.count
            )
        }, to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let rows = try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID()).scan()
            .rows
        let analysis = try RTPStreamAnalysis(stream: #require(RTPStreams.streams(rows: rows).first), rows: rows)
        #expect(String(format: "%.0f", analysis.clockDrift) == "-10")
        #expect(String(format: "%.0f", analysis.frequencyDrift) == "7842")
        #expect(String(format: "%.2f", analysis.frequencyDriftPercent) == "-0.99")
    }

    // MARK: Private

    private static func be32(_ value: UInt32) -> [UInt8] {
        [UInt8(value >> 24), UInt8(value >> 16 & 0xFF), UInt8(value >> 8 & 0xFF), UInt8(value & 0xFF)]
    }
}
