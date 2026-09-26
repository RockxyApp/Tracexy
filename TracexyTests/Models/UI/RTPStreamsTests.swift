import Foundation
import Testing
@testable import Tracexy

/// Statistics ▸ RTP Streams computes what `tshark -z rtp,streams`
/// reports — packets, lost, deltas and RFC 3550 jitter — for a two-way call with a
/// lost, jittery direction and a clean one.
struct RTPStreamsTests {
    // MARK: Internal

    @Test
    func streamsMatchWireshark() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let rows = try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID()).scan()
            .rows
        let streams = RTPStreams.streams(rows: rows)
        #expect(streams.count == 2)
        let lossy = try #require(streams.first { $0.ssrc == 0x11111111 })
        #expect(lossy.packets == 49)
        #expect(lossy.lost == 1)
        #expect(lossy.payloads == "g711U")
        #expect(lossy.hasProblem)
        #expect(lossy.term == "ip == 192.0.2.10 and ip == 198.51.100.7 and port == 40000 and port == 50000")
        let clean = try #require(streams.first { $0.ssrc == 0x22222222 })
        #expect(clean.lost == 0)
        #expect(!clean.hasProblem)
        #expect(clean.payloads == "g711A")
        // The frames stay UDP: RTP never relabels a session.
        #expect(rows.allSatisfy { $0.protocolName == "UDP" })

        guard WiresharkOracle.isAvailable, let tshark = WiresharkOracle.tsharkURL else {
            return
        }
        let process = Process()
        let pipe = Pipe()
        process.executableURL = tshark
        process.arguments = ["-r", url.path, "-o", "rtp.heuristic_rtp:TRUE", "-q", "-z", "rtp,streams"]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let text = String(bytes: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        process.waitUntilExit()
        // Start End SrcIP SrcPort DstIP DstPort SSRC Payload Pkts Lost (pct) MinΔ MeanΔ MaxΔ MinJ MeanJ MaxJ [X]
        var theirs: [UInt32: [String]] = [:]
        for line in text.split(separator: "\n") {
            let words = line.split(separator: " ").map(String.init)
            guard words.count >= 17, words[6].hasPrefix("0x"),
                  let ssrc = UInt32(words[6].dropFirst(2), radix: 16) else
            {
                continue
            }
            theirs[ssrc] = words
        }
        for stream in streams {
            let words = try #require(theirs[stream.ssrc])
            let jitter = try #require(stream.jitter)
            let ours = [
                String(stream.packets), String(stream.lost),
                Self.ms(stream.minDelta), Self.ms(stream.meanDelta), Self.ms(stream.maxDelta),
                Self.ms(jitter.min), Self.ms(jitter.mean), Self.ms(jitter.max),
            ]
            #expect(ours == [words[8], words[9], words[11], words[12], words[13], words[14], words[15], words[16]])
            #expect(stream.hasProblem == (words.count > 17 && words[17] == "X"))
        }
    }

    @Test
    func payloadTypesNameAndClockAsWireshark() {
        #expect(RTPStreams.payloadName(0) == "g711U")
        #expect(RTPStreams.payloadName(111) == "DynamicRTP-Type-111")
        #expect(RTPStreams.clockRate(0) == 8_000)
        #expect(RTPStreams.clockRate(9) == 8_000)
        #expect(RTPStreams.clockRate(96) == 0)
    }

    // MARK: Private

    /// Arrival offsets (ms) added to the lossy stream's 20 ms grid.
    private static let wobble: [Double] = [0, 1.7, 3.9, 0.4, 2.2, 3.1, 0.9, 1.5, 3.6, 2.8]

    private static func ms(_ value: Double) -> String {
        String(format: "%.3f", value)
    }

    private static func rtp(_ type: UInt8, _ sequence: UInt16, _ timestamp: UInt32, _ ssrc: UInt32, marker: Bool)
        -> [UInt8]
    {
        let words = [timestamp, ssrc]
            .flatMap { value in (0 ..< 4).map { UInt8(truncatingIfNeeded: value >> (24 - 8 * $0)) } }
        return [0x80, (marker ? 0x80 : 0) | type, UInt8(sequence >> 8), UInt8(sequence & 0xFF)] + words
            + [UInt8](repeating: 0xD5, count: 160)
    }

    /// A little-endian classic PCAP with microsecond timestamps from 2026-09-24.
    private static func classicPcap(_ frames: [(Double, [UInt8])]) -> [UInt8] {
        func le32(_ value: UInt32) -> [UInt8] {
            (0 ..< 4).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
        }
        var bytes = le32(0xA1B2C3D4) + [2, 0, 4, 0] + le32(0) + le32(0) + le32(65_535) + le32(1)
        for (offset, frame) in frames {
            let micros = UInt64((offset * 1_000_000).rounded())
            bytes += le32(1_790_000_000 + UInt32(micros / 1_000_000)) + le32(UInt32(micros % 1_000_000))
            bytes += le32(UInt32(frame.count)) + le32(UInt32(frame.count)) + frame
        }
        return bytes
    }

    /// Stream A: g711U, 50 packets with packet 10 lost and arrival wobble; stream B:
    /// g711A the other way, 40 packets, clean.
    private static func capture() throws -> URL {
        var frames: [(Double, [UInt8])] = []
        for index in 0 ..< 50 where index != 10 {
            let payload = rtp(0, UInt16(1_000 + index), UInt32(160 * index), 0x11111111, marker: index == 0)
            frames.append((Double(index) * 0.020 + wobble[index % wobble.count] / 1_000, PacketBuilder.ethernetIPv4(
                proto: 17, src: "192.0.2.10", dst: "198.51.100.7",
                payload: PacketBuilder.udp(srcPort: 40_000, dstPort: 50_000, payload: payload)
            )))
        }
        for index in 0 ..< 40 {
            let payload = rtp(8, UInt16(500 + index), UInt32(8_000 + 160 * index), 0x22222222, marker: false)
            frames.append((0.005 + Double(index) * 0.020, PacketBuilder.ethernetIPv4(
                proto: 17, src: "198.51.100.7", dst: "192.0.2.10",
                payload: PacketBuilder.udp(srcPort: 50_000, dstPort: 40_000, payload: payload)
            )))
        }
        frames.sort { $0.0 < $1.0 }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("rtp-\(UUID().uuidString).pcap")
        try Data(classicPcap(frames)).write(to: url)
        return url
    }
}
