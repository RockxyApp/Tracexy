import Foundation
import Testing
@testable import Tracexy

/// Statistics ▸ UDP Multicast Streams computes what Wireshark's dialog of the
/// same name reports. tshark has no multicast tap, so the expected values were read
/// from Wireshark 4.6's own dialog (its Copy output) for the capture built below.
struct MulticastStreamsTests {
    // MARK: Internal

    @Test
    func streamsMatchWireshark() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let rows = try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID()).scan()
            .rows
        let result = MulticastStreams.streams(rows: rows)
        // First seen first; Wireshark's copy followed its view, sorted by source address.
        #expect(result.streams.map(\.sourceText) == ["[fe80::1]:30000", "10.0.0.5:5000", "10.0.0.6:6000"])
        #expect(result.streams.map(\.groupText) == ["[ff05::1:3]:30000", "239.1.1.1:5004", "239.1.1.1:5004"])
        let ordered: [MulticastStreamRow] = [result.streams[0], result.streams[2], result.streams[1]]
        let values: [[String]] = ordered.map(Self.copyColumns)
        #expect(values == [
            ["5", "1.250000", "480.000000", "0.000000", "1", "0", "48", "0"],
            ["3", "1500.000000", "1296000.000000", "17280.000000", "2", "0", "108", "0"],
            ["210", "293.296089", "3106592.178771", "8473600.000000", "80", "1", "70741", "1"],
        ])
        // The summary line: "avg bw: 557 kbps, max bw: 8473 kbps, max burst: 80 / 100ms, max buffer: 48B".
        let totals = try #require(result.totals)
        #expect(Int(totals.averageBitsPerSecond / 1_000) == 557)
        #expect(totals.maxBitsPerSecond == 8_473_600)
        #expect(totals.maxBurst == 80)
        #expect(totals.maxBufferBytes == 48)
    }

    @Test
    func parametersChangeTheAlarms() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let rows = try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID()).scan()
            .rows
        var parameters = MulticastStreams.Parameters()
        parameters.burstAlarmThreshold = 100
        parameters.bufferAlarmThreshold = 100_000
        let quiet = try #require(MulticastStreams.streams(rows: rows, parameters: parameters).streams.last)
        #expect(quiet.burstAlarms == 0)
        #expect(quiet.bufferAlarms == 0)
        #expect(!MulticastStreams.Parameters(burstInterval: 0).isValid)
        #expect(MulticastStreams.Parameters().isValid)
    }

    @Test
    func onlyGroupsCount() throws {
        let unicast = try #require(IPAddressValue(parsing: "10.0.0.9"))
        let group = try #require(IPAddressValue(parsing: "239.255.255.250"))
        let group6 = try #require(IPAddressValue(parsing: "ff02::fb"))
        #expect(!MulticastFrameFact.isMulticast(unicast))
        #expect(MulticastFrameFact.isMulticast(group))
        #expect(MulticastFrameFact.isMulticast(group6))
    }

    // MARK: Private

    /// The numeric columns of Wireshark's Copy output.
    private static func copyColumns(_ row: MulticastStreamRow) -> [String] {
        let counts = [String(row.packets)]
        let rates = [row.packetsPerSecond, row.averageBitsPerSecond, row.maxBitsPerSecond]
            .map { String(format: "%.6f", $0) }
        let rest = [row.maxBurst, row.burstAlarms, row.maxBufferBytes, row.bufferAlarms].map(String.init)
        return counts + rates + rest
    }

    private static func v4(_ src: String, _ dst: String, _ sourcePort: UInt16, _ port: UInt16, _ size: Int)
        -> [UInt8]
    {
        PacketBuilder.ethernetIPv4(
            proto: 17, src: src, dst: dst,
            payload: PacketBuilder.udp(srcPort: sourcePort, dstPort: port, payload: [UInt8](repeating: 0, count: size))
        )
    }

    /// A little-endian classic PCAP with microsecond timestamps.
    private static func classicPcap(_ frames: [(Int, [UInt8])]) -> [UInt8] {
        func le32(_ value: UInt32) -> [UInt8] {
            (0 ..< 4).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
        }
        var bytes = le32(0xA1B2C3D4) + [2, 0, 4, 0] + le32(0) + le32(0) + le32(65_535) + le32(1)
        for (micros, frame) in frames {
            bytes += le32(1_790_000_000 + UInt32(micros / 1_000_000)) + le32(UInt32(micros % 1_000_000))
            bytes += le32(UInt32(frame.count)) + le32(UInt32(frame.count)) + frame
        }
        return bytes
    }

    private static func capture() throws -> URL {
        var frames: [(Int, [UInt8])] = [
            (0, v4("10.0.0.5", "10.0.0.9", 40_000, 9, 10)),
            (3_000_000, v4("10.0.0.5", "10.0.0.9", 40_000, 9, 10)),
        ]
        let times = (0 ..< 100).map { 500_000 + $0 * 4_000 } + (0 ..< 60).map { 1_000_000 + $0 * 200 }
            + (0 ..< 50).map { 1_020_000 + $0 * 4_000 }
        frames += times.map { ($0, v4("10.0.0.5", "239.1.1.1", 5_000, 5_004, 1_316)) }
        frames += (0 ..< 5).map { index in
            (250_000 + index * 1_000_000, PacketBuilder.ethernetIPv6(
                nextHeader: 17, src: [0xFE80, 0, 0, 0, 0, 0, 0, 1], dst: [0xFF05, 0, 0, 0, 0, 0, 1, 3],
                payload: PacketBuilder.udp(srcPort: 30_000, dstPort: 30_000, payload: [UInt8](repeating: 0, count: 40))
            ))
        }
        frames += (0 ..< 3).map { (2_000_000 + $0 * 1_000, v4("10.0.0.6", "239.1.1.1", 6_000, 5_004, 100)) }
        frames.sort { $0.0 < $1.0 }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("multicast-\(UUID().uuidString).pcap")
        try Data(classicPcap(frames)).write(to: url)
        return url
    }
}
