import Foundation
import Testing
@testable import Tracexy

/// Statistics ▸ IPv4 and IPv6 print Wireshark's IP stats trees: every row, count and
/// order of `tshark -z ip_hosts,tree`, `ptype`, `ip_srcdst`, `dests` and `ip_ttl` (and
/// their `ipv6_` forms) for a capture mixing TCP, UDP, ICMP and IPv6.
struct IPStatisticsTests {
    // MARK: Internal

    @Test
    func destinationsAndPortsReadAsWireshark() throws {
        let rows = try Self.rows()
        #expect(Self.flatten(IPStatistics.tree(.destinationsAndPorts, ipv6: false, rows: rows)) == [
            "0 Destinations and Ports 6",
            "1 198.51.100.1 3", "2 TCP 2", "3 443 2", "2 NONE 1", "3 0 1",
            "1 192.0.2.10 2", "2 UDP 1", "3 50001 1", "2 TCP 1", "3 50000 1",
            "1 198.51.100.2 1", "2 UDP 1", "3 53 1",
        ])
        #expect(Self.flatten(IPStatistics.tree(.sourceHopLimits, ipv6: true, rows: rows)) == [
            "0 Source Hop Limits 2",
            "1 2001:db8::2 1", "2 64 1", "3 2001:db8::1 1",
            "1 2001:db8::1 1", "2 255 1", "3 2001:db8::2 1",
        ])
    }

    @Test(.enabled(if: WiresharkOracle.isAvailable, "Wireshark is not installed on this machine"))
    func everyTreeMatchesTshark() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let rows = try Self.rows(url)
        for tree in IPStatistics.Tree.allCases {
            for ipv6 in [false, true] {
                let tap = ipv6 ? (tree == .sourceHopLimits ? "ipv6_hop" : "ipv6_" + tree.tapName.replacingOccurrences(
                    of: "ip_", with: ""
                )) : tree.tapName
                let ours = Self.flatten(IPStatistics.tree(tree, ipv6: ipv6, rows: rows))
                #expect(try ours == (Self.tshark(url, tap: tap)), "\(tap)")
            }
        }
    }

    /// Wireshark ticks once per IP header of each tunnel level, with the frame's final
    /// addresses and ports, and not for the header an ICMP error quotes — so GRE, VXLAN,
    /// IP in IP and ICMP errors read as tshark prints them, and 6in4 puts IPv6 addresses
    /// in the IPv4 trees, as Wireshark does.
    @Test(.enabled(if: WiresharkOracle.isAvailable, "Wireshark is not installed on this machine"))
    func tunnelsAndQuotedHeadersCountAsWireshark() throws {
        let url = try Self.write(Self.tunnelFrames, name: "iptunnel")
        defer { try? FileManager.default.removeItem(at: url) }
        let rows = try Self.rows(url)
        #expect(Self.flatten(IPStatistics.tree(.allAddresses, ipv6: false, rows: rows)).first == "0 All Addresses 8")
        for tree in IPStatistics.Tree.allCases {
            for ipv6 in [false, true] {
                let tap = ipv6 ? (tree == .sourceHopLimits ? "ipv6_hop" : "ipv6_" + tree.tapName.replacingOccurrences(
                    of: "ip_", with: ""
                )) : tree.tapName
                let ours = Self.flatten(IPStatistics.tree(tree, ipv6: ipv6, rows: rows))
                #expect(try ours == (Self.tshark(url, tap: tap)), "\(tap)")
            }
        }
    }

    // MARK: Private

    /// GRE-in-IPv4, 6in4, IPIP, an ICMP Port Unreachable quoting a UDP datagram, VXLAN, and an
    /// ICMPv6 Time Exceeded quoting an IPv6 packet.
    private static var tunnelFrames: [[UInt8]] {
        let v4 = { (src: String, dst: String, proto: UInt8, payload: [UInt8], ttl: UInt8) -> [UInt8] in
            Array(Self.v4(src, dst, proto, payload, ttl: ttl).dropFirst(14))
        }
        let v6 = { (src: UInt16, dst: UInt16, next: UInt8, payload: [UInt8], hop: UInt8) -> [UInt8] in
            var packet = Array(PacketBuilder.ethernetIPv6(
                nextHeader: next, src: [0x2001, 0xDB8, 0, 0, 0, 0, 0, src], dst: [0x2001, 0xDB8, 0, 0, 0, 0, 0, dst],
                payload: payload
            ).dropFirst(14))
            packet[7] = hop
            return packet
        }
        let inner = v4("10.0.0.1", "10.0.0.2", 17, udp(1_000, 53), 33)
        let vxlan: [UInt8] = [0x08, 0, 0, 0, 0, 0, 1, 0] + PacketBuilder.ethernetIPv4(
            proto: 6, src: "172.16.0.1", dst: "172.16.0.2", payload: tcp(5_000, 80)
        )
        var outer6 = PacketBuilder.ethernetIPv6(
            nextHeader: 58, src: [0x2001, 0xDB8, 0, 0, 0, 0, 0, 9], dst: [0x2001, 0xDB8, 0, 0, 0, 0, 0, 1],
            payload: [3, 0, 0, 0, 0, 0, 0, 0] + v6(1, 7, 17, udp(6_000, 443), 3)
        )
        outer6[21] = 60
        return [
            Self.v4("192.0.2.1", "192.0.2.2", 47, [0, 0, 0x08, 0x00] + inner),
            Self.v4("192.0.2.1", "192.0.2.3", 41, v6(0xA, 0xB, 17, udp(2_000, 5_353), 9)),
            Self.v4("192.0.2.1", "192.0.2.4", 4, v4("10.9.0.1", "10.9.0.2", 6, tcp(7_000, 22), 40)),
            Self.v4("198.51.100.9", "192.0.2.1", 1, [3, 3, 0, 0, 0, 0, 0, 0] + v4(
                "192.0.2.1", "198.51.100.7", 17, udp(3_000, 123), 5
            )),
            Self.v4("192.0.2.5", "192.0.2.6", 17, PacketBuilder.udp(srcPort: 4_000, dstPort: 4_789, payload: vxlan)),
            outer6,
        ]
    }

    private static func udp(_ source: UInt16, _ destination: UInt16) -> [UInt8] {
        PacketBuilder.udp(srcPort: source, dstPort: destination, payload: [0, 0, 0, 0])
    }

    private static func tcp(_ source: UInt16, _ destination: UInt16) -> [UInt8] {
        PacketBuilder.tcp(srcPort: source, dstPort: destination, flags: 0x02, payload: [], sequence: 1)
    }

    /// An IPv4 frame with its TTL byte set.
    private static func v4(_ src: String, _ dst: String, _ proto: UInt8, _ payload: [UInt8], ttl: UInt8 = 64)
        -> [UInt8]
    {
        var frame = PacketBuilder.ethernetIPv4(proto: proto, src: src, dst: dst, payload: payload)
        frame[22] = ttl
        return frame
    }

    private static func v6(_ src: UInt16, _ dst: UInt16, _ payload: [UInt8], hop: UInt8 = 255) -> [UInt8] {
        var frame = PacketBuilder.ethernetIPv6(
            nextHeader: 17, src: [0x2001, 0xDB8, 0, 0, 0, 0, 0, src], dst: [0x2001, 0xDB8, 0, 0, 0, 0, 0, dst],
            payload: payload
        )
        frame[21] = hop
        return frame
    }

    private static func capture() throws -> URL {
        let icmp: [UInt8] = [8, 0, 0, 0, 0, 1, 0, 1] + [UInt8](repeating: 0, count: 8)
        let frames = [
            v4("192.0.2.10", "198.51.100.1", 6, tcp(50_000, 443)),
            v4("198.51.100.1", "192.0.2.10", 6, tcp(443, 50_000), ttl: 57),
            v4("192.0.2.10", "198.51.100.2", 17, udp(50_001, 53)),
            v4("198.51.100.2", "192.0.2.10", 17, udp(53, 50_001), ttl: 120),
            v4("192.0.2.10", "198.51.100.1", 1, icmp),
            v4("192.0.2.11", "198.51.100.1", 6, tcp(50_002, 443)),
            v6(1, 2, udp(40_000, 5_353)),
            v6(2, 1, udp(5_353, 40_000), hop: 64),
        ]
        return try write(frames, name: "ipstats")
    }

    private static func write(_ frames: [[UInt8]], name: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("\(name)-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames.enumerated().map {
            CapturedFrame(
                bytes: $0.element,
                timestamp: Date(timeIntervalSince1970: 1_800_000_000 + Double($0.offset)),
                originalLength: $0.element.count
            )
        }, to: url)
        return url
    }

    private static func rows(_ url: URL? = nil) throws -> [CaptureFrameRow] {
        let file = try url ?? capture()
        defer {
            if url == nil {
                try? FileManager.default.removeItem(at: file)
            }
        }
        let identity = try CaptureStreamReader(contentsOf: file).identity
        return try CaptureFrameListScanner(contentsOf: file, expectedIdentity: identity, sourceToken: UUID()).scan()
            .rows
    }

    private static func flatten(_ nodes: [StatsTreeNode], depth: Int = 0) -> [String] {
        nodes.flatMap { ["\(depth) \($0.title) \($0.count)"] + flatten($0.children ?? [], depth: depth + 1) }
    }

    /// A tshark stats tree as "depth name count" lines, the "IPv4 Statistics/" prefix dropped.
    private static func tshark(_ url: URL, tap: String) throws -> [String] {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = WiresharkOracle.tsharkURL
        process.arguments = ["-r", url.path, "-q", "-z", "\(tap),tree"]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let text = String(bytes: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        process.waitUntilExit()
        let body = text.components(separatedBy: "\n").drop { !$0.hasPrefix("---") }.dropFirst()
        return body.compactMap { line -> String? in
            guard let match = line.firstMatch(of: #/^( *)(\S.*?)\s{2,}(\d+)\s/#) else {
                return nil
            }
            let name = String(match.2)
                .replacingOccurrences(of: "IPv4 Statistics/", with: "")
                .replacingOccurrences(of: "IPv6 Statistics/", with: "")
            return "\(match.1.count) \(name) \(match.3)"
        }
    }
}
