import Foundation
import Testing
@testable import Tracexy

/// `tracexy stats` prints the frame statistics under tshark's `-z` names: the ten IP
/// Statistics trees, HTTP request sequences, SIP and RTP streams — the same numbers the
/// windows show, which their own tests hold to tshark.
struct CommandLineFrameTapsTests {
    @Test
    func frameTapsPrintTheWindowsModels() throws {
        let frames = [
            PacketBuilder.ethernetIPv4(
                proto: 6, src: "192.0.2.10", dst: "198.51.100.7",
                payload: PacketBuilder.tcp(srcPort: 50_000, dstPort: 443, flags: 0x02, payload: [])
            ),
            PacketBuilder.dnsQueryFrame(name: "a.test", src: "192.0.2.10", dst: "192.0.2.53"),
            PacketBuilder.ethernetIPv4(
                proto: 17, src: "192.0.2.10", dst: "198.51.100.7",
                payload: PacketBuilder.udp(
                    srcPort: 40_000, dstPort: 40_002,
                    payload: [0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 9] + [UInt8](repeating: 0xFF, count: 160)
                )
            ),
        ]
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("taps-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames.enumerated().map {
            CapturedFrame(
                bytes: $0.element, timestamp: Date(timeIntervalSince1970: 1_800_000_000 + Double($0.offset)),
                originalLength: $0.element.count
            )
        }, to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let run = { (tap: String) -> String in
            var text = ""
            _ = TracexyCommandLine.runIfRequested(
                ["Tracexy", "stats", url.path, "-z", tap, "--format", "csv"], output: { text += $0 }, errors: { _ in }
            )
            return text
        }
        #expect(run("ip_hosts,tree")
            == "topic,count\nAll Addresses,3\n  192.0.2.10,3\n  198.51.100.7,2\n  192.0.2.53,1\n")
        #expect(run("ptype,tree").contains("UDP,2"))
        for name in [
            "ip_srcdst",
            "dests",
            "ip_ttl",
            "ipv6_hosts",
            "ipv6_ptype",
            "ipv6_srcdst",
            "ipv6_dests",
            "ipv6_hop"
        ] {
            #expect(run("\(name),tree").hasPrefix("topic,count\n"), "\(name)")
        }
        #expect(run("rtp,streams").contains("192.0.2.10,40000,198.51.100.7,40002,0x00000009,g711U,1"))
        #expect(run("http_seq,tree") == "topic,count\n")
        #expect(run("sip,stat").hasPrefix("topic,count\n"))
    }
}
