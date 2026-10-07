import Foundation
import Testing
@testable import Tracexy

/// Export Frames ▸ Headers strips tunnel encapsulation as Wireshark's Strip
/// Headers does — to the innermost IP packet (raw IP) or to the Ethernet frame a
/// VXLAN or GRE tunnel carries — and leaves out frames without that inner packet.
struct FrameHeaderStripTests {
    // MARK: Internal

    @Test
    func stripsToTheInnerPacketAndCountsTheRest() throws {
        let gre = TunnelDecoderTests.greFrame(key: 0xCAFE)
        let vxlan = TunnelDecoderTests.vxlanFrame(vni: 42)
        let plain = PacketBuilder.ethernetIPv4(
            proto: 6, src: "192.0.2.10", dst: "198.51.100.80",
            payload: PacketBuilder.tcp(srcPort: 51_000, dstPort: 80, flags: 0x02, payload: [])
        )
        let source = try Self.write([gre, vxlan, plain])
        defer { try? FileManager.default.removeItem(at: source) }

        let ipOut = Self.temporaryURL("pcap")
        defer { try? FileManager.default.removeItem(at: ipOut) }
        let ipSummary = try CaptureFrameExporter.export(
            from: source, scope: .wholeCapture,
            options: FrameExportOptions(format: .pcap, stripsHeaders: .innerIP), to: ipOut
        )
        #expect(ipSummary.writtenFrameCount == 3 && ipSummary.unstrippedFrameCount == 0)
        let ipFrames = try Self.frames(ipOut)
        #expect(ipFrames.allSatisfy { $0.reference.linkType == LinkType.raw })
        // GRE's inner IPv4 starts after outer Ethernet (14) + IPv4 (20) + GRE with key (8).
        #expect(ipFrames[0].bytes == Array(gre.dropFirst(42)))
        // VXLAN: outer Ethernet + IPv4 + UDP + VXLAN (50), then the inner Ethernet (14).
        #expect(ipFrames[1].bytes == Array(vxlan.dropFirst(64)))
        #expect(ipFrames[2].bytes == Array(plain.dropFirst(14)))

        let ethernetOut = Self.temporaryURL("pcap")
        defer { try? FileManager.default.removeItem(at: ethernetOut) }
        let ethernetSummary = try CaptureFrameExporter.export(
            from: source, scope: .wholeCapture,
            options: FrameExportOptions(format: .pcap, stripsHeaders: .innerEthernet), to: ethernetOut
        )
        #expect(ethernetSummary.writtenFrameCount == 1 && ethernetSummary.unstrippedFrameCount == 2)
        let ethernetFrames = try Self.frames(ethernetOut)
        #expect(ethernetFrames.map(\.bytes) == [Array(vxlan.dropFirst(50))])
        #expect(ethernetFrames.first?.reference.linkType == LinkType.ethernet)

        guard WiresharkOracle.isAvailable else {
            return
        }
        let rows = try WiresharkOracle.tsharkFields(ipOut, fields: ["frame.protocols", "ip.src", "ip.dst"])
        #expect(rows.map { $0[1] } == ["10.1.0.5", "10.9.0.2", "192.0.2.10"])
        #expect(rows.allSatisfy { $0[0].hasPrefix("raw:ip") })
        let inner = try WiresharkOracle.tsharkFields(ethernetOut, fields: ["dns.qry.name"])
        #expect(inner == [["tunnel.example.test"]])
    }

    // MARK: Private

    private static func temporaryURL(_ ext: String) -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("strip-\(UUID().uuidString).\(ext)")
    }

    private static func write(_ frames: [[UInt8]]) throws -> URL {
        let url = temporaryURL("pcap")
        let records = frames.enumerated().map {
            ReplayCorpus.Frame(bytes: $0.element, offsetSeconds: $0.offset, linkType: LinkType.ethernet)
        }
        try Data(ReplayCorpus.classicPcapBytes(records)).write(to: url)
        return url
    }

    private static func frames(_ url: URL) throws -> [CaptureFrameEvent] {
        let reader = try CaptureStreamReader(contentsOf: url)
        var events: [CaptureFrameEvent] = []
        while case let .frame(event) = try reader.next() {
            events.append(event)
        }
        return events
    }
}
