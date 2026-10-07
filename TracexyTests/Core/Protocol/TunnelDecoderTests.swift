import Foundation
import Testing
@testable import Tracexy

/// A tunnelled frame is a session of its inner flow, tagged with the tunnel.
struct TunnelDecoderTests {
    // MARK: Internal

    // MARK: Fixtures

    static func greFrame(key: UInt32?) -> [UInt8] {
        let innerIP = Array(PacketBuilder.ethernetIPv4(
            proto: 6, src: "10.1.0.5", dst: "10.2.0.9",
            payload: PacketBuilder.tcp(srcPort: 50_000, dstPort: 443, flags: 0x02, payload: [])
        ).dropFirst(14))
        var header: [UInt8] = [key == nil ? 0x00 : 0x20, 0x00, 0x08, 0x00]
        if let key {
            header += [UInt8(key >> 24), UInt8((key >> 16) & 0xFF), UInt8((key >> 8) & 0xFF), UInt8(key & 0xFF)]
        }
        return PacketBuilder.ethernetIPv4(
            proto: 47,
            src: "198.51.100.1",
            dst: "198.51.100.2",
            payload: header + innerIP
        )
    }

    static func vxlanFrame(vni: UInt32) -> [UInt8] {
        let inner = PacketBuilder.dnsQueryFrame(name: "tunnel.example.test", src: "10.9.0.2", dst: "10.9.0.53")
        let header: [UInt8] = [0x08, 0, 0, 0, UInt8(vni >> 16), UInt8((vni >> 8) & 0xFF), UInt8(vni & 0xFF), 0]
        return PacketBuilder.ethernetIPv4(
            proto: 17, src: "198.51.100.1", dst: "198.51.100.2",
            payload: PacketBuilder.udp(srcPort: 49_152, dstPort: 4_789, payload: header + inner)
        )
    }

    @Test
    func greCarriesTheInnerTCPFlow() throws {
        let packet = Self.decode(Self.greFrame(key: 0xCAFE))
        let tuple = try #require(packet.fiveTuple)
        #expect(tuple == FiveTuple(
            proto: .tcp,
            source: IPEndpoint(ip: "10.1.0.5", port: 50_000),
            destination: IPEndpoint(ip: "10.2.0.9", port: 443)
        ))
        #expect(packet.protocolStack.first == .gre)
        #expect(packet.protocolStack.contains(.tcp))
        #expect(!packet.protocolStack.contains(.udp))
        let gre = try #require(packet.layers.first { $0.proto == .gre })
        #expect(gre.fields.contains(DecodedField(name: "Key", value: "0x0000CAFE")))
        #expect(gre.summary == "IPv4")
    }

    @Test
    func vxlanCarriesTheInnerEthernetFrame() throws {
        let packet = Self.decode(Self.vxlanFrame(vni: 5_001))
        let tuple = try #require(packet.fiveTuple)
        #expect(tuple.proto == .udp)
        #expect(Set([tuple.a.ip, tuple.b.ip]) == ["10.9.0.2", "10.9.0.53"])
        #expect(packet.appProtocol == .dns)
        #expect(packet.protocolStack.first == .vxlan)
        #expect(packet.layers.first { $0.proto == .vxlan }?.summary == "VNI 5001")
    }

    @Test
    func nestingIsBoundedAndForeignPayloadsStopAtTheTunnel() {
        // GRE in GRE in GRE: the third level is not unwrapped.
        var inner = Self.greFrame(key: nil)
        for _ in 0 ..< 2 {
            let ipPacket = Array(inner.dropFirst(14))
            inner = PacketBuilder.ethernetIPv4(
                proto: 47, src: "198.51.100.1", dst: "198.51.100.2", payload: [0, 0, 0x08, 0x00] + ipPacket
            )
        }
        let packet = Self.decode(inner)
        // The third header is shown as a layer, but its payload is not unwrapped.
        #expect(packet.layers.count { $0.proto == .gre } == 3)
        #expect(!packet.layers.contains { $0.proto == .tcp })
        #expect(packet.fiveTuple == nil)
        // An unknown GRE payload type is a GRE layer and nothing more.
        let erspan = PacketBuilder.ethernetIPv4(
            proto: 47, src: "198.51.100.1", dst: "198.51.100.2", payload: [0, 0, 0x88, 0xBE] + [UInt8](
                repeating: 0,
                count: 40
            )
        )
        #expect(Self.decode(erspan).layers.last?.proto == .gre)
        // Port 4789 without the VXLAN I flag is ordinary UDP.
        let notVXLAN = PacketBuilder.ethernetIPv4(
            proto: 17, src: "198.51.100.1", dst: "198.51.100.2",
            payload: PacketBuilder.udp(srcPort: 5_000, dstPort: 4_789, payload: [UInt8](repeating: 0, count: 40))
        )
        #expect(!Self.decode(notVXLAN).protocolStack.contains(.vxlan))
    }

    @Test(.enabled(if: WiresharkOracle.isAvailable, "Wireshark is not installed on this machine"))
    func tsharkAgrees() throws {
        let frames = [Self.greFrame(key: 0xCAFE), Self.vxlanFrame(vni: 5_001)]
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("tunnel-\(UUID().uuidString).pcap")
        try Data(FollowDatagramReaderTests.classicPcap(frames.map { ($0, UInt32($0.count)) })).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let gre = try WiresharkOracle.tsharkFields(url, fields: ["gre.proto", "gre.key", "tcp.dstport"], filter: "gre")
        #expect(gre.first == ["0x0800", "0x0000cafe", "443"])
        let vxlan = try WiresharkOracle.tsharkFields(url, fields: ["vxlan.vni", "dns.qry.name"], filter: "vxlan")
        #expect(vxlan.first == ["5001", "tunnel.example.test"])
    }

    // MARK: Private

    private static func decode(_ bytes: [UInt8]) -> DecodedPacket {
        SessionBuilder.decodePacket(
            CapturedFrame(bytes: bytes, timestamp: nil, originalLength: bytes.count),
            linkType: LinkType.ethernet
        )
    }
}
