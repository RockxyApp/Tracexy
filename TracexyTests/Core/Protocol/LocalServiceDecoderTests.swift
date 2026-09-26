import Foundation
import Testing
@testable import Tracexy

// MARK: - LocalServiceDecoderTests

/// mDNS, DHCP and NTP: decoded from exact offsets, surfaced as their own protocol
/// kinds, bounded and fail-closed on short input, and in agreement with tshark.
struct LocalServiceDecoderTests {
    // MARK: Internal

    // MARK: Fixtures

    static var mdnsResponse: [UInt8] {
        udp(
            src: "192.0.2.77",
            dst: "224.0.0.251",
            sport: 5_353,
            dport: 5_353,
            payload: FollowDatagramReaderTests.dnsMessage(
                id: 0, flags: 0x8400, name: "printer.local", answers: ["192.0.2.77"]
            )
        )
    }

    static var dhcpAck: [UInt8] {
        udp(
            src: "192.0.2.1",
            dst: "192.0.2.50",
            sport: 67,
            dport: 68,
            payload: dhcpPayload(type: 5, your: [192, 0, 2, 50], requested: nil)
        )
    }

    static var dhcpDiscover: [UInt8] {
        udp(
            src: "0.0.0.0",
            dst: "255.255.255.255",
            sport: 68,
            dport: 67,
            payload: dhcpPayload(type: 1, your: [0, 0, 0, 0], requested: [192, 0, 2, 50])
        )
    }

    static var ntpServer: [UInt8] {
        // LI 0, VN 4, mode 4; stratum 2; poll 6; precision -20; ref id 192.0.2.123;
        // transmit timestamp 2026-01-01T00:00:00Z = 1,767,225,600 + 2,208,988,800.
        var header: [UInt8] = [0x24, 2, 6, 0xEC] + [UInt8](repeating: 0, count: 8) + [192, 0, 2, 123]
        header += [UInt8](repeating: 0, count: 24)
        header += be32(UInt32(1_767_225_600 + 2_208_988_800)) + [0, 0, 0, 0]
        return udp(src: "192.0.2.123", dst: "192.0.2.10", sport: 123, dport: 50_123, payload: header)
    }

    static var ntpClient: [UInt8] {
        let header: [UInt8] = [0x23] + [UInt8](repeating: 0, count: 47)
        return udp(src: "192.0.2.10", dst: "192.0.2.123", sport: 50_123, dport: 123, payload: header)
    }

    static func dhcpPayload(type: UInt8, your: [UInt8], requested: [UInt8]?) -> [UInt8] {
        var bootp: [UInt8] = [type == 5 ? 2 : 1, 1, 6, 0]
        bootp += be32(0x1234ABCD) + [0, 0, 0, 0]
        bootp += [0, 0, 0, 0] + your + [0, 0, 0, 0] + [0, 0, 0, 0]
        bootp += [0x02, 0, 0, 0, 0, 0x0A] + [UInt8](repeating: 0, count: 10)
        bootp += [UInt8](repeating: 0, count: 192)
        bootp += [0x63, 0x82, 0x53, 0x63]
        bootp += [53, 1, type]
        if let requested {
            bootp += [50, 4] + requested
        }
        if type == 5 {
            bootp += [54, 4, 192, 0, 2, 1]
            bootp += [51, 4] + be32(86_400)
            bootp += [3, 4, 192, 0, 2, 1]
            bootp += [6, 8, 192, 0, 2, 53, 198, 51, 100, 53]
        }
        bootp += [255]
        return bootp
    }

    @Test
    func mdnsIsReadAsMulticastDNSAndTeachesNames() {
        let packet = Self.decode(Self.mdnsResponse)
        #expect(packet.appProtocol == .mdns)
        #expect(packet.protocolStack.contains(.mdns))
        #expect(!packet.protocolStack.contains(.dns))
        #expect(packet.dnsQuery == "printer.local")
        #expect(packet.dnsAnswers == ["192.0.2.77"])
        #expect(packet.layers.last?.title == "Multicast DNS")

        var resolved: [String: String] = [:]
        SessionBuilder.learnResolved(from: packet, into: &resolved)
        #expect(resolved["192.0.2.77"] == "printer.local")
    }

    @Test
    func dhcpAckNamesTheLeaseAndItsOptions() throws {
        let packet = Self.decode(Self.dhcpAck)
        #expect(packet.appProtocol == .dhcp)
        let layer = try #require(packet.layers.last)
        #expect(layer.title == "Dynamic Host Configuration Protocol")
        #expect(layer.summary == "DHCP ACK 192.0.2.50")
        let fields = Dictionary(layer.fields.map { ($0.name, $0.value) }, uniquingKeysWith: { first, _ in first })
        #expect(fields["Message type"] == "DHCP ACK")
        #expect(fields["Your address"] == "192.0.2.50")
        #expect(fields["Server identifier"] == "192.0.2.1")
        #expect(fields["Lease time"] == "86400 s")
        #expect(fields["Router"] == "192.0.2.1")
        #expect(fields["DNS servers"] == "192.0.2.53, 198.51.100.53")
        #expect(fields["Client hardware address"] == "02:00:00:00:00:0a")
        #expect(fields["Transaction ID"] == "0x1234ABCD")
    }

    @Test
    func dhcpDiscoverSummarizesTheRequestedAddress() throws {
        let layer = try #require(Self.decode(Self.dhcpDiscover).layers.last)
        #expect(layer.summary == "DHCP Discover 192.0.2.50")
    }

    @Test
    func ntpServerReplyNamesStratumAndReference() throws {
        let packet = Self.decode(Self.ntpServer)
        #expect(packet.appProtocol == .ntp)
        let layer = try #require(packet.layers.last)
        #expect(layer.summary == "NTP v4 server, stratum 2")
        let fields = Dictionary(layer.fields.map { ($0.name, $0.value) }, uniquingKeysWith: { first, _ in first })
        #expect(fields["Reference ID"] == "192.0.2.123")
        #expect(fields["Transmit time"] == "2026-01-01T00:00:00Z")
        #expect(Self.decode(Self.ntpClient).layers.last?.summary == "NTP v4 client")
    }

    @Test
    func shortOrForeignPayloadsFailClosed() {
        // 40 bytes on port 123 is not an NTP header; a non-Ethernet BOOTP is not DHCP.
        let shortNTP = Self.udp(
            src: "192.0.2.10",
            dst: "192.0.2.123",
            sport: 50_000,
            dport: 123,
            payload: [UInt8](repeating: 0x23, count: 40)
        )
        #expect(Self.decode(shortNTP).appProtocol == nil)
        var tokenRing = Self.dhcpPayload(type: 1, your: [0, 0, 0, 0], requested: [192, 0, 2, 50])
        tokenRing[1] = 6
        let foreign = Self.udp(src: "0.0.0.0", dst: "255.255.255.255", sport: 68, dport: 67, payload: tokenRing)
        #expect(Self.decode(foreign).appProtocol == nil)
        // A truncated option list keeps what was read and claims nothing more.
        let cut = Array(Self.dhcpAck.prefix(Self.dhcpAck.count - 20))
        #expect(Self.decode(cut).appProtocol == .dhcp)
    }

    @Test
    func sessionsCarryTheNewProtocols() {
        let frames = [Self.mdnsResponse, Self.dhcpAck, Self.ntpServer].map {
            CapturedFrame(bytes: $0, timestamp: Date(timeIntervalSince1970: 1_000), originalLength: $0.count)
        }
        let stacks = SessionBuilder.build(from: frames, linkType: LinkType.ethernet).map(\.protocolStack)
        #expect(stacks.contains { $0.contains(.mdns) })
        #expect(stacks.contains { $0.contains(.dhcp) })
        #expect(stacks.contains { $0.contains(.ntp) })
    }

    @Test
    func expressionsNameTheNewProtocols() throws {
        let parser = SessionQueryParser()
        #expect(try parser.parse("mdns or dhcp or ntp") == .any([
            .leaf(.protocolStackContains(.mdns)),
            .leaf(.protocolStackContains(.dhcp)),
            .leaf(.protocolStackContains(.ntp)),
        ]))
    }

    @Test(.enabled(if: WiresharkOracle.isAvailable, "Wireshark is not installed on this machine"))
    func tsharkAgrees() throws {
        let frames = [Self.mdnsResponse, Self.dhcpAck, Self.ntpServer]
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("local-\(UUID().uuidString).pcap")
        try Data(FollowDatagramReaderTests.classicPcap(frames.map { ($0, UInt32($0.count)) })).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let dhcp = try WiresharkOracle.tsharkFields(
            url, fields: ["dhcp.option.dhcp", "dhcp.ip.your", "dhcp.option.dhcp_server_id"], filter: "dhcp"
        )
        #expect(dhcp.first == ["5", "192.0.2.50", "192.0.2.1"])
        let ntp = try WiresharkOracle.tsharkFields(url, fields: ["ntp.flags.mode", "ntp.stratum"], filter: "ntp")
        #expect(ntp.first == ["4", "2"])
        let mdns = try WiresharkOracle.tsharkFields(url, fields: ["dns.qry.name", "dns.a"], filter: "mdns")
        #expect(mdns.first == ["printer.local", "192.0.2.77"])
    }

    // MARK: Private

    private static func be32(_ value: UInt32) -> [UInt8] {
        [UInt8(value >> 24), UInt8((value >> 16) & 0xFF), UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]
    }

    private static func udp(src: String, dst: String, sport: UInt16, dport: UInt16, payload: [UInt8]) -> [UInt8] {
        PacketBuilder.ethernetIPv4(
            proto: 17, src: src, dst: dst,
            payload: PacketBuilder.udp(srcPort: sport, dstPort: dport, payload: payload)
        )
    }

    private static func decode(_ bytes: [UInt8]) -> DecodedPacket {
        SessionBuilder.decodePacket(
            CapturedFrame(bytes: bytes, timestamp: nil, originalLength: bytes.count),
            linkType: LinkType.ethernet
        )
    }
}
