import Foundation
import Testing
@testable import Tracexy

/// IP in IP (protocol 4) and 6in4 (protocol 41) are unwrapped like GRE: the outer
/// header is one layer and the session is the inner flow, as tshark dissects them.
struct IPInIPTests {
    // MARK: Internal

    @Test
    func innerFlowsBecomeTheSessions() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let loaded = try SavedCaptureStreamLoader(contentsOf: url).load()
        let flows = Set(loaded.sessions.compactMap { session in
            session.destinationEndpointValue.map { "\($0.ip):\($0.port)" }
        })
        #expect(flows == ["10.9.0.2:22", "2001:db8:0:0:0:0:0:b:5353"])

        let packet = SessionBuilder.decodePacket(
            CapturedFrame(bytes: Self.frames[1], timestamp: nil, originalLength: 0), linkType: LinkType.ethernet
        )
        #expect(packet.layers.map(\.proto) == [.ethernet, .ipv4, .ipv6, .udp])
        #expect(packet.layers[1].fields.first { $0.name == "Protocol" }?.value == "IPv6 (41)")

        // A protocol-4 payload that is not IPv4 stops at the outer header.
        let wrong = SessionBuilder.decodePacket(
            CapturedFrame(
                bytes: PacketBuilder.ethernetIPv4(
                    proto: 4,
                    src: "192.0.2.1",
                    dst: "192.0.2.4",
                    payload: [0x60] + [UInt8](repeating: 0, count: 39)
                ),
                timestamp: nil, originalLength: 0
            ),
            linkType: LinkType.ethernet
        )
        #expect(wrong.layers.map(\.proto) == [.ethernet, .ipv4])

        guard WiresharkOracle.isAvailable else {
            return
        }
        #expect(try WiresharkOracle.tsharkFields(url, fields: ["ip.src"], filter: "tcp") == [["192.0.2.1,10.9.0.1"]])
        #expect(try WiresharkOracle.tsharkFields(url, fields: ["ipv6.dst", "udp.dstport"], filter: "ipv6")
            == [["2001:db8::b", "5353"]])
    }

    // MARK: Private

    private static let frames: [[UInt8]] = {
        let inner4 = Array(PacketBuilder.ethernetIPv4(
            proto: 6, src: "10.9.0.1", dst: "10.9.0.2",
            payload: PacketBuilder.tcp(srcPort: 7_000, dstPort: 22, flags: 0x02, payload: [])
        ).dropFirst(14))
        let inner6 = Array(PacketBuilder.ethernetIPv6(
            nextHeader: 17, src: [0x2001, 0xDB8, 0, 0, 0, 0, 0, 0xA], dst: [0x2001, 0xDB8, 0, 0, 0, 0, 0, 0xB],
            payload: PacketBuilder.udp(srcPort: 2_000, dstPort: 5_353, payload: [0, 0, 0, 0])
        ).dropFirst(14))
        return [
            PacketBuilder.ethernetIPv4(proto: 4, src: "192.0.2.1", dst: "192.0.2.4", payload: inner4),
            PacketBuilder.ethernetIPv4(proto: 41, src: "192.0.2.1", dst: "192.0.2.3", payload: inner6),
        ]
    }()

    private static func capture() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("ipip-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames.enumerated().map {
            CapturedFrame(
                bytes: $0.element,
                timestamp: Date(timeIntervalSince1970: 1_800_000_000 + Double($0.offset)),
                originalLength: $0.element.count
            )
        }, to: url)
        return url
    }
}
