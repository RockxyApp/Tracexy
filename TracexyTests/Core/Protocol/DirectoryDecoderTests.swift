import Foundation
import Testing
@testable import Tracexy

/// Kerberos and LDAP read to their message type, operation and
/// error or result code, as Wireshark names them — never a principal, DN or credential.
struct DirectoryDecoderTests {
    // MARK: Internal

    @Test
    func readsTypesAndCodes() {
        let error = Self.decode(Self.kerberosError)
        #expect(error.appProtocol == .kerberos)
        #expect(error.layers.last?.summary == "KRB-ERROR: KDC_ERR_PREAUTH_REQUIRED")
        #expect(error.layers.last?.fields.first { $0.name == "realm" }?.value == "EXAMPLE.TEST")
        let bind = Self.decode(Self.ldapBind)
        #expect(bind.appProtocol == .ldap)
        #expect(bind.layers.last?.summary == "bindRequest (message 1)")
        let refused = Self.decode(Self.ldapRefused)
        #expect(refused.layers.last?.summary == "bindResponse invalidCredentials (message 1)")
        #expect(refused.layers.last?.fields.first { $0.name == "resultCode" }?.value == "invalidCredentials (49)")
    }

    @Test(.enabled(if: WiresharkOracle.isAvailable, "Wireshark is not installed on this machine"))
    func tsharkAgrees() throws {
        let frames = [Self.kerberosError, Self.ldapBind, Self.ldapRefused]
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("directory-\(UUID().uuidString).pcap")
        try Data(FollowDatagramReaderTests.classicPcap(frames.map { ($0, UInt32($0.count)) })).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(try WiresharkOracle.tsharkFields(
            url, fields: ["kerberos.msg_type", "kerberos.error_code", "kerberos.realm"], filter: "kerberos"
        ) == [["30", "25", "EXAMPLE.TEST"]])
        #expect(try WiresharkOracle.tsharkFields(
            url, fields: ["ldap.messageID", "ldap.protocolOp", "ldap.bindResponse_resultCode"], filter: "ldap"
        ) == [["1", "0", ""], ["1", "1", "49"]]) // a bind response's code is its own field in Wireshark
    }

    // MARK: Private

    private static let kerberosError: [UInt8] = {
        let realm = tlv(0x1B, Array("EXAMPLE.TEST".utf8))
        let body = tlv(0xA0, tlv(0x02, [5])) + tlv(0xA1, tlv(0x02, [30]))
            + tlv(0xA4, tlv(0x18, Array("20260924000000Z".utf8))) + tlv(0xA5, tlv(0x02, [0]))
            + tlv(0xA6, tlv(0x02, [25])) + tlv(0xA9, realm)
            + tlv(
                0xAA,
                tlv(0x30, tlv(0xA0, tlv(0x02, [2])) + tlv(0xA1, tlv(0x30, tlv(0x1B, Array("krbtgt".utf8)) + realm)))
            )
        return udp(tlv(0x7E, tlv(0x30, body)))
    }()

    private static let ldapBind = tcp(
        client: true, tlv(0x30, tlv(0x02, [1]) + tlv(0x60, tlv(0x02, [3]) + tlv(0x04, []) + tlv(0x80, [])))
    )
    private static let ldapRefused = tcp(
        client: false, tlv(0x30, tlv(0x02, [1]) + tlv(0x61, tlv(0x0A, [49]) + tlv(0x04, []) + tlv(0x04, [])))
    )

    private static func tlv(_ tag: UInt8, _ value: [UInt8]) -> [UInt8] {
        [tag] + (value.count < 0x80 ? [UInt8(value.count)] : [0x81, UInt8(value.count)]) + value
    }

    private static func udp(_ payload: [UInt8]) -> [UInt8] {
        PacketBuilder.ethernetIPv4(
            proto: 17, src: "192.0.2.5", dst: "192.0.2.10",
            payload: PacketBuilder.udp(srcPort: 88, dstPort: 52_000, payload: payload)
        )
    }

    private static func tcp(client: Bool, _ payload: [UInt8]) -> [UInt8] {
        PacketBuilder.ethernetIPv4(
            proto: 6, src: client ? "192.0.2.10" : "192.0.2.5", dst: client ? "192.0.2.5" : "192.0.2.10",
            payload: PacketBuilder.tcp(
                srcPort: client ? 50_000 : 389, dstPort: client ? 389 : 50_000, flags: 0x18, payload: payload,
                sequence: 1
            )
        )
    }

    private static func decode(_ bytes: [UInt8]) -> DecodedPacket {
        SessionBuilder.decodePacket(
            CapturedFrame(bytes: bytes, timestamp: nil, originalLength: bytes.count), linkType: LinkType.ethernet
        )
    }
}
