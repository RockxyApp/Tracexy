import Foundation
import Testing
@testable import Tracexy

/// SMB2 headers, LLMNR and NetBIOS Name Service, named the way
/// Wireshark names them.
struct WindowsServiceDecoderTests {
    // MARK: Internal

    @Test
    func decodesHeadersAndNames() throws {
        let negotiate = Self.decode(Self.smbRequest)
        #expect(negotiate.appProtocol == .smb)
        #expect(negotiate.layers.last?.summary == "Negotiate Protocol Request")
        let failure = Self.decode(Self.smbFailure)
        #expect(failure.layers.last?.summary == "Session Setup Response, Error: STATUS_LOGON_FAILURE")
        #expect(failure.layers.last?.fields.first { $0.name == "Session ID" }?.value == "0x0000000000001234")
        let llmnr = Self.decode(Self.llmnrQuery)
        #expect(llmnr.appProtocol == .llmnr)
        #expect(llmnr.dnsQuery == "printer")
        #expect(llmnr.layers.last?.title == "Link-local Multicast Name Resolution")
        let answer = Self.decode(Self.nbnsResponse)
        #expect(answer.appProtocol == .nbns)
        #expect(answer.layers.last?.fields.first { $0.name == "Name" }?.value == "FILESERVER<20> (Server service)")
        #expect(Self.decode(Self.nbnsQuery).layers.last?.fields.first { $0.name == "Name" }?.value == "FILESERVER<20>")
        // A request names no NT status (its bytes are a channel sequence), as in Wireshark.
        #expect(negotiate.layers.last?.fields.contains { $0.name == "NT Status" } == false)
        #expect(answer.layers.last?.fields.first { $0.name == "Addr" }?.value == "192.0.2.40")
        #expect(try SessionQueryParser().parse("smb2") == .leaf(.protocolStackContains(.smb)))
    }

    @Test(.enabled(if: WiresharkOracle.isAvailable, "Wireshark is not installed on this machine"))
    func tsharkAgrees() throws {
        let frames = [Self.smbRequest, Self.smbFailure, Self.llmnrQuery, Self.nbnsQuery, Self.nbnsResponse]
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("windows-\(UUID().uuidString).pcap")
        try Data(FollowDatagramReaderTests.classicPcap(frames.map { ($0, UInt32($0.count)) })).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(try WiresharkOracle.tsharkFields(
            url, fields: ["smb2.cmd", "smb2.nt_status", "smb2.msg_id"], filter: "smb2"
        ) == [["0", "", "0"], ["1", "0xc000006d", "2"]])
        #expect(try WiresharkOracle.tsharkFields(url, fields: ["dns.qry.name"], filter: "llmnr") == [["printer"]])
        #expect(try WiresharkOracle.tsharkFields(url, fields: ["nbns.name", "nbns.addr"], filter: "nbns")
            == [["FILESERVER<20>", ""], ["FILESERVER<20> (Server service)", "192.0.2.40"]])
    }

    // MARK: Private

    private static let smbRequest = tcp(client: true, smb(command: 0, status: 0, flags: 0, messageID: 0, session: 0))
    private static let smbFailure = tcp(
        client: false, smb(command: 1, status: 0xC000006D, flags: 1, messageID: 2, session: 0x1234)
    )
    private static let llmnrQuery = udp(
        src: "192.0.2.10", dst: "224.0.0.252", sport: 50_000, dport: 5_355,
        [0xAB, 0xCD, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7] + Array("printer".utf8) + [0, 0, 1, 0, 1]
    )
    private static let nbnsQuery = udp(
        src: "192.0.2.10", dst: "192.0.2.255", sport: 137, dport: 137,
        [0x12, 0x34, 0x01, 0x10, 0, 1, 0, 0, 0, 0, 0, 0] + encodedName + [0, 0x20, 0, 1]
    )
    private static let nbnsResponse = udp(
        src: "192.0.2.40", dst: "192.0.2.10", sport: 137, dport: 137,
        [0x12, 0x34, 0x85, 0x00, 0, 0, 0, 1, 0, 0, 0, 0] + encodedName
            + [0, 0x20, 0, 1, 0, 0, 0x0E, 0x10, 0, 6, 0, 0, 192, 0, 2, 40]
    )

    /// "FILESERVER" padded with spaces, suffix 0x20, in RFC 1001 first-level encoding.
    private static var encodedName: [UInt8] {
        let raw = Array("FILESERVER".utf8) + [UInt8](repeating: 0x20, count: 5) + [0x20]
        return [32] + raw.flatMap { [0x41 + ($0 >> 4), 0x41 + ($0 & 0x0F)] } + [0]
    }

    private static func smb(command: UInt16, status: UInt32, flags: UInt32, messageID: UInt64, session: UInt64)
        -> [UInt8]
    {
        func le(_ value: UInt64, _ count: Int) -> [UInt8] {
            (0 ..< count).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
        }
        let header = [0xFE, 0x53, 0x4D, 0x42] + le(64, 2) + le(0, 2) + le(UInt64(status), 4) + le(UInt64(command), 2)
            + le(1, 2) + le(UInt64(flags), 4) + le(0, 4) + le(messageID, 8) + le(0, 4) + le(0, 4) + le(session, 8)
            + [UInt8](repeating: 0, count: 16)
        let body: [UInt8] = [0x24, 0, 0, 0] + [UInt8](repeating: 0, count: 32)
        let message = header + body
        return [0, 0, UInt8(message.count >> 8), UInt8(message.count & 0xFF)] + message
    }

    private static func tcp(client: Bool, _ payload: [UInt8]) -> [UInt8] {
        PacketBuilder.ethernetIPv4(
            proto: 6, src: client ? "192.0.2.10" : "192.0.2.40", dst: client ? "192.0.2.40" : "192.0.2.10",
            payload: PacketBuilder.tcp(
                srcPort: client ? 50_000 : 445, dstPort: client ? 445 : 50_000, flags: 0x18, payload: payload,
                sequence: 1
            )
        )
    }

    private static func udp(src: String, dst: String, sport: UInt16, dport: UInt16, _ payload: [UInt8]) -> [UInt8] {
        PacketBuilder.ethernetIPv4(
            proto: 17, src: src, dst: dst, payload: PacketBuilder.udp(srcPort: sport, dstPort: dport, payload: payload)
        )
    }

    private static func decode(_ bytes: [UInt8]) -> DecodedPacket {
        SessionBuilder.decodePacket(
            CapturedFrame(bytes: bytes, timestamp: nil, originalLength: bytes.count), linkType: LinkType.ethernet
        )
    }
}
