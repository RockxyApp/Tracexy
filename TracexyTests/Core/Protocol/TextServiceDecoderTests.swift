import Foundation
import Testing
@testable import Tracexy

/// SSH, FTP, SMTP, POP3, IMAP and SSDP are recognized and their
/// command and response lines named the way Wireshark names them — except that a
/// user name or secret is never read out.
struct TextServiceDecoderTests {
    // MARK: Internal

    @Test
    func namesEachServiceLine() throws {
        #expect(try field(Self.sshBanner, "Protocol") == "SSH-2.0-OpenSSH_9.6")
        #expect(try field(Self.ftpGreeting, "Response code") == "220")
        #expect(try field(Self.ftpGreeting, "Response argument") == "Service ready")
        #expect(try field(Self.ftpRetrieve, "Request argument") == "notes.txt")
        #expect(try field(Self.smtpHello, "Request command") == "EHLO")
        #expect(try field(Self.smtpReply, "Response code") == "250")
        #expect(try field(Self.popGreeting, "Response indicator") == "+OK")
        #expect(try field(Self.imapLogin, "Request tag") == "a001")
        #expect(try field(Self.imapLogin, "Request command") == "LOGIN")
        #expect(try field(Self.ssdpSearch, "Method") == "M-SEARCH")
        #expect(try field(Self.ssdpSearch, "ST") == "ssdp:all")
        #expect(Self.decode(Self.ssdpSearch).layers.last?.summary == "M-SEARCH ssdp:all")
        #expect(Self.decode(Self.smtpHello).appProtocol == .smtp)
        #expect(Self.decode(Self.imapLogin).appProtocol == .imap)
    }

    /// Tracexy keeps that a login crossed the wire, never the name or the secret.
    @Test
    func loginArgumentsAreNeverReadOut() {
        for frame in [Self.ftpUser, Self.imapLogin] {
            let values = Self.decode(frame).layers.flatMap(\.fields).map(\.value)
            #expect(!values.contains { $0.contains("alice") || $0.contains("secret") })
            #expect(values.contains("Not shown"))
        }
    }

    /// Mail body lines, binary SSH packets and text on other ports are not commands.
    @Test
    func otherLinesStayData() {
        let body = Self.tcp(client: true, port: 25, "Subject: hello\r\n")
        #expect(Self.decode(body).layers.last?.fields.isEmpty == true)
        #expect(Self.decode(body).layers.last?.summary == "Message data, 16 bytes")
        let binary = Self.tcpRaw(
            client: false,
            port: 22,
            [0x00, 0x00, 0x01, 0x2C, 0x06, 0x14] + Array(repeating: 0, count: 10)
        )
        #expect(Self.decode(binary).appProtocol == .ssh)
        #expect(Self.decode(binary).layers.last?.fields.isEmpty == true)
        #expect(Self.decode(Self.tcp(client: true, port: 8_000, "USER alice\r\n")).appProtocol != .ftp)
    }

    @Test
    func expressionsNameTheServices() throws {
        let parser = SessionQueryParser()
        #expect(try parser.parse("ssh or ssdp") == .any([
            .leaf(.protocolStackContains(.ssh)), .leaf(.protocolStackContains(.ssdp)),
        ]))
        #expect(try parser.parse("pop") == .leaf(.protocolStackContains(.pop3)))
    }

    @Test(.enabled(if: WiresharkOracle.isAvailable, "Wireshark is not installed on this machine"))
    func tsharkAgrees() throws {
        let frames = [
            Self.sshBanner, Self.ftpGreeting, Self.ftpRetrieve, Self.smtpHello, Self.popGreeting, Self.imapLogin,
            Self.ssdpSearch,
        ]
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("text-\(UUID().uuidString).pcap")
        try Data(FollowDatagramReaderTests.classicPcap(frames.map { ($0, UInt32($0.count)) })).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(try WiresharkOracle.tsharkFields(url, fields: ["ssh.protocol"], filter: "ssh").first
            == ["SSH-2.0-OpenSSH_9.6"])
        #expect(try WiresharkOracle.tsharkFields(
            url, fields: ["ftp.response.code", "ftp.response.arg"], filter: "ftp.response.code"
        ).first == ["220", "Service ready"])
        #expect(try WiresharkOracle.tsharkFields(
            url, fields: ["ftp.request.command", "ftp.request.arg"], filter: "ftp.request.command"
        ).first == ["RETR", "notes.txt"])
        #expect(try WiresharkOracle.tsharkFields(url, fields: ["smtp.req.command"], filter: "smtp").first == ["EHLO"])
        #expect(try WiresharkOracle.tsharkFields(url, fields: ["pop.response.indicator"], filter: "pop").first
            == ["+OK"])
        #expect(try WiresharkOracle.tsharkFields(
            url, fields: ["imap.request_tag", "imap.request.command"], filter: "imap"
        ).first == ["a001", "LOGIN"])
        #expect(try WiresharkOracle.tsharkFields(url, fields: ["http.request.method"], filter: "ssdp").first
            == ["M-SEARCH"])
    }

    // MARK: Private

    private static let sshBanner = tcp(client: false, port: 22, "SSH-2.0-OpenSSH_9.6\r\n")
    private static let ftpGreeting = tcp(client: false, port: 21, "220 Service ready\r\n")
    private static let ftpUser = tcp(client: true, port: 21, "USER alice\r\nPASS secret\r\n")
    private static let ftpRetrieve = tcp(client: true, port: 21, "RETR notes.txt\r\n")
    private static let smtpHello = tcp(client: true, port: 25, "EHLO client.example\r\n")
    private static let smtpReply = tcp(client: false, port: 25, "250-mail.example\r\n250 OK\r\n")
    private static let popGreeting = tcp(client: false, port: 110, "+OK ready\r\n")
    private static let imapLogin = tcp(client: true, port: 143, "a001 LOGIN alice secret\r\n")
    private static let ssdpSearch = PacketBuilder.ethernetIPv4(
        proto: 17, src: "192.0.2.10", dst: "239.255.255.250",
        payload: PacketBuilder.udp(srcPort: 50_002, dstPort: 1_900, payload: Array((
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\n"
                + "ST: ssdp:all\r\n\r\n"
        ).utf8))
    )

    private static func tcp(client: Bool, port: UInt16, _ text: String) -> [UInt8] {
        tcpRaw(client: client, port: port, Array(text.utf8))
    }

    private static func tcpRaw(client: Bool, port: UInt16, _ payload: [UInt8]) -> [UInt8] {
        PacketBuilder.ethernetIPv4(
            proto: 6, src: client ? "192.0.2.10" : "198.51.100.20", dst: client ? "198.51.100.20" : "192.0.2.10",
            payload: PacketBuilder.tcp(
                srcPort: client ? 50_000 : port, dstPort: client ? port : 50_000, flags: 0x18, payload: payload,
                sequence: 1
            )
        )
    }

    private static func decode(_ bytes: [UInt8]) -> DecodedPacket {
        SessionBuilder.decodePacket(
            CapturedFrame(bytes: bytes, timestamp: nil, originalLength: bytes.count),
            linkType: LinkType.ethernet
        )
    }

    private func field(_ frame: [UInt8], _ name: String) throws -> String {
        try #require(Self.decode(frame).layers.last?.fields.first { $0.name == name }).value
    }
}
