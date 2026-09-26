import Foundation
import Testing
@testable import Tracexy

/// The HTTP/2 and WebSocket session filters find sessions where the switch is
/// visible: HTTP/2 from its cleartext preface or a TLS 1.2 ServerHello choosing ALPN
/// "h2", WebSocket from an HTTP/1 Upgrade — as tshark reads the same frames.
struct NegotiatedApplicationTests {
    // MARK: Internal

    @Test
    func sessionsCarryTheNegotiatedProtocol() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let loaded = try SavedCaptureStreamLoader(contentsOf: url).load()
        let byPort = Dictionary(uniqueKeysWithValues: loaded.sessions.compactMap { session in
            session.destinationEndpointValue.map { ($0.port, session.protocolStack) }
        })
        #expect(byPort[80]?.last == .http2)
        #expect(byPort[443]?.last == .http2)
        #expect(byPort[443]?.contains(.tls) == true)
        #expect(byPort[8_080]?.last == .websocket)
        #expect(byPort[8_081]?.contains(.websocket) == false)
        #expect(try SessionQueryParser().parse("http2") == .leaf(.protocolStackContains(.http2)))

        guard WiresharkOracle.isAvailable else {
            return
        }
        #expect(try WiresharkOracle.tsharkFields(url, fields: ["frame.number"], filter: "http2.magic").count == 1)
        #expect(try WiresharkOracle.tsharkFields(
            url, fields: ["tls.handshake.extensions_alpn_str"], filter: "tls.handshake.type == 2"
        ) == [["h2"]])
        #expect(try WiresharkOracle.tsharkFields(url, fields: ["http.upgrade"], filter: "http.upgrade").count == 2)
    }

    @Test
    func serverHelloALPNIsReadOnlyWhereItIs() {
        let hello = Self.serverHello(alpn: "h2")
        let packet = SessionBuilder.decodePacket(
            CapturedFrame(bytes: Self.tcp(port: 443, client: false, hello), timestamp: nil, originalLength: 0),
            linkType: LinkType.ethernet
        )
        #expect(packet.negotiatedApplication == .http2)
        let plain = SessionBuilder.decodePacket(
            CapturedFrame(
                bytes: Self.tcp(port: 443, client: false, Self.serverHello(alpn: nil)),
                timestamp: nil,
                originalLength: 0
            ),
            linkType: LinkType.ethernet
        )
        #expect(plain.negotiatedApplication == nil)
    }

    @Test
    func binaryAfterTheHeaderBlockKeepsTheFirstLine() {
        // The preface and the first frames often share one segment; HPACK and a
        // request body are not UTF-8, which must not hide the text before them.
        let settingsAndHeaders: [UInt8] = [0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]
            + [0x00, 0x00, 0x03, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01, 0x82, 0x86, 0xFF]
        let preface = SessionBuilder.decodePacket(
            CapturedFrame(
                bytes: Self.tcp(
                    port: 80,
                    client: true,
                    Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8) + settingsAndHeaders
                ),
                timestamp: nil,
                originalLength: 0
            ),
            linkType: LinkType.ethernet
        )
        #expect(preface.appProtocol == .http2)
        #expect(preface.negotiatedApplication == .http2)

        let post = SessionBuilder.decodePacket(
            CapturedFrame(
                bytes: Self.tcp(
                    port: 8_082,
                    client: true,
                    Array("POST /upload HTTP/1.1\r\nHost: b.test\r\n\r\n".utf8) + [0xFF, 0xD8, 0xFF, 0xE0]
                ),
                timestamp: nil,
                originalLength: 0
            ),
            linkType: LinkType.ethernet
        )
        #expect(post.layers.last?.summary == "POST /upload HTTP/1.1")
        #expect(post.layers.last?.fields.contains { $0.name == "Host" && $0.value == "b.test" } == true)
        #expect(PacketDecoder.headerBlock(Array("abc".utf8)) == Array("abc".utf8))
    }

    // MARK: Private

    private static func tcp(port: UInt16, client: Bool, _ payload: [UInt8], sequence: UInt32 = 1) -> [UInt8] {
        PacketBuilder.ethernetIPv4(
            proto: 6, src: client ? "192.0.2.10" : "198.51.100.80", dst: client ? "198.51.100.80" : "192.0.2.10",
            payload: PacketBuilder.tcp(
                srcPort: client ? 50_000 + port % 1_000 : port, dstPort: client ? port : 50_000 + port % 1_000,
                flags: 0x18, payload: payload, sequence: sequence
            )
        )
    }

    /// A TLS 1.2 ServerHello record, with an ALPN extension naming `alpn` when given.
    private static func serverHello(alpn: String?) -> [UInt8] {
        var extensions: [UInt8] = [0xFF, 0x01, 0x00, 0x01, 0x00] // renegotiation_info
        if let alpn {
            let name = Array(alpn.utf8)
            let list = [UInt8(name.count)] + name
            extensions += [0x00, 0x10] + be16(list.count + 2) + be16(list.count) + list
        }
        var body: [UInt8] = [0x03, 0x03] + [UInt8](repeating: 0x42, count: 32) + [0x00] + [0xC0, 0x2F] + [0x00]
        body += be16(extensions.count) + extensions
        let handshake = [0x02] + [0x00] + be16(body.count) + body
        return [0x16, 0x03, 0x03] + be16(handshake.count) + handshake
    }

    private static func be16(_ value: Int) -> [UInt8] {
        [UInt8(value >> 8 & 0xFF), UInt8(value & 0xFF)]
    }

    private static func capture() throws -> URL {
        let upgrade = "GET /chat HTTP/1.1\r\nHost: a.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        let switched = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            + "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
        let frames: [[UInt8]] = [
            tcp(port: 80, client: true, Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)),
            tcp(port: 443, client: false, serverHello(alpn: "h2")),
            tcp(port: 8_080, client: true, Array(upgrade.utf8)),
            tcp(port: 8_080, client: false, Array(switched.utf8)),
            tcp(port: 8_081, client: true, Array("GET / HTTP/1.1\r\nHost: a.test\r\n\r\n".utf8)),
        ]
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("negotiated-\(UUID().uuidString).pcap")
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
