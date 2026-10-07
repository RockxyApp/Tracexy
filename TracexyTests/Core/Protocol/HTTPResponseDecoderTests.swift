import Foundation
import Testing
@testable import Tracexy

/// HTTP/1 responses are read as a status line and a few explaining headers; request
/// decoding is unchanged; credentials are never surfaced.
struct HTTPResponseDecoderTests {
    // MARK: Internal

    @Test
    func responseStatusAndHeaders() throws {
        let layer = try #require(Self.httpLayer(Self.response(
            "HTTP/1.1 301 Moved Permanently",
            headers: [
                "Location: https://www.example.test/",
                "Content-Type: text/html; charset=utf-8",
                "Content-Length: 162",
                "Server: nginx",
                "Set-Cookie: session=secret-value; HttpOnly",
            ]
        )))
        #expect(layer.summary == "HTTP/1.1 301 Moved Permanently")
        let fields = Dictionary(layer.fields.map { ($0.name, $0.value) }, uniquingKeysWith: { first, _ in first })
        #expect(fields["Status"] == "301 Moved Permanently")
        #expect(fields["Version"] == "HTTP/1.1")
        #expect(fields["Location"] == "https://www.example.test/")
        #expect(fields["Content-Type"] == "text/html; charset=utf-8")
        #expect(fields["Content-Length"] == "162")
        #expect(fields["Server"] == "nginx")
        #expect(fields["Set-Cookie"] == "present (value not shown)")
        #expect(!layer.fields.contains { $0.value.contains("secret-value") })
        #expect(fields["Request"] == nil)
    }

    @Test
    func requestLayerIsUnchanged() throws {
        let frame = PacketBuilder.httpRequestFrame(
            host: "example.com", path: "/index.html", src: "192.0.2.10", dst: "198.51.100.5"
        )
        let layer = try #require(Self.httpLayer(frame))
        #expect(layer.fields == [
            DecodedField(name: "Request", value: "GET /index.html HTTP/1.1"),
            DecodedField(name: "Host", value: "example.com"),
        ])
    }

    @Test
    func headersPastTheWindowOrBodyAreNotRead() throws {
        let padding = (0 ..< 20).map { "X-Pad-\($0): \(String(repeating: "a", count: 20))" }
        let layer = try #require(Self.httpLayer(Self.response(
            "HTTP/1.1 200 OK", headers: padding + ["Server: late"], body: "Server: in-body"
        )))
        #expect(!layer.fields.contains { $0.name == "Server" })
        let statusOnly = try #require(Self.httpLayer(Self.response("HTTP/1.0 204", headers: [])))
        #expect(statusOnly.fields.first == DecodedField(name: "Status", value: "204"))
    }

    @Test(.enabled(if: WiresharkOracle.isAvailable, "Wireshark is not installed on this machine"))
    func tsharkAgreesOnTheStatus() throws {
        let frame = Self.response("HTTP/1.1 404 Not Found", headers: ["Content-Length: 0"])
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("http-\(UUID().uuidString).pcap")
        try Data(FollowDatagramReaderTests.classicPcap([(frame, UInt32(frame.count))])).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let rows = try WiresharkOracle.tsharkFields(
            url, fields: ["http.response.code", "http.response.phrase"], filter: "http.response"
        )
        #expect(rows.first == ["404", "Not Found"])
        #expect(Self.httpLayer(frame)?.fields.first?.value == "404 Not Found")
    }

    // MARK: Private

    private static func response(_ statusLine: String, headers: [String], body: String = "") -> [UInt8] {
        let text = ([statusLine] + headers).joined(separator: "\r\n") + "\r\n\r\n" + body
        return PacketBuilder.ethernetIPv4(
            proto: 6, src: "198.51.100.5", dst: "192.0.2.10",
            payload: PacketBuilder.tcp(srcPort: 80, dstPort: 51_000, flags: 0x18, payload: Array(text.utf8))
        )
    }

    private static func httpLayer(_ bytes: [UInt8]) -> DecodedLayer? {
        SessionBuilder.decodePacket(
            CapturedFrame(bytes: bytes, timestamp: nil, originalLength: bytes.count),
            linkType: LinkType.ethernet
        ).layers.first { $0.proto == .http }
    }
}
