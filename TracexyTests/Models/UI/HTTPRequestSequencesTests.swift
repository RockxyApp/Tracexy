import Foundation
import Testing
@testable import Tracexy

/// Statistics ▸ HTTP ▸ Request Sequences builds the tree `tshark -z http_seq,tree`
/// prints — requests under their referers, redirect targets under the request they
/// answered — with Wireshark's counting, on the exchanges built below.
struct HTTPRequestSequencesTests {
    // MARK: Internal

    @Test
    func treeMatchesWireshark() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let ours = try Self.flatten(HTTPRequestSequences.tree(rows: Self.rows(url)))
        #expect(ours == Self.expected)

        guard WiresharkOracle.isAvailable, let tshark = WiresharkOracle.tsharkURL else {
            return
        }
        let process = Process()
        let pipe = Pipe()
        process.executableURL = tshark
        process.arguments = ["-r", url.path, "-q", "-z", "http_seq,tree"]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let text = String(bytes: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        process.waitUntilExit()
        // "  http://a.test/home       5   …": depth from the leading spaces, then name and count.
        let theirs = text.split(separator: "\n").compactMap { line -> String? in
            let depth = line.prefix { $0 == " " }.count
            let words = line.split(separator: " ")
            guard words.count >= 4, let count = Int(words[words[0] == "HTTP" ? 3 : 1]) else {
                return nil
            }
            let name = words[0] == "HTTP" ? words[0 ... 2].joined(separator: " ") : String(words[0])
            return "\(depth) \(name) \(count)"
        }
        #expect(ours == theirs)
    }

    /// Wireshark's stats trees list tied rows by name, descending — checked on the
    /// HTTP Requests tree, where six URIs tie at one request each.
    @Test
    func statsTreeTiesFollowWiresharksOrder() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let tree = try HTTPStatistics(rows: Self.rows(url)).requestTree
        let uris = try #require(tree.first?.children?.first?.children).map(\.title)
        #expect(uris == ["/img.png", "/style.css", "/old", "/logo.svg", "/login", "/home", "/app.js", "/"])
        #expect(StatsTreeOrder.precedes(count: 1, name: "b", before: 1, "a"))
        #expect(StatsTreeOrder.precedes(count: 2, name: "a", before: 1, "b"))

        guard WiresharkOracle.isAvailable, let tshark = WiresharkOracle.tsharkURL else {
            return
        }
        let process = Process()
        let pipe = Pipe()
        process.executableURL = tshark
        process.arguments = ["-r", url.path, "-q", "-z", "http_req,tree"]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let text = String(bytes: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        process.waitUntilExit()
        let theirs = text.split(separator: "\n").compactMap { line -> String? in
            let words = line.split(separator: " ")
            return line.hasPrefix("  /") ? words.first.map(String.init) : nil
        }
        #expect(uris == theirs)
    }

    @Test
    func locationResolvesAsWiresharkDoes() {
        let base = "http://a.test/dir/page?x=1#f"
        #expect(HTTPRequestSequences.locationTarget(base: base, location: "/home") == "http://a.test/home")
        #expect(HTTPRequestSequences.locationTarget(base: base, location: "next") == "http://a.test/dir/next")
        #expect(HTTPRequestSequences.locationTarget(base: base, location: "?y=2") == "http://a.test/dir/page?y=2")
        #expect(HTTPRequestSequences.locationTarget(base: base, location: "//b.test/z") == "http://b.test/z")
        #expect(HTTPRequestSequences.locationTarget(base: base, location: "https://c.test/") == "https://c.test/")
        #expect(HTTPRequestSequences.locationTarget(base: base, location: "") == base)
        #expect(HTTPRequestSequences.locationTarget(base: "/relative", location: "x") == nil)
        #expect(HTTPRequestSequences.fullURI(host: "—", uri: "/") == nil)
        #expect(HTTPRequestSequences.fullURI(host: " a.test ", uri: "/p") == "http://a.test/p")
        #expect(HTTPRequestSequences.fullURI(host: "proxy", uri: "HTTP://x.test/") == "HTTP://x.test/")
    }

    @Test
    func refererAndLocationAreReadFromTheHeaders() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let http = try Self.rows(url).compactMap(\.http)
        #expect(http[2] == .request(method: "GET", host: "a.test", uri: "/style.css", referer: "http://a.test/"))
        #expect(http[7] == .response(status: 302, location: "/home"))
        #expect(http[0] == .request(method: "GET", host: "a.test", uri: "/"))
    }

    // MARK: Private

    /// tshark's output for this capture: depth, node, count.
    private static let expected = [
        "0 HTTP Request Sequences 9",
        "1 http://a.test/ 11",
        "2 http://a.test/home 5",
        "3 http://a.test/img.png 2",
        "2 http://a.test/login 3",
        "3 http://a.test/home 1",
        "2 http://a.test/style.css 1",
        "2 http://a.test/app.js 1",
        "1 http://a.test/old 3",
        "2 http://b.test/new 3",
        "3 http://a.test/logo.svg 1",
    ]

    private static let exchanges: [(port: UInt16, pairs: [(String, String)])] = [
        (50_001, [
            (request("/"), response(200, "OK")),
            (request("/style.css", referer: "http://a.test/"), response(200, "OK")),
            (request("/app.js", referer: "http://a.test/"), response(200, "OK")),
            (request("/login", referer: "http://a.test/"), response(302, "Found", location: "/home")),
        ]),
        (50_002, [
            (request("/home", referer: "http://a.test/"), response(200, "OK")),
            (request("/img.png", referer: "http://a.test/home"), response(200, "OK")),
            (request("/img.png", referer: "http://a.test/home"), response(200, "OK")),
        ]),
        (50_003, [
            (request("/old"), response(301, "Moved Permanently", location: "http://b.test/new")),
            (request("/logo.svg", referer: "http://b.test/new"), response(200, "OK")),
        ]),
    ]

    private static func request(_ path: String, referer: String? = nil) -> String {
        "GET \(path) HTTP/1.1\r\nHost: a.test\r\n" + (referer.map { "Referer: \($0)\r\n" } ?? "") + "\r\n"
    }

    private static func response(_ code: Int, _ reason: String, location: String? = nil) -> String {
        "HTTP/1.1 \(code) \(reason)\r\n" + (location.map { "Location: \($0)\r\n" } ?? "")
            + "Content-Length: 0\r\n\r\n"
    }

    private static func rows(_ url: URL) throws -> [CaptureFrameRow] {
        let identity = try CaptureStreamReader(contentsOf: url).identity
        return try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID()).scan()
            .rows
    }

    private static func flatten(_ nodes: [HTTPStatisticsNode], depth: Int = 0) -> [String] {
        nodes.flatMap { node in
            ["\(depth) \(node.title) \(node.count)"] + flatten(node.children ?? [], depth: depth + 1)
        }
    }

    private static func capture() throws -> URL {
        var frames: [(Int, [UInt8])] = []
        var time = 0
        for (port, pairs) in exchanges {
            var clientSequence: UInt32 = 1_000
            var serverSequence: UInt32 = 5_000
            for (request, response) in pairs {
                frames.append((time, segment(port: port, client: true, sequence: clientSequence, request)))
                clientSequence += UInt32(request.utf8.count)
                time += 10_000
                frames.append((time, segment(port: port, client: false, sequence: serverSequence, response)))
                serverSequence += UInt32(response.utf8.count)
                time += 10_000
            }
        }
        func le32(_ value: UInt32) -> [UInt8] {
            (0 ..< 4).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
        }
        var bytes = le32(0xA1B2C3D4) + [2, 0, 4, 0] + le32(0) + le32(0) + le32(65_535) + le32(1)
        for (micros, frame) in frames {
            bytes += le32(1_800_000_000 + UInt32(micros / 1_000_000)) + le32(UInt32(micros % 1_000_000))
            bytes += le32(UInt32(frame.count)) + le32(UInt32(frame.count)) + frame
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("httpseq-\(UUID().uuidString).pcap")
        try Data(bytes).write(to: url)
        return url
    }

    private static func segment(port: UInt16, client: Bool, sequence: UInt32, _ text: String) -> [UInt8] {
        PacketBuilder.ethernetIPv4(
            proto: 6, src: client ? "192.0.2.10" : "198.51.100.80", dst: client ? "198.51.100.80" : "192.0.2.10",
            payload: PacketBuilder.tcp(
                srcPort: client ? port : 80, dstPort: client ? 80 : port, flags: 0x18, payload: Array(text.utf8),
                sequence: sequence
            )
        )
    }
}
