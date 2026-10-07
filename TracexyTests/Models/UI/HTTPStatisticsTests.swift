import Foundation
import Testing
@testable import Tracexy

/// Statistics ▸ HTTP builds Wireshark's HTTP Requests, Load Distribution
/// and Packet Counter trees from the All Frames scan; every non-zero line matches
/// `tshark -z http_req,tree -z http_srv,tree -z http,tree`.
@MainActor
struct HTTPStatisticsTests {
    // MARK: Internal

    @Test
    func treesMatchWireshark() throws {
        let frames: [[UInt8]] = [
            PacketBuilder.httpRequestFrame(
                host: "a.test", path: "/x", src: "192.0.2.10", dst: "198.51.100.7", srcPort: 50_001
            ),
            PacketBuilder.httpRequestFrame(
                host: "a.test", path: "/x", src: "192.0.2.10", dst: "198.51.100.7", srcPort: 50_002
            ),
            PacketBuilder.httpRequestFrame(
                host: "a.test", path: "/y?q=1", src: "192.0.2.10", dst: "198.51.100.7", srcPort: 50_003
            ),
            PacketBuilder.httpRequestFrame(
                host: "b.test", path: "/z", src: "192.0.2.10", dst: "198.51.100.8", srcPort: 50_004
            ),
            Self.response("200 OK", from: "198.51.100.7", port: 50_001),
            Self.response("404 Not Found", from: "198.51.100.7", port: 50_002),
            Self.response("301 Moved Permanently", from: "198.51.100.8", port: 50_004),
            Self.response("500 Internal Server Error", from: "198.51.100.8", port: 50_003),
        ]
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("http-stats-\(UUID().uuidString).pcap")
        let records = frames.enumerated().map {
            ReplayCorpus.Frame(bytes: $0.element, offsetSeconds: $0.offset, linkType: LinkType.ethernet)
        }
        try Data(ReplayCorpus.classicPcapBytes(records)).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let identity = try CaptureStreamReader(contentsOf: url).identity
        let list = try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID()).scan()
        #expect(list.rows[0].http == .request(method: "GET", host: "a.test", uri: "/x"))
        #expect(list.rows[5].http == .response(status: 404))
        let statistics = HTTPStatistics(rows: list.rows)
        #expect(statistics.requestCount == 4 && statistics.responseCount == 4)

        let hosts = try #require(statistics.requestTree.first?.children)
        #expect(hosts.map(\.title) == ["a.test", "b.test"])
        #expect(hosts[0].children?.map(\.title) == ["/x", "/y?q=1"])
        #expect(hosts[0].children?.first?.count == 2)
        let csv = statistics.csv(.requests)
        #expect(csv.hasPrefix("Topic / Item,Count,Percent\r\nHTTP Requests by HTTP Host,4,\r\n  a.test,3,75.00%\r\n"))

        guard WiresharkOracle.isAvailable, let tshark = WiresharkOracle.tsharkURL else {
            return
        }
        let output = try Self.run(tshark, [
            "-r",
            url.path,
            "-q",
            "-z",
            "http_req,tree",
            "-z",
            "http_srv,tree",
            "-z",
            "http,tree"
        ])
        let theirs = Self.parseStatsTrees(output)
        var ours: Set<String> = []
        for tree in HTTPStatistics.Tree.allCases {
            Self.flatten(statistics.nodes(tree), prefix: "", into: &ours)
        }
        #expect(ours == theirs, "ours only: \(ours.subtracting(theirs)); tshark only: \(theirs.subtracting(ours))")
    }

    // MARK: Private

    private static func response(_ status: String, from server: String, port: UInt16) -> [UInt8] {
        let text = "HTTP/1.1 \(status)\r\nContent-Length: 0\r\n\r\n"
        return PacketBuilder.ethernetIPv4(
            proto: 6, src: server, dst: "192.0.2.10",
            payload: PacketBuilder.tcp(srcPort: 80, dstPort: port, flags: 0x18, payload: Array(text.utf8))
        )
    }

    private static func flatten(_ nodes: [HTTPStatisticsNode], prefix: String, into set: inout Set<String>) {
        for node in nodes where !node.isEmpty {
            let path = prefix + "/" + node.title
            set.insert("\(path)=\(node.count)")
            flatten(node.children ?? [], prefix: path, into: &set)
        }
    }

    /// Every non-zero line of tshark's stats trees as "/parent/…/name=count".
    private static func parseStatsTrees(_ output: String) -> Set<String> {
        var result: Set<String> = []
        var stack: [String] = []
        let line = /^( *)(\S.*?)\s{2,}(\d+)\s/
        for text in output.split(separator: "\n") {
            guard let match = String(text).firstMatch(of: line) else {
                continue
            }
            let depth = match.output.1.count
            let name = String(match.output.2)
            guard let count = Int(match.output.3), !name.hasPrefix("Packet Type"),
                  !name.hasPrefix("Request Type") else
            {
                continue
            }
            stack = Array(stack.prefix(depth)) + [name]
            if count > 0 {
                result.insert("/" + stack.joined(separator: "/") + "=\(count)")
            }
        }
        return result
    }

    private static func run(_ tool: URL, _ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = tool
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(bytes: data, encoding: .utf8) ?? ""
    }
}
