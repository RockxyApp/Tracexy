import Foundation
import Testing
@testable import Tracexy

/// Statistics ▸ DNS matches every non-zero line of `tshark -z dns,tree`: packet
/// types, query/answer types, classes, rcodes, opcodes, payload sizes, name and
/// section statistics, and request/response times.
@MainActor
struct DNSStatisticsTests {
    // MARK: Internal

    @Test
    func treeMatchesWireshark() throws {
        let frames = Self.frames()
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("dns-stats-\(UUID().uuidString).pcap")
        let records = frames.enumerated().map {
            ReplayCorpus.Frame(bytes: $0.element, offsetSeconds: $0.offset, linkType: LinkType.ethernet)
        }
        try Data(ReplayCorpus.classicPcapBytes(records)).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let list = try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID()).scan()
        let tree = DNSStatistics.tree(rows: list.rows)
        #expect(tree.first?.count == frames.count)
        #expect(StatsTreeNode.csv(tree).hasPrefix("Topic / Item,Count,Average,Min,Max\r\nTotal Packets,6,"))

        guard WiresharkOracle.isAvailable, let tshark = WiresharkOracle.tsharkURL else {
            return
        }
        let process = Process()
        process.executableURL = tshark
        process.arguments = ["-r", url.path, "-q", "-z", "dns,tree"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let output = String(bytes: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        process.waitUntilExit()

        var theirs = Self.parseStatsTree(output)
        var ours: [String: (count: Int, average: Double?)] = [:]
        func walk(_ nodes: [StatsTreeNode], prefix: String) {
            for node in nodes where !node.isEmpty || node.children != nil {
                let path = prefix + "/" + node.title
                if !node.isEmpty {
                    ours[path] = (node.count, node.average)
                }
                walk(node.children ?? [], prefix: path)
            }
        }
        walk(tree, prefix: "")
        // Wireshark adds each answered response to Response Stats twice; Tracexy
        // counts every response once. Check that exact relation, then compare the rest.
        let responses = list.rows.compactMap(\.dns).filter(\.isResponse).count
        let unsolicited = 1
        for path in ours.keys where path.hasPrefix("/Response Stats/") {
            #expect(ours[path]?.count == responses)
            #expect(theirs[path]?.count == responses + (responses - unsolicited))
            ours.removeValue(forKey: path)
            theirs.removeValue(forKey: path)
        }
        #expect(
            Set(ours.keys) == Set(theirs.keys),
            "ours only \(Set(ours.keys).subtracting(theirs.keys)); tshark only \(Set(theirs.keys).subtracting(ours.keys))"
        )
        for (path, value) in theirs {
            #expect(ours[path]?.count == value.count, "\(path)")
            if let average = value.average {
                #expect(abs((ours[path]?.average ?? -1) - average) < 0.01, "\(path) average")
            }
        }
    }

    // MARK: Private

    /// Every non-zero row of a tshark stats tree as path → (count, average), read by
    /// the header's column positions (a blank Average stays `nil`).
    private static func parseStatsTree(_ output: String) -> [String: (count: Int, average: Double?)] {
        let lines = output.components(separatedBy: "\n")
        guard let header = lines.first(where: { $0.hasPrefix("Packet Type") }),
              let countColumn = header.range(of: "Count")?.lowerBound,
              let averageColumn = header.range(of: "Average")?.lowerBound,
              let minimumColumn = header.range(of: "Min Val")?.lowerBound else
        {
            return [:]
        }
        let countOffset = header.distance(from: header.startIndex, to: countColumn)
        let averageOffset = header.distance(from: header.startIndex, to: averageColumn)
        let minimumOffset = header.distance(from: header.startIndex, to: minimumColumn)
        var result: [String: (count: Int, average: Double?)] = [:]
        var stack: [String] = []
        for line in lines where line.count > minimumOffset && !line.hasPrefix("Packet Type") {
            let characters = Array(line)
            let name = String(characters[..<countOffset]).trimmingCharacters(in: .whitespaces)
            let depth = characters.prefix { $0 == " " }.count
            guard !name.isEmpty,
                  let count = Int(String(characters[countOffset ..< averageOffset])
                      .trimmingCharacters(in: .whitespaces)) else
            {
                continue
            }
            stack = Array(stack.prefix(depth)) + [name]
            let average = Double(String(characters[averageOffset ..< minimumOffset])
                .trimmingCharacters(in: .whitespaces))
            if count > 0 {
                result["/" + stack.joined(separator: "/")] = (count, average)
            }
        }
        return result
    }

    /// Queries and answers between one client and its resolver: an A answer with two
    /// records, an NXDOMAIN, an unanswered query, a retransmission and an unsolicited
    /// response.
    private static func frames() -> [[UInt8]] {
        let query = PacketBuilder.dnsQueryFrame(name: "www.example.test", src: "192.0.2.10", dst: "192.0.2.53")
        let answer = PacketBuilder.dnsResponseFrame(
            name: "www.example.test", answers: ["198.51.100.1", "198.51.100.2"], src: "192.0.2.53", dst: "192.0.2.10"
        )
        let missing = PacketBuilder.dnsQueryFrame(name: "nope.test", src: "192.0.2.10", dst: "192.0.2.53")
        let nxdomain = PacketBuilder.dnsResponseFrame(
            name: "nope.test", answers: [], src: "192.0.2.53", dst: "192.0.2.10"
        )
        return [
            header(query, id: 0x1111, flags: 0x0100),
            header(answer, id: 0x1111, flags: 0x8180),
            header(missing, id: 0x2222, flags: 0x0100),
            header(missing, id: 0x2222, flags: 0x0100), // retransmitted
            header(nxdomain, id: 0x2222, flags: 0x8183), // NXDOMAIN
            header(answer, id: 0x3333, flags: 0x8180), // unsolicited
        ]
    }

    /// Sets the DNS header's ID and flags (Ethernet 14 + IPv4 20 + UDP 8).
    private static func header(_ frame: [UInt8], id: UInt16, flags: UInt16) -> [UInt8] {
        var copy = frame
        copy[42] = UInt8(id >> 8)
        copy[43] = UInt8(id & 0xFF)
        copy[44] = UInt8(flags >> 8)
        copy[45] = UInt8(flags & 0xFF)
        return copy
    }
}
