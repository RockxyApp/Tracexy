import Foundation
import Testing
@testable import Tracexy

/// Apply as Column: a decode-tree field becomes a View ▸ All Frames column holding
/// each frame's value (every occurrence, comma-separated), at most four, kept per
/// Project; applying a column again removes it.
@MainActor
struct FrameColumnsTests {
    @Test
    func rowsCarryTheAppliedFieldsValues() throws {
        let frames = [
            PacketBuilder.ethernetIPv4(
                proto: 6, src: "192.0.2.10", dst: "198.51.100.80",
                payload: PacketBuilder.tcp(srcPort: 51_000, dstPort: 80, flags: 0x02, payload: [])
            ),
            PacketBuilder.ethernetIPv4(
                proto: 17, src: "192.0.2.10", dst: "198.51.100.53",
                payload: PacketBuilder.udp(
                    srcPort: 53_000,
                    dstPort: 53,
                    payload: PacketBuilder.dnsQuery(name: "a.test")
                )
            ),
        ]
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("columns-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames.map {
            CapturedFrame(bytes: $0, timestamp: Date(timeIntervalSince1970: 1_800_000_000), originalLength: $0.count)
        }, to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let columns = [FieldKey(proto: .tcp, name: "Destination Port"), FieldKey(proto: .ipv4, name: "TTL")]
        let rows = try CaptureFrameListScanner(
            contentsOf: url, expectedIdentity: identity, sourceToken: UUID(), configuration: .init(columns: columns)
        ).scan().rows
        #expect(rows.map(\.columnValues) == [["80", "64"], ["", "64"]])
        #expect(try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID()).scan()
            .rows.allSatisfy(\.columnValues.isEmpty))
    }

    @Test
    func columnsToggleAreBoundedAndPersistPerProject() throws {
        let suite = "frame-columns-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let options = PacketDetailOptions()
        options.bind(to: defaults)
        let keys = ["Source Port", "Destination Port", "Window", "Seq", "Ack"].map { FieldKey(proto: .tcp, name: $0) }
        for key in keys.prefix(4) {
            #expect(options.toggleFrameColumn(key))
        }
        #expect(!options.toggleFrameColumn(keys[4]))
        #expect(options.toggleFrameColumn(keys[1]))
        #expect(options.frameColumns == [keys[0], keys[2], keys[3]])

        let reopened = PacketDetailOptions()
        reopened.bind(to: defaults)
        #expect(reopened.frameColumns == [keys[0], keys[2], keys[3]])
    }
}
