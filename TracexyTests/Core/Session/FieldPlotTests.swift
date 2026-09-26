import Foundation
import Testing
@testable import Tracexy

/// Statistics ▸ Plot draws a field's numeric values over time, as
/// Wireshark's Plots window — one point per occurrence at its frame's time.
struct FieldPlotTests {
    // MARK: Internal

    @Test
    func readsNumbersAsFieldsShowThem() {
        #expect(FieldPlot.number("64") == 64)
        #expect(FieldPlot.number("1500 bytes") == 1_500)
        #expect(FieldPlot.number("0x0800") == 2_048)
        #expect(FieldPlot.number("-3.5 ms") == -3.5)
        #expect(FieldPlot.number("12.") == 12)
        #expect(FieldPlot.number("a.test") == nil)
        #expect(FieldPlot.number("[SYN, ACK]") == nil)
        #expect(FieldPlot.number("0x") == nil)
    }

    @Test
    func pointsFollowTheFramesInTime() throws {
        let url = try Self.capture(ports: [53, 80, 443])
        defer { try? FileManager.default.removeItem(at: url) }
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let plot = try FieldValueScanner(contentsOf: url, expectedIdentity: identity)
            .scanPoints(FieldKey(proto: .udp, name: "Destination Port"))
        #expect(plot.points.map(\.value) == [53, 80, 443])
        #expect(plot.points.map(\.time) == [0, 0.5, 1])
        #expect(plot.points.map(\.frame) == [1, 2, 3])
        #expect(!plot.isThinned)
        let names = try FieldValueScanner(contentsOf: url, expectedIdentity: identity)
            .scanPoints(FieldKey(proto: .ipv4, name: "Source"))
        #expect(names.points.isEmpty || names.nonNumericCount == 0)
    }

    @Test
    func pointingFindsTheNearestPoint() {
        let points = [
            FieldPlot.Point(frame: 1, time: 0, value: -1),
            FieldPlot.Point(frame: 2, time: 1, value: 10),
            FieldPlot.Point(frame: 3, time: 2, value: 100),
        ]
        #expect(FieldPlotWindow.nearest(to: 1.4, in: points)?.frame == 2)
        #expect(FieldPlotWindow.nearest(to: 9, in: points)?.frame == 3)
        // A logarithmic axis cannot place zero or a negative value.
        #expect(FieldPlotWindow.drawable(points, logarithmic: true).map(\.frame) == [2, 3])
        #expect(FieldPlotWindow.drawable(points, logarithmic: false).count == 3)
    }

    // MARK: Private

    private static func capture(ports: [UInt16]) throws -> URL {
        let frames = ports.enumerated().map { index, port in
            CapturedFrame(
                bytes: PacketBuilder.ethernetIPv4(
                    proto: 17, src: "192.0.2.10", dst: "198.51.100.7",
                    payload: PacketBuilder.udp(srcPort: 40_000, dstPort: port, payload: [0, 1, 2, 3])
                ),
                timestamp: Date(timeIntervalSince1970: 1_800_000_000 + Double(index) * 0.5),
                originalLength: 46
            )
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("plot-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        return url
    }
}
