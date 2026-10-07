import Foundation
import Testing
@testable import Tracexy

/// Statistics ▸ Value Distribution counts every value one decode-tree field
/// took, with Wireshark's percentages and normalized Shannon entropy
/// (`distribution_dialog.cpp`'s `normalized_shannon`).
struct FieldValueScannerTests {
    // MARK: Internal

    @Test
    func countsEveryValueOfTheField() throws {
        let url = try Self.capture(ports: [53, 53, 53, 443])
        defer { try? FileManager.default.removeItem(at: url) }
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let key = FieldKey(proto: .udp, name: "Destination Port")
        let result = try FieldValueScanner(contentsOf: url, expectedIdentity: identity).scan(key)
        #expect(result.rows.map(\.value) == ["53", "443"])
        #expect(result.rows.map(\.count) == [3, 1])
        #expect(result.rows.map(\.percent) == [75, 25])
        #expect(result.occurrences == 4)
        #expect(result.framesWithField == 4)
        // −(¾·log₂¾ + ¼·log₂¼) / log₂2
        #expect(abs((result.entropy ?? 0) - 0.8112781244591328) < 1e-12)
        #expect(key.title == "UDP › Destination Port")
    }

    @Test
    func limitsToTheSessionsInView() throws {
        let url = try Self.capture(ports: [53, 53, 443])
        defer { try? FileManager.default.removeItem(at: url) }
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let dns = SessionBuilder.sessionID(for: FiveTuple(
            proto: .udp, source: IPEndpoint(ip: "192.0.2.10", port: 40_000),
            destination: IPEndpoint(ip: "198.51.100.7", port: 53)
        ))
        let result = try FieldValueScanner(contentsOf: url, expectedIdentity: identity)
            .scan(FieldKey(proto: .udp, name: "Destination Port"), sessions: [dns])
        #expect(result.rows.map(\.value) == ["53"])
        #expect(result.framesScanned == 2)
        // One distinct value has no spread to measure.
        #expect(result.entropy == nil)
    }

    @Test
    func entropyMatchesWiresharksDefinition() {
        #expect(FieldValueDistribution.normalizedEntropy([5, 5, 5, 5]) == 1)
        #expect(FieldValueDistribution.normalizedEntropy([7]) == nil)
        #expect(FieldValueDistribution.normalizedEntropy([]) == nil)
        let skewed = FieldValueDistribution.normalizedEntropy([98, 1, 1]) ?? 1
        #expect(skewed < 0.12)
        let distribution = FieldValueDistribution.make(
            key: FieldKey(proto: .dns, name: "Query"), counts: ["a,b": 2, "c": 1], framesWithField: 3,
            framesScanned: 3, otherOccurrences: 0
        )
        #expect(distribution.csv() == "Field Value,Occurrences,Percent\r\n\"a,b\",2,66.67\r\nc,1,33.33\r\n")
    }

    @Test
    func offersEachFieldOfTheSelectedFrameOnce() {
        let layers = [
            DecodedLayer(proto: .udp, title: "UDP", fields: [
                DecodedField(name: "Source Port", value: "1"), DecodedField(name: "Destination Port", value: "2"),
            ]),
            DecodedLayer(proto: .dns, title: "DNS", fields: [DecodedField(name: "Query", value: "a.test")], children: [
                DecodedLayer(proto: .dns, title: "Answer", fields: [DecodedField(name: "Query", value: "a.test")]),
            ]),
        ]
        #expect(ValueDistributionWindow.fields(in: layers).map(\.title) == [
            "UDP › Source Port", "UDP › Destination Port", "DNS › Query",
        ])
        #expect(FieldValueScanner.values(of: FieldKey(proto: .dns, name: "Query"), in: layers) == ["a.test", "a.test"])
    }

    /// The window's path: an open saved capture, counted off the main actor.
    @MainActor
    @Test
    func controllerCountsTheOpenCapture() async throws {
        let isolation = ProjectIsolationEnvironment(name: "value-distribution")
        defer { isolation.tearDown() }
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let url = try Self.capture(ports: [53, 53, 443])
        defer { try? FileManager.default.removeItem(at: url) }
        let size = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        coordinator.openSavedCapture(SavedCapture(url: url, name: "values", date: Date(), byteCount: size))
        await coordinator.waitForSavedCaptureOpen()

        let controller = FieldValueDistributionController()
        controller.limitToSessionsInView = false
        controller.field = FieldKey(proto: .udp, name: "Destination Port")
        controller.run(from: coordinator)
        for _ in 0 ..< 100 where controller.isLoading {
            try await Task.sleep(for: .milliseconds(20))
        }
        #expect(controller.error == nil)
        #expect(controller.result?.rows.map(\.count) == [2, 1])
    }

    // MARK: Private

    private static func capture(ports: [UInt16]) throws -> URL {
        let frames = ports.map { port in
            CapturedFrame(
                bytes: PacketBuilder.ethernetIPv4(
                    proto: 17, src: "192.0.2.10", dst: "198.51.100.7",
                    payload: PacketBuilder.udp(srcPort: 40_000, dstPort: port, payload: [0, 1, 2, 3])
                ),
                timestamp: Date(timeIntervalSince1970: 1_800_000_000),
                originalLength: 46
            )
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("values-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        return url
    }
}
