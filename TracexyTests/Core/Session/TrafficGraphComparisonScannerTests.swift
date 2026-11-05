import Foundation
import Testing
@testable import Tracexy

@Suite("I/O Graph comparison source scan")
struct TrafficGraphComparisonScannerTests {
    // MARK: Internal

    @Test
    func oneStableCapturePassBuildsSeriesOnOneCorrectedTimeAxis() throws {
        let url = try capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let configuration = try TrafficGraphComparisonConfiguration(validating: [
            TrafficGraphSeriesDraft(name: "Large", expressionText: "frame.len >= 100"),
            TrafficGraphSeriesDraft(name: "All", expressionText: "frame.len >= 0"),
        ])
        let correction = try CaptureTimeCorrection(shiftBy: 10)
        let result = try MainContentCoordinator.scanTrafficGraphComparisonSource(
            at: url, identity: identity, sourceToken: UUID(), configuration: configuration,
            requestedInterval: 1, timeCorrection: correction
        )

        #expect(result.scannedFrames == 3)
        #expect(result.series.map { $0.coverage?.matchedFrames } == [2, 3])
        #expect(result.series.map(\.graph.totalFrames) == [2, 3])
        #expect(result.series.allSatisfy { $0.graph.axis == result.axis })
        #expect(result.axis?.columnCount == 3)
        #expect(result.axis?.origin.timeIntervalSince1970 == 1_700_000_010)
    }

    @Test
    func incompleteStableSourceDoesNotProduceAComparison() throws {
        let url = try capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let handle = try FileHandle(forWritingTo: url)
        _ = try handle.seekToEnd()
        try handle.write(contentsOf: Data([0x01]))
        try handle.close()
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let configuration = try TrafficGraphComparisonConfiguration(validating: [
            TrafficGraphSeriesDraft(name: "All", expressionText: "frame.len >= 0"),
        ])

        #expect(throws: TrafficGraphComparisonScanError.incomplete) {
            try MainContentCoordinator.scanTrafficGraphComparisonSource(
                at: url, identity: identity, sourceToken: UUID(), configuration: configuration
            )
        }
    }

    @Test("Direction-aware Frame Expressions retain yes, no, and unknown graph coverage")
    func captureDirectionSeriesCoverage() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("traffic-direction-\(UUID().uuidString).pcapng")
        defer { try? FileManager.default.removeItem(at: url) }
        try PcapngWriter.write(defaultLinkType: LinkType.ethernet, frames: [
            CapturedFrame(
                bytes: [1],
                timestamp: Date(timeIntervalSince1970: 1),
                originalLength: 10,
                direction: .inbound
            ),
            CapturedFrame(
                bytes: [2],
                timestamp: Date(timeIntervalSince1970: 2),
                originalLength: 10,
                direction: .outbound
            ),
            CapturedFrame(bytes: [3], timestamp: Date(timeIntervalSince1970: 3), originalLength: 10),
        ], to: url)
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let configuration = try TrafficGraphComparisonConfiguration(validating: [
            TrafficGraphSeriesDraft(name: "Inbound", expressionText: "frame.capture_direction == inbound"),
        ])
        let result = try MainContentCoordinator.scanTrafficGraphComparisonSource(
            at: url, identity: identity, sourceToken: UUID(), configuration: configuration
        )

        #expect(result.scannedFrames == 3)
        #expect(result.series[0].coverage?.matchedFrames == 1)
        #expect(result.series[0].coverage?.nonmatchingFrames == 1)
        #expect(result.series[0].coverage?.unknownFrames == 1)
        #expect(result.series[0].graph.totalFrames == 1)
    }

    // MARK: Private

    private func capture() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("traffic-comparison-\(UUID().uuidString).pcapng")
        try PcapngWriter.write(defaultLinkType: LinkType.ethernet, frames: [
            CapturedFrame(
                bytes: [0x01], timestamp: Date(timeIntervalSince1970: 1_700_000_000.2), originalLength: 100
            ),
            CapturedFrame(
                bytes: [0x02], timestamp: Date(timeIntervalSince1970: 1_700_000_001.2), originalLength: 50
            ),
            CapturedFrame(
                bytes: [0x03], timestamp: Date(timeIntervalSince1970: 1_700_000_002.2), originalLength: 100
            ),
        ], to: url)
        return url
    }
}
