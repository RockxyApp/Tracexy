import Foundation
import Testing
@testable import Tracexy

struct TCPHealthSourceScanTests {
    // MARK: Internal

    @Test("One-session scan retains direction and fails at its explicit bound")
    func boundedAccumulator() throws {
        let source = IPEndpoint(ip: "192.0.2.1", port: 50_000)
        let destination = IPEndpoint(ip: "198.51.100.1", port: 443)
        let tuple = FiveTuple(proto: .tcp, source: source, destination: destination)
        let sessionID = SessionBuilder.sessionID(for: tuple)
        var accumulator = TCPHealthSourceAccumulator(sessionID: sessionID, maximumSegments: 2)
        let first = packet(source: source, destination: destination, tuple: tuple, sequence: 100)
        let reverse = packet(source: destination, destination: source, tuple: tuple, sequence: 200)
        let firstProvenance = provenance(1, captured: 60, original: 80)
        let secondProvenance = provenance(2, captured: 60, original: 60)
        try accumulator.offer(first, provenance: firstProvenance)
        try accumulator.offer(reverse, provenance: secondProvenance)
        let summary = try accumulator.summary()
        #expect(summary.observations.count == 2)
        #expect(summary.observations[0].direction != summary.observations[1].direction)
        #expect(summary.snapLengthTruncationObserved)
        #expect(summary.lossKnowledge == .unknown)
        #expect(throws: TCPHealthSourceScanError.segmentLimit(2)) {
            try accumulator.offer(first, provenance: provenance(3, captured: 60, original: 60))
        }
        #expect(accumulator.omittedSegmentCount == 1)
        #expect(throws: TCPHealthSourceScanError.segmentLimit(2)) {
            try accumulator.summary()
        }
        var missingFacts = first
        missingFacts.tcpFacts = nil
        var invalid = TCPHealthSourceAccumulator(sessionID: sessionID)
        #expect(throws: TCPHealthSourceScanError.incompleteSegment) {
            try invalid.offer(missingFacts, provenance: firstProvenance)
        }
        #expect(throws: TCPHealthSourceScanError.incompleteSegment) {
            try invalid.summary()
        }
        #expect(throws: TCPHealthSourceScanError.noSegments) {
            try TCPHealthSourceAccumulator(sessionID: sessionID).summary()
        }
    }

    @Test("Full-source scan preserves receiver-reported SACK ranges for chart derivation")
    func fullSourceScanCarriesSACKRanges() throws {
        let source = IPEndpoint(ip: "192.0.2.1", port: 50_000)
        let destination = IPEndpoint(ip: "198.51.100.1", port: 443)
        let tuple = FiveTuple(proto: .tcp, source: source, destination: destination)
        let sessionID = SessionBuilder.sessionID(for: tuple)
        var accumulator = TCPHealthSourceAccumulator(sessionID: sessionID)
        let blocks = [TCPSACKBlock(leftEdge: 1_100, rightEdge: 1_200)]
        try accumulator.offer(
            packet(source: source, destination: destination, tuple: tuple, sequence: 1_000),
            provenance: provenance(1, captured: 60, original: 60)
        )
        try accumulator.offer(
            packet(source: destination, destination: source, tuple: tuple, sequence: 2_000, sackBlocks: blocks),
            provenance: provenance(2, captured: 60, original: 60)
        )

        let summary = try accumulator.summary()
        #expect(summary.observations[1].sackBlocks == blocks)
        let health = TCPStreamHealth(summary: summary)
        let sack = try #require(health.series.first { $0.role == .sackRange })
        #expect(sack.points.map(\.value) == [100])
        #expect(sack.points.first?.provenance?.ordinal.rawValue == 2)
    }

    @Test("Bounded chart projection keeps group edges and extrema")
    func displayedPointsRetainExtremaAndCaptureOrder() {
        let points = (0 ..< 100).map { index in
            TCPStreamPoint(
                id: index, date: Date(timeIntervalSince1970: Double(index)),
                value: index == 10 ? -10 : (index == 55 ? 1_000 : Double(index)),
                provenance: nil, relatedProvenance: nil
            )
        }
        let selected = SessionStreamChartLine.displayPoints(points, maximum: 12)
        #expect(selected.count <= 12)
        #expect(selected.first?.id == 0)
        #expect(selected.last?.id == 99)
        #expect(selected.contains { $0.id == 10 })
        #expect(selected.contains { $0.id == 55 })
        #expect(selected.map(\.id) == selected.map(\.id).sorted())
    }

    // MARK: Private

    private func provenance(_ ordinal: UInt64, captured: Int, original: Int) -> SessionFrameProvenance {
        SessionFrameProvenance(
            ordinal: FrameOrdinal(ordinal), timestamp: Date(timeIntervalSince1970: Double(ordinal)),
            capturedLength: captured, originalLength: original, linkType: LinkType.ethernet
        )
    }

    private func packet(
        source: IPEndpoint,
        destination: IPEndpoint,
        tuple: FiveTuple,
        sequence: UInt32,
        sackBlocks: [TCPSACKBlock] = []
    )
        -> DecodedPacket
    {
        var packet = DecodedPacket(timestamp: Date(timeIntervalSince1970: 1), originalLength: 60)
        packet.transport = .tcp
        packet.sourceEndpoint = source
        packet.destinationEndpoint = destination
        packet.fiveTuple = tuple
        packet.tcpFacts = TCPSegmentFacts(
            sequenceNumber: sequence, acknowledgementNumber: 0, flags: [.ack], windowSize: 1_024,
            headerLength: 20, payloadSequence: sequence, payloadLength: 0,
            options: TCPOptionFacts(sackBlocks: sackBlocks)
        )
        return packet
    }
}
