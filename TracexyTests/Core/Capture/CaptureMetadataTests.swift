import Foundation
import Testing
@testable import Tracexy

// MARK: - CaptureMetadataTests

@Suite("Bounded capture metadata inventory and its presentation")
struct CaptureMetadataTests {
    // MARK: Internal

    @Test("Encountered link types are counted per frame and ordered deterministically")
    func countsLinkTypesPerFrame() {
        var accumulator = CaptureMetadataAccumulator()
        accumulator.add(linkType: LinkType.raw, timestamp: Date(timeIntervalSince1970: 0), hasDecodedLinkLayer: true)
        accumulator.add(
            linkType: LinkType.ethernet,
            timestamp: Date(timeIntervalSince1970: 0),
            hasDecodedLinkLayer: true
        )
        accumulator.add(
            linkType: LinkType.ethernet,
            timestamp: Date(timeIntervalSince1970: 0),
            hasDecodedLinkLayer: true
        )

        let summary = accumulator.summary()
        #expect(summary.totalFrames == 3)
        #expect(summary.linkTypeCounts.map(\.linkType) == [LinkType.ethernet, LinkType.raw])
        #expect(summary.linkTypeCounts.map(\.frameCount) == [2, 1])
        #expect(summary.linkTypeOverflowFrameCount == 0)
        #expect(summary.hasMixedLinkTypes)
        #expect(!summary.hasCoverageCaveat)
    }

    @Test("Untimed and undecodable frames are counted without affecting the link-type map")
    func countsCoverageCaveats() {
        var accumulator = CaptureMetadataAccumulator()
        accumulator.add(linkType: LinkType.ethernet, timestamp: nil, hasDecodedLinkLayer: true)
        accumulator.add(
            linkType: LinkType.ethernet,
            timestamp: Date(timeIntervalSince1970: 0),
            hasDecodedLinkLayer: false
        )
        accumulator.add(linkType: LinkType.ethernet, timestamp: nil, hasDecodedLinkLayer: false)

        let summary = accumulator.summary()
        #expect(summary.totalFrames == 3)
        #expect(summary.untimedFrameCount == 2)
        #expect(summary.undecodableLinkLayerFrameCount == 2)
        #expect(summary.linkTypeCounts.map(\.frameCount) == [3])
        #expect(!summary.hasMixedLinkTypes)
        #expect(summary.hasCoverageCaveat)
    }

    @Test("The link-type map stays bounded and counts the frames it could not key")
    func linkTypeMapStaysBounded() {
        var accumulator = CaptureMetadataAccumulator(maxLinkTypeKeys: 4)
        for linkType in UInt32(0) ..< 10 {
            accumulator.add(linkType: linkType, timestamp: Date(timeIntervalSince1970: 0), hasDecodedLinkLayer: true)
        }
        // A repeat of an already-retained key still counts against that key.
        accumulator.add(linkType: 0, timestamp: Date(timeIntervalSince1970: 0), hasDecodedLinkLayer: true)

        let summary = accumulator.summary()
        #expect(summary.linkTypeCounts.count == 4)
        #expect(summary.linkTypeCounts.map(\.linkType) == [0, 1, 2, 3])
        #expect(summary.linkTypeCounts.first?.frameCount == 2)
        // Nothing is silently dropped: the six unkeyed frames are reported.
        #expect(summary.linkTypeOverflowFrameCount == 6)
        #expect(summary.totalFrames == 11)
        #expect(summary.hasCoverageCaveat)
    }

    @Test("An injected cap cannot raise the production metadata bound")
    func productionBoundCannotBeRaised() {
        var accumulator = CaptureMetadataAccumulator(maxLinkTypeKeys: Int.max)
        for value in UInt32(0) ..< 100 {
            accumulator.add(linkType: value, timestamp: nil, hasDecodedLinkLayer: false)
        }
        #expect(accumulator.summary().linkTypeCounts.count == 64)
        #expect(accumulator.summary().linkTypeOverflowFrameCount == 36)
    }

    @Test("An empty inventory claims nothing")
    func emptyInventory() {
        let summary = CaptureMetadataAccumulator().summary()
        #expect(summary == .empty)
        #expect(!summary.hasCoverageCaveat)
        #expect(!summary.hasMixedLinkTypes)
    }

    // MARK: - Presentation

    @Test("The saved-source inventory line counts only what was observed")
    func metadataSummaryCopy() {
        var accumulator = CaptureMetadataAccumulator()
        accumulator.add(
            linkType: LinkType.ethernet,
            timestamp: Date(timeIntervalSince1970: 0),
            hasDecodedLinkLayer: true
        )
        accumulator.add(linkType: LinkType.raw, timestamp: nil, hasDecodedLinkLayer: false)

        let line = SessionCenterView.metadataSummary(accumulator.summary())
        #expect(line == "2 link types · 1 untimed · 1 undecoded link layer")

        var clean = CaptureMetadataAccumulator()
        clean.add(linkType: LinkType.ethernet, timestamp: Date(timeIntervalSince1970: 0), hasDecodedLinkLayer: true)
        #expect(SessionCenterView.metadataSummary(clean.summary()) == "1 link type")
    }

    @Test("The Overview labels a partial time range as the timed subset, and a fully untimed capture plainly")
    func untimedCoverageCopy() {
        let mixed = CaptureActivityBuilder.build(frames: [
            frame(timestamp: Date(timeIntervalSince1970: 1)),
            frame(timestamp: nil),
        ])
        let mixedLabel = OverviewView.untimedCoverageLabel(mixed)
        #expect(mixedLabel.contains("Timed frames only"))
        #expect(mixedLabel.contains("1 of 2 frames"))

        let none = CaptureActivityBuilder.build(frames: [frame(timestamp: nil), frame(timestamp: nil)])
        let noneLabel = OverviewView.untimedCoverageLabel(none)
        #expect(noneLabel.contains("no time for any of its 2 frames"))
        #expect(!noneLabel.contains("Timed frames only"))
    }

    // MARK: Private

    private func frame(timestamp: Date?) -> CapturedFrame {
        CapturedFrame(bytes: [0x01, 0x02, 0x03], timestamp: timestamp, originalLength: 3)
    }
}
