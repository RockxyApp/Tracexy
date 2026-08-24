import Testing
@testable import Tracexy

@Suite("Follow Stream presentation")
struct FollowStreamPresentationTests {
    @Test("Presentation keeps run boundaries and printable text")
    func textRunMarkers() {
        let snapshot = FollowStreamDirectionSnapshot(
            anchorSequence: 100,
            runs: [
                FollowStreamRun(sequenceAnchor: 100, firstCaptureOrdinal: 2, bytes: [65, 0, 66]),
                FollowStreamRun(sequenceAnchor: 110, firstCaptureOrdinal: 4, bytes: [67, 10]),
            ],
            retainedByteCount: 5,
            observedOmittedByteCount: 0,
            matchedFrameCount: 2
        )

        let presentation = FollowStreamDirectionPresentation(snapshot: snapshot, mode: .text)

        #expect(presentation.body.contains("sequence 0x00000064"))
        #expect(presentation.body.contains("A.B"))
        #expect(presentation.body.contains("gap between retained runs"))
        #expect(presentation.displayedByteCount == 5)
        #expect(presentation.viewOmittedByteCount == 0)
    }

    @Test("Presentation applies an independent hard display bound")
    func displayBound() {
        let bytes = [UInt8](repeating: 0x41, count: FollowStreamDirectionPresentation.maximumDisplayBytes + 10)
        let snapshot = FollowStreamDirectionSnapshot(
            anchorSequence: 1,
            runs: [FollowStreamRun(sequenceAnchor: 1, firstCaptureOrdinal: 1, bytes: bytes)],
            retainedByteCount: bytes.count,
            observedOmittedByteCount: 9,
            matchedFrameCount: 1
        )

        let presentation = FollowStreamDirectionPresentation(
            snapshot: snapshot,
            mode: .hex,
            maxDisplayBytes: .max
        )

        #expect(presentation.displayedByteCount == FollowStreamDirectionPresentation.maximumDisplayBytes)
        #expect(presentation.viewOmittedByteCount == 10)
        #expect(presentation.body.contains("0000"))
    }

    @Test("Limitation copy keeps independent observations separate")
    func limitationLabels() {
        let flags: FollowStreamLimitations = [.sequenceGap, .capturedFrameTruncated, .sourceTailTruncated]

        #expect(flags.presentationLabels.count == 3)
        #expect(flags.presentationLabels.contains("Sequence gap observed"))
        #expect(flags.presentationLabels.contains("A matched frame was capture-truncated"))
        #expect(flags.presentationLabels.contains("Capture source has a truncated tail"))
    }
}
