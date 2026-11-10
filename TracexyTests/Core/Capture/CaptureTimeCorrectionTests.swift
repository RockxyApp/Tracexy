import Foundation
import Testing
@testable import Tracexy

@Suite("Capture time correction")
struct CaptureTimeCorrectionTests {
    // MARK: Internal

    @Test("Constant shifts preserve an unknown time and a real corrected epoch")
    func constantShift() throws {
        let correction = try CaptureTimeCorrection(shiftBy: -10)
        #expect(correction.scale == 1)
        #expect(try correction.apply(nil) == nil)
        #expect(try correction.apply(date(10)) == date(0))
        #expect(try correction.apply(date(12.5)) == date(2.5))
    }

    @Test("One original frame anchors a constant offset across the capture")
    func singleAnchor() throws {
        let anchor = anchor(ordinal: 9, original: 100, corrected: 125)
        let correction = try CaptureTimeCorrection(anchor: anchor)
        #expect(correction.basis == .anchor(anchor))
        #expect(try correction.apply(date(100)) == date(125))
        #expect(try correction.apply(date(75)) == date(100))
        #expect(try correction.apply(date(150)) == date(175))
        #expect(try correction.apply(nil) == nil)
    }

    @Test("Two anchors interpolate and extrapolate one clock rate in either anchor order")
    func linearClockDrift() throws {
        let first = anchor(ordinal: 3, original: 100, corrected: 1_000)
        let second = anchor(ordinal: 17, original: 200, corrected: 1_150)
        let forward = try CaptureTimeCorrection(first: first, second: second)
        let reverse = try CaptureTimeCorrection(first: second, second: first)
        #expect(forward.scale == 1.5)
        #expect(reverse.scale == 1.5)
        for (original, expected) in [(0.0, 850.0), (100, 1_000), (150, 1_075), (200, 1_150), (300, 1_300)] {
            #expect(try forward.apply(date(original)) == date(expected))
            #expect(try reverse.apply(date(original)) == date(expected))
        }
    }

    @Test("Subsecond anchors remain exact and intermediate dates are not rounded by the model")
    func fractionalTimes() throws {
        let first = anchor(ordinal: 1, original: 100.25, corrected: 200.125)
        let second = anchor(ordinal: 2, original: 100.75, corrected: 201.125)
        let correction = try CaptureTimeCorrection(first: first, second: second)
        #expect(try correction.apply(first.originalTime) == first.correctedTime)
        #expect(try correction.apply(second.originalTime) == second.correctedTime)
        #expect(try correction.apply(date(100.375)) == date(200.375))
    }

    @Test("Repeated offsets compose without removing an existing clock-rate correction")
    func addingShiftPreservesClockRate() throws {
        let first = anchor(ordinal: 3, original: 100, corrected: 1_000)
        let second = anchor(ordinal: 17, original: 200, corrected: 1_150)
        let correction = try CaptureTimeCorrection(first: first, second: second).addingShift(5)
        #expect(try correction.apply(date(100)) == date(1_005))
        #expect(try correction.apply(date(150)) == date(1_080))
        #expect(try correction.apply(date(200)) == date(1_155))
    }

    @Test("Invalid anchor frame numbers and repeated frames are rejected")
    func invalidOrdinals() {
        let invalid = anchor(ordinal: 0, original: 10, corrected: 20)
        #expect(throws: CaptureTimeCorrection.Error.invalidFrameOrdinal) {
            try CaptureTimeCorrection(anchor: invalid)
        }
        #expect(throws: CaptureTimeCorrection.Error.duplicateAnchorFrames) {
            try CaptureTimeCorrection(
                first: anchor(ordinal: 1, original: 10, corrected: 20),
                second: anchor(ordinal: 1, original: 11, corrected: 21)
            )
        }
    }

    @Test("Different frames with the same source time cannot define drift")
    func coincidentSourceTimes() {
        #expect(throws: CaptureTimeCorrection.Error.coincidentOriginalTimes) {
            try CaptureTimeCorrection(
                first: anchor(ordinal: 1, original: 10, corrected: 20),
                second: anchor(ordinal: 2, original: 10, corrected: 21)
            )
        }
    }

    @Test("Clock rates cannot collapse or reverse time", arguments: [19.0, 20.0])
    func invalidClockRate(secondTarget: Double) {
        #expect(throws: CaptureTimeCorrection.Error.invalidScale) {
            try CaptureTimeCorrection(
                first: anchor(ordinal: 1, original: 10, corrected: 20),
                second: anchor(ordinal: 2, original: 11, corrected: secondTarget)
            )
        }
    }

    @Test("Nonfinite shifts and source instants fail explicitly", arguments: [Double.nan, .infinity, -.infinity])
    func nonfiniteValues(value: Double) throws {
        #expect(throws: CaptureTimeCorrection.Error.nonfiniteShift) {
            try CaptureTimeCorrection(shiftBy: value)
        }
        #expect(throws: CaptureTimeCorrection.Error.nonfiniteOriginalTime) {
            try CaptureTimeCorrection(anchor: anchor(ordinal: 1, original: value, corrected: 20))
        }
        let correction = try CaptureTimeCorrection(shiftBy: 0)
        #expect(throws: CaptureTimeCorrection.Error.nonfiniteOriginalTime) {
            try correction.apply(date(value))
        }
    }

    @Test("Corrected anchors must fit the output counter", arguments: [-1.0, Double.nan, .infinity, Double(UInt64.max)])
    func unrepresentableTargets(value: Double) {
        #expect(throws: CaptureTimeCorrection.Error.unrepresentableCorrectedTime) {
            try CaptureTimeCorrection(anchor: anchor(ordinal: 1, original: 10, corrected: value))
        }
    }

    @Test("Overflow and pre-epoch extrapolation fail without clamping")
    func unrepresentableOutputs() throws {
        let shift = try CaptureTimeCorrection(shiftBy: Double.greatestFiniteMagnitude)
        #expect(throws: CaptureTimeCorrection.Error.unrepresentableCorrectedTime) {
            try shift.apply(date(Double.greatestFiniteMagnitude))
        }
        let drift = try CaptureTimeCorrection(
            first: anchor(ordinal: 1, original: 100, corrected: 10),
            second: anchor(ordinal: 2, original: 200, corrected: 210)
        )
        #expect(throws: CaptureTimeCorrection.Error.unrepresentableCorrectedTime) {
            try drift.apply(date(0))
        }
        #expect(throws: CaptureTimeCorrection.Error.unrepresentableCorrectedTime) {
            try drift.apply(date(Double.greatestFiniteMagnitude))
        }
    }

    @Test("An overflowing source interval and an infinite fitted clock rate are rejected")
    func arithmeticBounds() {
        #expect(throws: CaptureTimeCorrection.Error.unrepresentableAnchorInterval) {
            try CaptureTimeCorrection(
                first: anchor(ordinal: 1, original: -Double.greatestFiniteMagnitude, corrected: 10),
                second: anchor(ordinal: 2, original: Double.greatestFiniteMagnitude, corrected: 20)
            )
        }
        let first = CaptureTimeCorrection.Anchor(
            frameOrdinal: 1, originalTime: Date(timeIntervalSinceReferenceDate: 0), correctedTime: date(10)
        )
        let second = CaptureTimeCorrection.Anchor(
            frameOrdinal: 2,
            originalTime: Date(timeIntervalSinceReferenceDate: Double.leastNonzeroMagnitude),
            correctedTime: date(20)
        )
        #expect(throws: CaptureTimeCorrection.Error.invalidScale) {
            try CaptureTimeCorrection(first: first, second: second)
        }
    }

    @Test("Unresolved requests validate and retain original ordinal meaning")
    func requestValidationAndResolution() throws {
        let request = CaptureTimeCorrectionRequest.anchors(
            firstFrameOrdinal: 2, firstCorrectedTime: date(20),
            secondFrameOrdinal: 5, secondCorrectedTime: date(40)
        )
        try request.validate()
        #expect(request.anchorOrdinals == [2, 5])
        #expect(throws: CaptureTimeCorrection.Error.missingAnchor(frameOrdinal: 5)) {
            try request.resolved(originalTimes: [2: date(10)])
        }
        let correction = try request.resolved(originalTimes: [2: date(10), 5: date(20)])
        #expect(try correction.apply(date(15)) == date(30))
        let shifted = try request.addingFrameOrdinalOffset(100)
        #expect(shifted.anchorOrdinals == [102, 105])
        #expect(shifted.provenanceComment.contains("frame 102"))
        #expect(shifted.provenanceComment.utf8.count < 1_024)
    }

    @Test("Request validation rejects malformed controls and overflowing ordinal offsets")
    func invalidRequests() throws {
        #expect(throws: CaptureTimeCorrection.Error.invalidFrameOrdinal) {
            try CaptureTimeCorrectionRequest.anchor(frameOrdinal: 0, correctedTime: date(1)).validate()
        }
        #expect(throws: CaptureTimeCorrection.Error.duplicateAnchorFrames) {
            try CaptureTimeCorrectionRequest.anchors(
                firstFrameOrdinal: 1, firstCorrectedTime: date(10),
                secondFrameOrdinal: 1, secondCorrectedTime: date(20)
            ).validate()
        }
        #expect(throws: CaptureTimeCorrection.Error.nonfiniteShift) {
            try CaptureTimeCorrectionRequest.shiftBy(.infinity).validate()
        }
        #expect(throws: CaptureTimeCorrection.Error.unrepresentableCorrectedTime) {
            try CaptureTimeCorrectionRequest.anchor(frameOrdinal: 1, correctedTime: date(-1)).validate()
        }
        #expect(throws: CaptureTimeCorrection.Error.anchorOrdinalOverflow) {
            try CaptureTimeCorrectionRequest.anchor(frameOrdinal: UInt64.max, correctedTime: date(10))
                .addingFrameOrdinalOffset(1)
        }
        #expect(try CaptureTimeCorrectionRequest.shiftBy(2).addingFrameOrdinalOffset(UInt64.max) == .shiftBy(2))
    }

    @Test("The model preserves representable Date fractions before the writer rounds microseconds")
    func preservesSubmicrosecondDateFraction() throws {
        let origin = Date(timeIntervalSinceReferenceDate: 0)
        let correction = try CaptureTimeCorrection(anchor: .init(
            frameOrdinal: 1, originalTime: origin, correctedTime: origin
        ))
        let fraction = Date(timeIntervalSinceReferenceDate: 0.00000025)
        #expect(try correction.apply(fraction) == fraction)
    }

    // MARK: Private

    private func date(_ seconds: Double) -> Date {
        Date(timeIntervalSince1970: seconds)
    }

    private func anchor(ordinal: UInt64, original: Double, corrected: Double) -> CaptureTimeCorrection.Anchor {
        .init(frameOrdinal: ordinal, originalTime: date(original), correctedTime: date(corrected))
    }
}
