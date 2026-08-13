import Foundation
import Testing
@testable import Tracexy

@Suite("Capture frame transport (typed XPC drain surface)")
struct CaptureFrameTransportTests {
    // MARK: Internal

    @Test("Two frames in one batch keep their own distinct timestamps")
    func framesKeepDistinctTimestamps() throws {
        let first = CapturedFrameMessage(
            bytes: Data([1, 2, 3]),
            timestampSeconds: 1_000, timestampMicroseconds: 500,
            capturedLength: 3, originalLength: 3, linkType: 1
        )
        let second = CapturedFrameMessage(
            bytes: Data([4, 5]),
            timestampSeconds: 2_000, timestampMicroseconds: 250_000,
            capturedLength: 2, originalLength: 60, linkType: 1
        )
        let batch = try roundTrip(FrameBatchMessage(
            frames: [first, second], bufferDroppedCount: 0, captureLinkType: 1, stats: nil
        ))

        let frames = batch.frames.compactMap(CapturedFrame.init(message:))
        #expect(frames.count == 2)
        // The legacy surface assigned one wall-clock `Date` to the whole batch;
        // now each frame carries its own precise libpcap instant.
        #expect(frames[0].timestamp != frames[1].timestamp)
        #expect(abs(frames[0].timestamp.timeIntervalSince1970 - 1_000.0005) < 1e-6)
        #expect(abs(frames[1].timestamp.timeIntervalSince1970 - 2_000.25) < 1e-6)
    }

    @Test("Captured and original lengths survive secure coding → CapturedFrame")
    func lengthsSurviveConversion() throws {
        // A snaplen-truncated frame: 40 captured bytes, 1500 on the wire.
        let message = CapturedFrameMessage(
            bytes: Data(repeating: 0xAB, count: 40),
            timestampSeconds: 5, timestampMicroseconds: 0,
            capturedLength: 40, originalLength: 1_500, linkType: 1
        )
        let batch = try roundTrip(FrameBatchMessage(
            frames: [message], bufferDroppedCount: 0, captureLinkType: 1, stats: nil
        ))

        let frame = try #require(batch.frames.first.flatMap(CapturedFrame.init(message:)))
        #expect(frame.bytes.count == 40)
        // Captured length is carried through and matches the bytes present.
        #expect(frame.capturedLength == 40)
        // The original length is preserved, never inferred from bytes.count, and
        // stays distinct from the captured length under snaplen truncation.
        #expect(frame.originalLength == 1_500)
        #expect(frame.linkType == 1)
    }

    @Test("An under-reported original length is rejected rather than inferred")
    func originalLengthBelowCapturedIsRejected() {
        // On-wire length below the bytes we actually hold is impossible. The app
        // must not invent a replacement from bytes.count.
        let message = CapturedFrameMessage(
            bytes: Data(repeating: 0, count: 20),
            timestampSeconds: 1, timestampMicroseconds: 0,
            capturedLength: 20, originalLength: 5, linkType: 1
        )
        #expect(CapturedFrame(message: message) == nil)
    }

    @Test("Malformed / negative / overflowing metadata is rejected, never trapped")
    func malformedMetadataRejected() {
        let negativeOriginal = message(originalLength: -5)
        let overflowOriginal = message(originalLength: Int64.max)
        let outOfRangeMicros = message(timestampMicroseconds: 2_000_000)
        let negativeSeconds = message(timestampSeconds: -1)
        // Captured length that disagrees with the bytes actually present is
        // corrupt metadata: over-reported, negative, and overflowing all reject.
        let capturedTooLarge = message(bytes: Data([0]), capturedLength: 2)
        let capturedTooSmall = message(bytes: Data([0, 1, 2]), capturedLength: 2)
        let negativeCaptured = message(bytes: Data([0]), capturedLength: -1)
        let overflowCaptured = message(bytes: Data([0]), capturedLength: Int64.max)

        // Each is rejected truthfully with `nil` rather than crashing or
        // fabricating a plausible frame.
        #expect(CapturedFrame(message: negativeOriginal) == nil)
        #expect(CapturedFrame(message: overflowOriginal) == nil)
        #expect(CapturedFrame(message: outOfRangeMicros) == nil)
        #expect(CapturedFrame(message: negativeSeconds) == nil)
        #expect(CapturedFrame(message: capturedTooLarge) == nil)
        #expect(CapturedFrame(message: capturedTooSmall) == nil)
        #expect(CapturedFrame(message: negativeCaptured) == nil)
        #expect(CapturedFrame(message: overflowCaptured) == nil)
    }

    @Test("The XPC drain and stop replies allow-list the frame-batch coding graph")
    func replyInterfacesAllowFrameBatchGraph() {
        let interface = TracexyHelperInterface.make()
        let fetchAllowed = interface.classes(
            for: #selector(TracexyHelperProtocol.fetchFrames(withReply:)),
            argumentIndex: 0,
            ofReply: true
        )
        let stopAllowed = interface.classes(
            for: #selector(TracexyHelperProtocol.stopCapture(withReply:)),
            argumentIndex: 0,
            ofReply: true
        )
        // Without every class in this graph on the allow-list, `NSSecureCoding`
        // silently fails to decode the batch at runtime — so assert it executably.
        for allowed in [fetchAllowed, stopAllowed] {
            #expect(contains(FrameBatchMessage.self, in: allowed))
            #expect(contains(CapturedFrameMessage.self, in: allowed))
            #expect(contains(NSArray.self, in: allowed))
            #expect(contains(NSData.self, in: allowed))
        }
    }

    @Test("A batch carries cumulative buffer drops and available pcap accounting")
    func batchCarriesDropsAndAccounting() throws {
        let withStats = try roundTrip(FrameBatchMessage(
            frames: [], bufferDroppedCount: 1_234, captureLinkType: 1,
            stats: HelperCaptureStats(received: 100, droppedByKernel: 3, droppedByInterface: 2)
        ))

        #expect(withStats.bufferDroppedCount == 1_234)
        let stats = try #require(withStats.stats)
        #expect(stats.received == 100)
        #expect(CaptureStatistics(helperStats: stats).totalDropped == 5)
    }

    @Test("Unavailable pcap accounting reads as unknown, not a clean figure")
    func unknownAccountingIsNilNotClean() throws {
        let unknown = try roundTrip(FrameBatchMessage(
            frames: [], bufferDroppedCount: 0, captureLinkType: 1, stats: nil
        ))

        #expect(unknown.statsAvailable == false)
        // Absence the UI must handle, never a reassuring 100%-captured number.
        #expect(unknown.stats == nil)
    }

    // MARK: Private

    private func roundTrip(_ batch: FrameBatchMessage) throws -> FrameBatchMessage {
        let data = try NSKeyedArchiver.archivedData(withRootObject: batch, requiringSecureCoding: true)
        return try #require(try NSKeyedUnarchiver.unarchivedObject(ofClass: FrameBatchMessage.self, from: data))
    }

    private func contains(_ expected: AnyClass, in allowed: Set<AnyHashable>) -> Bool {
        allowed.contains { value in
            guard let actual = value.base as? AnyClass else {
                return false
            }
            return actual === expected
        }
    }

    private func message(
        bytes: Data = Data([0]),
        timestampSeconds: Int64 = 1,
        timestampMicroseconds: Int64 = 0,
        capturedLength: Int64? = nil,
        originalLength: Int64 = 1
    )
        -> CapturedFrameMessage
    {
        CapturedFrameMessage(
            bytes: bytes,
            timestampSeconds: timestampSeconds,
            timestampMicroseconds: timestampMicroseconds,
            capturedLength: capturedLength ?? Int64(bytes.count),
            originalLength: originalLength,
            linkType: 1
        )
    }
}
