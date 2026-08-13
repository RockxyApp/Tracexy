import Foundation
import Testing
@testable import Tracexy

// MARK: - RetainedFrameBufferTests

@Suite("RetainedFrameBuffer save/export retention window")
struct RetainedFrameBufferTests {
    // MARK: Internal

    @Test("A full window evicts the oldest frames and counts them cumulatively")
    func evictsOldestAndCountsCumulatively() {
        var buffer = RetainedFrameBuffer(capacity: 3)

        buffer.append(contentsOf: frames(0 ..< 5))
        // Capacity holds only the newest three; the two oldest were trimmed.
        #expect(buffer.count == 3)
        #expect(buffer.evictionCount == 2)
        #expect(buffer.frames.map(\.originalLength) == [2, 3, 4])

        // The eviction count is cumulative across appends, not per-append.
        buffer.append(contentsOf: frames(5 ..< 8))
        #expect(buffer.count == 3)
        #expect(buffer.evictionCount == 5)
        #expect(buffer.frames.map(\.originalLength) == [5, 6, 7])
    }

    @Test("Reset clears both the window and the cumulative count")
    func resetClearsEverything() {
        var buffer = RetainedFrameBuffer(capacity: 3)
        buffer.append(contentsOf: frames(0 ..< 5))
        buffer.reset()
        #expect(buffer.isEmpty)
        #expect(buffer.isEmpty)
        #expect(buffer.evictionCount == 0)
    }

    @Test("Replace bypasses the capacity bound and zeroes the count for an opened file")
    func replaceShowsFileInFullWithoutTruncationCount() {
        var buffer = RetainedFrameBuffer(capacity: 3)
        buffer.append(contentsOf: frames(0 ..< 5)) // accrue an eviction count first
        #expect(buffer.evictionCount > 0)

        buffer.replace(with: frames(0 ..< 10))
        // A file is the source of truth: all ten frames are retained and no
        // truncation is reported, since none happened in this window.
        #expect(buffer.count == 10)
        #expect(buffer.evictionCount == 0)
    }

    @Test("Retention eviction never erases the cumulative sessions in LiveSessionEngine")
    func retentionEvictionDoesNotDropSessions() async throws {
        // The retention window and session accumulation are independent stages.
        // A tiny window trims raw frames aggressively; the engine, fed the same
        // frames, must still hold every distinct session.
        var buffer = RetainedFrameBuffer(capacity: 3)
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)

        let sessionFrames = (0 ..< 10).map { index in
            let bytes = PacketBuilder.tlsClientHelloFrame(
                sni: "s\(index).example", src: "10.0.0.5", dst: "203.0.113.\(index)",
                srcPort: UInt16(40_001 + index)
            )
            return CapturedFrame(
                bytes: bytes,
                timestamp: Self.base.addingTimeInterval(Double(index)),
                originalLength: bytes.count
            )
        }

        for frame in sessionFrames {
            buffer.append(contentsOf: [frame])
            await engine.ingest([frame], linkType: LinkType.ethernet, epoch: 1)
        }

        // The raw window kept only the newest three and counted the seven it trimmed…
        #expect(buffer.count == 3)
        #expect(buffer.evictionCount == 7)
        // …yet all ten sessions survive in the engine, untouched by retention.
        let snapshot = try #require(await engine.snapshot(epoch: 1))
        #expect(snapshot.count == 10)
        #expect(await engine.accumulatedSessionCount == 10)
    }

    // MARK: Private

    private static let base = Date(timeIntervalSince1970: 1_700_000_000)

    /// Distinct trivial frames whose `originalLength` encodes the index, so a test
    /// can assert exactly which frames survived eviction.
    private func frames(_ range: Range<Int>) -> [CapturedFrame] {
        range.map { index in
            CapturedFrame(
                bytes: [UInt8(index & 0xFF)],
                timestamp: Self.base.addingTimeInterval(Double(index)),
                originalLength: index
            )
        }
    }
}
