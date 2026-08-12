import Foundation
import Testing
@testable import Tracexy

// MARK: - LiveSessionEngineTests

@Suite("LiveSessionEngine incremental accumulation")
struct LiveSessionEngineTests {
    // MARK: Internal

    @Test("Incremental snapshot equals the batch SessionBuilder for the sample fixtures")
    func snapshotEqualsBatchBuild() async throws {
        let frames = SampleCapture.frames(now: Date())
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        await engine.ingest(frames, linkType: LinkType.ethernet, epoch: 1)

        let incremental = try #require(await engine.snapshot(epoch: 1))
        let batch = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)

        // Exact batch equivalence — same sessions, same order, same decoded
        // fields. This milestone changes where/when the work runs, not what it
        // produces. (Requires stable SessionSummary/DecodedLayer equality.)
        #expect(incremental == batch)
    }

    @Test("Splitting the same frames across batches yields the same snapshot")
    func splitIngestMatchesSingleBatch() async throws {
        let frames = SampleCapture.frames(now: Date())
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        for frame in frames {
            await engine.ingest([frame], linkType: LinkType.ethernet, epoch: 1)
        }
        let incremental = try #require(await engine.snapshot(epoch: 1))
        #expect(incremental == SessionBuilder.build(from: frames, linkType: LinkType.ethernet))
    }

    @Test("Each frame is decoded exactly once; updating a session never re-decodes")
    func eachFrameDecodedOnce() async {
        let counter = DecodeCounter()
        let engine = LiveSessionEngine(decode: { frame, link in
            counter.increment()
            return SessionBuilder.decodePacket(frame, linkType: link)
        })
        await engine.reset(epoch: 1)

        // Two frames of the SAME five-tuple, in two separate batches: the second
        // updates the existing session.
        await engine.ingest([tlsFrame(sni: "one.example", at: base)], linkType: LinkType.ethernet, epoch: 1)
        await engine.ingest(
            [tlsFrame(sni: "one.example", at: base.addingTimeInterval(1))],
            linkType: LinkType.ethernet, epoch: 1
        )
        // Snapshotting must not decode anything.
        _ = await engine.snapshot(epoch: 1)
        _ = await engine.snapshot(epoch: 1)

        #expect(counter.count == 2)
    }

    @Test("A new session appends without destabilizing existing IDs or order")
    func newSessionAppendsStably() async throws {
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        await engine.ingest(
            [
                tlsFrame(sni: "one.example", dst: "203.0.113.1", srcPort: 40_001, at: base),
                tlsFrame(sni: "two.example", dst: "203.0.113.2", srcPort: 40_002, at: base.addingTimeInterval(1)),
            ],
            linkType: LinkType.ethernet, epoch: 1
        )
        let first = try #require(await engine.snapshot(epoch: 1))

        await engine.ingest(
            [tlsFrame(sni: "three.example", dst: "203.0.113.3", srcPort: 40_003, at: base.addingTimeInterval(2))],
            linkType: LinkType.ethernet, epoch: 1
        )
        let second = try #require(await engine.snapshot(epoch: 1))

        let priorIDs = first.map(\.id)
        #expect(priorIDs.count == 2)
        #expect(second.count == 3)
        // Prior ids stay an exact prefix; the new session lands at the tail.
        #expect(Array(second.map(\.id).prefix(2)) == priorIDs)
        #expect(!priorIDs.contains(second[2].id))
        #expect(second.last?.sni == "three.example")
    }

    @Test("Sessions accumulate cumulatively across many batches, decoded once each")
    func cumulativeSessionsSurviveManyBatches() async throws {
        let counter = DecodeCounter()
        let engine = LiveSessionEngine(decode: { frame, link in
            counter.increment()
            return SessionBuilder.decodePacket(frame, linkType: link)
        })
        await engine.reset(epoch: 1)

        // Far more distinct sessions than any small raw-retention window would
        // keep. Sessions live in the engine, independent of raw-frame retention,
        // so none are lost and none are re-decoded when history scrolls past.
        let sessionCount = 60
        for index in 0 ..< sessionCount {
            let frame = tlsFrame(
                sni: "s\(index).example",
                dst: "203.0.113.\(index % 200)",
                srcPort: UInt16(41_000 + index),
                at: base.addingTimeInterval(Double(index))
            )
            await engine.ingest([frame], linkType: LinkType.ethernet, epoch: 1)
        }

        let snapshot = try #require(await engine.snapshot(epoch: 1))
        #expect(snapshot.count == sessionCount)
        #expect(counter.count == sessionCount)
    }

    @Test("Extending an existing session folds in place, decoded once, without growing state")
    func existingSessionUpdatesInPlace() async throws {
        let counter = DecodeCounter()
        let engine = LiveSessionEngine(decode: { frame, link in
            counter.increment()
            return SessionBuilder.decodePacket(frame, linkType: link)
        })
        await engine.reset(epoch: 1)

        await engine.ingest([tlsFrame(sni: "one.example", at: base)], linkType: LinkType.ethernet, epoch: 1)
        let before = try #require(await engine.snapshot(epoch: 1)).first

        // A later packet of the SAME five-tuple updates the existing session.
        await engine.ingest(
            [tlsFrame(sni: "one.example", at: base.addingTimeInterval(2))],
            linkType: LinkType.ethernet, epoch: 1
        )
        let after = try #require(await engine.snapshot(epoch: 1)).first

        #expect(before?.id == after?.id)
        #expect((after?.totalBytes ?? 0) > (before?.totalBytes ?? 0))
        #expect(before?.duration == 0)
        #expect((after?.duration ?? 0) > 0)
        // One conversation, two frames decoded exactly once each — history is not
        // re-decoded when the session updates.
        #expect(await engine.accumulatedSessionCount == 1)
        #expect(counter.count == 2)
    }

    @Test("Repeated packets fold into one session entry without packet-history entries")
    func repeatedPacketsFoldIntoOneEntry() async throws {
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)

        // Fold many packets into a single five-tuple across many batches. The old
        // engine held a growing [FiveTuple: [DecodedPacket]] array; this must not.
        for index in 0 ..< 500 {
            await engine.ingest(
                [tlsFrame(sni: "one.example", at: base.addingTimeInterval(Double(index)))],
                linkType: LinkType.ethernet, epoch: 1
            )
        }
        #expect(await engine.accumulatedSessionCount == 1)
        let snapshot = try #require(await engine.snapshot(epoch: 1))
        #expect(snapshot.count == 1)
    }

    @Test("Stale-epoch ingests and snapshots are dropped, not applied")
    func staleEpochWorkIsDropped() async throws {
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 2)

        // A leftover ingest from a superseded capture (epoch 1) must not land.
        await engine.ingest([tlsFrame(sni: "stale.example", at: base)], linkType: LinkType.ethernet, epoch: 1)
        #expect(await engine.snapshot(epoch: 1) == nil)

        let current = try #require(await engine.snapshot(epoch: 2))
        #expect(current.isEmpty)
    }

    // MARK: Private

    private static let baseline = Date(timeIntervalSince1970: 1_700_000_000)

    private var base: Date {
        LiveSessionEngineTests.baseline
    }

    private func tlsFrame(
        sni: String,
        dst: String = "203.0.113.1",
        srcPort: UInt16 = 40_001,
        at timestamp: Date
    )
        -> CapturedFrame
    {
        let bytes = PacketBuilder.tlsClientHelloFrame(sni: sni, src: "10.0.0.5", dst: dst, srcPort: srcPort)
        return CapturedFrame(bytes: bytes, timestamp: timestamp, originalLength: bytes.count)
    }
}

// MARK: - DecodeCounter

/// Thread-safe decode-call counter for the injectable engine decode seam.
private final class DecodeCounter: @unchecked Sendable {
    // MARK: Internal

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func increment() {
        lock.lock()
        defer { lock.unlock() }
        value += 1
    }

    // MARK: Private

    private let lock = NSLock()
    private var value = 0
}
