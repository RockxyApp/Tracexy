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

    @Test("A detailed snapshot equals the plain snapshot's sessions and adds a connection snapshot")
    func detailedSnapshotMatchesSessionsAndFoldsConnections() async throws {
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        await engine.ingest(frames, linkType: LinkType.ethernet, epoch: 1)

        let sessions = try #require(await engine.snapshot(epoch: 1))
        let detailed = try #require(await engine.detailedSnapshot(epoch: 1))
        #expect(detailed.sessions == sessions)
        #expect(!detailed.connections.summaries.isEmpty)
        #expect(detailed.connections.summaries.contains { $0.handshake == .threeWayObserved })
    }

    @Test("Exact positional locators attach to each connection's frame provenance")
    func positionalLocatorsAttach() async throws {
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        let token = UUID()
        let locators = frames.indices.map { index in
            SessionEvidenceLocator(sourceToken: token, offset: UInt64(index) * 100)
        }
        let suppliedOffsets = Set(locators.map(\.offset))

        let ok = await engine.ingest(frames, linkType: LinkType.ethernet, epoch: 1, locators: locators)
        #expect(ok)

        let detailed = try #require(await engine.detailedSnapshot(epoch: 1))
        #expect(!detailed.connections.summaries.isEmpty)
        for summary in detailed.connections.summaries {
            let first = try #require(summary.firstProvenance.locator)
            #expect(first.sourceToken == token)
            #expect(suppliedOffsets.contains(first.offset))
            for event in summary.events {
                for provenance in event.provenance {
                    let locator = try #require(provenance.locator)
                    #expect(locator.sourceToken == token)
                    #expect(suppliedOffsets.contains(locator.offset))
                }
            }
        }
    }

    @Test("A locator-count mismatch folds every frame once with nil locators and returns false")
    func mismatchFoldsNilLocatorsReturnsFalse() async throws {
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let counter = DecodeCounter()
        let engine = LiveSessionEngine(decode: { frame, link in
            counter.increment()
            return SessionBuilder.decodePacket(frame, linkType: link)
        })
        await engine.reset(epoch: 1)

        // One fewer locator than frames — a contract violation by the caller.
        let token = UUID()
        let locators = frames.dropLast().indices.map { index in
            SessionEvidenceLocator(sourceToken: token, offset: UInt64(index))
        }
        let ok = await engine.ingest(
            frames, linkType: LinkType.ethernet, epoch: 1, locators: Array(locators)
        )
        #expect(!ok)
        // Every frame was still decoded exactly once — never truncated.
        #expect(counter.count == frames.count)

        let detailed = try #require(await engine.detailedSnapshot(epoch: 1))
        #expect(!detailed.connections.summaries.isEmpty)
        // No provenance carries a locator when the count mismatched.
        let anyLocator = detailed.connections.summaries.contains { summary in
            summary.firstProvenance.locator != nil
                || summary.events.contains { $0.provenance.contains { $0.locator != nil } }
        }
        #expect(!anyLocator)
        // The fold is byte-equal to a batch build over all frames (no mis-pairing).
        #expect(detailed.sessions == SessionBuilder.build(from: frames, linkType: LinkType.ethernet))
    }

    @Test("A stale-epoch ingest folds nothing and returns false")
    func staleEpochIngestReturnsFalse() async throws {
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 2)
        let ok = await engine.ingest(
            [tlsFrame(sni: "stale.example", at: base)], linkType: LinkType.ethernet, epoch: 1
        )
        #expect(!ok)
        let current = try #require(await engine.snapshot(epoch: 2))
        #expect(current.isEmpty)
    }

    @Test("A current batch with nil or exact locators returns true")
    func currentBatchReturnsTrue() async {
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        let nilOK = await engine.ingest([tlsFrame(sni: "a.example", at: base)], linkType: LinkType.ethernet, epoch: 1)
        #expect(nilOK)
        let frame = tlsFrame(sni: "b.example", at: base.addingTimeInterval(1))
        let exactOK = await engine.ingest(
            [frame], linkType: LinkType.ethernet, epoch: 1,
            locators: [SessionEvidenceLocator(sourceToken: UUID(), offset: 0)]
        )
        #expect(exactOK)
    }

    @Test("Capture-loss knowledge merges stickily across batches for one connection")
    func lossKnowledgeMergesStickily() async throws {
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)

        // Same five-tuple across two batches: no-loss first, then loss-reported.
        await engine.ingest(
            [tlsFrame(sni: "a.example", at: base)],
            linkType: LinkType.ethernet, epoch: 1, loss: .noLossReported
        )
        let firstSnapshot = try #require(await engine.detailedSnapshot(epoch: 1))
        #expect(firstSnapshot.connections.summaries.allSatisfy { $0.lossKnowledge == .noLossReported })

        await engine.ingest(
            [tlsFrame(sni: "a.example", at: base.addingTimeInterval(1))],
            linkType: LinkType.ethernet, epoch: 1, loss: .lossReported
        )
        let secondSnapshot = try #require(await engine.detailedSnapshot(epoch: 1))
        // One connection; the stronger knowledge wins and never downgrades.
        #expect(secondSnapshot.connections.summaries.count == 1)
        #expect(secondSnapshot.connections.summaries.allSatisfy { $0.lossKnowledge == .lossReported })
    }

    @Test("An investigation snapshot's analysis equals a fresh assessor over its own connections")
    func investigationSnapshotAnalysisMatchesAssessor() async throws {
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        await engine.ingest(frames, linkType: LinkType.ethernet, epoch: 1)

        let investigation = try #require(await engine.investigationSnapshot(epoch: 1))
        // The wrapper projects the same fold `detailedSnapshot` produces — no copy.
        let detailed = try #require(await engine.detailedSnapshot(epoch: 1))
        #expect(investigation.sessions == detailed.sessions)
        #expect(investigation.connections == detailed.connections)
        // The analysis is exactly a production assessment of its own connections.
        #expect(investigation.connectionAnalysis == ConnectionAssessor().assess(investigation.connections))
        // The corpus actually produces findings (a reset is observed), so the
        // equality above is not vacuous on empty state.
        #expect(!investigation.connectionAnalysis.findings.isEmpty)
    }

    @Test("Repeated investigation snapshots never re-decode")
    func investigationSnapshotDecodesOnce() async {
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let counter = DecodeCounter()
        let engine = LiveSessionEngine(decode: { frame, link in
            counter.increment()
            return SessionBuilder.decodePacket(frame, linkType: link)
        })
        await engine.reset(epoch: 1)
        await engine.ingest(frames, linkType: LinkType.ethernet, epoch: 1)

        // Repeated investigation (and plain) snapshots must not re-decode anything.
        _ = await engine.investigationSnapshot(epoch: 1)
        _ = await engine.investigationSnapshot(epoch: 1)
        _ = await engine.snapshot(epoch: 1)
        #expect(counter.count == frames.count)
    }

    @Test("An investigation snapshot from a superseded epoch is nil")
    func investigationSnapshotStaleEpochIsNil() async {
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 2)
        // A leftover read from a superseded capture (epoch 1) must not land.
        #expect(await engine.investigationSnapshot(epoch: 1) == nil)
    }

    @Test("An empty capture yields an empty investigation analysis")
    func investigationSnapshotEmptyInputEmptyAnalysis() async throws {
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        let investigation = try #require(await engine.investigationSnapshot(epoch: 1))
        #expect(investigation.sessions.isEmpty)
        #expect(investigation.connections.summaries.isEmpty)
        #expect(investigation.connectionAnalysis.findings.isEmpty)
        #expect(investigation.connectionAnalysis == ConnectionAssessor().assess(investigation.connections))
    }

    @Test("An investigation snapshot's datagram analysis equals a fresh assessor over its own datagram evidence")
    func investigationSnapshotDatagramAnalysisMatchesAssessor() async throws {
        // The primary conversation carries UDP DNS (v4 + v6) and an ICMP echo — the
        // DNS+ICMP evidence this fold consumes.
        let frames = ReplayCorpus.conversationCapturedFrames()
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        await engine.ingest(frames, linkType: LinkType.ethernet, epoch: 1)

        let investigation = try #require(await engine.investigationSnapshot(epoch: 1))
        // The wrapper projects the same fold `detailedSnapshot` produces — no copy.
        let detailed = try #require(await engine.detailedSnapshot(epoch: 1))
        #expect(investigation.datagramEvidence == detailed.datagramEvidence)
        // The analysis is exactly a production assessment of its own datagram evidence.
        #expect(investigation.datagramAnalysis == DatagramAssessor().assess(investigation.datagramEvidence))
        // Not vacuous on empty state: this corpus retains DNS + ICMP observations, so
        // the propagated coverage counters are non-zero even though no TC finding maps.
        #expect(investigation.datagramAnalysis.retainedInputObservationCount == 5)
        #expect(investigation.datagramAnalysis.retainedICMPObservationCount > 0)
    }

    @Test("An empty capture yields an empty investigation datagram analysis")
    func investigationSnapshotEmptyInputEmptyDatagramAnalysis() async throws {
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        let investigation = try #require(await engine.investigationSnapshot(epoch: 1))
        #expect(investigation.datagramEvidence == .empty)
        #expect(investigation.datagramAnalysis == .empty)
        #expect(investigation.datagramAnalysis == DatagramAssessor().assess(investigation.datagramEvidence))
    }

    @Test("A reset epoch empties both the connection and datagram investigation analyses")
    func investigationSnapshotResetEmptiesBothAnalyses() async throws {
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        await engine.ingest(ReplayCorpus.conversationCapturedFrames(), linkType: LinkType.ethernet, epoch: 1)
        let before = try #require(await engine.investigationSnapshot(epoch: 1))
        #expect(before.datagramEvidence != .empty)

        // A new epoch clears the fold; the fresh investigation read is empty on both.
        await engine.reset(epoch: 2)
        #expect(await engine.investigationSnapshot(epoch: 1) == nil)
        let after = try #require(await engine.investigationSnapshot(epoch: 2))
        #expect(after.connectionAnalysis == .empty)
        #expect(after.datagramAnalysis == .empty)
        #expect(after.datagramEvidence == .empty)
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
