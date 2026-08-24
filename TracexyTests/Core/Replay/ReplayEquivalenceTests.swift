import Foundation
import Testing
@testable import Tracexy

// MARK: - ReplayEquivalenceTests

/// Deterministic replay equivalence: for one fixed ordered frame set, the batch
/// builder, the live engine (one-frame and varied-batch ingest) and the saved-file
/// loader must all produce the identical normalised session semantics. Saved raw
/// bytes are restored from evidence before comparison rather than ignored, and the
/// per-frame decode matrix pins each decoder tree. All fixture bytes are generated
/// by ``ReplayCorpus`` (see its provenance note); temp captures are per-test.
struct ReplayEquivalenceTests {
    // MARK: Internal

    // MARK: Primary session golden + cross-path equivalence

    @Test
    func primaryConversationMatchesGolden() {
        let sessions = SessionBuilder.build(
            from: ReplayCorpus.conversationCapturedFrames(), linkType: LinkType.ethernet
        )
        let problems = ReplayGoldens.verify(sessions: sessions)
        #expect(problems.isEmpty, "golden mismatches: \(problems)")
    }

    @Test
    func batchLiveAndSavedSnapshotsAgree() async throws {
        let frames = ReplayCorpus.conversationCapturedFrames()
        let batch = SessionSnapshot.snapshots(SessionBuilder.build(from: frames, linkType: LinkType.ethernet))

        // Live, one frame per ingest.
        let liveOne = await liveSnapshots(chunks: frames.map { [$0] })
        #expect(liveOne == batch)

        // Live, varied batch groupings (a decode-once accumulator must not care how
        // frames are chunked).
        let liveVaried = await liveSnapshots(chunks: Self.variedChunks(frames))
        #expect(liveVaried == batch)

        // Saved file, bytes restored from evidence before comparison.
        try ReplayCorpus.withTemporaryFile(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())) { url in
            let saved = try savedRestoredSnapshots(from: url)
            #expect(saved == batch)
        }
    }

    // MARK: Typed endpoint projection cross-path equivalence

    @Test
    func typedEndpointValuesAgreeAcrossBatchLiveAndSaved() async throws {
        let frames = ReplayCorpus.conversationCapturedFrames()
        let batch = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)
        let batchByID = Dictionary(uniqueKeysWithValues: batch.map { ($0.id, EndpointPair($0)) })

        // Non-vacuous: every conversation session carries typed client/server values,
        // at least one of them IPv6, and the typed value is exactly the source of the
        // rendered display string — never parsed back out of it.
        #expect(!batch.isEmpty)
        #expect(batch.allSatisfy { $0.sourceEndpointValue != nil && $0.destinationEndpointValue != nil })
        #expect(batch.contains { session in
            [session.sourceEndpointValue, session.destinationEndpointValue]
                .contains { $0?.ip.contains(":") == true }
        })
        for session in batch {
            #expect(session.sourceEndpoint == (session.sourceEndpointValue?.display ?? "—"))
            #expect(session.destinationEndpoint == (session.destinationEndpointValue?.display ?? "—"))
        }

        // Live over varied batch groupings agrees with the batch projection.
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        for chunk in Self.variedChunks(frames) {
            await engine.ingest(chunk, linkType: LinkType.ethernet, epoch: 1)
        }
        let live = try #require(await engine.snapshot(epoch: 1))
        #expect(Dictionary(uniqueKeysWithValues: live.map { ($0.id, EndpointPair($0)) }) == batchByID)

        // Saved opening preserves the typed values while clearing only the raw
        // representative bytes.
        try ReplayCorpus.withTemporaryFile(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())) { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            #expect(!result.sessions.contains { !$0.representativeBytes.isEmpty })
            #expect(result.sessions.allSatisfy { $0.sourceEndpointValue != nil })
            #expect(Dictionary(uniqueKeysWithValues: result.sessions.map { ($0.id, EndpointPair($0)) }) == batchByID)
        }
    }

    // MARK: Format corpus — classic variants and pcapng

    @Test
    func classicEndianAndTimestampVariantsMatchBatch() throws {
        let batch = SessionSnapshot.snapshots(
            SessionBuilder.build(from: ReplayCorpus.conversationCapturedFrames(), linkType: LinkType.ethernet)
        )
        for variant in ReplayCorpus.ClassicVariant.allCases {
            let bytes = ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation(), variant: variant)
            try ReplayCorpus.withTemporaryFile(bytes) { url in
                let saved = try savedRestoredSnapshots(from: url)
                #expect(saved == batch, "variant \(variant) diverged from batch")
            }
        }
    }

    @Test
    func pcapngConversationMatchesBatch() throws {
        let batch = SessionSnapshot.snapshots(
            SessionBuilder.build(from: ReplayCorpus.conversationCapturedFrames(), linkType: LinkType.ethernet)
        )
        for little in [true, false] {
            let bytes = ReplayCorpus.pcapngConversationBytes(little: little)
            try ReplayCorpus.withTemporaryFile(bytes, ext: "pcapng") { url in
                let saved = try savedRestoredSnapshots(from: url)
                #expect(saved == batch, "pcapng little=\(little) diverged from batch")
            }
        }
    }

    @Test
    func pcapngNanoResolutionAndSimplePacketRemainTruthful() throws {
        // Nanosecond resolution must decode to the same instant the micro path does.
        try ReplayCorpus.withTemporaryFile(ReplayCorpus.pcapngNanoResolutionBytes(), ext: "pcapng") { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            #expect(result.totalFrames == 1)
            let session = try #require(result.sessions.first)
            let expected = Date(timeIntervalSince1970: 1_700_000_001)
            #expect(abs(session.startTime.timeIntervalSince(expected)) < 1e-6)
        }
        // A Simple Packet Block carries no timestamp, so the frame is honestly at
        // the Unix epoch — not invented.
        try ReplayCorpus.withTemporaryFile(ReplayCorpus.pcapngSimplePacketBytes(), ext: "pcapng") { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            #expect(result.totalFrames == 1)
            let session = try #require(result.sessions.first)
            #expect(session.startTime == Date(timeIntervalSince1970: 0))
        }
    }

    @Test
    func multiSectionEndianSwitchReusesInterfaceZero() throws {
        try ReplayCorpus.withTemporaryFile(ReplayCorpus.pcapngMultiSectionBytes(), ext: "pcapng") { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            #expect(result.totalFrames == 2)
            #expect(result.completeness == .complete)
            #expect(result.sessions.contains { $0.host == "sect1.example" })
            #expect(result.sessions.contains { $0.host == "sect2.example" })
        }
    }

    // MARK: DLT rule — intrinsic wins, source default falls back

    @Test
    func classicRawLinkTypeUsesFileDefaultAcrossPaths() async throws {
        let frames = ReplayCorpus.rawIPv4CapturedFrames()
        let batch = SessionSnapshot.snapshots(SessionBuilder.build(from: frames, linkType: LinkType.raw))
        #expect(batch.allSatisfy { $0.protocolStack.contains(ProtocolKind.dns.rawValue) })

        let live = await liveSnapshots(chunks: frames.map { [$0] }, linkType: LinkType.raw)
        #expect(live == batch)

        let bytes = ReplayCorpus.classicPcapBytes(
            ReplayCorpus.rawIPv4ConversationFrames(), variant: .littleMicro, linkType: LinkType.raw
        )
        try ReplayCorpus.withTemporaryFile(bytes) { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            #expect(result.defaultLinkType == LinkType.raw)
            let saved = try savedRestoredSnapshots(from: url)
            #expect(saved == batch)
        }
    }

    @Test
    func mixedPcapngUsesPerFrameLinkTypeAcrossPaths() async throws {
        let frames = ReplayCorpus.mixedDLTCapturedFrames()
        // The per-frame link types win over the default passed to `build`.
        let batch = SessionSnapshot.snapshots(SessionBuilder.build(from: frames, linkType: LinkType.ethernet))
        #expect(batch.count == 2)
        #expect(batch.allSatisfy { $0.protocolStack.contains(ProtocolKind.tls.rawValue) })

        let live = await liveSnapshots(chunks: frames.map { [$0] })
        #expect(live == batch)

        try ReplayCorpus.withTemporaryFile(ReplayCorpus.pcapngMixedDLTBytes(), ext: "pcapng") { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            #expect(result.format == .pcapng)
            // Each frame's own interface link type is preserved on its evidence.
            let linkTypes = Set(result.evidence.values.map(\.linkType))
            #expect(linkTypes == [LinkType.ethernet, LinkType.raw])
            let saved = try savedRestoredSnapshots(from: url)
            #expect(saved == batch)
        }
    }

    // MARK: Saved raw bytes are empty but evidence restores them exactly

    @Test
    func savedSummariesAreRawEmptyButEvidenceEqualsBatchRepresentative() throws {
        let frames = ReplayCorpus.conversationCapturedFrames()
        let batch = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)
        let batchBytes = Dictionary(uniqueKeysWithValues: batch.map { ($0.id, $0.representativeBytes) })

        try ReplayCorpus.withTemporaryFile(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())) { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            // Separately asserted: saved summaries hold no raw representative bytes.
            #expect(!result.sessions.contains { !$0.representativeBytes.isEmpty })
            #expect(!result.sessions.isEmpty)

            for session in result.sessions {
                let reference = try #require(result.evidence[session.id])
                let bytes = try CaptureEvidenceReader.read(reference, from: url)
                #expect(bytes == batchBytes[session.id], "evidence for \(session.host) != batch representative")
                // The evidence is exactly one real frame (its byte count matches the
                // captured length), never a widened segment list.
                #expect(bytes.count == reference.capturedLength)
            }
        }
    }

    @Test
    func evidenceRejectsStaleIdentity() throws {
        let hello = ReplayCorpus.conversation()
        try ReplayCorpus.withTemporaryFile(ReplayCorpus.classicPcapBytes(hello)) { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            let reference = try #require(result.evidence.values.first)
            // Clean reopen works before the file changes.
            _ = try CaptureEvidenceReader.read(reference, from: url)
            // Rewriting the file with a different length changes its identity, so a
            // stale offset is refused rather than fed mismatched bytes.
            try Data(ReplayCorpus.classicPcapBytes(Array(hello.dropLast()))).write(to: url)
            #expect(throws: PacketError.self) {
                _ = try CaptureEvidenceReader.read(reference, from: url)
            }
        }
    }

    // MARK: Split-TCP reassembly honesty

    @Test
    func splitTLSReassemblyHasNoFalseRangesAndOneRealEvidenceFrame() throws {
        let frames = ReplayCorpus.conversationCapturedFrames()
        let batch = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)
        let session = try #require(batch.first { $0.host == "secure.example" })

        // The reassembled application (TLS) layers carry no single-frame byte range,
        // because their bytes legitimately span two frames.
        let tlsLayers = collectLayers(session.decodedLayers).filter { $0.proto == .tls }
        #expect(!tlsLayers.isEmpty)
        for layer in tlsLayers {
            #expect(layer.byteRange == nil, "reassembled TLS layer must not claim a frame range")
            #expect(layer.fields.allSatisfy { $0.byteRange == nil })
        }
        // The frame-local lower layers of the representative frame keep honest ranges.
        let framed = session.decodedLayers.filter { [.ethernet, .ipv4, .tcp].contains($0.proto) }
        #expect(!framed.isEmpty)
        #expect(framed.allSatisfy { $0.byteRange != nil })

        // The chosen evidence is exactly one real corpus frame (a single segment),
        // and it equals the batch representative bytes.
        #expect(!session.representativeBytes.isEmpty)
        let corpusFrames = Set(frames.map(\.bytes))
        #expect(corpusFrames.contains(session.representativeBytes))

        try ReplayCorpus.withTemporaryFile(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())) { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            let saved = try #require(result.sessions.first { $0.host == "secure.example" })
            let reference = try #require(result.evidence[saved.id])
            let evidenceBytes = try CaptureEvidenceReader.read(reference, from: url)
            #expect(evidenceBytes == session.representativeBytes)
        }
    }

    // MARK: Per-frame decoder matrix

    @Test
    func perFrameDecoderMatrixIsStable() {
        let frames = ReplayCorpus.conversation()
        var decodeSnapshots: [FrameDecodeSnapshot] = []
        for expected in ReplayGoldens.frameMatrix {
            let frame = frames[expected.index]
            let packet = PacketDecoder.decode(
                PacketBuffer(frame.bytes), linkType: frame.linkType,
                timestamp: frame.timestamp, originalLength: frame.bytes.count
            )
            #expect(packet.protocolStack == expected.protocolStack, "[\(expected.label)] stack")
            #expect(packet.appProtocol == expected.appProtocol, "[\(expected.label)] app")
            // No decoded byte range may point outside the real frame bytes.
            for layer in collectLayers(packet.layers) {
                assertRangesWithin(layer, frameLength: frame.bytes.count, label: expected.label)
            }
            decodeSnapshots.append(FrameDecodeSnapshot(packet))
        }

        // The decode-tree matrix serialises deterministically and carries no random
        // presentation ids (frames have no session id, so zero UUIDs at all).
        let json = FrameDecodeSnapshot.sortedJSON(decodeSnapshots)
        #expect(!json.isEmpty)
        #expect(FrameDecodeSnapshot.sortedJSON(decodeSnapshots) == json)
        #expect(Self.uuidMatches(in: json) == 0)
    }

    // MARK: Snapshot stability & no random ids

    @Test
    func snapshotJSONIsDeterministicAndCarriesNoLayerIDs() {
        let sessions = SessionBuilder.build(
            from: ReplayCorpus.conversationCapturedFrames(), linkType: LinkType.ethernet
        )
        let snapshots = SessionSnapshot.snapshots(sessions)
        let json = SessionSnapshot.sortedJSON(snapshots)
        #expect(!json.isEmpty)
        // Deterministic: encoding twice yields identical text.
        #expect(SessionSnapshot.sortedJSON(snapshots) == json)
        // Round-trips: decode(encode(x)) == x.
        let data = Data(json.utf8)
        let decoded = try? JSONDecoder().decode([SessionSnapshot].self, from: data)
        #expect(decoded == snapshots)

        let digest = SessionSnapshot.digest(json)
        #expect(
            digest == ReplayGoldens.conversationSnapshotDigest,
            "reviewed canonical snapshot digest changed: \(digest)"
        )

        // The only UUIDs in the schema are the stable session ids — one per session.
        // Random per-instance layer ids never enter the snapshot.
        let uuidCount = Self.uuidMatches(in: json)
        #expect(uuidCount == sessions.count)
    }

    // MARK: Decode-once on the live path

    @Test
    func liveEngineDecodesEachFrameExactlyOnce() async {
        let frames = ReplayCorpus.conversationCapturedFrames()
        let counter = Counter()
        let engine = LiveSessionEngine(decode: { frame, linkType in
            counter.increment()
            return SessionBuilder.decodePacket(frame, linkType: linkType)
        })
        await engine.reset(epoch: 1)
        for chunk in Self.variedChunks(frames) {
            await engine.ingest(chunk, linkType: LinkType.ethernet, epoch: 1)
        }
        // Snapshotting several times must not re-decode anything.
        _ = await engine.snapshot(epoch: 1)
        _ = await engine.snapshot(epoch: 1)
        #expect(counter.value == frames.count)
    }

    // MARK: Connection-fold cross-path equivalence

    @Test
    func tcpConnectionSemanticsAgreeAcrossPaths() async throws {
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let batch = ConnectionTableSnapshot(
            SessionBuilder.buildDetailed(from: frames, linkType: LinkType.ethernet).connections
        )

        // Live, one frame per ingest, and live with varied batch groupings — a
        // decode-once, ordinal-assigning fold must not care how frames are chunked.
        let liveOne = try await liveConnectionSnapshot(chunks: frames.map { [$0] })
        #expect(liveOne == batch)
        let liveVaried = try await liveConnectionSnapshot(chunks: Self.variedChunks(frames))
        #expect(liveVaried == batch)

        // Saved file over the same ordered frames.
        try ReplayCorpus.withTemporaryFile(ReplayCorpus.classicPcapBytes(ReplayCorpus.tcpConnectionFrames())) { url in
            let saved = try SavedCaptureStreamLoader(contentsOf: url).load().connections
            #expect(ConnectionTableSnapshot(saved) == batch)
        }

        // The corpus actually exercises every intended behavior, so a future change
        // that flattens it is caught rather than passing vacuously on empty state.
        #expect(batch.summaries.count == 4) // A, B, C-first (reused), C-second
        let kinds = Set(batch.summaries.flatMap { $0.events.map(\.kind) })
        #expect(kinds.isSuperset(of: [
            "handshakeCompleted", "retransmission", "outOfOrderBuffered",
            "pendingDrained", "fin", "rst",
        ]))
        // Tuple reuse: two distinct connection ids share conversation C's tuple.
        let cTuples = batch.summaries.filter { $0.tuple.contains("198.51.100.32") }
        #expect(cTuples.count == 2)
        #expect(Set(cTuples.map(\.id)).count == 2)
    }

    @Test
    func forcedTinyConnectionBoundsAreDeterministicAcrossPaths() async throws {
        let config = ConnectionTable.Configuration(
            maxActiveConnections: 1,
            maxEventsPerConnection: 2,
            maxTotalEvents: 3,
            maxPublishedSummaries: 2,
            maxPendingSegmentsPerDirection: 1
        )
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let batch = ConnectionTableSnapshot(
            SessionBuilder.buildDetailed(
                from: frames, linkType: LinkType.ethernet, connectionConfiguration: config
            ).connections
        )
        let liveVaried = try await liveConnectionSnapshot(
            chunks: Self.variedChunks(frames), connectionConfiguration: config
        )
        #expect(liveVaried == batch)

        try ReplayCorpus.withTemporaryFile(ReplayCorpus.classicPcapBytes(ReplayCorpus.tcpConnectionFrames())) { url in
            let saved = try SavedCaptureStreamLoader(
                contentsOf: url, configuration: .init(connectionConfiguration: config)
            ).load().connections
            #expect(ConnectionTableSnapshot(saved) == batch)
        }

        // The forced bounds actually bit: summaries dropped and/or events truncated,
        // so the equality above is not vacuous on empty state.
        #expect(batch.omittedSummaryCount > 0 || batch.summaries.contains { $0.omittedEventCount > 0 })
    }

    @Test
    func savedConnectionEventLocatorsPointToRealFrameBytes() throws {
        let frames = ReplayCorpus.tcpConnectionFrames()
        try ReplayCorpus.withTemporaryFile(ReplayCorpus.classicPcapBytes(frames)) { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            var checked = 0
            var sourceTokens = Set<UUID>()
            for summary in result.connections.summaries {
                for event in summary.events {
                    for provenance in event.provenance {
                        let locator = try #require(provenance.locator)
                        sourceTokens.insert(locator.sourceToken)
                        // Rebuild a guarded evidence reference purely from the cited
                        // provenance plus the load's file identity — the fold retains
                        // no per-frame history, only this opaque token + offset.
                        let reference = CaptureEvidenceReference(
                            identity: result.identity,
                            payloadOffset: locator.offset,
                            capturedLength: provenance.capturedLength,
                            originalLength: provenance.originalLength,
                            timestamp: provenance.timestamp,
                            linkType: provenance.linkType
                        )
                        let bytes = try CaptureEvidenceReader.read(reference, from: url)
                        #expect(bytes.count == provenance.capturedLength)
                        #expect(frames.contains { $0.bytes == bytes })
                        checked += 1
                    }
                }
            }
            #expect(checked > 0)
            #expect(sourceTokens.count == 1)
        }
    }

    @Test
    func conversationConnectionDigestIsStableAndCoversApplication() {
        let detailed = SessionBuilder.buildDetailed(
            from: ReplayCorpus.conversationCapturedFrames(), linkType: LinkType.ethernet
        )
        let snapshot = ConnectionTableSnapshot(detailed.connections)

        // Coverage: the split-TLS five-tuple and the single-segment HTTP five-tuple
        // are TCP connections whose first-record probe recovered application
        // metadata, each emitting exactly one availability event with typed kind and
        // completion — and no raw application detail.
        let appEvents = snapshot.summaries.flatMap(\.events).filter { $0.kind == "applicationRecord" }
        #expect(appEvents.contains { $0.applicationKind == "tls" && $0.applicationComplete == false })
        #expect(appEvents.contains { $0.applicationKind == "http" && $0.applicationComplete == true })
        #expect(!snapshot.summaries.contains { summary in
            summary.limitations & ConnectionLimitations.applicationProbeTruncated.rawValue != 0
        })

        // Deterministic canonical digest, additive to the session digest.
        let digest = ReplayGoldens.connectionDigest(snapshot)
        #expect(ReplayGoldens.connectionDigest(snapshot) == digest)
        #expect(
            digest == ReplayGoldens.conversationConnectionDigest,
            "reviewed connection digest changed (capture on first run): \(digest)"
        )
    }

    @Test
    func savedApplicationRecordEventLocatorReadsRealFrame() throws {
        let frames = ReplayCorpus.conversation()
        try ReplayCorpus.withTemporaryFile(ReplayCorpus.classicPcapBytes(frames)) { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            var checked = 0
            for summary in result.connections.summaries {
                for event in summary.events where event.kind == .applicationRecord {
                    #expect(event.applicationKind != nil)
                    let provenance = try #require(event.provenance.first)
                    let locator = try #require(provenance.locator)
                    // The availability event exact-reads its real triggering frame.
                    let reference = CaptureEvidenceReference(
                        identity: result.identity,
                        payloadOffset: locator.offset,
                        capturedLength: provenance.capturedLength,
                        originalLength: provenance.originalLength,
                        timestamp: provenance.timestamp,
                        linkType: provenance.linkType
                    )
                    let bytes = try CaptureEvidenceReader.read(reference, from: url)
                    #expect(bytes.count == provenance.capturedLength)
                    #expect(frames.contains { $0.bytes == bytes })
                    checked += 1
                }
            }
            #expect(checked >= 1)
        }
    }

    @Test
    func liveEngineDecodesEachFrameOnceEvenWithDetailedSnapshots() async {
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let counter = Counter()
        let engine = LiveSessionEngine(decode: { frame, linkType in
            counter.increment()
            return SessionBuilder.decodePacket(frame, linkType: linkType)
        })
        await engine.reset(epoch: 1)
        for chunk in Self.variedChunks(frames) {
            await engine.ingest(chunk, linkType: LinkType.ethernet, epoch: 1)
        }
        // Repeated detailed (and plain) snapshots must not re-decode anything.
        _ = await engine.detailedSnapshot(epoch: 1)
        _ = await engine.detailedSnapshot(epoch: 1)
        _ = await engine.snapshot(epoch: 1)
        #expect(counter.value == frames.count)
    }

    @Test
    func resetRestartsOrdinalsAndStaleEpochBlocksDetailedState() async throws {
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        for frame in frames {
            await engine.ingest([frame], linkType: LinkType.ethernet, epoch: 1)
        }
        let before = try #require(await engine.detailedSnapshot(epoch: 1))
        #expect(!before.connections.summaries.isEmpty)
        #expect(before.connections.summaries.first?.firstProvenance.ordinal == FrameOrdinal(1))

        // A new epoch clears both session and connection state and restarts ordinals.
        await engine.reset(epoch: 2)
        #expect(await engine.detailedSnapshot(epoch: 1) == nil)
        let empty = try #require(await engine.detailedSnapshot(epoch: 2))
        #expect(empty.connections.summaries.isEmpty)
        #expect(empty.sessions.isEmpty)

        // A stale-epoch ingest cannot land.
        await engine.ingest([frames[0]], linkType: LinkType.ethernet, epoch: 1)
        #expect(try #require(await engine.detailedSnapshot(epoch: 2)).connections.summaries.isEmpty)

        // A fresh ingest after reset opens its first connection at ordinal 1 again.
        await engine.ingest([frames[0]], linkType: LinkType.ethernet, epoch: 2)
        let after = try #require(await engine.detailedSnapshot(epoch: 2))
        #expect(after.connections.summaries.first?.firstProvenance.ordinal == FrameOrdinal(1))
    }

    // MARK: Connection-analysis cross-path equivalence

    @Test
    func connectionAnalysisAgreesAcrossBatchLiveAndSaved() async throws {
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()

        // Batch: assess the detailed batch connections directly.
        let batch = AnalysisSnapshotNorm(ConnectionAssessor().assess(
            SessionBuilder.buildDetailed(from: frames, linkType: LinkType.ethernet).connections
        ))

        // Live investigation snapshot over varied batch groupings — a decode-once,
        // ordinal-assigning fold must not care how frames are chunked.
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        for chunk in Self.variedChunks(frames) {
            await engine.ingest(chunk, linkType: LinkType.ethernet, epoch: 1)
        }
        let investigation = try #require(await engine.investigationSnapshot(epoch: 1))
        #expect(AnalysisSnapshotNorm(investigation.connectionAnalysis) == batch)

        // Saved file over the same ordered frames — normalisation drops the
        // saved-only evidence locator identity, exactly as the connection snapshot
        // comparison does, so the analysis *semantics* compare across paths.
        try ReplayCorpus.withTemporaryFile(ReplayCorpus.classicPcapBytes(ReplayCorpus.tcpConnectionFrames())) { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            #expect(AnalysisSnapshotNorm(result.connectionAnalysis) == batch)
        }

        // Not vacuous: the corpus yields findings of several kinds.
        #expect(!batch.findings.isEmpty)
        #expect(Set(batch.findings.map(\.kind)).count >= 2)
    }

    // MARK: Datagram-evidence cross-path equivalence

    @Test
    func datagramEvidenceAgreesAcrossBatchLiveAndSaved() async throws {
        // The primary conversation carries UDP DNS (v4 + v6) and an ICMP echo — the
        // DNS+ICMP corpus this fold consumes.
        let frames = ReplayCorpus.conversationCapturedFrames()
        let batch = DatagramNorm(SessionBuilder.buildDetailed(from: frames, linkType: LinkType.ethernet)
            .datagramEvidence)

        // Live detailed, one frame per ingest and varied batch groupings — a
        // decode-once, ordinal-assigning fold must not care how frames are chunked.
        // The investigation path wraps this identical fold, so it inherits the same
        // evidence by construction.
        let liveOne = try await liveDatagramSnapshot(chunks: frames.map { [$0] })
        #expect(liveOne == batch)
        let liveVaried = try await liveDatagramSnapshot(chunks: Self.variedChunks(frames))
        #expect(liveVaried == batch)

        // Saved file over the same ordered frames — normalisation drops only the
        // saved-only evidence locator identity (via ``ProvenanceSnapshot``), so the
        // datagram semantics compare across paths.
        try ReplayCorpus.withTemporaryFile(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())) { url in
            let saved = try SavedCaptureStreamLoader(contentsOf: url).load().datagramEvidence
            #expect(DatagramNorm(saved) == batch)
        }

        // Not vacuous: three flows (v4 DNS, v6 DNS, v4 ICMP) with five observations,
        // both DNS and ICMP kinds, and no TCP-DNS in this corpus.
        #expect(batch.summaries.count == 3)
        #expect(batch.retainedObservationCount == 5)
        let kinds = Set(batch.summaries.flatMap { $0.observations.map(\.kind) })
        #expect(kinds.contains { $0.hasPrefix("dns") })
        #expect(kinds.contains { $0.hasPrefix("icmp") })
        #expect(batch.excludedTCPDNSFactCount == 0)
    }

    // MARK: TLS-evidence cross-path equivalence

    @Test
    func tlsEvidenceAgreesAcrossBatchLiveAndSaved() async throws {
        // The primary conversation carries the split TLS ClientHello (frame 6 direct
        // fragment, frame 7 recovered-only) — the direct-vs-reassembled corpus this
        // fold distinguishes.
        let frames = ReplayCorpus.conversationCapturedFrames()
        let batch = TLSNorm(SessionBuilder.buildDetailed(from: frames, linkType: LinkType.ethernet).tlsEvidence)

        // Live detailed, one frame per ingest and varied batch groupings — a
        // decode-once, ordinal-assigning fold must not care how frames are chunked. The
        // investigation path wraps this identical fold, inheriting the same evidence.
        let liveOne = try await liveTLSSnapshot(chunks: frames.map { [$0] })
        #expect(liveOne == batch)
        let liveVaried = try await liveTLSSnapshot(chunks: Self.variedChunks(frames))
        #expect(liveVaried == batch)

        // Saved file over the same ordered frames — normalisation drops only the
        // saved-only evidence locator identity (via ``ProvenanceSnapshot``), so the TLS
        // semantics compare across paths.
        try ReplayCorpus.withTemporaryFile(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())) { url in
            let saved = try SavedCaptureStreamLoader(contentsOf: url).load().tlsEvidence
            #expect(TLSNorm(saved) == batch)
        }

        // Not vacuous: exactly one TLS flow, one retained direct record (an honest
        // fragment), and one excluded recovered multi-frame record — the exclusion the
        // provenance decision requires until a citation-set seam exists.
        #expect(batch.summaries.count == 1)
        #expect(batch.retainedObservationCount == 1)
        #expect(batch.excludedReassembledRecordCount == 1)
        #expect(batch.recoveredTruncationIndicatorCount == 0)
        let observation = try #require(batch.summaries.first?.observations.first)
        #expect(observation.bodyComplete == false)
    }

    // MARK: Datagram-analysis cross-path equivalence

    @Test
    func datagramAnalysisAgreesAcrossBatchLiveAndSaved() async throws {
        // Locally set the DNS TC bit on the generated IPv4 UDP-DNS response frame so
        // the datagram analysis is non-vacuous across every path. This is a byte-only
        // test mutation — no production decoder/builder API, no corpus/goldens change.
        let frames = Self.conversationWithTruncatedDNSResponse()
        let captured = frames.map {
            CapturedFrame(bytes: $0.bytes, timestamp: $0.timestamp, originalLength: $0.bytes.count)
        }

        // Batch: assess the detailed batch datagram evidence directly.
        let batch = DatagramAnalysisNorm(DatagramAssessor().assess(
            SessionBuilder.buildDetailed(from: captured, linkType: LinkType.ethernet).datagramEvidence
        ))

        // Live investigation snapshot over varied batch groupings — a decode-once,
        // ordinal-assigning fold must not care how frames are chunked. The
        // investigation path wraps this identical fold and assesses it once.
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        for chunk in Self.variedChunks(captured) {
            await engine.ingest(chunk, linkType: LinkType.ethernet, epoch: 1)
        }
        let investigation = try #require(await engine.investigationSnapshot(epoch: 1))
        #expect(DatagramAnalysisNorm(investigation.datagramAnalysis) == batch)

        // Saved file over the same ordered frames — normalisation drops only the
        // saved-only evidence locator identity (via ``ProvenanceSnapshot``), so the
        // datagram-analysis semantics compare across paths.
        try ReplayCorpus.withTemporaryFile(ReplayCorpus.classicPcapBytes(frames)) { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            #expect(DatagramAnalysisNorm(result.datagramAnalysis) == batch)
        }

        // Not vacuous: exactly one TC note, mapped from the mutated DNS response flow.
        #expect(batch.findings.count == 1)
        #expect(batch.findings.allSatisfy { $0.kind == "dnsTruncationIndicated" })
        #expect(batch.findings.allSatisfy { $0.severity == "note" })
    }

    // MARK: Investigation-query cross-path equivalence

    @Test
    func investigationQueryAgreesAcrossBatchLiveAndSaved() async throws {
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let queryEngine = InvestigationQueryEngine()
        // A finding-referencing query so evaluation returns a coverage summary and the
        // three-valued finding join is exercised across every path.
        let query = try queryEngine.compile(
            .any([.leaf(.findingKind(.reset)), .leaf(.findingKind(.retransmission))])
        )

        // Batch: wrap the detailed batch fold in one investigation snapshot.
        let batchSnapshot = InvestigationSnapshot(
            fold: SessionBuilder.buildDetailed(from: frames, linkType: LinkType.ethernet)
        )
        let batch = try QueryResultNorm(queryEngine.evaluate(query, over: batchSnapshot))

        // Live investigation snapshot over varied batch groupings — a decode-once,
        // ordinal-assigning fold must not care how frames are chunked.
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        for chunk in Self.variedChunks(frames) {
            await engine.ingest(chunk, linkType: LinkType.ethernet, epoch: 1)
        }
        let liveSnapshot = try #require(await engine.investigationSnapshot(epoch: 1))
        #expect(try QueryResultNorm(queryEngine.evaluate(query, over: liveSnapshot)) == batch)

        // Saved file over the same ordered frames — the query result is compared by
        // stable session id and coverage, so the saved-only evidence locator identity
        // never enters the comparison (the existing locator normalization).
        try ReplayCorpus.withTemporaryFile(ReplayCorpus.classicPcapBytes(ReplayCorpus.tcpConnectionFrames())) { url in
            let result = try SavedCaptureStreamLoader(contentsOf: url).load()
            let savedSnapshot = InvestigationSnapshot(fold: SessionFoldSnapshot(
                sessions: result.sessions,
                connections: result.connections,
                datagramEvidence: result.datagramEvidence,
                tlsEvidence: result.tlsEvidence
            ))
            #expect(try QueryResultNorm(queryEngine.evaluate(query, over: savedSnapshot)) == batch)
        }

        // Not vacuous: the query matched real sessions and returned a coverage summary.
        #expect(!batch.matched.isEmpty)
        #expect(batch.coverage != nil)
    }

    // MARK: Private

    /// A deterministic, cross-path projection of an ``InvestigationQueryResult``. It
    /// keeps only stable session ids and the coverage reasons (as sorted tokens), so
    /// batch/live/saved evaluations of the same frames compare equal without the
    /// per-frame evidence locator identity ever entering the comparison.
    private struct QueryResultNorm: Equatable {
        // MARK: Lifecycle

        init(_ result: InvestigationQueryResult) {
            matched = result.matched.map(\.id.uuidString)
            indeterminate = result.indeterminate.map(\.uuidString)
            coverage = result.coverage.map { $0.reasons.map { String(describing: $0) }.sorted() }
        }

        // MARK: Internal

        let matched: [String]
        let indeterminate: [String]
        let coverage: [String]?
    }

    /// The typed source/destination endpoint projection of one ``SessionSummary``,
    /// compared verbatim so any batch/live/saved drift in the additive typed fields
    /// fails. `IPEndpoint` is `Hashable`, so this composes into a per-id dictionary.
    private struct EndpointPair: Equatable {
        // MARK: Lifecycle

        init(_ summary: SessionSummary) {
            source = summary.sourceEndpointValue
            destination = summary.destinationEndpointValue
        }

        // MARK: Internal

        let source: IPEndpoint?
        let destination: IPEndpoint?
    }

    /// A deterministic, cross-path projection of a ``ConnectionAnalysisSnapshot``.
    /// Like ``ProvenanceSnapshot`` it excludes only the per-frame evidence *locator*
    /// identity (a saved frame carries a file-derived one, a batch or live frame
    /// carries none) so the analysis semantics compare equal across paths; every
    /// other field is preserved, so any real drift fails.
    private struct AnalysisSnapshotNorm: Equatable {
        // MARK: Lifecycle

        init(_ snapshot: ConnectionAnalysisSnapshot) {
            findings = snapshot.findings.map(FindingNorm.init)
            omittedFindingCount = snapshot.omittedFindingCount
            countersOverflowed = snapshot.countersOverflowed
        }

        // MARK: Internal

        let findings: [FindingNorm]
        let omittedFindingCount: UInt64
        let countersOverflowed: Bool
    }

    private struct FindingNorm: Equatable {
        // MARK: Lifecycle

        init(_ finding: ConnectionAnalysisFinding) {
            id = finding.id.uuidString
            kind = String(describing: finding.kind)
            severity = String(describing: finding.severity)
            connectionID = finding.connectionID.rawValue.uuidString
            tuple = "\(finding.tuple.proto.rawValue)|\(finding.tuple.a.display)|\(finding.tuple.b.display)"
            coverage = String(describing: finding.coverage)
            citations = finding.citations.map(CitationNorm.init)
            omittedCitationCount = finding.omittedCitationCount
        }

        // MARK: Internal

        let id: String
        let kind: String
        let severity: String
        let connectionID: String
        let tuple: String
        let coverage: String
        let citations: [CitationNorm]
        let omittedCitationCount: UInt64
    }

    private struct CitationNorm: Equatable {
        // MARK: Lifecycle

        init(_ citation: ConnectionAnalysisCitation) {
            connectionID = citation.connectionID.rawValue.uuidString
            sourceEventKind = String(describing: citation.sourceEventKind)
            direction = citation.direction.map { String(describing: $0) }
            provenance = citation.provenance.map(ProvenanceSnapshot.init)
        }

        // MARK: Internal

        let connectionID: String
        let sourceEventKind: String
        let direction: String?
        /// Each cited provenance drops only its locator (see ``ProvenanceSnapshot``).
        let provenance: [ProvenanceSnapshot]
    }

    /// A deterministic, cross-path projection of a ``DatagramEvidenceTable/Snapshot``.
    /// Like ``ProvenanceSnapshot`` it excludes only the per-frame evidence *locator*
    /// identity, so batch/live/saved folds of the same frames compare equal; every
    /// other field (session id, tuple, direction, typed kind, bounds/omission
    /// counters, loss, truncation) is preserved, so any real drift fails.
    private struct DatagramNorm: Equatable {
        // MARK: Lifecycle

        init(_ snapshot: DatagramEvidenceTable.Snapshot) {
            summaries = snapshot.summaries.map(DatagramSummaryNorm.init)
            omittedObservationCount = snapshot.omittedObservationCount
            retainedObservationCount = snapshot.retainedObservationCount
            excludedTCPDNSFactCount = snapshot.excludedTCPDNSFactCount
            capacityReached = snapshot.capacityReached
            countersOverflowed = snapshot.countersOverflowed
        }

        // MARK: Internal

        let summaries: [DatagramSummaryNorm]
        let omittedObservationCount: UInt64
        let retainedObservationCount: Int
        let excludedTCPDNSFactCount: UInt64
        let capacityReached: Bool
        let countersOverflowed: Bool
    }

    private struct DatagramSummaryNorm: Equatable {
        // MARK: Lifecycle

        init(_ summary: DatagramEvidenceSummary) {
            sessionID = summary.sessionID.uuidString
            tuple = "\(summary.tuple.proto.rawValue)|\(summary.tuple.a.display)|\(summary.tuple.b.display)"
            observations = summary.observations.map(DatagramObservationNorm.init)
            omittedObservationCount = summary.omittedObservationCount
            lossKnowledge = String(describing: summary.lossKnowledge)
            snapLengthTruncationObserved = summary.snapLengthTruncationObserved
        }

        // MARK: Internal

        let sessionID: String
        let tuple: String
        let observations: [DatagramObservationNorm]
        let omittedObservationCount: UInt64
        let lossKnowledge: String
        let snapLengthTruncationObserved: Bool
    }

    private struct DatagramObservationNorm: Equatable {
        // MARK: Lifecycle

        init(_ observation: DatagramEvidenceObservation) {
            sessionID = observation.sessionID.uuidString
            direction = String(describing: observation.direction)
            provenance = ProvenanceSnapshot(observation.provenance)
            // The typed DNS/ICMP facts stringify deterministically and carry no
            // name/answer/body — exactly the privacy-by-type guarantee under test.
            kind = String(describing: observation.kind)
        }

        // MARK: Internal

        let sessionID: String
        let direction: String
        /// Drops only the locator (see ``ProvenanceSnapshot``).
        let provenance: ProvenanceSnapshot
        let kind: String
    }

    /// A deterministic, cross-path projection of a ``TLSEvidenceTable/Snapshot``. Like
    /// ``ProvenanceSnapshot`` it excludes only the per-frame evidence *locator* identity,
    /// so batch/live/saved folds of the same frames compare equal; every other field
    /// (session id, tuple, direction, record index, typed fact, bounds/exclusion
    /// counters, loss, truncation) is preserved, so any real drift fails.
    private struct TLSNorm: Equatable {
        // MARK: Lifecycle

        init(_ snapshot: TLSEvidenceTable.Snapshot) {
            summaries = snapshot.summaries.map(TLSSummaryNorm.init)
            omittedObservationCount = snapshot.omittedObservationCount
            retainedObservationCount = snapshot.retainedObservationCount
            excludedReassembledRecordCount = snapshot.excludedReassembledRecordCount
            recoveredTruncationIndicatorCount = snapshot.recoveredTruncationIndicatorCount
            decoderTruncatedFrameCount = snapshot.decoderTruncatedFrameCount
            capacityReached = snapshot.capacityReached
            countersOverflowed = snapshot.countersOverflowed
        }

        // MARK: Internal

        let summaries: [TLSSummaryNorm]
        let omittedObservationCount: UInt64
        let retainedObservationCount: Int
        let excludedReassembledRecordCount: UInt64
        let recoveredTruncationIndicatorCount: UInt64
        let decoderTruncatedFrameCount: UInt64
        let capacityReached: Bool
        let countersOverflowed: Bool
    }

    private struct TLSSummaryNorm: Equatable {
        // MARK: Lifecycle

        init(_ summary: TLSEvidenceSummary) {
            sessionID = summary.sessionID.uuidString
            tuple = "\(summary.tuple.proto.rawValue)|\(summary.tuple.a.display)|\(summary.tuple.b.display)"
            observations = summary.observations.map(TLSObservationNorm.init)
            omittedObservationCount = summary.omittedObservationCount
            excludedReassembledRecordCount = summary.excludedReassembledRecordCount
            recoveredTruncationIndicatorCount = summary.recoveredTruncationIndicatorCount
            decoderTruncatedFrameCount = summary.decoderTruncatedFrameCount
            lossKnowledge = String(describing: summary.lossKnowledge)
            snapLengthTruncationObserved = summary.snapLengthTruncationObserved
        }

        // MARK: Internal

        let sessionID: String
        let tuple: String
        let observations: [TLSObservationNorm]
        let omittedObservationCount: UInt64
        let excludedReassembledRecordCount: UInt64
        let recoveredTruncationIndicatorCount: UInt64
        let decoderTruncatedFrameCount: UInt64
        let lossKnowledge: String
        let snapLengthTruncationObserved: Bool
    }

    private struct TLSObservationNorm: Equatable {
        // MARK: Lifecycle

        init(_ observation: TLSEvidenceObservation) {
            sessionID = observation.sessionID.uuidString
            direction = String(describing: observation.direction)
            provenance = ProvenanceSnapshot(observation.provenance)
            recordIndex = observation.recordIndex
            // The typed record fact stringifies deterministically and carries only
            // numeric wire values — no SNI, host or certificate material.
            fact = String(describing: observation.fact)
            bodyComplete = observation.fact.bodyComplete
        }

        // MARK: Internal

        let sessionID: String
        let direction: String
        /// Drops only the locator (see ``ProvenanceSnapshot``).
        let provenance: ProvenanceSnapshot
        let recordIndex: Int
        let fact: String
        let bodyComplete: Bool
    }

    /// A deterministic, cross-path projection of a ``DatagramAnalysisSnapshot``. Like
    /// ``ProvenanceSnapshot`` it excludes only the per-frame evidence *locator*
    /// identity (a saved frame carries a file-derived one, a batch or live frame
    /// carries none) so the analysis semantics compare equal across paths; every
    /// other field — findings, propagated coverage counters, overflow — is preserved,
    /// so any real drift fails.
    private struct DatagramAnalysisNorm: Equatable {
        // MARK: Lifecycle

        init(_ snapshot: DatagramAnalysisSnapshot) {
            findings = snapshot.findings.map(DatagramFindingNorm.init)
            omittedFindingCount = snapshot.omittedFindingCount
            retainedInputObservationCount = snapshot.retainedInputObservationCount
            inputOmittedObservationCount = snapshot.inputOmittedObservationCount
            excludedTCPDNSFactCount = snapshot.excludedTCPDNSFactCount
            retainedICMPObservationCount = snapshot.retainedICMPObservationCount
            inputCapacityReached = snapshot.inputCapacityReached
            countersOverflowed = snapshot.countersOverflowed
        }

        // MARK: Internal

        let findings: [DatagramFindingNorm]
        let omittedFindingCount: UInt64
        let retainedInputObservationCount: Int
        let inputOmittedObservationCount: UInt64
        let excludedTCPDNSFactCount: UInt64
        let retainedICMPObservationCount: UInt64
        let inputCapacityReached: Bool
        let countersOverflowed: Bool
    }

    private struct DatagramFindingNorm: Equatable {
        // MARK: Lifecycle

        init(_ finding: DatagramAnalysisFinding) {
            id = finding.id.uuidString
            kind = String(describing: finding.kind)
            severity = String(describing: finding.severity)
            sessionID = finding.sessionID.uuidString
            tuple = "\(finding.tuple.proto.rawValue)|\(finding.tuple.a.display)|\(finding.tuple.b.display)"
            coverage = String(describing: finding.coverage)
            citations = finding.citations.map(DatagramCitationNorm.init)
            omittedCitationCount = finding.omittedCitationCount
        }

        // MARK: Internal

        let id: String
        let kind: String
        let severity: String
        let sessionID: String
        let tuple: String
        let coverage: String
        let citations: [DatagramCitationNorm]
        let omittedCitationCount: UInt64
    }

    private struct DatagramCitationNorm: Equatable {
        // MARK: Lifecycle

        init(_ citation: DatagramAnalysisCitation) {
            sessionID = citation.sessionID.uuidString
            direction = String(describing: citation.direction)
            provenance = ProvenanceSnapshot(citation.provenance)
        }

        // MARK: Internal

        let sessionID: String
        let direction: String
        /// Drops only the locator (see ``ProvenanceSnapshot``).
        let provenance: ProvenanceSnapshot
    }

    /// Lock-guarded counter usable from the `@Sendable` decode closure.
    private final class Counter: @unchecked Sendable {
        // MARK: Internal

        var value: Int {
            lock.lock()
            defer { lock.unlock() }
            return count
        }

        func increment() {
            lock.lock()
            defer { lock.unlock() }
            count += 1
        }

        // MARK: Private

        private let lock = NSLock()
        private var count = 0
    }

    /// The primary conversation with the DNS TC (truncation) bit set on the first
    /// generated IPv4 UDP-DNS *response* frame. A local, test-only byte mutation: it
    /// locates the fixed DNS header signature (id `0x1234`, flags `0x8180` —
    /// response/RD/RA with TC clear) and ORs `0x02` into the flags high byte
    /// (`0x8180 -> 0x8380`). It adds no production decoder/builder API and changes no
    /// corpus or goldens — it is confined to this replay test.
    private static func conversationWithTruncatedDNSResponse() -> [ReplayCorpus.Frame] {
        let signature: [UInt8] = [0x12, 0x34, 0x81, 0x80]
        var frames = ReplayCorpus.conversation()
        for index in frames.indices {
            guard let start = indexOfSubsequence(signature, in: frames[index].bytes) else {
                continue
            }
            var bytes = frames[index].bytes
            bytes[start + 2] |= 0x02
            frames[index] = ReplayCorpus.Frame(
                bytes: bytes, offsetSeconds: frames[index].offsetSeconds, linkType: frames[index].linkType
            )
            break // only the first (IPv4) DNS response
        }
        return frames
    }

    private static func indexOfSubsequence(_ needle: [UInt8], in haystack: [UInt8]) -> Int? {
        guard !needle.isEmpty, haystack.count >= needle.count else {
            return nil
        }
        for start in 0 ... (haystack.count - needle.count)
            where Array(haystack[start ..< start + needle.count]) == needle
        {
            return start
        }
        return nil
    }

    private static func variedChunks(_ frames: [CapturedFrame]) -> [[CapturedFrame]] {
        // Deterministic, uneven groupings: [1][2][3]... capped, then the remainder.
        var chunks: [[CapturedFrame]] = []
        var index = 0
        var size = 1
        while index < frames.count {
            let end = min(frames.count, index + size)
            chunks.append(Array(frames[index ..< end]))
            index = end
            size = size % 3 + 1
        }
        return chunks
    }

    private static func uuidMatches(in text: String) -> Int {
        let pattern = "[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
        guard let regex = try? NSRegularExpression(pattern: pattern) else {
            return -1
        }
        return regex.numberOfMatches(in: text, range: NSRange(text.startIndex..., in: text))
    }

    private func liveSnapshots(
        chunks: [[CapturedFrame]],
        linkType: UInt32 = LinkType.ethernet
    )
        async -> [SessionSnapshot]
    {
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        for chunk in chunks {
            await engine.ingest(chunk, linkType: linkType, epoch: 1)
        }
        let summaries = await engine.snapshot(epoch: 1) ?? []
        return SessionSnapshot.snapshots(summaries)
    }

    /// Drive the live engine over `chunks` and return the deterministic connection
    /// snapshot from a detailed snapshot. Snapshotting twice proves repeated
    /// detailed snapshots neither re-decode nor mutate the fold.
    private func liveConnectionSnapshot(
        chunks: [[CapturedFrame]],
        linkType: UInt32 = LinkType.ethernet,
        connectionConfiguration: ConnectionTable.Configuration = ConnectionTable.Configuration()
    )
        async throws -> ConnectionTableSnapshot
    {
        let engine = LiveSessionEngine(connectionConfiguration: connectionConfiguration)
        await engine.reset(epoch: 1)
        for chunk in chunks {
            await engine.ingest(chunk, linkType: linkType, epoch: 1)
        }
        _ = await engine.detailedSnapshot(epoch: 1)
        let detailed = try #require(await engine.detailedSnapshot(epoch: 1))
        return ConnectionTableSnapshot(detailed.connections)
    }

    /// Drive the live engine over `chunks` and return the normalised datagram
    /// evidence from a detailed snapshot. Snapshotting twice proves repeated detailed
    /// snapshots neither re-decode nor mutate the fold.
    private func liveDatagramSnapshot(
        chunks: [[CapturedFrame]],
        linkType: UInt32 = LinkType.ethernet
    )
        async throws -> DatagramNorm
    {
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        for chunk in chunks {
            await engine.ingest(chunk, linkType: linkType, epoch: 1)
        }
        _ = await engine.detailedSnapshot(epoch: 1)
        let detailed = try #require(await engine.detailedSnapshot(epoch: 1))
        return DatagramNorm(detailed.datagramEvidence)
    }

    /// Drive the live engine over `chunks` and return the normalised TLS evidence from a
    /// detailed snapshot. Snapshotting twice proves repeated detailed snapshots neither
    /// re-decode nor mutate the fold.
    private func liveTLSSnapshot(
        chunks: [[CapturedFrame]],
        linkType: UInt32 = LinkType.ethernet
    )
        async throws -> TLSNorm
    {
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        for chunk in chunks {
            await engine.ingest(chunk, linkType: linkType, epoch: 1)
        }
        _ = await engine.detailedSnapshot(epoch: 1)
        let detailed = try #require(await engine.detailedSnapshot(epoch: 1))
        return TLSNorm(detailed.tlsEvidence)
    }

    private func savedRestoredSnapshots(from url: URL) throws -> [SessionSnapshot] {
        let result = try SavedCaptureStreamLoader(contentsOf: url).load()
        var sessions = result.sessions
        for index in sessions.indices {
            let reference = try #require(result.evidence[sessions[index].id])
            sessions[index].representativeBytes = try CaptureEvidenceReader.read(reference, from: url)
        }
        return SessionSnapshot.snapshots(sessions)
    }

    private func collectLayers(_ layers: [DecodedLayer]) -> [DecodedLayer] {
        layers.flatMap { [$0] + collectLayers($0.children) }
    }

    private func assertRangesWithin(_ layer: DecodedLayer, frameLength: Int, label: String) {
        if let range = layer.byteRange {
            #expect(range.lowerBound >= 0 && range.upperBound <= frameLength, "[\(label)] layer range OOB")
        }
        for field in layer.fields {
            if let range = field.byteRange {
                #expect(range.lowerBound >= 0 && range.upperBound <= frameLength, "[\(label)] field range OOB")
            }
        }
    }
}
