import Foundation
import Testing
@testable import Tracexy

@MainActor
@Suite("Saved capture opening activation")
struct SavedCaptureOpeningTests {
    // MARK: Internal

    @Test("Open publishes only one final bounded result and lazy-loads selected evidence")
    func finalOnlyOpenAndLazyEvidence() async throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let frames = SampleCapture.frames(now: Date())
        let capture = try writeCapture(named: "bounded", frames: frames, in: environment.directory)

        environment.coordinator.openSavedCapture(capture)

        #expect(environment.coordinator.isOpeningSavedCapture)
        #expect(environment.coordinator.sessions.isEmpty)
        await environment.coordinator.waitForSavedCaptureOpen()

        let coordinator = environment.coordinator
        #expect(!coordinator.isOpeningSavedCapture)
        #expect(coordinator.activeSavedCapture == capture)
        #expect(!coordinator.sessions.isEmpty)
        #expect(!coordinator.sessions.contains { !$0.representativeBytes.isEmpty })
        #expect(coordinator.savedCaptureEvidence.count == coordinator.sessions.count)
        #expect(coordinator.retainedFrameCount <= coordinator.retainedFrameCapacity)
        #expect(coordinator.savedCaptureActivity?.totalFrames == frames.count)

        let selected = try #require(coordinator.sessions.first)
        let reference = try #require(coordinator.savedCaptureEvidence[selected.id])
        let expected = try CaptureEvidenceReader.read(reference, from: capture.url)
        coordinator.select(selected)
        await coordinator.waitForSelectedSavedCaptureEvidence()

        #expect(coordinator.evidenceBytes(for: selected) == expected)
        #expect(coordinator.selectedSessionEvidenceID == selected.id)
    }

    @Test("A malformed newer open preserves the previously published capture")
    func malformedOpenPreservesPublishedState() async throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let valid = try writeCapture(
            named: "valid",
            frames: SampleCapture.frames(now: Date()),
            in: environment.directory
        )
        environment.coordinator.openSavedCapture(valid)
        await environment.coordinator.waitForSavedCaptureOpen()
        let priorIDs = environment.coordinator.sessions.map(\.id)

        let malformedURL = environment.directory.appendingPathComponent("malformed.pcap")
        try Data([0x01, 0x02, 0x03]).write(to: malformedURL)
        let malformed = SavedCapture(url: malformedURL, name: "malformed", date: Date(), byteCount: 3)
        environment.coordinator.openSavedCapture(malformed)
        await environment.coordinator.waitForSavedCaptureOpen()

        #expect(environment.coordinator.activeSavedCapture == valid)
        #expect(environment.coordinator.sessions.map(\.id) == priorIDs)
        #expect(environment.coordinator.captureError?.contains("Couldn’t open") == true)
    }

    @Test("A newer open retires every result and progress callback from the older request")
    func newerOpenWins() async throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let first = try writeCapture(
            named: "first",
            frames: SampleCapture.frames(now: Date()),
            in: environment.directory
        )
        let secondFrames = Array(SampleCapture.frames(now: Date()).prefix(2))
        let second = try writeCapture(named: "second", frames: secondFrames, in: environment.directory)

        environment.coordinator.openSavedCapture(first)
        environment.coordinator.openSavedCapture(second)
        await environment.coordinator.waitForSavedCaptureOpen()

        #expect(environment.coordinator.activeSavedCapture == second)
        #expect(environment.coordinator.savedCaptureActivity?.totalFrames == secondFrames.count)
        #expect(environment.coordinator.savedCaptureOpenProgress?.bytesConsumed == UInt64(second.byteCount))
    }

    @Test("Clear retires a pending saved open without publishing partial state")
    func clearRetiresPendingOpen() async throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let capture = try writeCapture(
            named: "cancelled",
            frames: SampleCapture.frames(now: Date()),
            in: environment.directory
        )

        environment.coordinator.openSavedCapture(capture)
        let pendingBoundary = environment.coordinator.savedCaptureBoundaryTask
        environment.coordinator.clearSessions()
        await pendingBoundary?.value

        #expect(!environment.coordinator.isOpeningSavedCapture)
        #expect(environment.coordinator.activeSavedCapture == nil)
        #expect(environment.coordinator.sessions.isEmpty)
        #expect(environment.coordinator.savedCaptureEvidence.isEmpty)
    }

    @Test("A multi-gigabyte sparse open cancels without publishing or traversing the sparse tail")
    func sparseOpenCancelsIncrementally() async throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let firstFrame = try #require(SampleCapture.frames(now: Date()).first)
        let base = try writeCapture(named: "sparse", frames: [firstFrame], in: environment.directory)
        let sparseSize: UInt64 = 4 * 1_024 * 1_024 * 1_024
        let handle = try FileHandle(forWritingTo: base.url)
        try handle.truncate(atOffset: sparseSize)
        try handle.close()
        let sparse = SavedCapture(
            url: base.url,
            name: base.name,
            date: base.date,
            byteCount: Int(sparseSize)
        )

        environment.coordinator.openSavedCapture(sparse)
        for _ in 0 ..< 20 where environment.coordinator.savedCaptureOpenTask == nil {
            await Task.yield()
        }
        let loader = try #require(environment.coordinator.savedCaptureOpenTask)
        environment.coordinator.clearSessions()
        await loader.value

        #expect(environment.coordinator.sessions.isEmpty)
        #expect(environment.coordinator.activeSavedCapture == nil)
        #expect(!environment.coordinator.isOpeningSavedCapture)
    }

    @Test("A truncated tail publishes prior sessions with an explicit warning")
    func truncatedTailIsExplicit() async throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let frames = SampleCapture.frames(now: Date())
        let capture = try writeCapture(named: "truncated", frames: frames, in: environment.directory)
        let handle = try FileHandle(forWritingTo: capture.url)
        try handle.seekToEnd()
        try handle.write(contentsOf: Data([0xAA, 0xBB, 0xCC]))
        try handle.close()
        let byteCount = try #require(
            try capture.url.resourceValues(forKeys: [.fileSizeKey]).fileSize
        )
        let truncated = SavedCapture(
            url: capture.url,
            name: capture.name,
            date: capture.date,
            byteCount: byteCount
        )

        environment.coordinator.openSavedCapture(truncated)
        await environment.coordinator.waitForSavedCaptureOpen()

        #expect(!environment.coordinator.sessions.isEmpty)
        #expect(environment.coordinator.savedCaptureActivity?.totalFrames == frames.count)
        #expect(environment.coordinator.savedCaptureWarning?.contains("incomplete record") == true)
    }

    @Test("Opening a saved capture adopts the loader's connection snapshot")
    func openAdoptsConnectionSnapshot() async throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let capture = try writeCapture(named: "connections", frames: frames, in: environment.directory)

        environment.coordinator.openSavedCapture(capture)
        await environment.coordinator.waitForSavedCaptureOpen()

        let coordinator = environment.coordinator
        #expect(!coordinator.sessions.isEmpty)
        #expect(!coordinator.connectionSnapshot.summaries.isEmpty)
        // Matches an independent load of the same unchanged file.
        let result = try SavedCaptureStreamLoader(contentsOf: capture.url).load()
        #expect(coordinator.connectionSnapshot == result.connections)
        // The analysis is adopted exactly equal to the loader result, paired with
        // its exact connections — never re-derived on the coordinator.
        #expect(!coordinator.connectionAnalysisSnapshot.findings.isEmpty)
        #expect(coordinator.connectionAnalysisSnapshot == result.connectionAnalysis)
        #expect(
            coordinator.connectionAnalysisSnapshot == ConnectionAssessor().assess(coordinator.connectionSnapshot)
        )
        // The datagram analysis is adopted through the same seam. This TCP-only corpus
        // has no datagram evidence, so it is empty — the non-vacuous adoption is
        // proven by ``openAdoptsNonVacuousDatagramAnalysisAndClearResetsIt``.
        #expect(coordinator.datagramAnalysisSnapshot == result.datagramAnalysis)
        #expect(coordinator.datagramAnalysisSnapshot == .empty)
    }

    @Test("Clear removes both the sessions and the connection snapshot")
    func clearRemovesSessionsAndConnections() async throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let capture = try writeCapture(named: "clearable", frames: frames, in: environment.directory)
        environment.coordinator.openSavedCapture(capture)
        await environment.coordinator.waitForSavedCaptureOpen()
        #expect(!environment.coordinator.connectionSnapshot.summaries.isEmpty)
        #expect(!environment.coordinator.connectionAnalysisSnapshot.findings.isEmpty)

        environment.coordinator.clearSessions()

        // Clear empties sessions, connections and both analyses together.
        #expect(environment.coordinator.sessions.isEmpty)
        #expect(environment.coordinator.connectionSnapshot == .empty)
        #expect(environment.coordinator.connectionAnalysisSnapshot == .empty)
        #expect(environment.coordinator.datagramAnalysisSnapshot == .empty)
    }

    @Test("A malformed newer open preserves the previously published session/connection pair")
    func malformedOpenPreservesConnectionPair() async throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let valid = try writeCapture(
            named: "valid-connections",
            frames: ReplayCorpus.tcpConnectionCapturedFrames(),
            in: environment.directory
        )
        environment.coordinator.openSavedCapture(valid)
        await environment.coordinator.waitForSavedCaptureOpen()
        let priorSessions = environment.coordinator.sessions.map(\.id)
        let priorConnections = environment.coordinator.connectionSnapshot
        let priorAnalysis = environment.coordinator.connectionAnalysisSnapshot
        let priorDatagramAnalysis = environment.coordinator.datagramAnalysisSnapshot
        #expect(!priorConnections.summaries.isEmpty)
        #expect(!priorAnalysis.findings.isEmpty)

        let malformedURL = environment.directory.appendingPathComponent("malformed.pcap")
        try Data([0x01, 0x02, 0x03]).write(to: malformedURL)
        let malformed = SavedCapture(url: malformedURL, name: "malformed", date: Date(), byteCount: 3)
        environment.coordinator.openSavedCapture(malformed)
        await environment.coordinator.waitForSavedCaptureOpen()

        // The failed open revives no part of the set: the valid
        // session/connection/analysis values are preserved intact together.
        #expect(environment.coordinator.sessions.map(\.id) == priorSessions)
        #expect(environment.coordinator.connectionSnapshot == priorConnections)
        #expect(environment.coordinator.connectionAnalysisSnapshot == priorAnalysis)
        #expect(environment.coordinator.datagramAnalysisSnapshot == priorDatagramAnalysis)
    }

    @Test("A live investigation publication adopts the exact pair only for the current generation and state")
    func liveInvestigationPublicationHonorsGenerationAndState() async throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator

        // Build one real investigation snapshot off-main from the live engine — no
        // capture backend is started. The corpus produces connections and findings.
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        await engine.ingest(ReplayCorpus.tcpConnectionCapturedFrames(), linkType: LinkType.ethernet, epoch: 1)
        let snapshot = try #require(await engine.investigationSnapshot(epoch: 1))
        #expect(snapshot.connections != .empty)
        #expect(!snapshot.connectionAnalysis.findings.isEmpty)

        // A stale generation adopts no value — the empty state is untouched.
        coordinator.publishLiveDetailed(
            snapshot,
            expectedGeneration: coordinator.startGeneration + 1,
            isCapturing: coordinator.isCapturing
        )
        await drainMainActor()
        #expect(coordinator.connectionSnapshot == .empty)
        #expect(coordinator.connectionAnalysisSnapshot == .empty)
        #expect(coordinator.datagramAnalysisSnapshot == .empty)
        #expect(coordinator.sessions.isEmpty)

        // A wrong capture-state guard likewise adopts no value.
        coordinator.publishLiveDetailed(
            snapshot,
            expectedGeneration: coordinator.startGeneration,
            isCapturing: !coordinator.isCapturing
        )
        await drainMainActor()
        #expect(coordinator.connectionSnapshot == .empty)
        #expect(coordinator.connectionAnalysisSnapshot == .empty)
        #expect(coordinator.datagramAnalysisSnapshot == .empty)
        #expect(coordinator.sessions.isEmpty)

        // The current generation and matching state adopts the exact
        // connection+analysis+datagram values together with the sessions. This
        // TCP-only corpus carries no datagram evidence, so the datagram value is
        // adopted exactly equal to the (empty) snapshot value; the non-vacuous live
        // adoption is proven by ``liveDatagramPublicationHonorsGenerationAndState``.
        coordinator.publishLiveDetailed(
            snapshot,
            expectedGeneration: coordinator.startGeneration,
            isCapturing: coordinator.isCapturing
        )
        await drainMainActor()
        #expect(!coordinator.sessions.isEmpty)
        #expect(coordinator.connectionSnapshot == snapshot.connections)
        #expect(coordinator.connectionAnalysisSnapshot == snapshot.connectionAnalysis)
        #expect(coordinator.datagramAnalysisSnapshot == snapshot.datagramAnalysis)
    }

    @Test("Opening a saved capture adopts a non-vacuous datagram analysis and clear resets it")
    func openAdoptsNonVacuousDatagramAnalysisAndClearResetsIt() async throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        // A capture whose IPv4 UDP-DNS response has the TC bit set, so the datagram
        // analysis is a non-vacuous single note rather than empty.
        let frames = Self.truncatedDNSConversationCapturedFrames()
        let capture = try writeCapture(named: "datagram", frames: frames, in: environment.directory)

        environment.coordinator.openSavedCapture(capture)
        await environment.coordinator.waitForSavedCaptureOpen()

        let coordinator = environment.coordinator
        let result = try SavedCaptureStreamLoader(contentsOf: capture.url).load()
        // Adopted exactly equal to the loader result — never re-derived on the
        // coordinator — and non-vacuous (one TC note).
        #expect(coordinator.datagramAnalysisSnapshot == result.datagramAnalysis)
        #expect(coordinator.datagramAnalysisSnapshot == DatagramAssessor().assess(result.datagramEvidence))
        #expect(coordinator.datagramAnalysisSnapshot.findings.contains { $0.kind == .dnsTruncationIndicated })

        coordinator.clearSessions()
        #expect(coordinator.datagramAnalysisSnapshot == .empty)
    }

    @Test("A malformed newer open preserves a non-vacuous datagram analysis")
    func malformedOpenPreservesNonVacuousDatagramAnalysis() async throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let valid = try writeCapture(
            named: "valid-datagram",
            frames: Self.truncatedDNSConversationCapturedFrames(),
            in: environment.directory
        )
        environment.coordinator.openSavedCapture(valid)
        await environment.coordinator.waitForSavedCaptureOpen()
        let priorDatagramAnalysis = environment.coordinator.datagramAnalysisSnapshot
        #expect(priorDatagramAnalysis.findings.contains { $0.kind == .dnsTruncationIndicated })

        let malformedURL = environment.directory.appendingPathComponent("malformed.pcap")
        try Data([0x01, 0x02, 0x03]).write(to: malformedURL)
        let malformed = SavedCapture(url: malformedURL, name: "malformed", date: Date(), byteCount: 3)
        environment.coordinator.openSavedCapture(malformed)
        await environment.coordinator.waitForSavedCaptureOpen()

        // The failed open preserves the prior non-vacuous datagram analysis intact.
        #expect(environment.coordinator.datagramAnalysisSnapshot == priorDatagramAnalysis)
    }

    @Test("A live datagram publication adopts the exact non-vacuous value only for the current generation/state")
    func liveDatagramPublicationHonorsGenerationAndState() async throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator

        // Build one real investigation snapshot off-main from the live engine over a
        // TC-mutated conversation — a non-vacuous datagram analysis, no capture backend.
        let engine = LiveSessionEngine()
        await engine.reset(epoch: 1)
        await engine.ingest(Self.truncatedDNSConversationCapturedFrames(), linkType: LinkType.ethernet, epoch: 1)
        let snapshot = try #require(await engine.investigationSnapshot(epoch: 1))
        #expect(snapshot.datagramAnalysis.findings.contains { $0.kind == .dnsTruncationIndicated })

        // A stale generation adopts nothing — the empty datagram state is untouched.
        coordinator.publishLiveDetailed(
            snapshot,
            expectedGeneration: coordinator.startGeneration + 1,
            isCapturing: coordinator.isCapturing
        )
        await drainMainActor()
        #expect(coordinator.datagramAnalysisSnapshot == .empty)

        // A wrong capture-state guard likewise adopts nothing.
        coordinator.publishLiveDetailed(
            snapshot,
            expectedGeneration: coordinator.startGeneration,
            isCapturing: !coordinator.isCapturing
        )
        await drainMainActor()
        #expect(coordinator.datagramAnalysisSnapshot == .empty)

        // The current generation and matching state adopts the exact non-vacuous value.
        coordinator.publishLiveDetailed(
            snapshot,
            expectedGeneration: coordinator.startGeneration,
            isCapturing: coordinator.isCapturing
        )
        await drainMainActor()
        #expect(coordinator.datagramAnalysisSnapshot == snapshot.datagramAnalysis)
        #expect(coordinator.datagramAnalysisSnapshot.findings.contains { $0.kind == .dnsTruncationIndicated })
    }

    // MARK: Private

    private struct Environment {
        let coordinator: MainContentCoordinator
        let directory: URL
        let teardown: () -> Void
    }

    /// The primary conversation as `CapturedFrame`s with the DNS TC (truncation) bit
    /// set on the first generated IPv4 UDP-DNS *response* frame, so the folded
    /// datagram analysis is a non-vacuous single note. A local, test-only byte
    /// mutation: it locates the fixed DNS header signature (id `0x1234`, flags
    /// `0x8180` — response/RD/RA with TC clear) and ORs `0x02` into the flags high
    /// byte. It adds no production decoder/builder API and changes no corpus/goldens.
    private static func truncatedDNSConversationCapturedFrames() -> [CapturedFrame] {
        let signature: [UInt8] = [0x12, 0x34, 0x81, 0x80]
        var frames = ReplayCorpus.conversationCapturedFrames()
        for index in frames.indices {
            guard let start = indexOfSubsequence(signature, in: frames[index].bytes) else {
                continue
            }
            var bytes = frames[index].bytes
            bytes[start + 2] |= 0x02
            frames[index] = CapturedFrame(
                bytes: bytes,
                timestamp: frames[index].timestamp,
                originalLength: frames[index].originalLength,
                capturedLength: frames[index].capturedLength,
                linkType: frames[index].linkType
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

    /// `publishLiveDetailed` commits its adoption inside a `Task { @MainActor }`
    /// that hops one runloop turn. Yield enough times for that single queued task
    /// to run before asserting, without sleeping on a wall clock.
    private func drainMainActor() async {
        for _ in 0 ..< 50 {
            await Task.yield()
        }
    }

    private func makeEnvironment(function: String = #function) throws -> Environment {
        let suiteName = "com.amunx.tracexy.saved-open.\(function).\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tracexy-saved-open-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let coordinator = MainContentCoordinator(
            layoutPreferences: WorkspaceLayoutPreferences(defaults: defaults)
        )
        return Environment(coordinator: coordinator, directory: directory) {
            defaults.removePersistentDomain(forName: suiteName)
            try? FileManager.default.removeItem(at: directory)
        }
    }

    private func writeCapture(
        named name: String,
        frames: [CapturedFrame],
        in directory: URL
    )
        throws -> SavedCapture
    {
        let url = directory.appendingPathComponent("\(name).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        let byteCount = try #require(
            try url.resourceValues(forKeys: [.fileSizeKey]).fileSize
        )
        return SavedCapture(url: url, name: name, date: Date(), byteCount: byteCount)
    }
}
