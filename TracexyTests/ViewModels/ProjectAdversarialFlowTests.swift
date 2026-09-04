import Foundation
import Testing
@testable import Tracexy

// MARK: - AdversarialGate

/// A deterministic continuation gate. It parks an asynchronous operation exactly
/// where a competing action must be attempted, so every race in this suite is
/// exercised by ordering rather than by sleeping.
private actor AdversarialGate {
    // MARK: Internal

    func pause() async {
        entered = true
        entryWaiter?.resume()
        entryWaiter = nil
        await withCheckedContinuation { releaseWaiter = $0 }
    }

    func waitForEntry() async {
        if !entered {
            await withCheckedContinuation { entryWaiter = $0 }
        }
    }

    func release() {
        releaseWaiter?.resume()
        releaseWaiter = nil
    }

    // MARK: Private

    private var entered = false
    private var entryWaiter: CheckedContinuation<Void, Never>?
    private var releaseWaiter: CheckedContinuation<Void, Never>?
}

// MARK: - ProjectAdversarialFlowTests

/// Adversarial Project/capture-source lifecycle flows: an accepted Save or export
/// competing with Clear/Start/Open/Trash, a queued engine reset outliving the
/// Project that owns its spool, a failed transition's selection-scoped evidence,
/// and a real synthetic A → B → A → B round trip.
///
/// Every coordinator is built on an isolated storage root and defaults namespace,
/// every capture is a real synthetic file, and no test installs a helper, touches
/// the network, presents a panel, or sleeps for a race.
@MainActor
@Suite("Project adversarial flows")
struct ProjectAdversarialFlowTests {
    // MARK: Internal

    @Test("An accepted save owns its source until it finishes")
    func saveHoldFreezesDestructiveSourceMutations() async throws {
        let environment = ProjectIsolationEnvironment(name: "adversarial-save-hold")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let directory = try #require(coordinator.capturesDirectory())
        let library = try Self.fixture(named: "library", frames: SampleCapture.frames(now: Self.epoch), in: directory)
        coordinator.refreshSavedCaptures()

        let frames = SampleCapture.frames(now: Self.epoch)
        let spool = coordinator.liveCaptureSpool
        try await spool.reset(epoch: coordinator.startGeneration)
        _ = try await spool.append(frames, defaultLinkType: LinkType.ethernet, epoch: coordinator.startGeneration)
        coordinator.retainedFrames.append(contentsOf: frames)
        coordinator.sessions = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)

        let gate = AdversarialGate()
        // Released on every exit path — including a failed expectation — so the
        // save can always finish and the temporary storage can always be removed.
        defer { let pending = gate
            Task { await pending.release() }
        }
        coordinator.captureSaveOperation = CaptureSaveOperation { source, ownedSpool, destination in
            await gate.pause()
            try await CaptureSaveOperation.copy.run(source, ownedSpool, destination)
        }
        coordinator.saveCurrentCapture()
        await gate.waitForEntry()
        let save = coordinator.pendingCaptureIOTask
        let generation = coordinator.startGeneration
        let sessionIDs = coordinator.sessions.map(\.id)
        #expect(coordinator.isCaptureSourceHeld)

        // Start would mint a new generation and reset the very spool being copied.
        #expect(coordinator.captureStartBlockedMessage != nil)
        coordinator.startCapture()
        #expect(!coordinator.isStarting)
        #expect(coordinator.startGeneration == generation)
        // Clear resets the same spool.
        coordinator.clearSessions()
        #expect(coordinator.sessions.map(\.id) == sessionIDs)
        #expect(coordinator.startGeneration == generation)
        // Adopting another saved capture resets it too.
        coordinator.openSavedCapture(library)
        #expect(!coordinator.isOpeningSavedCapture)
        #expect(coordinator.captureError != nil)
        // Trashing removes a Library file the save may be reading or writing beside.
        #expect(throws: CaptureMutationError.self) { try coordinator.moveSavedCaptureToTrash(library) }
        do {
            try coordinator.moveSavedCaptureToTrash(library)
            Issue.record("A busy source must not be removed")
        } catch {
            #expect(error.localizedDescription == coordinator.captureSourceHoldMessage)
        }
        #expect(FileManager.default.fileExists(atPath: library.url.path))

        await gate.release()
        await save?.value

        // The complete capture reached the Library, byte for byte.
        #expect(!coordinator.isCaptureSourceHeld)
        #expect(coordinator.captureStartBlockedMessage == nil)
        #expect(coordinator.captureError == nil)
        let saved = try #require(coordinator.savedCaptures.first { $0.name.hasPrefix("Capture ") })
        let written = try CaptureFileReader.read(contentsOf: saved.url)
        #expect(written.frames.map(\.bytes) == frames.map(\.bytes))
        // The gate is gone, so the source is mutable again.
        coordinator.clearSessions()
        #expect(coordinator.sessions.isEmpty)
        #expect(coordinator.startGeneration != generation)
        await coordinator.ingestChain?.value
    }

    @Test("An in-flight export owns its source across the modal window, with no privacy bypass")
    func exportHoldFreezesSourceMutationsWithoutPrivacyBypass() async throws {
        let environment = ProjectIsolationEnvironment(name: "adversarial-export-hold")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let directory = try #require(coordinator.capturesDirectory())
        let frames = SampleCapture.frames(now: Self.epoch)
        let library = try Self.fixture(named: "library", frames: frames, in: directory)
        coordinator.refreshSavedCaptures()
        coordinator.retainedFrames.append(contentsOf: frames)
        coordinator.sessions = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)
        let generation = coordinator.startGeneration
        let sessionIDs = coordinator.sessions.map(\.id)

        // This is the exact hold `exportSession` now takes *before* it presents the
        // raw-capture acknowledgement, so it covers that reentrant modal too. No
        // panel or alert is presented here.
        coordinator.setSessionExporting(true)
        defer { coordinator.setSessionExporting(false) }
        #expect(coordinator.isCaptureSourceHeld)
        #expect(!coordinator.canExport())
        #expect(coordinator.captureStartBlockedMessage != nil)
        coordinator.startCapture()
        #expect(!coordinator.isStarting)
        #expect(coordinator.startGeneration == generation)
        coordinator.clearSessions()
        #expect(coordinator.sessions.map(\.id) == sessionIDs)
        #expect(coordinator.startGeneration == generation)
        coordinator.openSavedCapture(library)
        #expect(!coordinator.isOpeningSavedCapture)
        #expect(throws: CaptureMutationError.self) { try coordinator.moveSavedCaptureToTrash(library) }

        // Holding the source earlier does not relax the acknowledgement itself: a
        // protected configuration still refuses a raw format without confirmation.
        let protected = SessionExportPrivacyPolicy(
            redactPayloadBodies: true,
            stripCredentials: true,
            maskIPAddresses: true
        )
        #expect(MainContentCoordinator.resolvedExportPrivacyPolicy(
            for: .pcap, configuredPrivacy: protected, didConfirmRawExport: false
        ) == nil)
        #expect(MainContentCoordinator.resolvedExportPrivacyPolicy(
            for: .pcap, configuredPrivacy: protected, didConfirmRawExport: true
        ) == SessionExportPrivacyPolicy.none)

        coordinator.setSessionExporting(false)
        #expect(!coordinator.isCaptureSourceHeld)
        #expect(coordinator.captureStartBlockedMessage == nil)
        await coordinator.ingestChain?.value
    }

    @Test("A queued engine reset that fails after a Project change reports into its own Project")
    func queuedEngineResetCannotPublishIntoAnotherProject() async throws {
        let environment = ProjectIsolationEnvironment(name: "adversarial-stale-reset")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let projectA = coordinator.projectStore.activeProjectID

        // A spool that cannot prepare a file: its directory's parent is a regular
        // file, so `reset` fails deterministically without any timing.
        try FileManager.default.createDirectory(at: environment.root, withIntermediateDirectories: true)
        let blocker = environment.root.appendingPathComponent("blocked")
        try Data([0]).write(to: blocker)
        coordinator.liveCaptureSpool = LiveCaptureSpool(
            directory: blocker.appendingPathComponent("Spool", isDirectory: true)
        )

        let gate = AdversarialGate()
        defer { let pending = gate
            Task { await pending.release() }
        }
        coordinator.ingestChain = Task { @MainActor in await gate.pause() }
        coordinator.resetSessionEngineForSavedCapture(token: coordinator.startGeneration)
        let queuedReset = coordinator.ingestChain
        await gate.waitForEntry()

        // The Project changes while the reset is still queued behind the gate.
        let projectB = try #require(await Self.created(coordinator, named: "Bravo"))
        #expect(coordinator.projectStore.activeProjectID == projectB.id)

        await gate.release()
        await queuedReset?.value
        // The failure describes A's spool, so B — which is on screen — is untouched.
        #expect(coordinator.captureError == nil)

        #expect(await Self.switched(coordinator, to: projectA))
        #expect(coordinator.captureError != nil)
    }

    @Test("A failed transition rebuilds the outgoing selection's evidence without losing its state")
    func failedTransitionRebuildsSavedEvidenceForTheOutgoingSelection() async throws {
        let environment = ProjectIsolationEnvironment(name: "adversarial-failed-evidence")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let directory = try #require(coordinator.capturesDirectory())
        let capture = try Self.fixture(named: "alpha", frames: SampleCapture.frames(now: Self.epoch), in: directory)
        coordinator.refreshSavedCaptures()
        coordinator.openSavedCapture(capture)
        await coordinator.waitForSavedCaptureOpen()
        await coordinator.waitForHistory()
        await coordinator.ingestChain?.value

        let selected = try #require(coordinator.sessions.first { coordinator.savedCaptureEvidence[$0.id] != nil })
        coordinator.select(selected)
        await coordinator.waitForSelectedSavedCaptureEvidence()
        await coordinator.evidenceProjection.task?.value
        let bytes = coordinator.evidenceBytes(for: selected)
        #expect(!bytes.isEmpty)
        #expect(coordinator.evidenceProjection.selection != nil)
        let sessionIDs = coordinator.sessions.map(\.id)
        let snapshotIDs = coordinator.investigationSnapshot.sessions.map(\.id)
        coordinator.activeWorkspace.filterText = "handshake"

        // The destination's private settings store cannot be opened, so the
        // transition fails after the outgoing evidence work was already retired.
        environment.provider.failsSettingsForNewProjects = true
        #expect(coordinator.createProject(named: "Unavailable") != nil)
        #expect(await !coordinator.waitForProjectTransition())
        await coordinator.waitForSelectedSavedCaptureEvidence()
        await coordinator.evidenceProjection.task?.value

        #expect(coordinator.projectTransitionStatus.failureMessage != nil)
        #expect(coordinator.activeWorkspace.selectedSessionID == selected.id)
        #expect(coordinator.evidenceProjection.selection != nil)
        #expect(coordinator.evidenceBytes(for: selected) == bytes)
        // Nothing else about the still-active Project moved.
        #expect(coordinator.sessions.map(\.id) == sessionIDs)
        #expect(coordinator.investigationSnapshot.sessions.map(\.id) == snapshotIDs)
        #expect(coordinator.isViewingSavedCapture)
        #expect(coordinator.activeSavedCapture == capture)
        #expect(coordinator.activeWorkspace.filterText == "handshake")
        #expect(coordinator.historyCaptures.count == 1)
    }

    @Test("A real A → B → A → B flow keeps each Project's configuration, evidence and History its own")
    func syntheticRoundTripKeepsEveryProjectIntact() async throws {
        let environment = ProjectIsolationEnvironment(name: "adversarial-roundtrip")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        // Project A: a real synthetic capture, its own settings, spool and History.
        let projectA = coordinator.projectStore.activeProjectID
        let framesA = SampleCapture.frames(now: Self.epoch)
        let directoryA = try #require(coordinator.capturesDirectory())
        let captureA = try Self.fixture(named: "alpha", frames: framesA, in: directoryA)
        let defaultsA = coordinator.activeProjectDefaults
        defaultsA.set(CaptureFilterMode.custom.rawValue, forKey: SettingsKeys.captureFilterMode)
        defaultsA.set("tcp port 443", forKey: SettingsKeys.bpfExpression)
        defaultsA.set(true, forKey: SettingsKeys.maskIPs)
        coordinator.refreshSavedCaptures()
        coordinator.openSavedCapture(captureA)
        await coordinator.waitForSavedCaptureOpen()
        await coordinator.waitForHistory()
        await coordinator.ingestChain?.value
        let spoolA = coordinator.liveCaptureSpool
        try await spoolA.reset(epoch: coordinator.startGeneration)
        _ = try await spoolA.append(framesA, defaultLinkType: LinkType.ethernet, epoch: coordinator.startGeneration)
        let selectedA = try #require(coordinator.sessions.first { coordinator.savedCaptureEvidence[$0.id] != nil })
        coordinator.select(selectedA)
        await coordinator.waitForSelectedSavedCaptureEvidence()
        let bytesA = coordinator.evidenceBytes(for: selectedA)
        let hostsA = Set(coordinator.sessions.map(\.host))
        #expect(!bytesA.isEmpty)
        #expect(coordinator.historyCaptures.count == 1)

        // Project B: different bytes, different settings, its own everything.
        let projectB = try #require(await Self.created(coordinator, named: "Bravo"))
        #expect(coordinator.sessions.isEmpty)
        #expect(coordinator.savedCaptures.isEmpty)
        #expect(coordinator.liveCaptureSpool !== spoolA)
        coordinator.refreshHistory()
        await coordinator.waitForHistory()
        #expect(coordinator.historyCaptures.isEmpty)

        let framesB = Array(SampleCapture.frames(now: Self.epoch).prefix(3))
        let directoryB = try #require(coordinator.capturesDirectory())
        #expect(directoryB != directoryA)
        let captureB = try Self.fixture(named: "bravo", frames: framesB, in: directoryB)
        coordinator.activeProjectDefaults.set(20_000, forKey: SettingsKeys.retainPackets)
        coordinator.refreshSavedCaptures()
        coordinator.openSavedCapture(captureB)
        await coordinator.waitForSavedCaptureOpen()
        await coordinator.waitForHistory()
        await coordinator.ingestChain?.value
        let spoolB = coordinator.liveCaptureSpool
        try await spoolB.reset(epoch: coordinator.startGeneration)
        _ = try await spoolB.append(framesB, defaultLinkType: LinkType.ethernet, epoch: coordinator.startGeneration)
        let hostsB = Set(coordinator.sessions.map(\.host))
        #expect(hostsB != hostsA)
        #expect(coordinator.historyCaptures.count == 1)

        // Back to A: its configuration, selection, evidence bytes, Library, History
        // and parked spool are exactly as they were, and nothing of B's is visible.
        // Repeat the round trip to expose stale generations and state accumulating
        // across several park/adopt cycles, not only a one-time initialization.
        for _ in 0 ..< 12 {
            #expect(await Self.switched(coordinator, to: projectA))
            #expect(Set(coordinator.sessions.map(\.host)) == hostsA)
            #expect(coordinator.isViewingSavedCapture)
            #expect(coordinator.activeSavedCapture == captureA)
            #expect(coordinator.activeWorkspace.selectedSessionID == selectedA.id)
            #expect(coordinator.readinessCaptureConfiguration.bpf == "tcp port 443")
            #expect(coordinator.readinessRetentionCapacity == CaptureSettingsResolver.defaultRetainPackets)
            #expect(PrivacySettingsResolver.exportPolicy(defaults: coordinator.activeProjectDefaults).maskIPAddresses)
            #expect(coordinator.savedCaptures.map(\.name) == ["alpha"])
            #expect(coordinator.liveCaptureSpool === spoolA)
            let parkedA = try await coordinator.liveCaptureSpool.capture()
            #expect(parkedA.frames.map(\.bytes) == framesA.map(\.bytes))
            await coordinator.evidenceProjection.task?.value
            #expect(coordinator.evidenceProjection.selection != nil)
            #expect(coordinator.evidenceBytes(for: selectedA) == bytesA)
            coordinator.refreshHistory()
            await coordinator.waitForHistory()
            #expect(coordinator.historyCaptures.count == 1)

            // And back to B: the same must hold from the other side.
            #expect(await Self.switched(coordinator, to: projectB.id))
            #expect(Set(coordinator.sessions.map(\.host)) == hostsB)
            #expect(coordinator.activeSavedCapture == captureB)
            #expect(coordinator.savedCaptures.map(\.name) == ["bravo"])
            #expect(coordinator.readinessCaptureConfiguration.bpf == nil)
            #expect(coordinator.readinessRetentionCapacity == 20_000)
            #expect(!PrivacySettingsResolver.exportPolicy(defaults: coordinator.activeProjectDefaults).maskIPAddresses)
            #expect(coordinator.liveCaptureSpool === spoolB)
            let parkedB = try await coordinator.liveCaptureSpool.capture()
            #expect(parkedB.frames.map(\.bytes) == framesB.map(\.bytes))
            coordinator.refreshHistory()
            await coordinator.waitForHistory()
            #expect(coordinator.historyCaptures.count == 1)
        }
    }

    // MARK: Private

    private static let epoch = Date(timeIntervalSince1970: 1_700_000_000)

    /// A real synthetic capture file inside the given Project's Library folder.
    private static func fixture(named name: String, frames: [CapturedFrame], in directory: URL) throws -> SavedCapture {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("\(name).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        let byteCount = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
        return SavedCapture(url: url, name: name, date: Date(), byteCount: byteCount)
    }

    /// Start a switch and await the durable completion the change requires.
    private static func switched(_ coordinator: MainContentCoordinator, to id: UUID) async -> Bool {
        guard coordinator.switchToProject(id: id) else {
            return false
        }
        return await coordinator.waitForProjectTransition()
    }

    /// Start a creation and await its durable completion.
    private static func created(_ coordinator: MainContentCoordinator, named name: String) async -> Project? {
        guard let project = coordinator.createProject(named: name),
              await coordinator.waitForProjectTransition() else
        {
            return nil
        }
        return project
    }
}
