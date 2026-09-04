import Foundation
import Testing
@testable import Tracexy

// MARK: - ChallengeSaveGate

private actor ChallengeSaveGate {
    // MARK: Internal

    func pause() async {
        entered = true
        entry?.resume()
        entry = nil
        await withCheckedContinuation { releaseContinuation = $0 }
    }

    func waitForEntry() async {
        if !entered {
            await withCheckedContinuation { entry = $0 }
        }
    }

    func release() {
        releaseContinuation?.resume()
        releaseContinuation = nil
    }

    // MARK: Private

    private var entered = false
    private var entry: CheckedContinuation<Void, Never>?
    private var releaseContinuation: CheckedContinuation<Void, Never>?
}

// MARK: - ProjectChallengeTests

@MainActor
@Suite("Project adversarial lifecycle")
struct ProjectChallengeTests {
    @Test("An old successful stop completion cannot release a reset still finalizing its prefix")
    func resetRejectsOldCompletionBeforePrefixFinalization() async {
        let environment = ProjectIsolationEnvironment(name: "challenge-reset-late-completion")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let token = coordinator.startGeneration
        let operation = coordinator.beginFinalCaptureDrain(stoppedToken: token, captureToken: token)
        let gate = ChallengeSaveGate()
        coordinator.ingestChain = Task { await gate.pause() }
        await gate.waitForEntry()
        coordinator.prepareForDestructiveHelperReset()
        // The old callback arrives after reset accepted responsibility for the
        // prefix but before that prefix's fold/publication has finished.
        coordinator.completeFinalCaptureDrain(stoppedToken: token)
        #expect(coordinator.isFinalDrainPending)
        await gate.release()
        await coordinator.ingestChain?.value
        #expect(await !coordinator.waitForFinalCaptureDrain(timeout: .milliseconds(200), operationID: operation))
        #expect(!coordinator.isFinalDrainPending)
    }

    @Test("A failed Project transition restores the outgoing selected evidence projection")
    func failedTransitionKeepsSelectedEvidenceUsable() async throws {
        let environment = ProjectIsolationEnvironment(name: "challenge-failed-evidence")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let frames = SampleCapture.frames(now: Date())
        let sessions = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)
        coordinator.sessions = sessions
        let session = try #require(sessions.first)
        coordinator.select(session)
        await coordinator.evidenceProjection.task?.value
        #expect(coordinator.evidenceProjection.selection != nil)
        environment.provider.failsSettingsForNewProjects = true
        _ = coordinator.createProject(named: "Unavailable")
        #expect(await !coordinator.waitForProjectTransition())
        await coordinator.evidenceProjection.task?.value
        #expect(coordinator.activeWorkspace.selectedSessionID == session.id)
        #expect(coordinator.evidenceProjection.selection != nil)
    }

    @Test("An in-flight session export owns its capture source until completion")
    func sourceMutationsRefusedDuringSessionExport() async {
        let environment = ProjectIsolationEnvironment(name: "challenge-export-source")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let token = coordinator.startGeneration
        coordinator.setSessionExporting(true)
        defer { coordinator.setSessionExporting(false) }
        #expect(coordinator.captureStartBlockedMessage != nil)
        coordinator.clearSessions()
        #expect(coordinator.startGeneration == token)
        await coordinator.ingestChain?.value
    }

    @Test("Start cannot supersede a stopped capture that still owes its final tail")
    func startBlockedDuringOwedDrain() async {
        let environment = ProjectIsolationEnvironment(name: "challenge-start-drain")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let token = coordinator.startGeneration
        coordinator.beginFinalCaptureDrain(stoppedToken: token)
        // Inspect the same guard used by startCapture without starting a real backend.
        #expect(coordinator.captureStartBlockedMessage != nil)
        coordinator.completeFinalCaptureDrain(stoppedToken: token)
        #expect(coordinator.captureStartBlockedMessage == nil)
    }

    @Test("An accepted live save retains its source through a competing Clear action")
    func clearCannotResetPendingSaveSource() async throws {
        let environment = ProjectIsolationEnvironment(name: "challenge-save-clear")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let frames = SampleCapture.frames(now: Date())
        let spool = coordinator.liveCaptureSpool
        try await spool.reset(epoch: coordinator.startGeneration)
        try await spool.append(frames, defaultLinkType: LinkType.ethernet, epoch: coordinator.startGeneration)
        coordinator.retainedFrames.append(contentsOf: frames)
        let gate = ChallengeSaveGate()
        coordinator.captureSaveOperation = CaptureSaveOperation { source, ownedSpool, destination in
            await gate.pause()
            try await CaptureSaveOperation.copy.run(source, ownedSpool, destination)
        }
        coordinator.saveCurrentCapture()
        await gate.waitForEntry()
        let save = coordinator.pendingCaptureIOTask
        coordinator.clearSessions()
        await coordinator.ingestChain?.value
        await gate.release()
        await save?.value
        #expect(coordinator.captureError == nil)
        #expect(coordinator.savedCaptures.count == 1)
        if let saved = coordinator.savedCaptures.first {
            let result = try CaptureFileReader.read(contentsOf: saved.url)
            #expect(result.frames.map(\.bytes) == frames.map(\.bytes))
        }
    }
}
