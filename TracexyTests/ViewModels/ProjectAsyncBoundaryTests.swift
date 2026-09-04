import Foundation
import Testing
@testable import Tracexy

// MARK: - ProjectLoaderGate

private actor ProjectLoaderGate {
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

// MARK: - ProjectOperationCounter

private actor ProjectOperationCounter {
    // MARK: Internal

    func next() -> Int {
        value += 1
        return value
    }

    // MARK: Private

    private var value = 0
}

// MARK: - ProjectAsyncBoundaryTests

@MainActor
@Suite("Project asynchronous boundaries")
struct ProjectAsyncBoundaryTests {
    // MARK: Internal

    @Test("Two queued saves retain their final task and stay in the originating Library")
    func queuedSavesStayOwnedUntilBothFinish() async throws {
        let environment = ProjectIsolationEnvironment(name: "queued-saves")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let capture = try fixture(in: environment)
        coordinator.openSavedCapture(capture)
        await coordinator.waitForSavedCaptureOpen()
        await coordinator.waitForHistory()
        let directoryA = try #require(coordinator.capturesDirectory())
        let first = ProjectLoaderGate()
        let second = ProjectLoaderGate()
        let counter = ProjectOperationCounter()
        coordinator.captureSaveOperation = CaptureSaveOperation { source, spool, destination in
            if await counter.next() == 1 {
                await first.pause()
            } else {
                await second.pause()
            }
            try await CaptureSaveOperation.copy.run(source, spool, destination)
        }
        coordinator.saveCurrentCapture()
        await first.waitForEntry()
        coordinator.saveCurrentCapture()
        await first.release()
        await second.waitForEntry()
        // The first completion must not erase the handle of the second save.
        #expect(coordinator.pendingCaptureIOTask != nil)
        _ = coordinator.createProject(named: "Bravo")
        #expect(coordinator.projectTransitionStatus.isPending)
        await second.release()
        #expect(await coordinator.waitForProjectTransition())
        #expect(coordinator.pendingCaptureIOTask == nil)
        #expect(coordinator.savedCaptures.isEmpty)
        let saved = try FileManager.default.contentsOfDirectory(at: directoryA, includingPropertiesForKeys: nil)
        #expect(saved.filter { $0.pathExtension == "pcap" }.count == 2)
        for url in saved where url.pathExtension == "pcap" {
            #expect(try Data(contentsOf: url) == Data(contentsOf: capture.url))
        }
    }

    @Test("Reset prepares resources before discarding any Project runtime")
    func resetFailurePreservesRuntimeAndSuccessRetiresOwnership() async throws {
        let environment = ProjectIsolationEnvironment(name: "reset-preflight")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let capture = try fixture(in: environment)
        coordinator.openSavedCapture(capture)
        await coordinator.waitForSavedCaptureOpen()
        await coordinator.waitForHistory()
        let original = coordinator.activeRuntime
        let projectA = coordinator.projectStore.activeProjectID
        let sessionIDs = coordinator.sessions.map(\.id)
        environment.provider.failsSettingsForNewProjects = true
        await coordinator.resetProjectCatalog()
        #expect(coordinator.projectStore.activeProjectID == projectA)
        #expect(coordinator.activeRuntime === original)
        #expect(coordinator.sessions.map(\.id) == sessionIDs)
        #expect(coordinator.projectTransitionStatus.failureMessage != nil)
        environment.provider.failsSettingsForNewProjects = false
        await coordinator.resetProjectCatalog()
        #expect(coordinator.projectStore.activeProjectID != projectA)
        #expect(coordinator.projectStore.legacyDataOwnerProjectID == projectA)
        #expect(coordinator.sessions.isEmpty)
        #expect(coordinator.activeRuntime !== original)
        #expect(coordinator.sessionStore !== original.sessionStore)
        #expect(FileManager.default.fileExists(atPath: capture.url.path))
    }

    @Test("A refused inactive deletion retains its runtime and does not stop the active capture")
    func inactiveDeleteIsDurableWithoutStoppingCapture() async {
        let environment = ProjectIsolationEnvironment(name: "inactive-delete")
        defer { environment.tearDown() }
        let repository = ControllableProjectCatalogRepository()
        environment.catalogRepository = repository
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let projectA = coordinator.projectStore.activeProjectID
        let runtimeA = coordinator.activeRuntime
        _ = coordinator.createProject(named: "Bravo")
        #expect(await coordinator.waitForProjectTransition())
        coordinator.isCapturing = true // State-only: no backend was started.
        defer { coordinator.isCapturing = false }
        await repository.refuseSaveWithProjectCount(1)
        #expect(coordinator.deleteProject(id: projectA))
        #expect(await !(coordinator.waitForProjectTransition()))
        #expect(coordinator.projectStore.projects.contains { $0.id == projectA })
        #expect(coordinator.projectRuntimes[projectA] === runtimeA)
        #expect(coordinator.isCapturing)
        #expect(coordinator.pendingProjectSwitchConfirmation == nil)
        await repository.refuseSaveWithProjectCount(nil)
        coordinator.retryProjectTransition()
        #expect(await coordinator.waitForProjectTransition())
        #expect(!coordinator.projectStore.projects.contains { $0.id == projectA })
        #expect(coordinator.isCapturing)
    }

    @Test("A slow saved loader is retired before a Project transition can await storage")
    func delayedLoaderCannotPublishAcrossProjects() async throws {
        let environment = ProjectIsolationEnvironment(name: "delayed-loader")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let capture = try fixture(in: environment)
        let result = try await Task.detached {
            try SavedCaptureStreamLoader(contentsOf: capture.url).load()
        }.value
        let gate = ProjectLoaderGate()
        coordinator.savedCaptureLoadOperation = SavedCaptureLoadOperation { _, _, progress in
            await gate.pause()
            // Deliberately ignore cancellation and even send late progress.
            // The coordinator must retire both callbacks, not trust the worker.
            progress(result.finalProgress)
            return result
        }
        coordinator.openSavedCapture(capture)
        await gate.waitForEntry()
        let oldLoad = coordinator.savedCaptureOpenTask
        let oldRequest = coordinator.savedCaptureOpenRequestID
        let projectA = coordinator.projectStore.activeProjectID
        let projectB = coordinator.createProject(named: "Bravo")
        #expect(projectB != nil)
        #expect(!coordinator.isOpeningSavedCapture)
        #expect(coordinator.savedCaptureOpenRequestID > oldRequest)
        #expect(await coordinator.waitForProjectTransition())
        await gate.release()
        await oldLoad?.value
        await coordinator.waitForHistory()
        #expect(coordinator.projectStore.activeProjectID == projectB?.id)
        #expect(coordinator.sessions.isEmpty)
        #expect(coordinator.savedCaptureEvidence.isEmpty)
        #expect(coordinator.activeSavedCapture == nil)
        #expect(coordinator.savedCaptureOpenProgress == nil)
        #expect(coordinator.historyCaptures.isEmpty)
        #expect(coordinator.switchToProject(id: projectA))
        #expect(await coordinator.waitForProjectTransition())
        #expect(coordinator.sessions.isEmpty)
    }

    @Test("Saved open waits for the owed helper tail, not just the current ingest task")
    func savedOpenWaitsForExactDrain() async throws {
        let environment = ProjectIsolationEnvironment(name: "saved-drain")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let capture = try fixture(in: environment)
        let token = coordinator.startGeneration
        coordinator.beginFinalCaptureDrain(stoppedToken: token)
        coordinator.openSavedCapture(capture)
        #expect(coordinator.isOpeningSavedCapture)
        #expect(coordinator.savedCaptureBoundaryTask == nil)
        #expect(coordinator.savedCaptureOpenTask == nil)
        coordinator.completeFinalCaptureDrain(stoppedToken: token)
        coordinator.resumePendingSavedCaptureOpenAfterLiveDrain()
        await coordinator.waitForSavedCaptureOpen()
        await coordinator.waitForHistory()
        #expect(coordinator.activeSavedCapture == capture)
        #expect(!coordinator.sessions.isEmpty)
    }

    @Test("An unconfirmed final drain fails the transition; explicit retry remains possible")
    func failedDrainDoesNotActivateDestination() async {
        let environment = ProjectIsolationEnvironment(name: "failed-drain")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let projectA = coordinator.projectStore.activeProjectID
        let token = coordinator.startGeneration
        coordinator.beginFinalCaptureDrain(stoppedToken: token)
        _ = coordinator.createProject(named: "Bravo")
        coordinator.completeFinalCaptureDrain(stoppedToken: token, succeeded: false)
        // A completion before the transition task registers its waiter must not
        // disappear: the accepted operation remembers its failure outcome.
        #expect(await !(coordinator.waitForProjectTransition()))
        #expect(coordinator.projectStore.activeProjectID == projectA)
        #expect(coordinator.projectStore.projects.count == 1)
        coordinator.retryProjectTransition()
        #expect(await coordinator.waitForProjectTransition())
        #expect(coordinator.projectStore.activeProject.name == "Bravo")
    }

    @Test("A stale Library row cannot delete a capture owned by another Project")
    func staleLibraryActionCannotCrossProjects() async throws {
        let environment = ProjectIsolationEnvironment(name: "stale-library")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let directory = try #require(coordinator.capturesDirectory())
        let capture = try fixture(in: environment, directory: directory)
        _ = coordinator.createProject(named: "Bravo")
        #expect(await coordinator.waitForProjectTransition())
        #expect(throws: CocoaError.self) { try coordinator.moveSavedCaptureToTrash(capture) }
        #expect(FileManager.default.fileExists(atPath: capture.url.path))
    }

    // MARK: Private

    private func fixture(in environment: ProjectIsolationEnvironment, directory: URL? = nil) throws -> SavedCapture {
        let folder = directory ?? environment.root
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let url = folder.appendingPathComponent("synthetic.pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: SampleCapture.frames(now: Date()), to: url)
        let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
        return SavedCapture(url: url, name: "synthetic", date: Date(), byteCount: size)
    }
}
