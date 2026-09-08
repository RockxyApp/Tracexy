import Foundation
import Testing
@testable import Tracexy

// MARK: - SourceRaceGate

private actor SourceRaceGate {
    // MARK: Internal

    func pause() async {
        entered = true
        entry?.resume()
        entry = nil
        await withCheckedContinuation { completion = $0 }
    }

    func waitForEntry() async {
        if !entered {
            await withCheckedContinuation { entry = $0 }
        }
    }

    func release() {
        completion?.resume()
        completion = nil
    }

    // MARK: Private

    private var entered = false
    private var entry: CheckedContinuation<Void, Never>?
    private var completion: CheckedContinuation<Void, Never>?
}

// MARK: - ProjectSourceRaceTests

@MainActor
@Suite("Project reverse-order source races")
struct ProjectSourceRaceTests {
    // MARK: Internal

    @Test("Cancelling an import keeps its hold until cleanup and preserves the open capture")
    func importCancellationPreservesEvidence() async throws {
        let environment = ProjectIsolationEnvironment(name: "import-cancel")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let directory = try #require(coordinator.capturesDirectory())
        let original = try fixture("original", frames: SampleCapture.frames(now: Date()), directory: directory)
        coordinator.openSavedCapture(original)
        await coordinator.waitForSavedCaptureOpen()
        let oldIDs = coordinator.sessions.map(\.id)
        let gate = SourceRaceGate()
        coordinator.captureImportOperation = CaptureImportOperation { _, _, progress in
            progress(PcapStreamProgress(bytesConsumed: 1, totalBytes: 10))
            await gate.pause()
            try Task.checkCancellation()
            throw CocoaError(.fileReadUnknown)
        }
        coordinator.importCapture(from: original.url)
        await gate.waitForEntry()
        #expect(coordinator.isImportingCapture)
        #expect(coordinator.isCaptureSourceHeld)
        #expect(!coordinator.canSaveCapture)
        #expect(!coordinator.canExport())
        coordinator.beginSessionSearch()
        #expect(coordinator.activeWorkspace.searchFocusRequest != nil)
        coordinator.clearSessions()
        #expect(coordinator.sessions.map(\.id) == oldIDs)
        coordinator.cancelCaptureImport()
        #expect(coordinator.isCaptureSourceHeld)
        await gate.release()
        await coordinator.waitForCaptureImport()
        #expect(!coordinator.isCaptureSourceHeld)
        #expect(coordinator.captureError == nil)
        #expect(coordinator.activeSavedCapture?.url == original.url)
        #expect(coordinator.sessions.map(\.id) == oldIDs)
        #expect(coordinator.savedCaptures.count == 1)
        await coordinator.waitForHistory()
    }

    @Test("Project transition waits for import but never opens its result in the incoming Project")
    func projectSwitchWaitsForImport() async throws {
        let environment = ProjectIsolationEnvironment(name: "import-project-drain")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let originalProject = try #require(coordinator.activeRuntime.projectID)
        let library = try #require(coordinator.capturesDirectory())
        let external = try fixture(
            "incoming",
            frames: SampleCapture.frames(now: Date()),
            directory: environment.root.appendingPathComponent("Input")
        )
        let gate = SourceRaceGate()
        coordinator.captureImportOperation = CaptureImportOperation { source, directory, progress in
            await gate.pause()
            return try await CaptureImportOperation.copy.run(source, directory, progress)
        }
        coordinator.importCapture(from: external.url)
        await gate.waitForEntry()
        _ = try #require(coordinator.createProject(named: "Incoming Project"))
        #expect(coordinator.projectTransitionStatus.isPending)
        #expect(coordinator.activeRuntime.projectID == originalProject)
        await gate.release()
        #expect(await coordinator.waitForProjectTransition())
        #expect(coordinator.activeRuntime.projectID != originalProject)
        #expect(coordinator.savedCaptures.isEmpty)
        #expect(!coordinator.isViewingSavedCapture)
        #expect(try Data(contentsOf: library.appendingPathComponent("incoming.pcap")) == Data(contentsOf: external.url))
        await coordinator.waitForHistory()
    }

    @Test("Import failure preserves current evidence and releases the source hold")
    func failedImportPreservesEvidence() async throws {
        let environment = ProjectIsolationEnvironment(name: "import-error")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let original = try fixture(
            "original",
            frames: SampleCapture.frames(now: Date()),
            directory: #require(coordinator.capturesDirectory())
        )
        coordinator.openSavedCapture(original)
        await coordinator.waitForSavedCaptureOpen()
        let oldIDs = coordinator.sessions.map(\.id)
        coordinator
            .captureImportOperation = CaptureImportOperation { _, _, _ in throw CocoaError(.fileWriteOutOfSpace) }
        coordinator.importCapture(from: original.url)
        await coordinator.waitForCaptureImport()
        #expect(coordinator.captureError?.contains("Couldn’t import") == true)
        #expect(coordinator.sessions.map(\.id) == oldIDs)
        #expect(coordinator.activeSavedCapture?.url == original.url)
        #expect(!coordinator.isImportingCapture)
        await coordinator.waitForHistory()
    }

    @Test("Save/export outcomes preserve Stop diagnostics and reject foreign Project errors")
    func captureIOOutcomesRespectSourceOwnership() async {
        let environment = ProjectIsolationEnvironment(name: "capture-io-outcomes")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let origin = coordinator.projectStore.activeProjectID
        let generation = coordinator.startGeneration
        coordinator.startGeneration &+= 1 // Publication-only Stop boundary.
        coordinator.captureError = "Stop diagnostic"
        coordinator.reportCaptureIOOutcome(
            failure: nil,
            warning: nil,
            didWrite: true,
            originProjectID: origin,
            originGeneration: generation
        )
        #expect(coordinator.captureError == "Stop diagnostic")
        coordinator.reportCaptureIOOutcome(
            failure: "Couldn’t export session",
            warning: nil,
            didWrite: false,
            originProjectID: origin,
            originGeneration: generation
        )
        #expect(coordinator.captureError == "Couldn’t export session")
        coordinator.reportCaptureIOOutcome(
            failure: nil,
            warning: "Incomplete exported prefix",
            didWrite: true,
            originProjectID: origin,
            originGeneration: generation
        )
        #expect(coordinator.captureError == "Incomplete exported prefix")
        coordinator.reportCaptureIOOutcome(
            failure: "Foreign error",
            warning: nil,
            didWrite: false,
            originProjectID: UUID(),
            originGeneration: coordinator.startGeneration
        )
        #expect(coordinator.captureError == "Incomplete exported prefix")
        coordinator.reportCaptureIOOutcome(
            failure: nil,
            warning: nil,
            didWrite: true,
            originProjectID: origin,
            originGeneration: coordinator.startGeneration
        )
        #expect(coordinator.captureError == nil)
    }

    @Test("A Save failure remains visible when Stop advances the same capture's generation")
    func failedSaveIsReportedAcrossStop() async {
        let environment = ProjectIsolationEnvironment(name: "save-stop-failure")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        coordinator.resetSessionEngineForSavedCapture(token: coordinator.startGeneration)
        await coordinator.ingestChain?.value
        coordinator.isCapturing = true
        coordinator.ingest(SampleCapture.frames(now: Date()), linkType: LinkType.ethernet)
        await coordinator.ingestChain?.value
        let gate = SourceRaceGate()
        coordinator.captureSaveOperation = CaptureSaveOperation { _, _, _ in
            await gate.pause()
            throw CocoaError(.fileWriteUnknown)
        }
        coordinator.saveCurrentCapture()
        await gate.waitForEntry()
        let save = coordinator.pendingCaptureIOTask
        let generation = coordinator.startGeneration
        // This takes the real local Stop boundary without reaching a helper proxy.
        coordinator.prepareForDestructiveHelperReset()
        await coordinator.ingestChain?.value
        #expect(coordinator.startGeneration != generation)
        await gate.release()
        await save?.value
        #expect(!coordinator.isCaptureSourceHeld)
        #expect(coordinator.captureError?.contains("Couldn’t save") == true)
    }

    @Test("Stop-and-Switch confirmation rechecks an export started while confirmation was open")
    func confirmationCannotBypassExportHold() async {
        let environment = ProjectIsolationEnvironment(name: "confirmation-export-hold")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let projectA = coordinator.projectStore.activeProjectID
        coordinator.isCapturing = true // State only; no backend or network is started.
        _ = coordinator.createProject(named: "Bravo")
        #expect(coordinator.pendingProjectSwitchConfirmation != nil)
        // Model Stop having completed while the confirmation remains open, then
        // an export taking the source before the old confirmation is accepted.
        coordinator.isCapturing = false
        coordinator.setSessionExporting(true)
        defer { coordinator.setSessionExporting(false) }
        coordinator.confirmPendingProjectSwitch()
        _ = await coordinator.projectTransitionTask?.value
        #expect(coordinator.projectStore.activeProjectID == projectA)
        #expect(coordinator.projectTransitionStatus.failureMessage != nil)
        #expect(coordinator.retryableProjectTransition != nil)
        coordinator.setSessionExporting(false)
        coordinator.retryProjectTransition()
        #expect(await coordinator.waitForProjectTransition())
        #expect(coordinator.projectStore.activeProjectID != projectA)
    }

    @Test("A loader started before Save cannot replace the source at late adoption")
    func lateOpenCannotReplaceSavingSource() async throws {
        let environment = ProjectIsolationEnvironment(name: "reverse-open-save")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let directory = try #require(coordinator.capturesDirectory())
        let original = try fixture("original", frames: SampleCapture.frames(now: Date()), directory: directory)
        let replacement = try fixture(
            "replacement",
            frames: Array(SampleCapture.frames(now: Date()).prefix(2)),
            directory: directory
        )
        coordinator.openSavedCapture(original)
        await coordinator.waitForCaptureImport()
        await coordinator.waitForSavedCaptureOpen()
        await coordinator.waitForHistory()
        let ids = coordinator.sessions.map(\.id)
        let result = try SavedCaptureStreamLoader(contentsOf: replacement.url).load()
        let loaderGate = SourceRaceGate()
        let saveGate = SourceRaceGate()
        coordinator.savedCaptureLoadOperation = SavedCaptureLoadOperation { _, _, _ in
            await loaderGate.pause()
            return result
        }
        coordinator.captureSaveOperation = CaptureSaveOperation { source, spool, destination in
            await saveGate.pause()
            try await CaptureSaveOperation.copy.run(source, spool, destination)
        }
        coordinator.openSavedCapture(replacement)
        await loaderGate.waitForEntry()
        let loader = coordinator.savedCaptureOpenTask
        coordinator.saveCurrentCapture()
        await saveGate.waitForEntry()
        let save = coordinator.pendingCaptureIOTask
        let generation = coordinator.startGeneration
        await loaderGate.release()
        await loader?.value
        #expect(coordinator.activeSavedCapture == original)
        #expect(coordinator.sessions.map(\.id) == ids)
        #expect(coordinator.startGeneration == generation)
        #expect(!coordinator.isOpeningSavedCapture)
        #expect(coordinator.isCaptureSourceHeld)
        await saveGate.release()
        await save?.value
        #expect(!coordinator.isCaptureSourceHeld)
        let saved = try #require(coordinator.savedCaptures.first { $0.name.hasPrefix("Capture ") })
        #expect(try Data(contentsOf: saved.url) == Data(contentsOf: original.url))
    }

    @Test("Import cannot replace a Library source while an accepted Save reads it")
    func importCollisionCannotReplaceSavingSource() async throws {
        let environment = ProjectIsolationEnvironment(name: "import-save-collision")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let directory = try #require(coordinator.capturesDirectory())
        let original = try fixture("collision", frames: SampleCapture.frames(now: Date()), directory: directory)
        let external = try fixture(
            "collision",
            frames: Array(SampleCapture.frames(now: Date()).prefix(2)),
            directory: environment.root.appendingPathComponent("Import")
        )
        let bytes = try Data(contentsOf: original.url)
        coordinator.openSavedCapture(original)
        await coordinator.waitForCaptureImport()
        await coordinator.waitForSavedCaptureOpen()
        await coordinator.waitForHistory()
        let gate = SourceRaceGate()
        coordinator.captureSaveOperation = CaptureSaveOperation { source, spool, destination in
            await gate.pause()
            try await CaptureSaveOperation.copy.run(source, spool, destination)
        }
        coordinator.saveCurrentCapture()
        await gate.waitForEntry()
        let save = coordinator.pendingCaptureIOTask
        coordinator.importCapture(from: external.url)
        #expect(coordinator.captureError == coordinator.captureSourceHoldMessage)
        #expect(try Data(contentsOf: original.url) == bytes)
        #expect(coordinator.activeSavedCapture == original)
        await gate.release()
        await save?.value
        let saved = try #require(coordinator.savedCaptures.first { $0.name.hasPrefix("Capture ") })
        #expect(try Data(contentsOf: saved.url) == bytes)
    }

    @Test("An import panel opened in one Project never files its capture into another")
    func importRefusesAfterTheOriginProjectChanged() async throws {
        let environment = ProjectIsolationEnvironment(name: "import-panel-origin")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let origin = try #require(coordinator.activeRuntime.projectID)
        let external = try fixture(
            "panel-origin",
            frames: SampleCapture.frames(now: Date()),
            directory: environment.root.appendingPathComponent("Import")
        )

        // The panel is modal: the user opened it in the first Project and switched
        // Projects before choosing a file.
        _ = try #require(coordinator.createProject(named: "Second"))
        #expect(await coordinator.waitForProjectTransition())
        #expect(coordinator.activeRuntime.projectID != origin)

        coordinator.importCapture(from: external.url, originProjectID: origin)

        // Refused with a reason, and nothing landed in the Project now on screen.
        #expect(coordinator.captureError?.contains("switched Projects") == true)
        coordinator.refreshSavedCaptures()
        #expect(coordinator.savedCaptures.isEmpty)
        #expect(!coordinator.isViewingSavedCapture)

        // A fresh import started in this Project still works normally.
        coordinator.importCapture(from: external.url, originProjectID: coordinator.activeRuntime.projectID)
        await coordinator.waitForCaptureImport()
        await coordinator.waitForSavedCaptureOpen()
        await coordinator.waitForHistory()
        #expect(coordinator.savedCaptures.map(\.name) == ["panel-origin"])
    }

    @Test("A failed Save releases its source hold and permits an explicit retry")
    func failedSaveReleasesHold() async throws {
        let environment = ProjectIsolationEnvironment(name: "failed-save-unlock")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let original = try fixture(
            "original",
            frames: SampleCapture.frames(now: Date()),
            directory: #require(coordinator.capturesDirectory())
        )
        coordinator.openSavedCapture(original)
        await coordinator.waitForCaptureImport()
        await coordinator.waitForSavedCaptureOpen()
        await coordinator.waitForHistory()
        coordinator.captureSaveOperation = CaptureSaveOperation { _, _, _ in throw CocoaError(.fileWriteUnknown) }
        coordinator.saveCurrentCapture()
        await coordinator.pendingCaptureIOTask?.value
        #expect(!coordinator.isCaptureSourceHeld)
        #expect(coordinator.captureStartBlockedMessage == nil)
        #expect(coordinator.captureError?.contains("Couldn’t save") == true)
        coordinator.captureSaveOperation = .copy
        coordinator.saveCurrentCapture()
        await coordinator.pendingCaptureIOTask?.value
        #expect(coordinator.captureError == nil)
        #expect(coordinator.savedCaptures.count == 2)
    }

    // MARK: Private

    private func fixture(_ name: String, frames: [CapturedFrame], directory: URL) throws -> SavedCapture {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("\(name).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        return try SavedCapture(url: url, name: name, date: Date(), byteCount: Data(contentsOf: url).count)
    }
}
