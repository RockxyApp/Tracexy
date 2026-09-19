import Foundation
import Testing
@testable import Tracexy

// MARK: - CaptureSourceWorkflowTests

/// File ▸ Open… in place, references in the Library, unavailable sources with
/// Locate…/Reload, Finder/drop routing, Open Recent, Close Capture and Reload.
@MainActor
@Suite("Capture sources: open in place, references, recents")
struct CaptureSourceWorkflowTests {
    // MARK: Internal

    @Test("Open in place records a reference and opens without copying")
    func openInPlaceCreatesReference() async throws {
        let env = try await makeEnvironment()
        defer { env.tearDown() }
        let source = try env.externalCapture("outside")
        env.coordinator.openExternalCapture(source, copiesIntoLibrary: false)
        await env.coordinator.waitForExternalCaptureOpen()

        #expect(env.coordinator.captureError == nil)
        #expect(env.coordinator.isViewingSavedCapture)
        #expect(env.coordinator.activeSavedCapture?.url.standardizedFileURL == source.standardizedFileURL)
        #expect(env.coordinator.activeSavedCapture?.isReferenced == true)
        #expect(env.coordinator.savedCaptures.count == 1)
        #expect(env.coordinator.savedCaptures[0].availability == .available)
        let directory = try #require(env.coordinator.capturesDirectory())
        let contents = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        #expect(contents == ["outside.tracexyref"])
        #expect(env.coordinator.savedCaptureProperties?.totalFrames == env.coordinator.savedCaptureMetadata?
            .totalFrames)
        #expect(env.coordinator.recentCaptureURLs.first?.standardizedFileURL == source.standardizedFileURL)
    }

    @Test("Opening the same file again reuses the reference")
    func reopeningReusesReference() async throws {
        let env = try await makeEnvironment()
        defer { env.tearDown() }
        let source = try env.externalCapture("twice")
        env.coordinator.openExternalCapture(source, copiesIntoLibrary: false)
        await env.coordinator.waitForExternalCaptureOpen()
        env.coordinator.openExternalCapture(source, copiesIntoLibrary: false)
        await env.coordinator.waitForExternalCaptureOpen()
        #expect(env.coordinator.savedCaptures.count == 1)
    }

    @Test("Copy into Library keeps the managed import path")
    func copyIntoLibraryImports() async throws {
        let env = try await makeEnvironment()
        defer { env.tearDown() }
        let source = try env.externalCapture("copied")
        env.coordinator.openExternalCapture(source, copiesIntoLibrary: true)
        await env.coordinator.waitForExternalCaptureOpen()
        #expect(env.coordinator.savedCaptures.count == 1)
        #expect(env.coordinator.savedCaptures[0].isReferenced == false)
        #expect(env.coordinator.savedCaptures[0].url.pathExtension == "pcap")
        #expect(env.coordinator.activeSavedCapture?.isReferenced == false)
    }

    @Test("Finder and drop route through the Project's open preference")
    func finderOpenHonoursPreference() async throws {
        let env = try await makeEnvironment()
        defer { env.tearDown() }
        let source = try env.externalCapture("finder")
        #expect(env.coordinator.copiesOpenedCapturesIntoLibrary == false)
        env.coordinator.importExternalCaptures([source])
        await env.coordinator.waitForExternalCaptureOpen()
        #expect(env.coordinator.activeSavedCapture?.isReferenced == true)

        env.coordinator.closeCapture()
        env.coordinator.copiesOpenedCapturesIntoLibrary = true
        let other = try env.externalCapture("finder-copy")
        env.coordinator.importExternalCaptures([other])
        await env.coordinator.waitForExternalCaptureOpen()
        #expect(env.coordinator.activeSavedCapture?.isReferenced == false)
        #expect(env.coordinator.savedCaptures.count == 2)
    }

    @Test("A gzip source always expands into a managed capture")
    func compressedSourceIsImported() async throws {
        let env = try await makeEnvironment()
        defer { env.tearDown() }
        let plain = try env.externalCapture("plain")
        let gz = plain.deletingLastPathComponent().appendingPathComponent("plain.pcap.gz")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/gzip")
        process.arguments = ["-k", "-f", plain.path]
        try process.run()
        process.waitUntilExit()
        #expect(process.terminationStatus == 0)
        env.coordinator.openExternalCapture(gz, copiesIntoLibrary: false)
        await env.coordinator.waitForExternalCaptureOpen()
        #expect(env.coordinator.captureError == nil)
        #expect(env.coordinator.activeSavedCapture?.isReferenced == false)
        #expect(env.coordinator.savedCaptures.count == 1)
    }

    @Test("A missing referenced file is an unavailable state, not an error, and Locate restores it")
    func missingReferenceOffersLocate() async throws {
        let env = try await makeEnvironment()
        defer { env.tearDown() }
        let source = try env.externalCapture("mover")
        env.coordinator.openExternalCapture(source, copiesIntoLibrary: false)
        await env.coordinator.waitForExternalCaptureOpen()
        let sessionIDs = env.coordinator.sessions.map(\.id)
        env.coordinator.closeCapture()

        let moved = source.deletingLastPathComponent().appendingPathComponent("elsewhere")
            .appendingPathComponent("mover.pcap")
        try FileManager.default.createDirectory(
            at: moved.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try FileManager.default.moveItem(at: source, to: moved)
        env.coordinator.refreshSavedCaptures()
        let item = try #require(env.coordinator.savedCaptures.first)
        #expect(item.availability == .missing)
        #expect(!item.isReadable)

        env.coordinator.openSavedCapture(item)
        await env.coordinator.waitForSavedCaptureOpen()
        #expect(env.coordinator.unavailableReferencedCapture?.id == item.id)
        #expect(env.coordinator.captureError == nil)
        #expect(!env.coordinator.isViewingSavedCapture)

        // Locate with the moved file (the panel is bypassed; the validation and
        // relocation are the same code the panel route calls).
        let reference = try #require(item.reference)
        guard case let .relocated(identity) = reference.match(candidate: moved) else {
            Issue.record("expected relocated")
            return
        }
        try reference.relocated(to: moved, identity: identity).write(to: #require(item.sidecarURL))
        env.coordinator.unavailableReferencedCapture = nil
        env.coordinator.refreshSavedCaptures()
        let relocated = try #require(env.coordinator.savedCaptures.first)
        #expect(relocated.availability == .available)
        #expect(relocated.id == item.id)
        env.coordinator.openSavedCapture(relocated)
        await env.coordinator.waitForSavedCaptureOpen()
        #expect(env.coordinator.sessions.map(\.id) == sessionIDs)
    }

    @Test("A file replaced on disk enables Reload and reload re-reads it")
    func changedFileEnablesReload() async throws {
        let env = try await makeEnvironment()
        defer { env.tearDown() }
        let source = try env.externalCapture("changer")
        env.coordinator.openExternalCapture(source, copiesIntoLibrary: false)
        await env.coordinator.waitForExternalCaptureOpen()
        let before = env.coordinator.sessions.count
        #expect(!env.coordinator.canReloadActiveSavedCapture)

        // Replace with a different capture (more sessions), ensuring a distinct mtime.
        try Data(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation() + ReplayCorpus.tcpConnectionFrames()))
            .write(to: source)
        try FileManager.default.setAttributes(
            [.modificationDate: Date(timeIntervalSinceNow: 5)], ofItemAtPath: source.path
        )
        env.coordinator.noteActiveSavedCaptureAvailability()
        #expect(env.coordinator.activeSavedCaptureChangedOnDisk)
        #expect(env.coordinator.canReloadActiveSavedCapture)

        env.coordinator.reloadActiveSavedCapture()
        await env.coordinator.waitForSavedCaptureOpen()
        #expect(env.coordinator.sessions.count > before)
        #expect(env.coordinator.savedCaptures.first?.availability == .available)
        #expect(!env.coordinator.canReloadActiveSavedCapture)
    }

    @Test("Removing a reference trashes only the sidecar")
    func removeReferenceKeepsFile() async throws {
        let env = try await makeEnvironment()
        defer { env.tearDown() }
        let source = try env.externalCapture("keeper")
        env.coordinator.openExternalCapture(source, copiesIntoLibrary: false)
        await env.coordinator.waitForExternalCaptureOpen()
        let item = try #require(env.coordinator.savedCaptures.first)
        try env.coordinator.removeReferencedCapture(item)
        #expect(env.coordinator.savedCaptures.isEmpty)
        #expect(FileManager.default.fileExists(atPath: source.path))
        #expect(!env.coordinator.isViewingSavedCapture)
    }

    @Test("Close Capture and Reload availability follow the workspace state")
    func closeAndReloadAvailability() async throws {
        let env = try await makeEnvironment()
        defer { env.tearDown() }
        #expect(!env.coordinator.canCloseCapture)
        #expect(!env.coordinator.canReloadActiveSavedCapture)
        let source = try env.externalCapture("closer")
        env.coordinator.openExternalCapture(source, copiesIntoLibrary: false)
        await env.coordinator.waitForExternalCaptureOpen()
        #expect(env.coordinator.canCloseCapture)
        env.coordinator.closeCapture()
        #expect(!env.coordinator.isViewingSavedCapture)
        #expect(env.coordinator.sessions.isEmpty)
        #expect(!env.coordinator.canCloseCapture)
    }

    @Test("Open Recent refuses a vanished file with a message and keeps the list fresh")
    func openRecentMissingFile() async throws {
        let env = try await makeEnvironment()
        defer { env.tearDown() }
        let ghost = env.root.appendingPathComponent("ghost.pcap")
        env.coordinator.openRecentCapture(ghost)
        #expect(env.coordinator.captureError?.contains("ghost.pcap") == true)
    }

    // MARK: Private

    @MainActor
    private struct Environment {
        let coordinator: MainContentCoordinator
        let root: URL
        let isolation: ProjectIsolationEnvironment

        func externalCapture(_ name: String) throws -> URL {
            let url = root.appendingPathComponent("\(name).pcap")
            try Data(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())).write(to: url)
            return url
        }

        func tearDown() {
            coordinator.clearRecentCaptures()
            isolation.tearDown()
            try? FileManager.default.removeItem(at: root)
        }
    }

    private func makeEnvironment(function: String = #function) async throws -> Environment {
        let isolation = ProjectIsolationEnvironment(name: function)
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-sources-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        coordinator.clearRecentCaptures()
        return Environment(coordinator: coordinator, root: root, isolation: isolation)
    }
}
