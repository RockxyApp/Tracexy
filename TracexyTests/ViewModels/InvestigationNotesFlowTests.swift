import Foundation
import Testing
@testable import Tracexy

// MARK: - InvestigationNotesFlowTests

/// End to end through the coordinator: a note written on an opened capture stays
/// with that capture's content, stays inside its Project, survives a relaunch, does
/// not appear on a different capture with the same session, and travels in the
/// session export.
@MainActor
@Suite("Investigation notes")
struct InvestigationNotesFlowTests {
    // MARK: Internal

    @Test("A note stays with its capture and its Project, and survives relaunch")
    func notesFollowCaptureAndProject() async throws {
        let environment = ProjectIsolationEnvironment(name: "notes", persistsCatalog: true)
        defer { environment.tearDown() }
        let directory = environment.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let first = try Self.write("first", frames: frames, in: directory)
        // The same conversation plus one unrelated frame: same session ids, other content.
        let second = try Self.write(
            "second",
            frames: frames + [CapturedFrame(
                bytes: PacketBuilder.dnsQueryFrame(name: "x.example.test", src: "10.9.9.9", dst: "192.0.2.53"),
                timestamp: Date(timeIntervalSince1970: 2_000),
                originalLength: 74,
                linkType: LinkType.ethernet
            )],
            in: directory
        )

        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        #expect(coordinator.investigationNotesUnavailableReason != nil)

        let session = try await Self.open(first, in: coordinator)
        let target = InvestigationNoteTarget.session(session)
        #expect(coordinator.investigationNotesUnavailableReason == nil)
        #expect(coordinator.investigationNotes.setText("Handshake looks slow here", for: target))

        // Another capture with the same session id shows nothing of it.
        #expect(try await Self.open(second, in: coordinator) == session)
        #expect(coordinator.investigationNotes.text(for: target).isEmpty)
        #expect(!coordinator.investigationNotes.hasNote(onSession: session))

        // Another Project shows nothing of it, even on the same file.
        let projectA = coordinator.projectStore.activeProjectID
        #expect(coordinator.createProject(named: "Second") != nil)
        #expect(await coordinator.waitForProjectTransition())
        _ = try await Self.open(first, in: coordinator)
        #expect(coordinator.investigationNotes.text(for: target).isEmpty)

        #expect(coordinator.switchToProject(id: projectA))
        #expect(await coordinator.waitForProjectTransition())
        await coordinator.flushProjectStateForTermination()

        // "Relaunch" and reopen the first file: the note is back.
        let relaunched = environment.makeCoordinator()
        await relaunched.hydrateProjectsOnLaunch()
        if relaunched.projectStore.activeProjectID != projectA {
            #expect(relaunched.switchToProject(id: projectA))
            #expect(await relaunched.waitForProjectTransition())
        }
        _ = try await Self.open(first, in: relaunched)
        #expect(relaunched.investigationNotes.text(for: target) == "Handshake looks slow here")
    }

    @Test("A session export carries the notes on that session and says they are unmasked")
    func exportCarriesNotes() throws {
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let session = try #require(SessionBuilder.build(from: frames, linkType: LinkType.ethernet).first)
        let notes = [
            SessionExportNote(subject: "session", findingTitle: nil, text: "Check the proxy", updatedAt: .init()),
            SessionExportNote(
                subject: "finding", findingTitle: "TCP reset observed", text: "Expected", updatedAt: .init()
            ),
        ]

        let plain = try Self.json(SessionExporter.artifact(
            for: session, frames: frames, defaultLinkType: LinkType.ethernet, format: .session, notes: notes
        ))
        let exported = try #require(plain["notes"] as? [[String: Any]])
        #expect(exported.map { $0["text"] as? String } == ["Check the proxy", "Expected"])
        #expect(exported.last?["findingTitle"] as? String == "TCP reset observed")

        let protected = try Self.json(SessionExporter.artifact(
            for: session, frames: frames, defaultLinkType: LinkType.ethernet, format: .session,
            privacy: SessionExportPrivacyPolicy(
                redactPayloadBodies: true,
                stripCredentials: true,
                maskIPAddresses: true
            ),
            notes: notes
        ))
        #expect((protected["notes"] as? [[String: Any]])?.count == 2)
        #expect((protected["privacy"] as? [String: Any])?["includesInvestigationNotes"] as? Bool == true)

        // Without notes the document is exactly what it was before notes existed.
        let bare = try Self.json(SessionExporter.artifact(
            for: session, frames: frames, defaultLinkType: LinkType.ethernet, format: .session,
            privacy: SessionExportPrivacyPolicy(
                redactPayloadBodies: true,
                stripCredentials: true,
                maskIPAddresses: true
            )
        ))
        #expect(bare["notes"] == nil)
        #expect((bare["privacy"] as? [String: Any])?["includesInvestigationNotes"] == nil)
    }

    @Test("Saving a live run's capture carries its notes to the file")
    func liveNotesFollowTheSavedFile() async throws {
        let environment = ProjectIsolationEnvironment(name: "notes-live")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let directory = environment.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let saved = try Self.write("saved-run", frames: ReplayCorpus.tcpConnectionCapturedFrames(), in: directory)

        coordinator.beginLiveHistoryLifetime(captureGeneration: coordinator.startGeneration)
        let live = try #require(coordinator.investigationNotes.scope)
        #expect(live.isLiveRun)
        let session = UUID()
        coordinator.investigationNotes.setText("noted while capturing", for: .session(session))

        let projectID = try #require(coordinator.activeRuntime.projectID)
        coordinator.carryInvestigationNotes(from: live, toCaptureAt: saved.url, projectID: projectID)
        await coordinator.waitForInvestigationNoteScope()
        let fileScope = try InvestigationNoteScope.capture(at: saved.url)
        #expect(coordinator.investigationNotes.text(for: .session(session), in: fileScope) == "noted while capturing")
        #expect(!coordinator.investigationNotes.notes.contains { $0.scope == live })
    }

    // MARK: Private

    private static func write(_ name: String, frames: [CapturedFrame], in directory: URL) throws -> SavedCapture {
        let url = directory.appendingPathComponent("\(name).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        let byteCount = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        return SavedCapture(url: url, name: name, date: Date(), byteCount: byteCount)
    }

    /// Open `capture`, wait for its notes scope, and return its TCP session id.
    private static func open(_ capture: SavedCapture, in coordinator: MainContentCoordinator) async throws -> UUID {
        coordinator.openSavedCapture(capture)
        await coordinator.waitForSavedCaptureOpen()
        await coordinator.waitForInvestigationNoteScope()
        #expect(coordinator.investigationNotes.scope != nil)
        let tuple = try #require(coordinator.connectionSnapshot.summaries.first?.tuple)
        return SessionBuilder.sessionID(for: tuple)
    }

    private static func json(_ artifact: SessionExportArtifact) throws -> [String: Any] {
        try #require(JSONSerialization.jsonObject(with: artifact.data) as? [String: Any])
    }
}
