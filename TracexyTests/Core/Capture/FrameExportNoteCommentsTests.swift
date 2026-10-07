import Foundation
import Testing
@testable import Tracexy

// MARK: - FrameExportNoteCommentsTests

/// Export Frames… can carry the investigator's notes as PCAPNG capture comments:
/// written into the section header, bounded, readable by Wireshark, limited to the
/// exported sessions, and never forced into classic PCAP.
@MainActor
struct FrameExportNoteCommentsTests {
    @Test
    func commentsAreWrittenBoundedAndReadable() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("note-comments-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let source = directory.appendingPathComponent("conv.pcap")
        try Data(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())).write(to: source)

        let long = String(repeating: "é", count: 9_000) // 18,000 UTF-8 bytes
        var options = FrameExportOptions(format: .pcapng)
        options.captureComments = ["Tracexy note on api.example.test: slow handshake", long]
        let output = directory.appendingPathComponent("out.pcapng")
        _ = try CaptureFrameExporter.export(from: source, scope: .wholeCapture, options: options, to: output)
        let section = try #require(try SavedCaptureStreamLoader(contentsOf: output).load().properties.sections.first)
        let comments = section.comments.values.map(\.text)
        #expect(comments.first == "Tracexy note on api.example.test: slow handshake")
        // Cut at a character boundary within the byte bound.
        #expect(comments.count == 2)
        #expect(comments.last
            .map { $0.utf8.count <= FrameExportOptions.maximumCommentBytes && $0.allSatisfy { $0 == "é" } } == true)

        if WiresharkOracle.isAvailable {
            let report = try WiresharkOracle.capinfos(output)
            #expect(report["Capture comment"] == "Tracexy note on api.example.test: slow handshake")
        }

        // Classic PCAP has nowhere to put them and is written as before.
        let classic = directory.appendingPathComponent("out.pcap")
        var classicOptions = options
        classicOptions.format = .pcap
        _ = try CaptureFrameExporter.export(from: source, scope: .wholeCapture, options: classicOptions, to: classic)
        #expect(try SavedCaptureStreamLoader(contentsOf: classic).load().format == .pcap)
    }

    @Test
    func aSessionNoteLandsOnItsFirstExportedFrameOnly() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("frame-comments-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let source = directory.appendingPathComponent("conv.pcap")
        try Data(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())).write(to: source)
        let sessions = try SavedCaptureStreamLoader(contentsOf: source).load().sessions
        let noted = try #require(sessions.first { $0.protocolStack.contains(.tcp) })

        var options = FrameExportOptions(format: .pcapng)
        options.sessionFrameComments = [noted.id: "Tracexy note: server resets after login"]
        let output = directory.appendingPathComponent("noted.pcapng")
        _ = try CaptureFrameExporter.export(from: source, scope: .wholeCapture, options: options, to: output)
        let loaded = try SavedCaptureStreamLoader(contentsOf: output).load()
        #expect(loaded.properties.commentedFrameCount == 1)
        #expect(loaded.sessions.map(\.id) == sessions.map(\.id))

        if WiresharkOracle.isAvailable {
            let rows = try WiresharkOracle.tsharkFields(
                output,
                fields: ["frame.number", "frame.comment"],
                filter: "frame.comment"
            )
            #expect(rows.count == 1)
            #expect(rows.first?.last == "Tracexy note: server resets after login")
            let first = try WiresharkOracle.tsharkFields(
                output, fields: ["frame.number"], filter: "tcp.port == \(noted.sourceEndpointValue?.port ?? 0)"
            ).first?.first
            #expect(rows.first?.first == first)
        }

        // A source frame comment is kept beside the note.
        let showcase = directory.appendingPathComponent("showcase.pcapng")
        try Data(CaptureContainerFixtures.showcasePcapng()).write(to: showcase)
        let showcaseSessions = try SavedCaptureStreamLoader(contentsOf: showcase).load().sessions
        var preserving = FrameExportOptions(format: .pcapng, preservesMetadata: true)
        preserving.sessionFrameComments = Dictionary(uniqueKeysWithValues: showcaseSessions.map { ($0.id, "note") })
        let both = directory.appendingPathComponent("both.pcapng")
        let summary = try CaptureFrameExporter.export(
            from: showcase,
            scope: .wholeCapture,
            options: preserving,
            to: both
        )
        #expect(summary.omittedFrameOptionCount == 0)
        let sourceCommented = try SavedCaptureStreamLoader(contentsOf: showcase).load().properties.commentedFrameCount
        #expect(try SavedCaptureStreamLoader(contentsOf: both).load().properties.commentedFrameCount >= sourceCommented)
    }

    @Test
    func aNoteWaitsForTheSessionsFirstTimedFrame() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("untimed-note-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let bytes = PacketBuilder.ethernetIPv4(
            proto: 6, src: "10.0.0.5", dst: "192.0.2.80",
            payload: PacketBuilder.tcp(srcPort: 50_000, dstPort: 80, flags: 0x18, payload: [1, 2, 3])
        )
        let source = directory.appendingPathComponent("mixed.pcapng")
        try PcapngWriter.write(
            defaultLinkType: LinkType.ethernet,
            frames: [
                CapturedFrame(bytes: bytes, timestamp: nil, originalLength: bytes.count),
                CapturedFrame(
                    bytes: bytes,
                    timestamp: Date(timeIntervalSince1970: 1_800_000_000),
                    originalLength: bytes.count
                ),
            ],
            to: source
        )
        let session = try #require(try SavedCaptureStreamLoader(contentsOf: source).load().sessions.first)
        var options = FrameExportOptions(format: .pcapng)
        options.sessionFrameComments = [session.id: "Tracexy note: kept"]
        let output = directory.appendingPathComponent("out.pcapng")
        _ = try CaptureFrameExporter.export(from: source, scope: .wholeCapture, options: options, to: output)
        #expect(try SavedCaptureStreamLoader(contentsOf: output).load().properties.commentedFrameCount == 1)
    }

    @Test
    func coordinatorWritesTheNotesOfTheExportedSessions() async throws {
        let environment = ProjectIsolationEnvironment(name: "note-comments")
        defer { environment.tearDown() }
        let directory = environment.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("conv.pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: ReplayCorpus.conversationCapturedFrames(), to: url)
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let size = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        coordinator.openSavedCapture(SavedCapture(url: url, name: "conv", date: Date(), byteCount: size))
        await coordinator.waitForSavedCaptureOpen()
        await coordinator.waitForInvestigationNoteScope()

        let noted = try #require(coordinator.presentedSessions.first { $0.protocolStack.contains(.tcp) })
        let other = try #require(coordinator.presentedSessions.first { $0.id != noted.id })
        #expect(coordinator.investigationNotes.setText("Server resets after login", for: .session(noted.id)))

        let all = coordinator.frameExportNoteComments(for: .wholeCapture)
        #expect(all ==
            [
                "Tracexy note on \(noted.host) (\(noted.sourceEndpoint) to \(noted.destinationEndpoint)): Server resets after login"
            ])
        #expect(coordinator.frameExportNoteComments(for: .sessions([other.id])).isEmpty)
        #expect(coordinator.frameExportContext(preselectedSessions: nil).noteCount == 1)

        let output = directory.appendingPathComponent("with-notes.pcapng")
        coordinator.exportFrames(to: output, scope: .wholeCapture, options: .init(format: .pcapng), includesNotes: true)
        await coordinator.waitForFrameExport()
        let exported = try SavedCaptureStreamLoader(contentsOf: output).load()
        let section = try #require(exported.properties.sections.first)
        #expect(section.comments.values.map(\.text) == all)
        #expect(exported.properties.commentedFrameCount == 1)
        #expect(coordinator.frameExportSessionFrameComments() == [noted.id: "Tracexy note: Server resets after login"])

        let plain = directory.appendingPathComponent("without-notes.pcapng")
        coordinator.exportFrames(to: plain, scope: .wholeCapture, options: .init(format: .pcapng))
        await coordinator.waitForFrameExport()
        let plainSection = try #require(try SavedCaptureStreamLoader(contentsOf: plain).load().properties.sections
            .first)
        #expect(plainSection.comments.values.isEmpty)
    }
}
