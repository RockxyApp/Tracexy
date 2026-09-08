import Foundation
import Testing
@testable import Tracexy

@Suite("Portable project codec")
struct PortableProjectCodecTests {
    // MARK: Internal

    @Test("Round trip remains configuration-only and regenerates every identity")
    func roundTripRegeneratesIdentity() throws {
        let rule = ProjectFilterRuleSnapshot(value: "private.example")
        let workspace = ProjectWorkspaceSnapshot(
            title: "Review",
            filterText: "dns",
            filterRules: [rule]
        )
        let project = Project(
            name: "Portable",
            workspaces: [workspace],
            activeWorkspaceID: workspace.id
        )

        let data = try PortableProjectCodec.encode(project)
        let json = try #require(String(data: data, encoding: .utf8))
        for forbidden in ["capture", "payload", "filePath", "history", "selectedSession"] {
            #expect(!json.localizedCaseInsensitiveContains(forbidden))
        }

        let imported = try PortableProjectCodec.decode(data, now: Date(timeIntervalSince1970: 9))
        #expect(imported.id != project.id)
        #expect(imported.workspaces[0].id != workspace.id)
        #expect(imported.workspaces[0].filterRules[0].id != rule.id)
        #expect(imported.activeWorkspaceID == imported.workspaces[0].id)
        #expect(imported.name == "Portable")
        #expect(imported.createdAt == Date(timeIntervalSince1970: 9))
    }

    @Test("Oversized portable input is rejected before JSON decoding")
    func oversizedInputRejected() {
        let data = Data(count: ProjectLimits.maximumPortableProjectBytes + 1)
        #expect(throws: PortableProjectCodecError.documentTooLarge(
            limit: ProjectLimits.maximumPortableProjectBytes
        )) {
            _ = try PortableProjectCodec.decode(data)
        }
    }

    @Test("Document IO writes privately, reads bounded data and rejects symlinks")
    func safeDocumentIO() throws {
        let directory = Self.temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let workspace = ProjectWorkspaceSnapshot(title: "Live", isClosable: false)
        let project = Project(
            name: "Exported",
            workspaces: [workspace],
            activeWorkspaceID: workspace.id
        )
        let url = directory.appendingPathComponent("Exported.tracexyproject")
        try PortableProjectDocumentIO.write(project, to: url)
        #expect(try PortableProjectDocumentIO.read(from: url).name == "Exported")

        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)

        let link = directory.appendingPathComponent("Alias.tracexyproject")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: url)
        #expect(throws: PortableProjectCodecError.documentIsSymbolicLink) {
            _ = try PortableProjectDocumentIO.read(from: link)
        }
        #expect(throws: PortableProjectCodecError.documentIsSymbolicLink) {
            try PortableProjectDocumentIO.write(project, to: link)
        }
    }

    // MARK: Private

    private static func temporaryDirectory() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("portable-project-\(UUID().uuidString)", isDirectory: true)
    }
}
