import Foundation
import Testing
@testable import Tracexy

/// Deterministic filesystem coverage for lossless, idempotent capture import.
/// Each test runs in its own throwaway temporary directory so no state leaks
/// into the real managed Captures folder.
@Suite("Capture import is lossless and idempotent")
struct CaptureImporterTests {
    // MARK: Internal

    @Test("A source that is already the managed file is reopened in place, never removed or copied")
    func sameManagedURLIsPreserved() throws {
        try withTemporaryDirectory { directory in
            let managed = directory.appendingPathComponent("existing.pcap")
            let payload = Data("managed-capture".utf8)
            try payload.write(to: managed)

            let result = try CaptureImporter.importCapture(from: managed, intoDirectory: directory)

            #expect(result == directory.appendingPathComponent("existing.pcap"))
            // The file survives untouched...
            #expect(FileManager.default.fileExists(atPath: managed.path))
            #expect(try Data(contentsOf: managed) == payload)
            // ...and no duplicate or temporary artifact is left behind.
            #expect(try directoryEntryCount(directory) == 1)
        }
    }

    @Test("A same-named symlink resolving into the managed directory is treated as the same file")
    func symlinkedSourceIsSameFile() throws {
        try withTemporaryDirectory { directory in
            try withTemporaryDirectory { externalDirectory in
                let managed = directory.appendingPathComponent("existing.pcap")
                let payload = Data("managed-capture".utf8)
                try payload.write(to: managed)

                // A symlink (e.g. handed back by a file picker) that carries the
                // same name but resolves back to the managed file. Resolution,
                // not the name, must recognise it as the managed file so nothing
                // is copied or removed.
                let link = externalDirectory.appendingPathComponent("existing.pcap")
                try FileManager.default.createSymbolicLink(at: link, withDestinationURL: managed)

                let result = try CaptureImporter.importCapture(from: link, intoDirectory: directory)

                #expect(result == managed)
                #expect(FileManager.default.fileExists(atPath: managed.path))
                #expect(try Data(contentsOf: managed) == payload)
                // No copy landed in the managed directory.
                #expect(try directoryEntryCount(directory) == 1)
            }
        }
    }

    @Test("An external file with no name collision is copied in and the source is left intact")
    func externalFileIsCopied() throws {
        try withTemporaryDirectory { directory in
            try withTemporaryDirectory { externalDirectory in
                let source = externalDirectory.appendingPathComponent("fresh.pcap")
                let payload = Data("brand-new-capture".utf8)
                try payload.write(to: source)

                let result = try CaptureImporter.importCapture(from: source, intoDirectory: directory)

                let destination = directory.appendingPathComponent("fresh.pcap")
                #expect(result == destination)
                #expect(try Data(contentsOf: destination) == payload)
                // Source untouched.
                #expect(try Data(contentsOf: source) == payload)
                #expect(try directoryEntryCount(directory) == 1)
            }
        }
    }

    @Test("A colliding external file replaces the managed copy only after the new copy fully succeeds")
    func collisionReplacesAfterSuccessfulCopy() throws {
        try withTemporaryDirectory { directory in
            try withTemporaryDirectory { externalDirectory in
                let managed = directory.appendingPathComponent("capture.pcap")
                try Data("old-managed".utf8).write(to: managed)

                let source = externalDirectory.appendingPathComponent("capture.pcap")
                let incoming = Data("new-external".utf8)
                try incoming.write(to: source)

                let result = try CaptureImporter.importCapture(from: source, intoDirectory: directory)

                #expect(result == managed)
                // Destination now holds the incoming payload.
                #expect(try Data(contentsOf: managed) == incoming)
                // Source is not consumed.
                #expect(try Data(contentsOf: source) == incoming)
                // The staged temporary sibling was consumed by the replace.
                #expect(try directoryEntryCount(directory) == 1)
            }
        }
    }

    @Test("A copy failure on collision preserves both the source and the pre-existing managed file")
    func failedCollisionPreservesBothFiles() throws {
        try withTemporaryDirectory { directory in
            let managed = directory.appendingPathComponent("capture.pcap")
            let existing = Data("old-managed".utf8)
            try existing.write(to: managed)

            // A source that does not exist forces the staging copy to fail with
            // ENOENT — the same failure that previously destroyed the managed
            // file when it was removed up front. The managed file must survive.
            let missingSource = directory
                .appendingPathComponent("elsewhere", isDirectory: true)
                .appendingPathComponent("capture.pcap")

            #expect(throws: (any Error).self) {
                try CaptureImporter.importCapture(from: missingSource, intoDirectory: directory)
            }

            // Pre-existing managed file is intact, unchanged, and no temporary
            // artifact leaked into the directory.
            #expect(FileManager.default.fileExists(atPath: managed.path))
            #expect(try Data(contentsOf: managed) == existing)
            #expect(try directoryEntryCount(directory) == 1)
        }
    }

    // MARK: Private

    /// Number of non-hidden entries directly in `directory`. Also asserts that
    /// no leftover `.import-*.tmp` staging artifacts remain.
    private func directoryEntryCount(_ directory: URL) throws -> Int {
        let all = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        #expect(!all.contains { $0.contains(".import-") })
        return all.filter { !$0.hasPrefix(".") }.count
    }

    private func withTemporaryDirectory(_ body: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-import-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory)
    }
}
