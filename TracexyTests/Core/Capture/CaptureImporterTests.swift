import Darwin
import Foundation
import Testing
@testable import Tracexy

// MARK: - CaptureImporterTests

/// Deterministic filesystem coverage for content-recognized, lossless,
/// no-overwrite capture import. Each test runs in its own throwaway temporary
/// directory so no state leaks into the real managed Captures folder.
///
/// These fixtures are well-formed enough to be recognized *and* read; the suite
/// deliberately never treats a successful import as proof that a file parses end
/// to end, which stays the streaming reader's job.
@Suite("Capture import recognizes content, preserves user data, and stays idempotent")
struct CaptureImporterTests {
    // MARK: Internal

    // MARK: Content recognition

    @Test(
        "Every classic magic variant is recognized as PCAP whatever the file is named",
        arguments: zip(
            [UInt32(0xA1B2C3D4), 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1],
            [false, true, false, true]
        )
    )
    func recognizesEveryClassicMagic(magic: UInt32, littleEndian: Bool) throws {
        try withTemporaryDirectory { directory in
            try withTemporaryDirectory { externalDirectory in
                // An extension that says nothing about the content: recognition
                // must come from the header alone.
                let source = externalDirectory.appendingPathComponent("evidence.bin")
                let payload = pcapFile(magic: magic, littleEndian: littleEndian)
                try payload.write(to: source)

                #expect(try CaptureImporter.recognizedFormat(of: source) == .pcap)

                let result = try CaptureImporter.importCapture(from: source, intoDirectory: directory)

                // Normalized so Library discovery can list and reopen it, with the
                // user's own filename kept intact ahead of the added suffix.
                #expect(result == directory.appendingPathComponent("evidence.bin.pcap"))
                #expect(try Data(contentsOf: result) == payload)
                #expect(try Data(contentsOf: source) == payload)
                #expect(try directoryEntryCount(directory) == 1)
            }
        }
    }

    @Test(
        "A section header block is recognized as PCAPNG in either byte order",
        arguments: [false, true]
    )
    func recognizesPcapngSectionHeader(littleEndian: Bool) throws {
        try withTemporaryDirectory { directory in
            try withTemporaryDirectory { externalDirectory in
                let source = externalDirectory.appendingPathComponent("session-dump")
                let payload = pcapngSectionHeader(littleEndian: littleEndian)
                try payload.write(to: source)

                #expect(try CaptureImporter.recognizedFormat(of: source) == .pcapng)

                let result = try CaptureImporter.importCapture(from: source, intoDirectory: directory)

                // A source with no extension at all still lands discoverable.
                #expect(result == directory.appendingPathComponent("session-dump.pcapng"))
                #expect(try Data(contentsOf: result) == payload)
            }
        }
    }

    @Test("A name the Library already discovers is never given a second extension")
    func supportedExtensionIsKeptVerbatim() throws {
        try withTemporaryDirectory { directory in
            try withTemporaryDirectory { externalDirectory in
                // Classic pcap content under a .pcapng name. The reader sniffs
                // content, so the file opens correctly and the name is left alone
                // rather than becoming "mislabelled.pcapng.pcap".
                let source = externalDirectory.appendingPathComponent("mislabelled.pcapng")
                try pcapFile().write(to: source)

                let result = try CaptureImporter.importCapture(from: source, intoDirectory: directory)
                #expect(result == directory.appendingPathComponent("mislabelled.pcapng"))

                // Re-importing the managed copy is a no-op: no further suffix, no
                // duplicate, no rewrite.
                let repeated = try CaptureImporter.importCapture(from: result, intoDirectory: directory)
                #expect(repeated == result)
                #expect(try directoryEntryCount(directory) == 1)
            }
        }
    }

    // MARK: Refusals before anything reaches the Library

    @Test("An empty file is refused with an actionable reason and adds nothing")
    func emptySourceIsRefused() throws {
        try withTemporaryDirectory { directory in
            try withTemporaryDirectory { externalDirectory in
                let source = externalDirectory.appendingPathComponent("empty.pcap")
                try Data().write(to: source)

                #expect(throws: CaptureImportError.sourceIsEmpty) {
                    try CaptureImporter.importCapture(from: source, intoDirectory: directory)
                }
                #expect(try directoryEntryCount(directory) == 0)
            }
        }
    }

    @Test("A file too short to hold a magic is reported as truncated, not unsupported")
    func truncatedSourceIsRefused() throws {
        try withTemporaryDirectory { directory in
            try withTemporaryDirectory { externalDirectory in
                let source = externalDirectory.appendingPathComponent("partial.pcap")
                try Data([0x0A, 0x0D, 0x0D]).write(to: source)

                #expect(throws: CaptureImportError.sourceIsTruncated) {
                    try CaptureImporter.importCapture(from: source, intoDirectory: directory)
                }
                #expect(try directoryEntryCount(directory) == 0)
            }
        }
    }

    @Test("Content with no recognized capture header is refused")
    func unknownContentIsRefused() throws {
        try withTemporaryDirectory { directory in
            try withTemporaryDirectory { externalDirectory in
                // A plausible-looking sibling artifact (a HAR-style JSON document)
                // that Tracexy deliberately does not import.
                let source = externalDirectory.appendingPathComponent("network.pcap")
                try Data(#"{"log":{"version":"1.2"}}"#.utf8).write(to: source)

                #expect(throws: CaptureImportError.unsupportedContent) {
                    try CaptureImporter.importCapture(from: source, intoDirectory: directory)
                }
                #expect(try directoryEntryCount(directory) == 0)
            }
        }
    }

    /// gzip and ZIP are deliberately absent: those two are expanded rather than
    /// refused, and `CaptureArchiveImportTests` owns that behaviour. Recognition
    /// itself still names them — see `recognitionStaysDirect` there.
    @Test(
        "A compressed capture Tracexy does not expand names its container so the user knows what to do",
        arguments: zip(
            [
                [0x28, 0xB5, 0x2F, 0xFD] as [UInt8],
                [0x42, 0x5A, 0x68, 0x39],
                [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],
                [0x04, 0x22, 0x4D, 0x18],
                [0x1F, 0x9D, 0x90, 0x00],
            ],
            ["Zstandard", "bzip2", "xz", "LZ4", "Unix compress"]
        )
    )
    func compressedSourceIsRefused(signature: [UInt8], container: String) throws {
        try withTemporaryDirectory { directory in
            try withTemporaryDirectory { externalDirectory in
                let source = externalDirectory.appendingPathComponent("capture.pcap.compressed")
                var payload = Data(signature)
                payload.append(pcapFile())
                try payload.write(to: source)

                #expect(throws: CaptureImportError.compressed(container)) {
                    try CaptureImporter.importCapture(from: source, intoDirectory: directory)
                }
                #expect(try directoryEntryCount(directory) == 0)
            }
        }
    }

    @Test("A directory — including one named like a capture — is refused")
    func directorySourceIsRefused() throws {
        try withTemporaryDirectory { directory in
            try withTemporaryDirectory { externalDirectory in
                let source = externalDirectory.appendingPathComponent("bundle.pcap", isDirectory: true)
                try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)

                #expect(throws: CaptureImportError.sourceIsDirectory) {
                    try CaptureImporter.importCapture(from: source, intoDirectory: directory)
                }
                #expect(try directoryEntryCount(directory) == 0)
            }
        }
    }

    // MARK: Same-file identity

    @Test("A source that is already the managed file is reopened in place, never removed or copied")
    func sameManagedURLIsPreserved() throws {
        try withTemporaryDirectory { directory in
            let managed = directory.appendingPathComponent("existing.pcap")
            let payload = pcapFile()
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
                let payload = pcapFile()
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

    @Test("A differently named symlink onto a managed capture reopens it instead of duplicating it")
    func renamedSymlinkResolvesToTheManagedCapture() throws {
        try withTemporaryDirectory { directory in
            try withTemporaryDirectory { externalDirectory in
                let managed = directory.appendingPathComponent("existing.pcap")
                let payload = pcapFile()
                try payload.write(to: managed)

                let link = externalDirectory.appendingPathComponent("alias.pcap")
                try FileManager.default.createSymbolicLink(at: link, withDestinationURL: managed)

                let result = try CaptureImporter.importCapture(from: link, intoDirectory: directory)

                #expect(result == managed)
                #expect(try Data(contentsOf: managed) == payload)
                #expect(try directoryEntryCount(directory) == 1)
            }
        }
    }

    @Test("A hardlink to the managed capture is recognized by file identity, not by path")
    func hardlinkedSourceIsSameFile() throws {
        try withTemporaryDirectory { directory in
            try withTemporaryDirectory { externalDirectory in
                let managed = directory.appendingPathComponent("existing.pcap")
                let payload = pcapFile()
                try payload.write(to: managed)

                let hardlink = externalDirectory.appendingPathComponent("existing.pcap")
                try FileManager.default.linkItem(at: managed, to: hardlink)

                let result = try CaptureImporter.importCapture(from: hardlink, intoDirectory: directory)

                #expect(result == managed)
                #expect(try Data(contentsOf: managed) == payload)
                #expect(try directoryEntryCount(directory) == 1)
            }
        }
    }

    // MARK: No-overwrite publication

    @Test("An external file with no name collision is copied in and the source is left intact")
    func externalFileIsCopied() throws {
        try withTemporaryDirectory { directory in
            try withTemporaryDirectory { externalDirectory in
                let source = externalDirectory.appendingPathComponent("fresh.pcap")
                let payload = pcapFile()
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

    @Test("A colliding external file is kept under a unique name and never replaces the existing capture")
    func collisionPreservesBothCaptures() throws {
        try withTemporaryDirectory { directory in
            try withTemporaryDirectory { externalDirectory in
                let managed = directory.appendingPathComponent("capture.pcap")
                let existing = pcapFile(marker: [0x01, 0x02, 0x03, 0x04])
                try existing.write(to: managed)

                let source = externalDirectory.appendingPathComponent("capture.pcap")
                let incoming = pcapFile(marker: [0x0A, 0x0B, 0x0C, 0x0D])
                try incoming.write(to: source)

                let result = try CaptureImporter.importCapture(from: source, intoDirectory: directory)

                // Both captures survive: the pre-existing one under its own name,
                // the incoming one beside it.
                #expect(result == directory.appendingPathComponent("capture-2.pcap"))
                #expect(try Data(contentsOf: managed) == existing)
                #expect(try Data(contentsOf: result) == incoming)
                #expect(try Data(contentsOf: source) == incoming)
                #expect(try directoryEntryCount(directory) == 2)

                // A further collision keeps counting rather than reusing a name.
                let again = try CaptureImporter.importCapture(from: source, intoDirectory: directory)
                #expect(again == directory.appendingPathComponent("capture-3.pcap"))
                #expect(try Data(contentsOf: managed) == existing)
                #expect(try directoryEntryCount(directory) == 3)
            }
        }
    }

    @Test("A copy failure preserves both the source and the pre-existing managed file")
    func failedImportPreservesExistingCapture() throws {
        try withTemporaryDirectory { directory in
            let managed = directory.appendingPathComponent("capture.pcap")
            let existing = pcapFile()
            try existing.write(to: managed)

            // A source that does not exist is refused before any staging — the
            // same failure that previously destroyed the managed file when it was
            // removed up front. The managed file must survive.
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

    @Test("External symlinks import independent bytes rather than another symlink")
    func externalSymlinkCopiesTargetBytes() throws {
        try withTemporaryDirectory { library in
            try withTemporaryDirectory { external in
                let target = external.appendingPathComponent("original.pcap")
                let alias = external.appendingPathComponent("alias.cap")
                let bytes = pcapFile()
                try bytes.write(to: target)
                try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: target)
                let result = try CaptureImporter.importCapture(from: alias, intoDirectory: library)
                #expect(try result.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink == false)
                try FileManager.default.removeItem(at: target)
                #expect(try Data(contentsOf: result) == bytes)
            }
        }
    }

    @Test("Magic without the complete fixed header never enters the Library", arguments: [4, 12, 23])
    func incompleteFixedHeaderIsRefused(length: Int) throws {
        try withTemporaryDirectory { directory in
            let source = directory.appendingPathComponent("partial.bin")
            try pcapFile().prefix(length).write(to: source)
            #expect(throws: CaptureImportError.sourceIsTruncated) {
                try CaptureImporter.recognizedFormat(of: source)
            }
            try pcapngSectionHeader(littleEndian: true).prefix(length).write(to: source)
            #expect(throws: CaptureImportError.sourceIsTruncated) {
                try CaptureImporter.recognizedFormat(of: source)
            }
        }
    }

    @Test("A named pipe is rejected without waiting for a writer")
    func fifoIsRefused() throws {
        try withTemporaryDirectory { directory in
            let fifo = directory.appendingPathComponent("input.pcap")
            #expect(fifo.path.withCString { mkfifo($0, 0o600) } == 0)
            #expect(throws: CaptureImportError.sourceIsNotRegularFile) {
                try CaptureImporter.recognizedFormat(of: fifo)
            }
        }
    }

    @Test("Cancellation after a copied chunk preserves source and collision and removes staging")
    func chunkCancellationCleansOnlyStaging() throws {
        try withTemporaryDirectory { library in
            try withTemporaryDirectory { external in
                let source = external.appendingPathComponent("capture.pcap")
                let existing = library.appendingPathComponent("capture.pcap")
                let original = pcapFile()
                try original.write(to: existing)
                var incoming = original
                incoming.append(Data(repeating: 0xA5, count: 700_000))
                try incoming.write(to: source)
                let probe = ImportProbe()
                #expect(throws: CancellationError.self) {
                    try CaptureImporter.importCapture(
                        from: source, intoDirectory: library,
                        onProgress: { probe.record($0) },
                        isCancelled: { probe.lastCopied > 0 }
                    )
                }
                #expect(probe.lastCopied > 0 && probe.lastCopied < UInt64(incoming.count))
                #expect(try Data(contentsOf: source) == incoming)
                #expect(try Data(contentsOf: existing) == original)
                #expect(try directoryEntryCount(library) == 1)
            }
        }
    }

    @Test("A source shortened during copy is refused and its partial copy is removed")
    func changedSourceIsRefused() throws {
        try withTemporaryDirectory { library in
            try withTemporaryDirectory { external in
                let source = external.appendingPathComponent("capture.pcap")
                var bytes = pcapFile()
                bytes.append(Data(repeating: 0, count: 700_000))
                try bytes.write(to: source)
                #expect(throws: CaptureImportError.sourceChangedDuringImport) {
                    try CaptureImporter.importCapture(from: source, intoDirectory: library, onProgress: { progress in
                        if progress.bytesConsumed == 0 {
                            let handle = try? FileHandle(forWritingTo: source)
                            try? handle?.truncate(atOffset: 24)
                            try? handle?.close()
                        }
                    })
                }
                #expect(try Data(contentsOf: source).count == 24)
                #expect(try directoryEntryCount(library) == 0)
            }
        }
    }

    @Test("Publication failure preserves the source and removes its staged copy")
    func publicationFailurePreservesSource() throws {
        try withTemporaryDirectory { library in
            try withTemporaryDirectory { external in
                // Valid source name, but appending the managed suffix exceeds NAME_MAX.
                let source = external.appendingPathComponent(String(repeating: "a", count: 255))
                let bytes = pcapFile()
                try bytes.write(to: source)
                #expect(throws: (any Error).self) {
                    try CaptureImporter.importCapture(from: source, intoDirectory: library)
                }
                #expect(try Data(contentsOf: source) == bytes)
                #expect(try directoryEntryCount(library) == 0)
            }
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

    // MARK: Fixtures

    /// A classic capture: global header for the requested magic plus one record
    /// carrying `marker`, so two fixtures can be told apart byte for byte.
    private func pcapFile(
        magic: UInt32 = 0xA1B2C3D4,
        littleEndian: Bool = false,
        marker: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
    )
        -> Data
    {
        var data = Data()
        // The magic is laid down in the byte order its constant already encodes;
        // the remaining fields follow the file's own byte order.
        data.append(contentsOf: bigEndianBytes(magic))
        data.append(contentsOf: u16(2, littleEndian: littleEndian))
        data.append(contentsOf: u16(4, littleEndian: littleEndian))
        data.append(contentsOf: u32(0, littleEndian: littleEndian))
        data.append(contentsOf: u32(0, littleEndian: littleEndian))
        data.append(contentsOf: u32(65_535, littleEndian: littleEndian))
        data.append(contentsOf: u32(1, littleEndian: littleEndian))
        data.append(contentsOf: u32(1, littleEndian: littleEndian))
        data.append(contentsOf: u32(0, littleEndian: littleEndian))
        data.append(contentsOf: u32(UInt32(marker.count), littleEndian: littleEndian))
        data.append(contentsOf: u32(UInt32(marker.count), littleEndian: littleEndian))
        data.append(contentsOf: marker)
        return data
    }

    /// A minimal 28-byte pcapng Section Header Block. Its leading type bytes are
    /// byte-order independent; the byte-order magic identifies the section.
    private func pcapngSectionHeader(littleEndian: Bool) -> Data {
        var data = Data([0x0A, 0x0D, 0x0D, 0x0A])
        data.append(contentsOf: u32(28, littleEndian: littleEndian))
        data.append(contentsOf: u32(0x1A2B3C4D, littleEndian: littleEndian))
        data.append(contentsOf: u16(1, littleEndian: littleEndian))
        data.append(contentsOf: u16(0, littleEndian: littleEndian))
        data.append(contentsOf: u64(UInt64.max, littleEndian: littleEndian))
        data.append(contentsOf: u32(28, littleEndian: littleEndian))
        return data
    }

    private func bigEndianBytes(_ value: UInt32) -> [UInt8] {
        [
            UInt8((value >> 24) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8(value & 0xFF),
        ]
    }

    private func u16(_ value: UInt16, littleEndian: Bool) -> [UInt8] {
        let bytes: [UInt8] = [UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]
        return littleEndian ? Array(bytes.reversed()) : bytes
    }

    private func u32(_ value: UInt32, littleEndian: Bool) -> [UInt8] {
        let bytes = bigEndianBytes(value)
        return littleEndian ? Array(bytes.reversed()) : bytes
    }

    private func u64(_ value: UInt64, littleEndian: Bool) -> [UInt8] {
        let bytes = (0 ..< 8).map { UInt8((value >> (8 * (7 - $0))) & 0xFF) }
        return littleEndian ? Array(bytes.reversed()) : bytes
    }
}

// MARK: - ImportProbe

nonisolated private final class ImportProbe: @unchecked Sendable {
    // MARK: Internal

    var lastCopied: UInt64 {
        lock.withLock { copied }
    }

    func record(_ progress: PcapStreamProgress) {
        lock.withLock { copied = progress.bytesConsumed }
    }

    // MARK: Private

    private let lock = NSLock()
    private var copied: UInt64 = 0
}
