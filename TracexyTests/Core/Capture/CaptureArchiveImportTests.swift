import Foundation
import Testing
@testable import Tracexy
import zlib

// MARK: - ArchiveImportProbe

/// Records the last progress report so a test can cancel or mutate the source
/// part way through an extraction.
nonisolated private final class ArchiveImportProbe: @unchecked Sendable {
    // MARK: Internal

    var lastConsumed: UInt64 {
        lock.withLock { consumed }
    }

    var reports: [UInt64] {
        lock.withLock { history }
    }

    func record(_ progress: PcapStreamProgress) {
        lock.withLock {
            consumed = progress.bytesConsumed
            history.append(progress.bytesConsumed)
        }
    }

    // MARK: Private

    private let lock = NSLock()
    private var consumed: UInt64 = 0
    private var history = [UInt64]()
}

// MARK: - ZipEntryFixture

/// One archive entry, with every knob a malformed-archive test needs.
///
/// Fixtures are built byte by byte rather than by shelling out, so each defect
/// under test is exactly the one intended and nothing else varies.
nonisolated private struct ZipEntryFixture {
    var name: String
    var data: [UInt8] = []
    /// 0 = stored, 8 = deflate.
    var method: UInt16 = 8
    var flags: UInt16 = 0
    var externalAttributes: UInt32 = 0
    /// Writes zero CRC/sizes in the local header, the shape a writer streaming
    /// with a trailing data descriptor produces.
    var zeroLocalSizes = false
    var appendDataDescriptor = false
    var nameBytesOverride: [UInt8]?
    var localNameOverride: String?
    var localMethodOverride: UInt16?
    var centralCrc: UInt32?
    var centralCompressedSize: UInt32?
    var centralUncompressedSize: UInt32?
    var centralLocalOffset: UInt32?
}

// MARK: - CaptureArchiveImportTests

/// Bounded capture-archive import: content-sniffed gzip and the exact
/// `TCPViewerSession` schema-1 session ZIP, expanded through the same
/// `importCapture` entry point and published by the same no-overwrite `link(2)`.
///
/// Every fixture is generated programmatically (zlib for the compressed streams,
/// hand-assembled records for the ZIP structures), so the suite is deterministic
/// and each refusal test isolates a single defect.
@Suite("Capture archive import expands gzip and session ZIP within hard bounds")
struct CaptureArchiveImportTests {
    // MARK: Internal

    // MARK: gzip — the happy paths

    @Test(
        "A gzipped classic capture is expanded byte for byte, whatever its magic or byte order",
        arguments: zip(
            [UInt32(0xA1B2C3D4), 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1],
            [false, true, false, true]
        )
    )
    func expandsEveryClassicMagic(magic: UInt32, littleEndian: Bool) throws {
        try withDirectories { library, external in
            let payload = pcapFile(magic: magic, littleEndian: littleEndian)
            let source = external.appendingPathComponent("evidence.pcap.gz")
            try Data(gzipped(payload)).write(to: source)

            let result = try CaptureImporter.importCapture(from: source, intoDirectory: library)

            // The container extension is dropped; the capture name inside it is kept.
            #expect(result == library.appendingPathComponent("evidence.pcap"))
            #expect(try Data(contentsOf: result) == Data(payload))
            #expect(try directoryEntryCount(library) == 1)
        }
    }

    @Test("A gzipped PCAPNG is recognized from content even under a misleading name")
    func expandsPcapngUnderAnyName() throws {
        try withDirectories { library, external in
            let payload = pcapngSectionHeader(littleEndian: true)
            // No .gz anywhere: recognition comes from the leading bytes alone.
            let source = external.appendingPathComponent("session-dump")
            try Data(gzipped(payload)).write(to: source)

            let result = try CaptureImporter.importCapture(from: source, intoDirectory: library)

            #expect(result == library.appendingPathComponent("session-dump.pcapng"))
            #expect(try Data(contentsOf: result) == Data(payload))
        }
    }

    @Test("A nanosecond capture survives expansion unchanged")
    func expandsNanosecondCapture() throws {
        try withDirectories { library, external in
            let payload = pcapFile(magic: 0xA1B23C4D, marker: [0x11, 0x22, 0x33, 0x44])
            let source = external.appendingPathComponent("nano.gz")
            try Data(gzipped(payload)).write(to: source)

            let result = try CaptureImporter.importCapture(from: source, intoDirectory: library)

            #expect(result == library.appendingPathComponent("nano.pcap"))
            #expect(try Data(contentsOf: result) == Data(payload))
        }
    }

    @Test("Concatenated gzip members are joined in order, as `gzip` itself produces them")
    func expandsConcatenatedMembers() throws {
        try withDirectories { library, external in
            let payload = pcapFile(marker: Array(repeating: 0x5A, count: 64))
            let split = 30
            var archive = gzipped(Array(payload.prefix(split)))
            archive.append(contentsOf: gzipped(Array(payload.dropFirst(split))))
            let source = external.appendingPathComponent("split.pcap.gz")
            try Data(archive).write(to: source)

            let result = try CaptureImporter.importCapture(from: source, intoDirectory: library)

            #expect(try Data(contentsOf: result) == Data(payload))
        }
    }

    @Test("Progress rises monotonically and is measured in compressed source bytes")
    func progressTracksCompressedBytes() throws {
        try withDirectories { library, external in
            let payload = pcapFile(marker: Array(repeating: 0xA5, count: 900_000))
            let archive = gzipped(payload)
            let source = external.appendingPathComponent("large.pcap.gz")
            try Data(archive).write(to: source)
            let probe = ArchiveImportProbe()

            _ = try CaptureImporter.importCapture(
                from: source, intoDirectory: library, onProgress: { probe.record($0) }
            )

            let reports = probe.reports
            #expect(reports.first == 0)
            #expect(reports.last == UInt64(archive.count))
            #expect(zip(reports, reports.dropFirst()).allSatisfy { $0 <= $1 })
            #expect(reports.allSatisfy { $0 <= UInt64(archive.count) })
        }
    }

    // MARK: gzip — refusals

    @Test("A corrupt CRC is caught by zlib, not waved through")
    func refusesCorruptChecksum() throws {
        try withDirectories { library, external in
            var archive = gzipped(pcapFile())
            archive[archive.count - 8] ^= 0xFF
            try Data(archive).write(to: external.appendingPathComponent("bad-crc.pcap.gz"))

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(
                    from: external.appendingPathComponent("bad-crc.pcap.gz"), intoDirectory: library
                )
            }
            expectMalformed(error)
            #expect(try directoryEntryCount(library) == 0)
        }
    }

    @Test("A corrupt ISIZE is caught by zlib's own trailer check")
    func refusesCorruptSize() throws {
        try withDirectories { library, external in
            var archive = gzipped(pcapFile())
            archive[archive.count - 4] ^= 0xFF
            let source = external.appendingPathComponent("bad-size.pcap.gz")
            try Data(archive).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            expectMalformed(error)
            #expect(try directoryEntryCount(library) == 0)
        }
    }

    @Test("Bytes after the last member are refused rather than ignored")
    func refusesTrailingGarbage() throws {
        try withDirectories { library, external in
            var archive = gzipped(pcapFile())
            archive.append(contentsOf: [0x00, 0x01, 0x02, 0x03])
            let source = external.appendingPathComponent("trailer.pcap.gz")
            try Data(archive).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            #expect(error == .trailingContent)
            #expect(try directoryEntryCount(library) == 0)
        }
    }

    @Test("A truncated member is refused, and never published as a short capture", arguments: [1, 9, 40])
    func refusesTruncatedMember(dropped: Int) throws {
        try withDirectories { library, external in
            // Deliberately incompressible, so dropping a few dozen bytes shortens
            // the stream rather than emptying the file.
            let archive = gzipped(pcapFile(marker: noisyBytes(count: 4_096)))
            let source = external.appendingPathComponent("partial.pcap.gz")
            try Data(archive.dropLast(dropped)).write(to: source)

            #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            #expect(try directoryEntryCount(library) == 0)
        }
    }

    @Test("A reserved header flag is refused before any data is inflated")
    func refusesReservedHeaderFlag() throws {
        try withDirectories { library, external in
            var archive = gzipped(pcapFile())
            archive[3] |= 0xE0
            let source = external.appendingPathComponent("reserved.pcap.gz")
            try Data(archive).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            expectMalformed(error)
            #expect(try directoryEntryCount(library) == 0)
        }
    }

    @Test("A gzip whose payload is not a capture is one refusal, not a second container round")
    func refusesNonCapturePayload() throws {
        try withDirectories { library, external in
            let source = external.appendingPathComponent("report.gz")
            try Data(gzipped(Array(#"{"log":{"version":"1.2"}}"#.utf8))).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            #expect(error == .extractedContentUnsupported)
            #expect(try directoryEntryCount(library) == 0)
        }
    }

    @Test("A gzipped archive is not unwrapped recursively")
    func refusesNestedArchive() throws {
        try withDirectories { library, external in
            let inner = makeZip([ZipEntryFixture(name: "TCPViewerSession/capture.pcapng", data: pcapFile())])
            let source = external.appendingPathComponent("nested.gz")
            try Data(gzipped(inner)).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            #expect(error == .extractedContentUnsupported)
        }
    }

    // MARK: Bounds

    @Test("A compressed file above the source ceiling is refused before it is read")
    func refusesOversizedSource() throws {
        try withDirectories { library, external in
            let source = external.appendingPathComponent("big.pcap.gz")
            try Data(gzipped(pcapFile(marker: Array(repeating: 0x00, count: 4_096)))).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(
                    from: source, intoDirectory: library,
                    limits: CaptureArchiveLimits(maximumSourceBytes: 16)
                )
            }
            #expect(error == .sourceTooLarge(limit: 16))
            #expect(try directoryEntryCount(library) == 0)
        }
    }

    @Test("Expansion stops at the output ceiling instead of filling the disk")
    func refusesOversizedOutput() throws {
        try withDirectories { library, external in
            let source = external.appendingPathComponent("wide.pcap.gz")
            try Data(gzipped(pcapFile(marker: Array(repeating: 0x33, count: 8_192)))).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(
                    from: source, intoDirectory: library,
                    limits: CaptureArchiveLimits(maximumOutputBytes: 512)
                )
            }
            #expect(error == .expandedTooLarge(limit: 512))
            #expect(try directoryEntryCount(library) == 0)
        }
    }

    @Test("A payload that outruns the expansion ratio is refused after the grace")
    func refusesExpansionBomb() throws {
        try withDirectories { library, external in
            let source = external.appendingPathComponent("bomb.pcap.gz")
            try Data(gzipped(pcapFile(marker: Array(repeating: 0x00, count: 200_000)))).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(
                    from: source, intoDirectory: library,
                    limits: CaptureArchiveLimits(expansionRatio: 2, expansionGraceBytes: 1_024)
                )
            }
            #expect(error == .expansionRatioExceeded(ratio: 2))
            #expect(try directoryEntryCount(library) == 0)
        }
    }

    @Test("Limits only ever narrow: a caller cannot widen a shipped ceiling")
    func limitsClampDownwards() {
        let widened = CaptureArchiveLimits(
            maximumSourceBytes: .max,
            maximumOutputBytes: .max,
            expansionRatio: .max,
            expansionGraceBytes: .max,
            maximumCentralDirectoryBytes: .max,
            maximumEntryCount: .max,
            maximumEntryNameBytes: .max,
            maximumManifestBytes: .max
        )
        #expect(widened == .standard)
        #expect(CaptureArchiveLimits.standard.maximumSourceBytes == 512 * 1_024 * 1_024)
        #expect(CaptureArchiveLimits.standard.maximumOutputBytes == 4 * 1_024 * 1_024 * 1_024)
        #expect(CaptureArchiveLimits.standard.expansionRatio == 200)
        #expect(CaptureArchiveLimits.standard.expansionGraceBytes == 64 * 1_024 * 1_024)
        #expect(CaptureArchiveLimits.standard.maximumCentralDirectoryBytes == 4 * 1_024 * 1_024)
        #expect(CaptureArchiveLimits.standard.maximumEntryCount == 4_096)
        #expect(CaptureArchiveLimits.standard.maximumEntryNameBytes == 1_024)
        #expect(CaptureArchiveLimits.standard.maximumManifestBytes == 64 * 1_024)
        #expect(CaptureArchiveLimits(expansionRatio: 3).expansionRatio == 3)
    }

    // MARK: Cancellation, mutation and collision

    @Test("Cancelling before the source is opened adds nothing and leaves no staging file")
    func cancelsBeforeOpening() throws {
        try withDirectories { library, external in
            let source = external.appendingPathComponent("capture.pcap.gz")
            try Data(gzipped(pcapFile())).write(to: source)

            #expect(throws: CancellationError.self) {
                try CaptureImporter.importCapture(
                    from: source, intoDirectory: library, isCancelled: { true }
                )
            }
            #expect(try directoryEntryCount(library) == 0)
        }
    }

    @Test("Cancelling mid-expansion removes only this import's staging file")
    func cancelsMidExpansion() throws {
        try withDirectories { library, external in
            let existing = library.appendingPathComponent("capture.pcap")
            let original = pcapFile(marker: [0x01, 0x02, 0x03, 0x04])
            try Data(original).write(to: existing)
            let source = external.appendingPathComponent("capture.pcap.gz")
            try Data(gzipped(pcapFile(marker: Array(repeating: 0xA5, count: 1_500_000)))).write(to: source)
            let probe = ArchiveImportProbe()

            #expect(throws: CancellationError.self) {
                try CaptureImporter.importCapture(
                    from: source, intoDirectory: library,
                    onProgress: { probe.record($0) },
                    isCancelled: { probe.lastConsumed > 0 }
                )
            }
            #expect(try Data(contentsOf: existing) == Data(original))
            #expect(try directoryEntryCount(library) == 1)
        }
    }

    @Test("A source touched during expansion is refused by the closing identity check")
    func refusesMutatedSource() throws {
        try withDirectories { library, external in
            let source = external.appendingPathComponent("capture.pcap.gz")
            let archive = gzipped(pcapFile(marker: Array(repeating: 0x5C, count: 200_000)))
            try Data(archive).write(to: source)

            #expect(throws: CaptureImportError.sourceChangedDuringImport) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library, onProgress: { progress in
                    guard progress.bytesConsumed == 0 else {
                        return
                    }
                    // Rewrite identical bytes: the content is unchanged, but the
                    // modification and change times are not.
                    let handle = try? FileHandle(forUpdating: source)
                    try? handle?.seek(toOffset: 0)
                    try? handle?.write(contentsOf: Data([0x1F]))
                    try? handle?.close()
                })
            }
            #expect(try directoryEntryCount(library) == 0)
        }
    }

    @Test("A colliding extracted name is uniquified and never replaces an existing capture")
    func collisionPreservesBothCaptures() throws {
        try withDirectories { library, external in
            let managed = library.appendingPathComponent("capture.pcap")
            let existing = pcapFile(marker: [0x01, 0x02, 0x03, 0x04])
            try Data(existing).write(to: managed)
            let incoming = pcapFile(marker: [0x0A, 0x0B, 0x0C, 0x0D])
            let source = external.appendingPathComponent("capture.pcap.gz")
            try Data(gzipped(incoming)).write(to: source)

            let first = try CaptureImporter.importCapture(from: source, intoDirectory: library)
            #expect(first == library.appendingPathComponent("capture-2.pcap"))
            #expect(try Data(contentsOf: managed) == Data(existing))
            #expect(try Data(contentsOf: first) == Data(incoming))

            // The name is stable, so a second import collides predictably rather
            // than short-circuiting on the container it was expanded from.
            let second = try CaptureImporter.importCapture(from: source, intoDirectory: library)
            #expect(second == library.appendingPathComponent("capture-3.pcap"))
            #expect(try directoryEntryCount(library) == 3)
        }
    }

    @Test("A container sitting inside the Library is still expanded, never reported as already managed")
    func containerInLibraryIsExpanded() throws {
        try withDirectories { library, _ in
            let source = library.appendingPathComponent("session.pcapng.gz")
            let payload = pcapngSectionHeader(littleEndian: false)
            try Data(gzipped(payload)).write(to: source)

            let result = try CaptureImporter.importCapture(from: source, intoDirectory: library)

            #expect(result == library.appendingPathComponent("session.pcapng"))
            #expect(try Data(contentsOf: result) == Data(payload))
            #expect(FileManager.default.fileExists(atPath: source.path))
        }
    }

    // MARK: Session ZIP — the happy paths

    @Test("The observed session layout yields its capture byte for byte", arguments: [UInt16(0), 8])
    func expandsSessionArchive(captureMethod: UInt16) throws {
        try withDirectories { library, external in
            let capture = pcapngSectionHeader(littleEndian: true)
            let archive = makeZip(sessionEntries(capture: capture, captureMethod: captureMethod))
            let source = external.appendingPathComponent("recording-1844.tcpviewsession")
            try Data(archive).write(to: source)

            let result = try CaptureImporter.importCapture(from: source, intoDirectory: library)

            // The name comes from the source file, never from a manifest field.
            #expect(result == library.appendingPathComponent("recording-1844.pcapng"))
            #expect(try Data(contentsOf: result) == Data(capture))
            #expect(try directoryEntryCount(library) == 1)
        }
    }

    @Test("A capture written with a trailing data descriptor and zero local sizes is accepted")
    func expandsDataDescriptorEntry() throws {
        try withDirectories { library, external in
            let capture = pcapngSectionHeader(littleEndian: false)
            var entries = sessionEntries(capture: capture)
            entries[entries.count - 1].flags = 0x0008
            entries[entries.count - 1].zeroLocalSizes = true
            entries[entries.count - 1].appendDataDescriptor = true
            let source = external.appendingPathComponent("streamed.tcpviewsession")
            try Data(makeZip(entries)).write(to: source)

            let result = try CaptureImporter.importCapture(from: source, intoDirectory: library)

            #expect(try Data(contentsOf: result) == Data(capture))
        }
    }

    @Test("A session ZIP is recognized from content even when it is named .zip")
    func expandsSessionArchiveNamedZip() throws {
        try withDirectories { library, external in
            let capture = pcapFile()
            let source = external.appendingPathComponent("export.zip")
            try Data(makeZip(sessionEntries(capture: capture))).write(to: source)

            let result = try CaptureImporter.importCapture(from: source, intoDirectory: library)

            #expect(result == library.appendingPathComponent("export.pcap"))
            #expect(try Data(contentsOf: result) == Data(capture))
        }
    }

    // MARK: Session ZIP — schema refusals

    @Test("A ZIP with no session manifest is refused with an export instruction")
    func refusesPlainZip() throws {
        try withDirectories { library, external in
            let archive = makeZip([ZipEntryFixture(name: "capture.pcapng", data: pcapFile())])
            let source = external.appendingPathComponent("bundle.zip")
            try Data(archive).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            #expect(error == .unsupportedSessionArchive)
            #expect(error?.errorDescription?.contains("export a PCAPNG capture") == true)
            #expect(try directoryEntryCount(library) == 0)
        }
    }

    @Test("Entries outside the session folder mean this is not the layout Tracexy reads")
    func refusesForeignEntries() throws {
        try withDirectories { library, external in
            var entries = sessionEntries(capture: pcapFile())
            entries.append(ZipEntryFixture(name: "__MACOSX/._capture", data: [0x01, 0x02]))
            let source = external.appendingPathComponent("mixed.tcpviewsession")
            try Data(makeZip(entries)).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            #expect(error == .unsupportedSessionArchive)
        }
    }

    @Test("A foreign magic is refused even when the rest of the manifest looks right")
    func refusesForeignMagic() throws {
        try withDirectories { library, external in
            let manifest = manifestJSON(magic: "SomeOtherSession")
            let source = external.appendingPathComponent("foreign.tcpviewsession")
            try Data(makeZip(sessionEntries(capture: pcapFile(), manifest: manifest))).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            #expect(error == .unsupportedSessionArchive)
        }
    }

    @Test(
        "A schema this build has not seen is refused, even when it claims to stay compatible",
        arguments: [
            (2, 1),
            (1, 2),
            (2, 2),
        ]
    )
    func refusesUnknownSchema(schemaVersion: Int, minimum: Int) throws {
        try withDirectories { library, external in
            let manifest = manifestJSON(schemaVersion: schemaVersion, minimum: minimum)
            let source = external.appendingPathComponent("future.tcpviewsession")
            try Data(makeZip(sessionEntries(capture: pcapFile(), manifest: manifest))).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            #expect(error == .unsupportedSessionSchema)
            #expect(try directoryEntryCount(library) == 0)
        }
    }

    @Test("A manifest naming a different capture file is refused rather than followed")
    func refusesRedirectedCaptureFile() throws {
        try withDirectories { library, external in
            let manifest = manifestJSON(captureFile: "../../elsewhere.pcapng")
            let source = external.appendingPathComponent("redirect.tcpviewsession")
            try Data(makeZip(sessionEntries(capture: pcapFile(), manifest: manifest))).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            #expect(error == .unsupportedSessionSchema)
        }
    }

    @Test("A manifest with no capture beside it is refused")
    func refusesMissingCapture() throws {
        try withDirectories { library, external in
            var entries = sessionEntries(capture: pcapFile())
            entries.removeAll { $0.name == "TCPViewerSession/capture.pcapng" }
            let source = external.appendingPathComponent("empty.tcpviewsession")
            try Data(makeZip(entries)).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            #expect(error == .sessionCaptureMissing)
        }
    }

    @Test("The session's own state, packets, annotations, clients and icons are never imported")
    func ignoresNonCaptureEntries() throws {
        try withDirectories { library, external in
            let capture = pcapngSectionHeader(littleEndian: true)
            var entries = sessionEntries(capture: capture)
            // Deliberately hostile content in entries Tracexy must not read.
            for index in entries.indices where entries[index].name.hasSuffix("packets.jsonl") {
                entries[index].data = Array(repeating: 0xFF, count: 4_096)
            }
            let source = external.appendingPathComponent("noisy.tcpviewsession")
            try Data(makeZip(entries)).write(to: source)

            let result = try CaptureImporter.importCapture(from: source, intoDirectory: library)

            #expect(try Data(contentsOf: result) == Data(capture))
            #expect(try directoryEntryCount(library) == 1)
        }
    }

    // MARK: Session ZIP — structural refusals

    @Test("An encrypted entry is refused by name, not attempted")
    func refusesEncryptedEntry() throws {
        try withDirectories { library, external in
            var entries = sessionEntries(capture: pcapFile())
            entries[entries.count - 1].flags = 0x0001
            let source = external.appendingPathComponent("locked.tcpviewsession")
            try Data(makeZip(entries)).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            #expect(error == .unsupportedFeature("encryption"))
        }
    }

    @Test("An unsupported compression method is refused by number")
    func refusesUnsupportedMethod() throws {
        try withDirectories { library, external in
            var entries = sessionEntries(capture: pcapFile())
            entries[entries.count - 1].method = 12
            let source = external.appendingPathComponent("bzip.tcpviewsession")
            try Data(makeZip(entries)).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            #expect(error == .unsupportedFeature("compression method 12"))
        }
    }

    @Test("A symbolic-link entry is refused during indexing")
    func refusesSymlinkEntry() throws {
        try withDirectories { library, external in
            var entries = sessionEntries(capture: pcapFile())
            entries.append(ZipEntryFixture(
                name: "TCPViewerSession/alias",
                data: Array("/etc/passwd".utf8),
                externalAttributes: 0xA1FF0000
            ))
            let source = external.appendingPathComponent("link.tcpviewsession")
            try Data(makeZip(entries)).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            #expect(error == .unsupportedFeature("symbolic-link entries"))
        }
    }

    @Test("ZIP64 fields are refused rather than misread as 32-bit values")
    func refusesZip64Entry() throws {
        try withDirectories { library, external in
            var entries = sessionEntries(capture: pcapFile())
            entries[entries.count - 1].centralUncompressedSize = 0xFFFFFFFF
            let source = external.appendingPathComponent("zip64.tcpviewsession")
            try Data(makeZip(entries)).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            #expect(error == .unsupportedFeature("the ZIP64 extension"))
        }
    }

    @Test("A ZIP64 locator before the end record is refused")
    func refusesZip64Locator() throws {
        try withDirectories { library, external in
            let archive = makeZip(sessionEntries(capture: pcapFile()), zip64Locator: true)
            let source = external.appendingPathComponent("zip64-locator.tcpviewsession")
            try Data(archive).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            #expect(error == .unsupportedFeature("the ZIP64 extension"))
        }
    }

    @Test("A multi-disk archive is refused")
    func refusesMultiDisk() throws {
        try withDirectories { library, external in
            let archive = makeZip(sessionEntries(capture: pcapFile()), diskNumber: 1)
            let source = external.appendingPathComponent("split.tcpviewsession")
            try Data(archive).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            #expect(error == .unsupportedFeature("multiple disks"))
        }
    }

    @Test(
        "Every unsafe entry name is refused before it can reach a path",
        arguments: [
            "TCPViewerSession/../../escape.pcapng",
            "/TCPViewerSession/capture.pcapng",
            "TCPViewerSession\\capture.pcapng",
            "C:/TCPViewerSession/capture.pcapng",
        ]
    )
    func refusesUnsafeNames(name: String) throws {
        try withDirectories { library, external in
            var entries = sessionEntries(capture: pcapFile())
            entries.append(ZipEntryFixture(name: name, data: [0x00]))
            let source = external.appendingPathComponent("unsafe.tcpviewsession")
            try Data(makeZip(entries)).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            expectMalformed(error)
            #expect(try directoryEntryCount(library) == 0)
        }
    }

    @Test("An entry name containing NUL is refused")
    func refusesNulInName() throws {
        try withDirectories { library, external in
            var entries = sessionEntries(capture: pcapFile())
            var poisoned = ZipEntryFixture(name: "TCPViewerSession/x", data: [0x01])
            poisoned.nameBytesOverride = Array("TCPViewerSession/x".utf8) + [0x00] + Array(".png".utf8)
            entries.append(poisoned)
            let source = external.appendingPathComponent("nul.tcpviewsession")
            try Data(makeZip(entries)).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            expectMalformed(error)
        }
    }

    @Test("A duplicated entry name is refused instead of silently taking one of them")
    func refusesDuplicateEntries() throws {
        try withDirectories { library, external in
            var entries = sessionEntries(capture: pcapFile())
            entries.append(ZipEntryFixture(
                name: "TCPViewerSession/capture.pcapng",
                data: pcapngSectionHeader(littleEndian: true)
            ))
            let source = external.appendingPathComponent("double.tcpviewsession")
            try Data(makeZip(entries)).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            expectMalformed(error)
        }
    }

    @Test("A local header that disagrees with the index is refused", arguments: [0, 1])
    func refusesLocalCentralMismatch(variant: Int) throws {
        try withDirectories { library, external in
            var entries = sessionEntries(capture: pcapFile())
            if variant == 0 {
                entries[entries.count - 1].localMethodOverride = 0
            } else {
                entries[entries.count - 1].localNameOverride = "TCPViewerSession/capture.pcapNG"
            }
            let source = external.appendingPathComponent("mismatch.tcpviewsession")
            try Data(makeZip(entries)).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            expectMalformed(error)
        }
    }

    @Test("An entry index pointing outside the archive is refused")
    func refusesBadDirectoryOffset() throws {
        try withDirectories { library, external in
            let archive = makeZip(sessionEntries(capture: pcapFile()), centralDirectoryOffsetOverride: 0x7FFFFFF0)
            let source = external.appendingPathComponent("offset.tcpviewsession")
            try Data(archive).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            expectMalformed(error)
        }
    }

    @Test("An entry count that disagrees with the index is refused")
    func refusesBadEntryCount() throws {
        try withDirectories { library, external in
            let archive = makeZip(sessionEntries(capture: pcapFile()), entryCountDelta: -1)
            let source = external.appendingPathComponent("count.tcpviewsession")
            try Data(archive).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            expectMalformed(error)
        }
    }

    @Test("Two plausible end-of-archive records make the archive ambiguous, not a guess")
    func refusesAmbiguousEndRecord() throws {
        try withDirectories { library, external in
            // A comment that itself begins with a structurally consistent record.
            var comment = [UInt8]()
            comment.append(contentsOf: le32(0x06054B50))
            comment.append(contentsOf: le16(0))
            comment.append(contentsOf: le16(0))
            comment.append(contentsOf: le16(0))
            comment.append(contentsOf: le16(0))
            comment.append(contentsOf: le32(0))
            comment.append(contentsOf: le32(0))
            comment.append(contentsOf: le16(22))
            comment.append(contentsOf: Array(repeating: 0x20, count: 22))
            let archive = makeZip(sessionEntries(capture: pcapFile()), comment: comment)
            let source = external.appendingPathComponent("ambiguous.tcpviewsession")
            try Data(archive).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            expectMalformed(error)
        }
    }

    @Test("Entries whose byte spans overlap are refused")
    func refusesOverlappingEntries() throws {
        try withDirectories { library, external in
            var entries = sessionEntries(capture: pcapFile())
            // A streamed entry may legally leave its local sizes zero, so the
            // index is the only place this overrun can be caught.
            for index in entries.indices where entries[index].name.hasSuffix("state.json") {
                entries[index].flags = 0x0008
                entries[index].zeroLocalSizes = true
                entries[index].centralCompressedSize = 64
            }
            let source = external.appendingPathComponent("overlap.tcpviewsession")
            try Data(makeZip(entries)).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            expectMalformed(error)
        }
    }

    @Test("An entry whose checksum does not match its bytes is refused")
    func refusesChecksumMismatch() throws {
        try withDirectories { library, external in
            var entries = sessionEntries(capture: pcapFile())
            entries[entries.count - 1].centralCrc = 0xDEADBEEF
            entries[entries.count - 1].flags = 0x0008
            entries[entries.count - 1].zeroLocalSizes = true
            let source = external.appendingPathComponent("crc.tcpviewsession")
            try Data(makeZip(entries)).write(to: source)

            let error = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            expectMalformed(error)
            #expect(try directoryEntryCount(library) == 0)
        }
    }

    @Test("A truncated archive is refused rather than partially read")
    func refusesTruncatedArchive() throws {
        try withDirectories { library, external in
            let archive = makeZip(sessionEntries(capture: pcapFile()))
            let source = external.appendingPathComponent("cut.tcpviewsession")
            try Data(archive.dropLast(8)).write(to: source)

            #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(from: source, intoDirectory: library)
            }
            #expect(try directoryEntryCount(library) == 0)
        }
    }

    // MARK: Session ZIP — bounds

    @Test("Structural bounds are enforced with an actionable refusal")
    func refusesOversizedStructures() throws {
        try withDirectories { library, external in
            let source = external.appendingPathComponent("bounded.tcpviewsession")
            try Data(makeZip(sessionEntries(capture: pcapFile()))).write(to: source)

            let byCount = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(
                    from: source, intoDirectory: library,
                    limits: CaptureArchiveLimits(maximumEntryCount: 2)
                )
            }
            expectExceedsBound(byCount)

            let byDirectory = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(
                    from: source, intoDirectory: library,
                    limits: CaptureArchiveLimits(maximumCentralDirectoryBytes: 32)
                )
            }
            expectExceedsBound(byDirectory)

            let byName = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(
                    from: source, intoDirectory: library,
                    limits: CaptureArchiveLimits(maximumEntryNameBytes: 4)
                )
            }
            expectExceedsBound(byName)

            let byManifest = #expect(throws: CaptureArchiveError.self) {
                try CaptureImporter.importCapture(
                    from: source, intoDirectory: library,
                    limits: CaptureArchiveLimits(maximumManifestBytes: 8)
                )
            }
            expectExceedsBound(byManifest)

            #expect(try directoryEntryCount(library) == 0)
        }
    }

    // MARK: The direct-copy contract is unchanged

    @Test("Recognition stays a direct-content question and never expands a container")
    func recognitionStaysDirect() throws {
        try withDirectories { _, external in
            let gzipSource = external.appendingPathComponent("capture.pcap.gz")
            try Data(gzipped(pcapFile())).write(to: gzipSource)
            #expect(throws: CaptureImportError.compressed("gzip")) {
                try CaptureImporter.recognizedFormat(of: gzipSource)
            }

            let zipSource = external.appendingPathComponent("session.tcpviewsession")
            try Data(makeZip(sessionEntries(capture: pcapFile()))).write(to: zipSource)
            #expect(throws: CaptureImportError.compressed("Zip")) {
                try CaptureImporter.recognizedFormat(of: zipSource)
            }
        }
    }

    @Test("A plain capture still takes the direct copy path and stays idempotent")
    func directCopyIsUnchanged() throws {
        try withDirectories { library, external in
            let payload = pcapFile()
            let source = external.appendingPathComponent("plain.pcap")
            try Data(payload).write(to: source)

            let first = try CaptureImporter.importCapture(from: source, intoDirectory: library)
            #expect(first == library.appendingPathComponent("plain.pcap"))
            #expect(try Data(contentsOf: first) == Data(payload))

            let repeated = try CaptureImporter.importCapture(from: first, intoDirectory: library)
            #expect(repeated == first)
            #expect(try directoryEntryCount(library) == 1)
        }
    }

    // MARK: Private

    private func expectMalformed(_ error: CaptureArchiveError?, sourceLocation: SourceLocation = #_sourceLocation) {
        guard case .malformed = error else {
            Issue.record(
                "Expected a damaged-archive refusal, got \(String(describing: error))",
                sourceLocation: sourceLocation
            )
            return
        }
    }

    private func expectExceedsBound(_ error: CaptureArchiveError?, sourceLocation: SourceLocation = #_sourceLocation) {
        guard case .exceedsBound = error else {
            Issue.record(
                "Expected a safety-limit refusal, got \(String(describing: error))",
                sourceLocation: sourceLocation
            )
            return
        }
    }

    /// Number of non-hidden entries in `directory`, asserting that no staging
    /// artifact from a failed or cancelled import was left behind.
    private func directoryEntryCount(_ directory: URL) throws -> Int {
        let all = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        #expect(!all.contains { $0.contains(".import-") })
        return all.filter { !$0.hasPrefix(".") }.count
    }

    private func withTemporaryDirectory(_ body: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-archive-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory)
    }

    private func withDirectories(_ body: (_ library: URL, _ external: URL) throws -> Void) throws {
        try withTemporaryDirectory { library in
            try withTemporaryDirectory { external in
                try body(library, external)
            }
        }
    }

    // MARK: Capture fixtures

    private func pcapFile(
        magic: UInt32 = 0xA1B2C3D4,
        littleEndian: Bool = false,
        marker: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
    )
        -> [UInt8]
    {
        var data = [UInt8]()
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

    /// Bytes deflate cannot meaningfully shrink, for fixtures whose compressed
    /// length has to stay predictable.
    private func noisyBytes(count: Int) -> [UInt8] {
        var state: UInt64 = 0x2545F4914F6CDD1D
        return (0 ..< count).map { _ in
            state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            return UInt8(truncatingIfNeeded: state >> 33)
        }
    }

    private func pcapngSectionHeader(littleEndian: Bool) -> [UInt8] {
        var data: [UInt8] = [0x0A, 0x0D, 0x0D, 0x0A]
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

    // MARK: Compression fixtures

    private func le16(_ value: UInt16) -> [UInt8] {
        [UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF)]
    }

    private func le32(_ value: UInt32) -> [UInt8] {
        [
            UInt8(value & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 24) & 0xFF),
        ]
    }

    private func checksum(_ bytes: [UInt8]) -> UInt32 {
        guard !bytes.isEmpty else {
            return 0
        }
        let value = bytes.withUnsafeBufferPointer { crc32(0, $0.baseAddress, uInt($0.count)) }
        return UInt32(truncatingIfNeeded: value)
    }

    private func gzipped(_ bytes: [UInt8]) -> [UInt8] {
        compressed(bytes, windowBits: 15 + 16)
    }

    private func rawDeflated(_ bytes: [UInt8]) -> [UInt8] {
        compressed(bytes, windowBits: -15)
    }

    /// Produces a real zlib stream, so the fixtures exercise the same encoder
    /// shapes the decoder will meet in the wild.
    private func compressed(_ bytes: [UInt8], windowBits: Int32) -> [UInt8] {
        var stream = z_stream()
        let started = deflateInit2_(
            &stream, 6, Z_DEFLATED, windowBits, 8, Z_DEFAULT_STRATEGY,
            zlibVersion(), Int32(MemoryLayout<z_stream>.size)
        )
        guard started == Z_OK else {
            return []
        }
        defer { deflateEnd(&stream) }
        var input = bytes.isEmpty ? [UInt8](repeating: 0, count: 1) : bytes
        let inputCount = bytes.count
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
        var output = [UInt8]()
        var offset = 0
        var finished = false
        while !finished {
            var produced = 0
            input.withUnsafeMutableBufferPointer { source in
                buffer.withUnsafeMutableBufferPointer { destination in
                    guard let sourceBase = source.baseAddress, let destinationBase = destination.baseAddress else {
                        return
                    }
                    stream.next_in = sourceBase + offset
                    stream.avail_in = uInt(inputCount - offset)
                    stream.next_out = destinationBase
                    stream.avail_out = uInt(destination.count)
                    let status = deflate(&stream, Z_FINISH)
                    offset = inputCount - Int(stream.avail_in)
                    produced = destination.count - Int(stream.avail_out)
                    finished = status == Z_STREAM_END
                    stream.next_in = nil
                    stream.avail_in = 0
                    stream.next_out = nil
                    stream.avail_out = 0
                }
            }
            output.append(contentsOf: buffer.prefix(produced))
            if produced == 0, !finished {
                break
            }
        }
        return output
    }

    // MARK: Session archive fixtures

    private func manifestJSON(
        magic: String = "TCPViewerSession",
        schemaVersion: Int = 1,
        minimum: Int = 1,
        captureFile: String = "capture.pcapng"
    )
        -> [UInt8]
    {
        let json = """
        {"magic":"\(magic)","schemaVersion":\(schemaVersion),\
        "minimumCompatibleSchemaVersion":\(minimum),"captureFile":"\(captureFile)",\
        "applicationName":"Fixture","packetCount":1,"stateFile":"state.json",\
        "packetsFile":"packets.jsonl","annotationsFile":"annotations.json",\
        "clientsFile":"clients.json","iconsDirectory":"icons","files":[],\
        "applicationVersion":"1.0","applicationBuild":"1","createdAt":"2026-09-05T00:00:00Z"}
        """
        return Array(json.utf8)
    }

    /// The observed layout: a session folder, a manifest, four sidecar documents,
    /// an icons folder and the capture.
    private func sessionEntries(
        capture: [UInt8],
        manifest: [UInt8]? = nil,
        captureMethod: UInt16 = 8
    )
        -> [ZipEntryFixture]
    {
        [
            ZipEntryFixture(name: "TCPViewerSession/", method: 0),
            ZipEntryFixture(name: "TCPViewerSession/manifest.json", data: manifest ?? manifestJSON()),
            ZipEntryFixture(name: "TCPViewerSession/state.json", data: Array(#"{"pins":[]}"#.utf8)),
            ZipEntryFixture(name: "TCPViewerSession/packets.jsonl", data: Array("{\"a\":1}\n".utf8)),
            ZipEntryFixture(name: "TCPViewerSession/annotations.json", data: Array(#"{"annotations":[]}"#.utf8)),
            ZipEntryFixture(name: "TCPViewerSession/clients.json", data: Array(#"{"clients":[]}"#.utf8)),
            ZipEntryFixture(name: "TCPViewerSession/icons/", method: 0),
            ZipEntryFixture(name: "TCPViewerSession/capture.pcapng", data: capture, method: captureMethod),
        ]
    }

    /// Assembles a ZIP byte for byte so each structural defect under test is the
    /// only thing that differs from a well-formed archive.
    private func makeZip(
        _ entries: [ZipEntryFixture],
        comment: [UInt8] = [],
        diskNumber: UInt16 = 0,
        entryCountDelta: Int = 0,
        centralDirectoryOffsetOverride: UInt32? = nil,
        zip64Locator: Bool = false
    )
        -> [UInt8]
    {
        var output = [UInt8]()
        var records = [(entry: ZipEntryFixture, offset: UInt32, payload: [UInt8], crc: UInt32)]()
        for entry in entries {
            let nameBytes = entry.nameBytesOverride ?? Array(entry.name.utf8)
            let localNameBytes = entry.localNameOverride.map { Array($0.utf8) } ?? nameBytes
            let payload = entry.method == 8 ? rawDeflated(entry.data) : entry.data
            let crc = checksum(entry.data)
            let offset = UInt32(output.count)
            output.append(contentsOf: le32(0x04034B50))
            output.append(contentsOf: le16(20))
            output.append(contentsOf: le16(entry.flags))
            output.append(contentsOf: le16(entry.localMethodOverride ?? entry.method))
            output.append(contentsOf: le16(0))
            output.append(contentsOf: le16(0))
            output.append(contentsOf: le32(entry.zeroLocalSizes ? 0 : crc))
            output.append(contentsOf: le32(entry.zeroLocalSizes ? 0 : UInt32(payload.count)))
            output.append(contentsOf: le32(entry.zeroLocalSizes ? 0 : UInt32(entry.data.count)))
            output.append(contentsOf: le16(UInt16(localNameBytes.count)))
            output.append(contentsOf: le16(0))
            output.append(contentsOf: localNameBytes)
            output.append(contentsOf: payload)
            if entry.appendDataDescriptor {
                output.append(contentsOf: le32(0x08074B50))
                output.append(contentsOf: le32(crc))
                output.append(contentsOf: le32(UInt32(payload.count)))
                output.append(contentsOf: le32(UInt32(entry.data.count)))
            }
            records.append((entry, offset, payload, crc))
        }
        let directoryOffset = UInt32(output.count)
        for record in records {
            let nameBytes = record.entry.nameBytesOverride ?? Array(record.entry.name.utf8)
            output.append(contentsOf: le32(0x02014B50))
            output.append(contentsOf: le16(20))
            output.append(contentsOf: le16(20))
            output.append(contentsOf: le16(record.entry.flags))
            output.append(contentsOf: le16(record.entry.method))
            output.append(contentsOf: le16(0))
            output.append(contentsOf: le16(0))
            output.append(contentsOf: le32(record.entry.centralCrc ?? record.crc))
            output.append(contentsOf: le32(record.entry.centralCompressedSize ?? UInt32(record.payload.count)))
            output.append(contentsOf: le32(record.entry.centralUncompressedSize ?? UInt32(record.entry.data.count)))
            output.append(contentsOf: le16(UInt16(nameBytes.count)))
            output.append(contentsOf: le16(0))
            output.append(contentsOf: le16(0))
            output.append(contentsOf: le16(0))
            output.append(contentsOf: le16(0))
            output.append(contentsOf: le32(record.entry.externalAttributes))
            output.append(contentsOf: le32(record.entry.centralLocalOffset ?? record.offset))
            output.append(contentsOf: nameBytes)
        }
        let directorySize = UInt32(output.count) - directoryOffset
        if zip64Locator {
            output.append(contentsOf: le32(0x07064B50))
            output.append(contentsOf: Array(repeating: 0, count: 16))
        }
        let declaredCount = UInt16(max(0, records.count + entryCountDelta))
        output.append(contentsOf: le32(0x06054B50))
        output.append(contentsOf: le16(diskNumber))
        output.append(contentsOf: le16(0))
        output.append(contentsOf: le16(declaredCount))
        output.append(contentsOf: le16(declaredCount))
        output.append(contentsOf: le32(directorySize))
        output.append(contentsOf: le32(centralDirectoryOffsetOverride ?? directoryOffset))
        output.append(contentsOf: le16(UInt16(comment.count)))
        output.append(contentsOf: comment)
        return output
    }
}
