import Foundation
import Testing
@testable import Tracexy

// MARK: - CaptureReferenceTests

/// In-place Library references: sidecar round trip, identity/digest validation,
/// moved-versus-different detection, availability, and the bounded preview scan
/// that backs the Open panel.
struct CaptureReferenceTests {
    // MARK: Internal

    @Test
    func referenceRoundTripsThroughSidecar() throws {
        try withCaptureFile { url, directory in
            let reference = try CaptureReference.create(for: url, now: Date(timeIntervalSince1970: 1_700_000_000))
            let sidecar = directory.appendingPathComponent("sample.tracexyref")
            try reference.write(to: sidecar)
            let read = try CaptureReference.read(from: sidecar)
            #expect(read == reference)
            #expect(read.displayName == "sample")
            #expect(read.headDigest.count == 64)
            #expect(read.currentAvailability() == .available)
        }
    }

    @Test
    func missingAndChangedFilesAreDistinguished() throws {
        try withCaptureFile { url, _ in
            let reference = try CaptureReference.create(for: url)
            try FileManager.default.removeItem(at: url)
            #expect(reference.currentAvailability() == .missing)
            try Data(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation(), variant: .bigMicro)).write(to: url)
            #expect(reference.currentAvailability() == .changed)
        }
    }

    @Test
    func relocatedFileMatchesAndDifferentFileIsRefused() throws {
        try withCaptureFile { url, directory in
            let reference = try CaptureReference.create(for: url)
            let moved = directory.appendingPathComponent("moved.pcap")
            try FileManager.default.copyItem(at: url, to: moved)
            guard case let .relocated(identity) = reference.match(candidate: moved) else {
                Issue.record("expected relocated match")
                return
            }
            #expect(identity.size == reference.identity.size)
            let updated = reference.relocated(to: moved, identity: identity)
            #expect(updated.url == moved.standardizedFileURL)
            #expect(updated.currentAvailability() == .available)

            let other = directory.appendingPathComponent("other.pcap")
            try Data(ReplayCorpus.classicPcapBytes(ReplayCorpus.tcpConnectionFrames())).write(to: other)
            guard case .mismatch = reference.match(candidate: other) else {
                Issue.record("expected mismatch")
                return
            }
            #expect(reference.match(candidate: url) == .identical)
        }
    }

    @Test
    func damagedOrOversizedSidecarIsRefused() throws {
        try withCaptureFile { _, directory in
            let sidecar = directory.appendingPathComponent("bad.tracexyref")
            try Data("{\"formatVersion\":1}".utf8).write(to: sidecar)
            #expect(throws: (any Error).self) {
                try CaptureReference.read(from: sidecar)
            }
            let big = directory.appendingPathComponent("big.tracexyref")
            try Data(repeating: 0x20, count: CaptureReference.maxSidecarBytes + 1).write(to: big)
            #expect(throws: CaptureReferenceError.invalidSidecar("size \(CaptureReference.maxSidecarBytes + 1)")) {
                try CaptureReference.read(from: big)
            }
            let future = directory.appendingPathComponent("future.tracexyref")
            try Data(
                """
                {"formatVersion":9,"path":"/x","displayName":"x","identity":{"size":1,"device":0,"inode":0},\
                "headDigest":"\(String(repeating: "a", count: 64))","addedAt":1700000000}
                """.utf8
            ).write(to: future)
            #expect(throws: CaptureReferenceError.unsupportedVersion(9)) {
                try CaptureReference.read(from: future)
            }
        }
    }

    // MARK: Preview

    @Test
    func previewScansCompleteFileWithTimes() throws {
        try withCaptureFile { url, _ in
            let preview = CapturePreviewScanner.scan(url)
            #expect(preview.status == .complete)
            #expect(preview.records == ReplayCorpus.conversation().count)
            #expect(preview.formatDescription.contains("PCAP"))
            let offsets = ReplayCorpus.conversation().map(\.offsetSeconds)
            #expect(preview.elapsed == TimeInterval((offsets.max() ?? 0) - (offsets.min() ?? 0)))
            #expect(preview.fileSize > 0)
        }
    }

    @Test
    func previewStopsAtRecordBudgetAndReportsLowerBound() throws {
        try withCaptureFile { url, _ in
            let preview = CapturePreviewScanner.scan(url, budget: .init(maxRecords: 3))
            #expect(preview.status == .timedOut)
            #expect(preview.records == 3)
            #expect(preview.elapsed == nil)
            #expect(CaptureOpenAccessoryView.sizeText(preview).contains("timed out at 3 records"))
        }
    }

    @Test
    func previewReportsUnknownFormatDirectoryAndCompressed() throws {
        try withCaptureFile { url, directory in
            let text = directory.appendingPathComponent("notes.txt")
            try Data("hello, this is not a capture at all".utf8).write(to: text)
            #expect(CapturePreviewScanner.scan(text).status == .unknownFormat)
            #expect(CapturePreviewScanner.scan(directory).status == .directory)
            let gzip = directory.appendingPathComponent("capture.pcap.gz")
            try Data([0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]).write(to: gzip)
            guard case .compressed = CapturePreviewScanner.scan(gzip).status else {
                Issue.record("expected compressed")
                return
            }
            #expect(CapturePreviewScanner.scan(url.appendingPathExtension("missing")).status == .unreadable)
        }
    }

    @Test
    func previewTruncatedFileIsErrorAfterRecords() throws {
        try withCaptureFile { url, directory in
            var bytes = try [UInt8](Data(contentsOf: url))
            bytes.removeLast(5)
            let cut = directory.appendingPathComponent("cut.pcap")
            try Data(bytes).write(to: cut)
            let preview = CapturePreviewScanner.scan(cut)
            // A cut tail is a terminal, not an error: the reader reports the frames
            // it could read completely.
            #expect(preview.status == .complete)
            #expect(preview.records == ReplayCorpus.conversation().count - 1)
        }
    }

    @Test
    func accessoryTextMatchesWiresharkDistinctions() {
        let complete = CapturePreview(
            status: .complete, formatDescription: "PCAPNG", fileSize: 12_345, records: 10,
            firstTimestamp: Date(timeIntervalSince1970: 0), lastTimestamp: Date(timeIntervalSince1970: 90_061)
        )
        #expect(CaptureOpenAccessoryView.sizeText(complete).hasSuffix("10 records"))
        #expect(CaptureOpenAccessoryView.elapsedText(90_061) == "1 day(s) 01:01:01")
        let untimed = CapturePreview(
            status: .complete, formatDescription: "PCAPNG", fileSize: 1, records: 1,
            firstTimestamp: nil, lastTimestamp: nil
        )
        #expect(CaptureOpenAccessoryView.timeText(untimed) == "unknown / unknown")
        let unknown = CapturePreview(
            status: .unknownFormat, formatDescription: "", fileSize: 1, records: 0,
            firstTimestamp: nil, lastTimestamp: nil
        )
        #expect(CaptureOpenAccessoryView.formatText(unknown) == "Unknown file format")
    }

    // MARK: Private

    private func withCaptureFile(_ body: (URL, URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-ref-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("sample.pcap")
        try Data(ReplayCorpus.classicPcapBytes(ReplayCorpus.conversation())).write(to: url)
        try body(url, directory)
    }
}
