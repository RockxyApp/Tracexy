import Foundation

/// Disk-backed, append-only pcapng spool for the current live capture.
///
/// The UI keeps only a bounded frame window in memory, while this actor preserves
/// every accepted frame for complete save/session export. All file IO is actor-
/// isolated and therefore stays off `@MainActor`. The spool is local, temporary,
/// and replaced only at an explicit capture boundary.
actor LiveCaptureSpool {
    // MARK: Lifecycle

    init(directoryName: String) {
        let base = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        self.init(directory: base
            .appendingPathComponent(directoryName, isDirectory: true)
            .appendingPathComponent("LiveCaptureSpool", isDirectory: true))
    }

    /// Test/inspection seam: root the spool at an explicit directory. Production
    /// code uses `init(directoryName:)`, which places the spool under the app cache.
    init(directory: URL) {
        self.directory = directory
    }

    deinit {
        // Normal teardown: release the advisory lock and drop this actor's own
        // current spool file so it is never left behind for later cleanup.
        try? handle?.close()
        if let url {
            try? FileManager.default.removeItem(at: url)
        }
    }

    // MARK: Internal

    enum Failure: Error, LocalizedError {
        case unavailable(String)
        case empty
        /// The evidence locator's epoch or source token no longer matches this
        /// spool — a locator from a superseded capture generation.
        case staleEvidence
        /// The locator's length/offset is out of bounds, overruns the current
        /// file, or the exact read came up short/truncated.
        case invalidEvidence(String)
        /// A frame arrived with no capture time. Live frames come from the helper's
        /// validated `pcap_pkthdr`, which always carries one, so this is rejected
        /// rather than written with a substituted instant.
        case untimedFrame
        /// The frame's file was closed into the capture's file set and later removed
        /// by its "keep newest" limit.
        case rotatedOut

        // MARK: Internal

        var errorDescription: String? {
            switch self {
            case let .unavailable(message): message
            case .empty: "The live capture spool has no frames."
            case .staleEvidence: "The requested capture evidence is no longer available."
            case let .invalidEvidence(message): "The capture evidence is invalid: \(message)"
            case .untimedFrame: "A live capture frame arrived without a capture time and was not recorded."
            case .rotatedOut:
                "This frame’s file was removed by the capture’s file-set limit, so its bytes are no longer available."
            }
        }
    }

    /// Settings → Capture → Save as a file set: the spool closes its file and starts
    /// a new one after `maxFileBytes` or `maxFileDuration` (whichever comes first),
    /// moving each closed file into `directory` under the `CaptureFileSet` naming.
    /// With `keepFiles > 0` only that many newest files are kept (the open one
    /// included) — older ones are deleted, which is what the user chose; evidence
    /// cited from them then fails closed as rotated out.
    struct FileSetPolicy: Sendable, Equatable {
        var maxFileBytes: UInt64?
        var maxFileDuration: TimeInterval?
        var keepFiles: Int = 0
        var directory: URL
        var prefix: String = "capture"

        var isEnabled: Bool {
            (maxFileBytes ?? 0) > 0 || (maxFileDuration ?? 0) > 0
        }
    }

    /// What the file set holds once a capture ends.
    struct FileSetSummary: Sendable, Equatable {
        let directory: URL
        let files: [URL]
        let removedFileCount: Int
    }

    /// The typed outcome of an ``append(_:defaultLinkType:epoch:)``. A stale-epoch
    /// append writes nothing and is reported distinctly from a current append,
    /// which returns exactly one locator per input frame in order (empty for an
    /// empty batch).
    enum AppendResult: Sendable {
        case staleEpoch
        case appended([SessionEvidenceLocator])
    }

    func reset(epoch: Int, fileSet: FileSetPolicy? = nil) throws {
        self.fileSet = fileSet?.isEnabled == true ? fileSet : nil
        closedSegments.removeAll()
        rotatedOutTokens.removeAll()
        removedFileCount = 0
        segmentSequence = 0
        segmentStart = nil
        // Invalidate all prior evidence *before* preparing the new file: no
        // locator minted against the old source token can resolve once reset
        // begins, and a failed preparation leaves no valid token behind.
        sourceToken = nil
        try handle?.close()
        handle = nil
        if let url {
            try? FileManager.default.removeItem(at: url)
        }
        self.epoch = epoch
        url = nil
        interfaceIDs.removeAll(keepingCapacity: false)
        frameCount = 0
        writeOffset = 0
        failure = nil
        do {
            try prepareFile()
        } catch {
            failure = error.localizedDescription
            throw error
        }
        // The new file is valid: mint a fresh opaque token for the evidence
        // locators appended into it.
        sourceToken = UUID()
    }

    @discardableResult
    func append(_ frames: [CapturedFrame], defaultLinkType: UInt32, epoch: Int) throws -> AppendResult {
        guard epoch == self.epoch else {
            // A superseded generation never writes; the caller distinguishes this
            // from a real failure and offers the frames with nil locators.
            return .staleEpoch
        }
        guard !frames.isEmpty else {
            return .appended([])
        }
        guard failure == nil, handle != nil, sourceToken != nil else {
            throw Failure.unavailable(failure ?? "The local capture spool is unavailable.")
        }
        // The spool writes Enhanced Packet Blocks, whose timestamp field is
        // mandatory. A live frame always carries one (the helper validates its
        // `pcap_pkthdr` before the frame is built), so an untimed frame is rejected
        // outright rather than written with the epoch or the current clock.
        let timedFrames = try frames.map { frame -> (CapturedFrame, UInt64) in
            guard let timestamp = frame.timestamp else {
                throw Failure.untimedFrame
            }
            return try (frame, CaptureTimestampEncoding.microseconds(timestamp))
        }
        var locators: [SessionEvidenceLocator] = []
        locators.reserveCapacity(frames.count)
        do {
            for (frame, microseconds) in timedFrames {
                if let timestamp = frame.timestamp, shouldRotate(before: timestamp) {
                    try rotate()
                }
                guard let handle, let token = sourceToken else {
                    throw Failure.unavailable("The local capture spool is unavailable.")
                }
                if segmentStart == nil {
                    segmentStart = frame.timestamp
                }
                let linkType = frame.linkType ?? defaultLinkType
                let interfaceID: UInt32
                if let existing = interfaceIDs[linkType] {
                    interfaceID = existing
                } else {
                    guard linkType <= UInt32(UInt16.max) else {
                        throw Failure.unavailable("Capture link type \(linkType) cannot be written to pcapng.")
                    }
                    interfaceID = UInt32(interfaceIDs.count)
                    let idb = Self.interfaceDescriptionBlock(linkType: linkType)
                    try handle.write(contentsOf: idb)
                    // A newly emitted interface block advances the offset before the
                    // enhanced block, so the locator points past it — not skewed.
                    try advanceWriteOffset(by: idb.count)
                    interfaceIDs[linkType] = interfaceID
                }
                let block = Self.enhancedPacketBlock(frame: frame, interfaceID: interfaceID, microseconds: microseconds)
                // The absolute payload-byte offset of this frame's captured bytes
                // inside its enhanced packet block (fixed prefix past the block and
                // record headers). Independent of any link-type mix.
                let (payloadOffset, payloadOverflow) = writeOffset.addingReportingOverflow(
                    UInt64(Self.enhancedPacketPayloadPrefix)
                )
                guard !payloadOverflow else {
                    throw Failure.unavailable("The local capture spool offset overflowed.")
                }
                try handle.write(contentsOf: block)
                try advanceWriteOffset(by: block.count)
                locators.append(SessionEvidenceLocator(sourceToken: token, offset: payloadOffset))
                frameCount += 1
            }
        } catch {
            let message = error.localizedDescription
            failure = message
            throw Failure.unavailable(message)
        }
        return .appended(locators)
    }

    /// Read exactly the captured bytes an evidence locator points at, validated
    /// against the current capture generation and file.
    ///
    /// Everything is checked before the read: the epoch and source token must be
    /// the live ones, the length must be within `0...CapturedFrame.maxReasonableLength`,
    /// and `offset + length` must neither overflow nor overrun the synchronized
    /// current file size. The read happens through a *separate* read handle, so the
    /// append handle's write offset is never disturbed, and no URL or file identity
    /// is exposed. Every failure is a typed, controlled ``Failure`` — never a trap.
    func read(_ locator: SessionEvidenceLocator, capturedLength: Int, epoch: Int) throws -> [UInt8] {
        guard epoch == self.epoch else {
            throw Failure.staleEvidence
        }
        return try readCurrentSource(locator, capturedLength: capturedLength)
    }

    /// Read one locator from the spool source that is current now, regardless of
    /// the coordinator generation used to publish it. Stopping a capture advances
    /// the coordinator generation without replacing the spool; the opaque source
    /// token remains the authority for whether a locator still belongs here.
    /// A reset mints a new token, so evidence from every superseded spool still
    /// fails as stale before any offset is read.
    func readCurrentSource(_ locator: SessionEvidenceLocator, capturedLength: Int) throws -> [UInt8] {
        if let closed = closedSegments.first(where: { $0.token == locator.sourceToken }) {
            return try Self.read(locator, capturedLength: capturedLength, from: closed.url)
        }
        if rotatedOutTokens.contains(locator.sourceToken) {
            throw Failure.rotatedOut
        }
        guard let token = sourceToken, locator.sourceToken == token else {
            throw Failure.staleEvidence
        }
        // Evidence written before a mid-append failure is still recoverable — the
        // offset-vs-size check below bounds the read to bytes actually present — so
        // this does not gate on `failure`, only on a usable file/handle.
        guard let url, let handle else {
            throw Failure.unavailable(failure ?? "The local capture spool is unavailable.")
        }
        guard capturedLength >= 0, capturedLength <= CapturedFrame.maxReasonableLength else {
            throw Failure.invalidEvidence("captured length \(capturedLength) out of bounds")
        }
        let (end, overflow) = locator.offset.addingReportingOverflow(UInt64(capturedLength))
        guard !overflow else {
            throw Failure.invalidEvidence("evidence offset/length overflow")
        }
        // Flush the append handle so a read handle opened now sees every byte
        // written so far, then bound the read against the synchronized size.
        try handle.synchronize()
        let readHandle = try FileHandle(forReadingFrom: url)
        defer { try? readHandle.close() }
        let size = try readHandle.seekToEnd()
        guard end <= size else {
            throw Failure.invalidEvidence("evidence overruns the current spool file")
        }
        try readHandle.seek(toOffset: locator.offset)
        var collected = Data()
        collected.reserveCapacity(capturedLength)
        while collected.count < capturedLength {
            guard let chunk = try readHandle.read(upToCount: capturedLength - collected.count),
                  !chunk.isEmpty else
            {
                break
            }
            collected.append(chunk)
        }
        guard collected.count == capturedLength else {
            throw Failure.invalidEvidence("short read of selected evidence")
        }
        return [UInt8](collected)
    }

    /// Close the file set when a capture ends: a copy of the open file becomes the
    /// set's last member, so the folder holds everything still kept. The spool file
    /// itself stays for Save, export and evidence. `nil` when no file set is on.
    func finishFileSet() throws -> FileSetSummary? {
        guard let fileSet, frameCount > 0 || !closedSegments.isEmpty else {
            return nil
        }
        var files = closedSegments.map(\.url)
        if frameCount > 0, let url {
            try handle?.synchronize()
            let destination = try nextSetMemberURL(in: fileSet)
            try FileManager.default.copyItem(at: url, to: destination)
            files.append(destination)
            segmentSequence += 1
        }
        let summary = FileSetSummary(directory: fileSet.directory, files: files, removedFileCount: removedFileCount)
        self.fileSet = nil
        return summary
    }

    func capture() throws -> (linkType: UInt32, frames: [CapturedFrame]) {
        guard frameCount > 0, let url else {
            throw Failure.empty
        }
        try handle?.synchronize()
        return try CaptureFileReader.read(contentsOf: url)
    }

    /// The opaque token locators of the current spool source carry. A scan over a
    /// byte-identical copy of the spool may mint locators with this token, because
    /// the copy's payload offsets equal the spool's; ``readCurrentSource`` still
    /// validates every read against the live file.
    func currentSourceToken() -> UUID? {
        sourceToken
    }

    func copy(to destination: URL) throws {
        guard frameCount > 0, let url else {
            throw Failure.empty
        }
        try handle?.synchronize()
        try FileManager.default.copyItem(at: url, to: destination)
    }

    /// Write every frame this capture still keeps to `destination`: the open file
    /// alone, or — once a file set has closed files — those files and the open one
    /// merged in capture order. Save Capture and whole-capture exports use this;
    /// evidence scans that need byte-identical offsets keep using ``copy(to:)``.
    func copyWholeCapture(to destination: URL) throws {
        guard !closedSegments.isEmpty else {
            try copy(to: destination)
            return
        }
        try handle?.synchronize()
        var sources = closedSegments.map(\.url)
        if frameCount > 0, let url {
            sources.append(url)
        }
        if sources.count == 1 {
            try FileManager.default.copyItem(at: sources[0], to: destination)
        } else {
            _ = try CaptureMerger.merge(sources: sources, to: destination)
        }
    }

    /// Whether earlier frames of this capture live in file-set files beside the
    /// open one (so a byte-identical copy of the open file is not the whole capture).
    func hasClosedFileSetFiles() -> Bool {
        !closedSegments.isEmpty
    }

    /// Non-nil means the file is a valid recoverable prefix, not a complete
    /// capture. Callers keep this warning visible after an explicit save/export.
    func incompletenessReason() -> String? {
        failure
    }

    // MARK: Private

    /// One closed file of the current capture's file set: where it now lives and the
    /// evidence token its locators carry.
    private struct ClosedSegment: Sendable {
        let url: URL
        let token: UUID
    }

    /// Byte length of an enhanced packet block's fixed prefix before the captured
    /// payload: the 8-byte block header (type + total length) plus the 20-byte
    /// fixed record fields (interface id, timestamp high/low, captured length,
    /// original length). The payload bytes begin exactly here.
    private static let enhancedPacketPayloadPrefix = 28

    /// Tokens of set members removed by the keep limit, bounded; reads citing them
    /// report ``Failure/rotatedOut`` instead of a generic stale answer.
    private static let maxRememberedRotatedTokens = 4_096

    private let directory: URL
    private var fileSet: FileSetPolicy?
    private var closedSegments: [ClosedSegment] = []
    private var rotatedOutTokens: Set<UUID> = []
    private var removedFileCount = 0
    private var segmentSequence = 0
    /// Capture time of the open file's first frame, for the duration limit and its name.
    private var segmentStart: Date?
    private var epoch = -1
    private var url: URL?
    private var handle: FileHandle?
    private var interfaceIDs: [UInt32: UInt32] = [:]
    private var frameCount = 0
    private var failure: String?
    /// The current file's fresh opaque evidence token, minted only after a valid
    /// reset and cleared whenever the file is invalid. `nil` means no locator can
    /// resolve.
    private var sourceToken: UUID?
    /// The next byte position the append handle will write, tracked so a locator's
    /// payload offset is known before the block is written. Bounded counter state;
    /// no locator array or ordinal map is retained.
    private var writeOffset: UInt64 = 0

    private static func sectionHeaderBlock() -> Data {
        block(type: 0x0A0D0D0A) { body in
            append32(0x1A2B3C4D, to: &body)
            append16(1, to: &body)
            append16(0, to: &body)
            append64(UInt64.max, to: &body)
        }
    }

    private static func interfaceDescriptionBlock(linkType: UInt32) -> Data {
        block(type: 0x00000001) { body in
            append16(UInt16(linkType), to: &body)
            append16(0, to: &body)
            append32(PcapWriter.snapLength, to: &body)
        }
    }

    private static func enhancedPacketBlock(frame: CapturedFrame, interfaceID: UInt32, microseconds: UInt64) -> Data {
        block(type: 0x00000006) { body in
            append32(interfaceID, to: &body)
            append32(UInt32(microseconds >> 32), to: &body)
            append32(UInt32(microseconds & UInt64(UInt32.max)), to: &body)
            append32(UInt32(frame.bytes.count), to: &body)
            append32(UInt32(max(frame.originalLength, frame.bytes.count)), to: &body)
            body.append(contentsOf: frame.bytes)
        }
    }

    private static func block(type: UInt32, body build: (inout Data) -> Void) -> Data {
        var body = Data()
        build(&body)
        while body.count % 4 != 0 {
            body.append(0)
        }
        var data = Data()
        let totalLength = UInt32(12 + body.count)
        append32(type, to: &data)
        append32(totalLength, to: &data)
        data.append(body)
        append32(totalLength, to: &data)
        return data
    }

    private static func append16(_ value: UInt16, to data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
    }

    private static func append32(_ value: UInt32, to data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
    }

    private static func append64(_ value: UInt64, to data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
    }

    private static func isOrphanCandidate(_ url: URL) -> Bool {
        let name = url.lastPathComponent
        let published = name.hasPrefix("capture-") && name.hasSuffix(".pcapng")
        let staging = name.hasPrefix(".capture-") && name.hasSuffix(".pcapng.staging")
        return published || staging
    }

    private static func read(_ locator: SessionEvidenceLocator, capturedLength: Int, from url: URL) throws -> [UInt8] {
        guard capturedLength >= 0, capturedLength <= CapturedFrame.maxReasonableLength else {
            throw Failure.invalidEvidence("captured length \(capturedLength) out of bounds")
        }
        let readHandle: FileHandle
        do {
            readHandle = try FileHandle(forReadingFrom: url)
        } catch {
            throw Failure.rotatedOut
        }
        defer { try? readHandle.close() }
        let size = try readHandle.seekToEnd()
        let (end, overflow) = locator.offset.addingReportingOverflow(UInt64(capturedLength))
        guard !overflow, end <= size else {
            throw Failure.invalidEvidence("evidence overruns its file-set member")
        }
        try readHandle.seek(toOffset: locator.offset)
        let data = try readHandle.read(upToCount: capturedLength) ?? Data()
        guard data.count == capturedLength else {
            throw Failure.invalidEvidence("short read of selected evidence")
        }
        return [UInt8](data)
    }

    /// Whether the open file must close before a frame captured at `timestamp` is
    /// written: only with a file set on, and never while the open file is empty.
    private func shouldRotate(before timestamp: Date) -> Bool {
        guard let fileSet, frameCount > 0 else {
            return false
        }
        if let limit = fileSet.maxFileBytes, limit > 0, writeOffset >= limit {
            return true
        }
        if let limit = fileSet.maxFileDuration, limit > 0, let start = segmentStart,
           timestamp.timeIntervalSince(start) >= limit
        {
            return true
        }
        return false
    }

    /// Close the open file into the set and start a new one with a fresh token.
    private func rotate() throws {
        guard let fileSet, let url, let token = sourceToken else {
            return
        }
        try handle?.synchronize()
        try handle?.close()
        handle = nil
        let destination = try nextSetMemberURL(in: fileSet)
        try FileManager.default.moveItem(at: url, to: destination)
        segmentSequence += 1
        closedSegments.append(ClosedSegment(url: destination, token: token))
        // The open file counts as one of the kept files.
        while fileSet.keepFiles > 0, closedSegments.count >= fileSet.keepFiles {
            let oldest = closedSegments.removeFirst()
            try? FileManager.default.removeItem(at: oldest.url)
            removedFileCount += 1
            if rotatedOutTokens.count < Self.maxRememberedRotatedTokens {
                rotatedOutTokens.insert(oldest.token)
            }
        }
        self.url = nil
        interfaceIDs.removeAll(keepingCapacity: true)
        frameCount = 0
        segmentStart = nil
        sourceToken = nil
        try prepareFile()
        sourceToken = UUID()
    }

    private func nextSetMemberURL(in fileSet: FileSetPolicy) throws -> URL {
        try FileManager.default.createDirectory(at: fileSet.directory, withIntermediateDirectories: true)
        let name = CaptureSplitter.fileName(
            prefix: fileSet.prefix, sequence: segmentSequence + 1, time: segmentStart ?? Date(), timeZone: .current
        )
        return fileSet.directory.appendingPathComponent(name)
    }

    private func advanceWriteOffset(by byteCount: Int) throws {
        let (next, overflow) = writeOffset.addingReportingOverflow(UInt64(byteCount))
        guard !overflow else {
            throw Failure.unavailable("The local capture spool offset overflowed.")
        }
        writeOffset = next
    }

    private func prepareFile() throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        removeInactiveOrphans()

        // Stage under a hidden name the cleanup pattern never matches, lock it, then
        // publish it under the final `capture-*.pcapng` name via an atomic rename. The
        // file is therefore already locked the instant it becomes a cleanup candidate,
        // so a concurrent spool can never delete this actor's file mid-preparation.
        let name = UUID().uuidString
        let stagingURL = directory.appendingPathComponent(".capture-\(name).pcapng.staging")
        let finalURL = directory.appendingPathComponent("capture-\(name).pcapng")

        guard FileManager.default.createFile(atPath: stagingURL.path, contents: nil) else {
            throw Failure.unavailable("Couldn’t create the local capture spool.")
        }

        let nextHandle: FileHandle
        do {
            nextHandle = try FileHandle(forWritingTo: stagingURL)
        } catch {
            try? FileManager.default.removeItem(at: stagingURL)
            throw Failure.unavailable(error.localizedDescription)
        }

        guard flock(nextHandle.fileDescriptor, LOCK_EX | LOCK_NB) == 0 else {
            try? nextHandle.close()
            try? FileManager.default.removeItem(at: stagingURL)
            throw Failure.unavailable("Couldn’t lock the local capture spool.")
        }

        let header = Self.sectionHeaderBlock()
        do {
            try nextHandle.write(contentsOf: header)
            try FileManager.default.moveItem(at: stagingURL, to: finalURL)
        } catch {
            try? nextHandle.close() // releases the advisory lock
            try? FileManager.default.removeItem(at: stagingURL)
            try? FileManager.default.removeItem(at: finalURL)
            throw Failure.unavailable(error.localizedDescription)
        }

        url = finalURL
        handle = nextHandle
        // The append offset starts past the section header block.
        writeOffset = UInt64(header.count)
    }

    /// Best-effort recovery of spool files left by crashed instances. Scoped strictly
    /// to this spool's directory and exact filename pattern; a candidate is removed only
    /// when an exclusive advisory lock proves no live handle holds it. Never throws.
    private func removeInactiveOrphans() {
        guard let entries = try? FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: nil,
            options: [.skipsSubdirectoryDescendants]
        ) else {
            return
        }
        for entry in entries where Self.isOrphanCandidate(entry) {
            removeIfUnlocked(entry)
        }
    }

    private func removeIfUnlocked(_ candidate: URL) {
        // O_NOFOLLOW refuses symlinks; O_NONBLOCK avoids blocking on special files.
        let descriptor = open(candidate.path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW)
        guard descriptor >= 0 else {
            return
        }
        defer { close(descriptor) }
        // A directory can be named like a spool file. Prove the opened object is
        // a regular file before any removal so cleanup never recurses into a
        // directory or touches another filesystem object type.
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG else
        {
            return
        }
        // A live spool holds LOCK_EX on its open handle, so this fails for active files.
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            return
        }
        try? FileManager.default.removeItem(at: candidate)
    }
}
