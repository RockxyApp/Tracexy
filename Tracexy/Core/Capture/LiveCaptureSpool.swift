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

        // MARK: Internal

        var errorDescription: String? {
            switch self {
            case let .unavailable(message): message
            case .empty: "The live capture spool has no frames."
            case .staleEvidence: "The requested capture evidence is no longer available."
            case let .invalidEvidence(message): "The capture evidence is invalid: \(message)"
            }
        }
    }

    /// The typed outcome of an ``append(_:defaultLinkType:epoch:)``. A stale-epoch
    /// append writes nothing and is reported distinctly from a current append,
    /// which returns exactly one locator per input frame in order (empty for an
    /// empty batch).
    enum AppendResult: Sendable {
        case staleEpoch
        case appended([SessionEvidenceLocator])
    }

    func reset(epoch: Int) throws {
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
        guard failure == nil, let handle, let token = sourceToken else {
            throw Failure.unavailable(failure ?? "The local capture spool is unavailable.")
        }
        var locators: [SessionEvidenceLocator] = []
        locators.reserveCapacity(frames.count)
        do {
            for frame in frames {
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
                let block = Self.enhancedPacketBlock(frame: frame, interfaceID: interfaceID)
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

    func capture() throws -> (linkType: UInt32, frames: [CapturedFrame]) {
        guard frameCount > 0, let url else {
            throw Failure.empty
        }
        try handle?.synchronize()
        return try CaptureFileReader.read(contentsOf: url)
    }

    func copy(to destination: URL) throws {
        guard frameCount > 0, let url else {
            throw Failure.empty
        }
        try handle?.synchronize()
        try FileManager.default.copyItem(at: url, to: destination)
    }

    /// Non-nil means the file is a valid recoverable prefix, not a complete
    /// capture. Callers keep this warning visible after an explicit save/export.
    func incompletenessReason() -> String? {
        failure
    }

    // MARK: Private

    /// Byte length of an enhanced packet block's fixed prefix before the captured
    /// payload: the 8-byte block header (type + total length) plus the 20-byte
    /// fixed record fields (interface id, timestamp high/low, captured length,
    /// original length). The payload bytes begin exactly here.
    private static let enhancedPacketPayloadPrefix = 28

    private let directory: URL
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

    private static func enhancedPacketBlock(frame: CapturedFrame, interfaceID: UInt32) -> Data {
        block(type: 0x00000006) { body in
            let microseconds = timestampMicroseconds(frame.timestamp)
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

    private static func timestampMicroseconds(_ date: Date) -> UInt64 {
        let interval = max(0, date.timeIntervalSince1970)
        return UInt64(min((interval * 1_000_000).rounded(), Double(UInt64.max)))
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
