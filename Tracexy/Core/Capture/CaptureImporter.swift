import Darwin
import Foundation

// MARK: - CaptureContentFormat

/// A capture container Tracexy can open, recognized from a file's leading magic
/// bytes rather than from its name.
nonisolated enum CaptureContentFormat: Sendable, Equatable {
    case pcap
    case pcapng

    // MARK: Internal

    /// The filename extension a managed Library copy must carry. Library
    /// discovery is extension-based, so a copy without one of these could never
    /// be listed or reopened.
    var managedPathExtension: String {
        switch self {
        case .pcap: "pcap"
        case .pcapng: "pcapng"
        }
    }
}

// MARK: - CaptureImportError

/// Why an import was refused *before* anything was added to the Library.
///
/// Every message names the next thing the user can do. None of them claims the
/// file parses end to end: recognition only inspects a bounded header.
nonisolated enum CaptureImportError: LocalizedError, Equatable {
    case sourceIsDirectory
    case sourceIsNotRegularFile
    case sourceIsEmpty
    case sourceIsTruncated
    case sourceChangedDuringImport
    case compressed(String)
    case unsupportedContent
    case unreadableSource(String)
    case publicationFailed(String)
    case noAvailableManagedName

    // MARK: Internal

    var errorDescription: String? {
        switch self {
        case .sourceIsDirectory:
            "Choose a single capture file. Folders and packages can’t be imported."
        case .sourceIsNotRegularFile:
            "Choose a regular file. Devices, sockets and pipes can’t be imported."
        case .sourceIsEmpty:
            "The file is empty, so it holds no capture data."
        case .sourceIsTruncated:
            "The file is too short to hold a complete capture header. It may still be downloading."
        case .sourceChangedDuringImport:
            "The file changed while it was being copied, so nothing was added to the Library. "
                + "Import it again once it has finished changing."
        case let .compressed(container):
            "This file is compressed with \(container). Expand it first, then choose a PCAP or PCAPNG capture."
        case .unsupportedContent:
            "Tracexy opens PCAP and PCAPNG captures. This file doesn’t begin with either format’s header."
        case let .unreadableSource(reason):
            "The file couldn’t be read — \(reason)."
        case let .publicationFailed(reason):
            "The capture couldn’t be added to the Library — \(reason)."
        case .noAvailableManagedName:
            "Too many captures already use this name. Rename the file, then import it again."
        }
    }
}

// MARK: - CaptureImporter

/// Lossless, idempotent, no-overwrite import of an external capture file into
/// the app's managed Captures directory.
///
/// Four invariants make this safe against the failure modes that destroy user
/// data or produce a Library item nothing can reopen:
///
///  * **Recognized content before any Library change.** A bounded header read
///    decides whether the bytes are PCAP or PCAPNG, whatever the file is named.
///    An unknown, compressed, empty, truncated or non-regular input is refused
///    *before* a copy is staged. Recognition requires the *complete* fixed header
///    (24 bytes classic, 28 for a Section Header Block) but proves only that the
///    file *starts* with a supported header; the streaming reader stays the sole
///    authority on whether the records that follow parse.
///  * **Managed suffix normalization.** A recognized capture whose name the
///    Library could not discover gains the detected extension, and a name that
///    already ends in `.pcap`/`.pcapng` is left exactly as it is — so importing
///    a managed file again can never grow another extension.
///  * **Same-file short-circuit.** If the source already *is* a managed file
///    (equivalent path, symlink, hardlink, or another path onto a discoverable
///    Library item), nothing is removed or copied — the existing file is
///    reported back so the caller can refresh and reopen it in place.
///  * **Bounded descriptor copy, then exclusive publication.** The source is read
///    through one descriptor whose regular-file identity was checked with
///    `fstat`, in cancellable chunks, into a temporary sibling that is published
///    with `link(2)` — which fails rather than clobbering. Owning the bytes is the
///    point: a symlinked source produces a real managed file, not another link.
///    A name already in use is preserved and the incoming file lands under a
///    unique name instead; a cancellation, a short source or any failure removes
///    only this import's temporary artifact and leaves both the source and every
///    existing managed file untouched.
///
/// Two containers are expanded rather than refused: a gzip stream and the exact
/// `TCPViewerSession` schema-1 session ZIP, both recognized from content and
/// whatever the file is named. A container takes a longer route to the *same*
/// publication step — expand into an exclusive 0600 sibling under
/// ``CaptureArchiveLimits``, recognize the extracted header, re-check the source
/// identity, then `link(2)` — and deliberately skips the same-file
/// short-circuits, because a container is never itself a managed capture and
/// re-importing one must produce a real capture rather than report the archive.
/// Every other compressed signature stays a refusal that names its container.
nonisolated enum CaptureImporter {
    // MARK: Internal

    /// The extensions Library discovery accepts. A managed copy must end in one
    /// of these or it becomes invisible to the Library and unopenable.
    static let libraryPathExtensions: Set<String> = ["pcap", "pcapng"]

    /// Recognizes the container format from a bounded read of the leading header.
    ///
    /// This is deliberately a **direct-content** question and stays one: it
    /// reports what the file *itself* begins with and never expands anything, so
    /// a gzip or session ZIP is still answered with `.compressed`. Callers that
    /// want the archive-aware behaviour import the file;
    /// ``importCapture(from:intoDirectory:onProgress:isCancelled:limits:)``
    /// is the single entry point that expands containers.
    ///
    /// - Returns: the detected format when the file begins with a complete
    ///   supported header. This is *not* a claim of whole-file validity.
    /// - Throws: ``CaptureImportError`` describing what the user should do next
    ///   for a directory, a non-regular file, an empty or too-short file, a
    ///   compressed container, or content with no recognized header.
    static func recognizedFormat(of source: URL) throws -> CaptureContentFormat {
        let opened = try openRegularSource(source)
        defer { close(opened.descriptor) }
        return try format(ofHeader: headerPrefix(opened.descriptor))
    }

    /// Imports `source` into `directory`, returning the managed file URL.
    ///
    /// A plain capture is copied directly. A gzip stream or a `TCPViewerSession`
    /// schema-1 session ZIP — recognized from content, whatever the file is
    /// named — is expanded first and its capture payload published instead.
    ///
    /// Both routes run in bounded chunks and ask `isCancelled` before each one,
    /// so a large file can be abandoned promptly; `onProgress` reports monotonic
    /// byte progress against the validated *source* size, which for a container
    /// means compressed bytes consumed rather than bytes written.
    ///
    /// - Parameter limits: the expansion bounds. Only ever narrows: the
    ///   initializer clamps every field against the shipped ceiling, so a test
    ///   can reach a limit path cheaply and no caller can widen one.
    /// - Returns: the destination URL inside `directory`. When the source is
    ///   already a managed file this is that file's own location; otherwise it is
    ///   the normalized name, or a uniquified variant of it when that name is
    ///   already taken by a different capture.
    /// - Throws: ``CaptureImportError`` for unrecognized, unusable, or
    ///   concurrently changed input, ``CaptureArchiveError`` for a damaged,
    ///   unsupported or over-limit container, or `CancellationError` when the
    ///   work was abandoned. On throw, the source and every pre-existing managed
    ///   file are left intact and only this import's temporary artifact is
    ///   removed.
    @discardableResult
    static func importCapture(
        from source: URL,
        intoDirectory directory: URL,
        onProgress: @Sendable (PcapStreamProgress) -> Void = { _ in },
        isCancelled: @Sendable () -> Bool = { Task.isCancelled },
        limits: CaptureArchiveLimits = .standard
    )
        throws -> URL
    {
        if isCancelled() {
            throw CancellationError()
        }
        let opened = try openRegularSource(source)
        defer { close(opened.descriptor) }
        let prefix = try headerPrefix(opened.descriptor)
        if let container = CaptureArchiveContainer(header: prefix) {
            return try importArchive(
                container,
                from: source,
                opened: opened,
                intoDirectory: directory,
                limits: limits,
                onProgress: onProgress,
                isCancelled: isCancelled
            )
        }
        let format = try format(ofHeader: prefix)
        let managedName = managedFileName(for: source, format: format)
        let destination = directory.appendingPathComponent(managedName)

        // Already the managed file: never mutate it. This is the case that once
        // removed the destination and then failed the copy with ENOENT,
        // destroying the only copy of the capture.
        if isSameFile(source, destination) {
            return destination
        }
        // The same identity reached under another name — a link or an alternate
        // path onto a file that the Library already lists. Copying it would only
        // duplicate a capture the user already has.
        if let managed = existingManagedLocation(of: source, in: directory) {
            return managed
        }

        // Stage beside the destination so publication is a same-volume link and a
        // partially copied file is never visible to the Library.
        let temporary = directory.appendingPathComponent(".capture.import-\(UUID().uuidString).tmp")
        try copyContents(of: opened, to: temporary, onProgress: onProgress, isCancelled: isCancelled)
        // The copier has successfully created this exact staging file. Never
        // remove a path after a failed exclusive create: it may belong to someone else.
        defer { try? FileManager.default.removeItem(at: temporary) }
        if isCancelled() {
            throw CancellationError()
        }
        var current = stat()
        guard source.path.withCString({ stat($0, &current) }) == 0,
              SourceIdentity(current) == opened.identity else
        {
            throw CaptureImportError.sourceChangedDuringImport
        }
        return try publish(temporary, as: managedName, in: directory)
    }

    // MARK: Private

    /// The immutable facts a source must still satisfy when the copy ends. The
    /// held descriptor already pins inode and device; they are compared anyway so
    /// the check states the whole identity it verifies.
    private struct SourceIdentity: Equatable {
        // MARK: Lifecycle

        init(_ info: stat) {
            size = UInt64(max(info.st_size, 0))
            inode = info.st_ino
            device = info.st_dev
            modifiedSeconds = info.st_mtimespec.tv_sec
            modifiedNanoseconds = info.st_mtimespec.tv_nsec
            changedSeconds = info.st_ctimespec.tv_sec
            changedNanoseconds = info.st_ctimespec.tv_nsec
        }

        // MARK: Internal

        let size: UInt64
        let inode: UInt64
        let device: dev_t
        let modifiedSeconds: Int
        let modifiedNanoseconds: Int
        let changedSeconds: Int
        let changedNanoseconds: Int
    }

    /// Bytes read to recognize a format: the longest complete fixed header
    /// (a 28-byte Section Header Block), which also covers the 24-byte classic
    /// global header and every compressed-container signature Tracexy names.
    private static let headerProbeLength = 28
    private static let minimumMagicLength = 4
    private static let classicGlobalHeaderLength = 24
    private static let sectionHeaderBlockLength = 28

    /// Copy granularity: the unit of both cancellation latency and progress.
    private static let copyChunkLength = 256 * 1_024

    /// Uniquifying suffixes tried before falling back to a UUID. Bounded so a
    /// pathological directory cannot spin here.
    private static let maximumNameAttempts = 64

    /// Leading signatures of containers Tracexy deliberately does not decompress.
    /// Naming the container is what makes the refusal actionable.
    private static let compressedSignatures: [(bytes: [UInt8], name: String)] = [
        ([0x1F, 0x8B], "gzip"),
        ([0x1F, 0x9D], "Unix compress"),
        ([0x42, 0x5A, 0x68], "bzip2"),
        ([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], "xz"),
        ([0x28, 0xB5, 0x2F, 0xFD], "Zstandard"),
        ([0x04, 0x22, 0x4D, 0x18], "LZ4"),
        ([0x50, 0x4B, 0x03, 0x04], "Zip"),
    ]

    /// Opens the source once and decides from the *descriptor* — never from a path
    /// that could be swapped underneath the copy — whether this is a readable,
    /// non-empty regular file. `O_NONBLOCK` is what keeps a FIFO or a device from
    /// parking the worker inside `open`; `fstat` then refuses it by kind. The open
    /// follows symlinks, so a link to a real capture stays a valid source and the
    /// copy that follows reads the target's bytes.
    private static func openRegularSource(_ source: URL) throws -> (descriptor: Int32, identity: SourceIdentity) {
        let descriptor = source.path.withCString { open($0, O_RDONLY | O_NONBLOCK | O_CLOEXEC) }
        guard descriptor >= 0 else {
            throw CaptureImportError.unreadableSource(String(cString: strerror(errno)))
        }
        do {
            var info = stat()
            guard fstat(descriptor, &info) == 0 else {
                throw CaptureImportError.unreadableSource(String(cString: strerror(errno)))
            }
            let type = info.st_mode & S_IFMT
            guard type != S_IFDIR else {
                throw CaptureImportError.sourceIsDirectory
            }
            guard type == S_IFREG else {
                throw CaptureImportError.sourceIsNotRegularFile
            }
            guard info.st_size > 0 else {
                throw CaptureImportError.sourceIsEmpty
            }
            // Regular-file validation is complete; copy I/O remains off-main.
            let flags = fcntl(descriptor, F_GETFL)
            if flags >= 0 {
                _ = fcntl(descriptor, F_SETFL, flags & ~O_NONBLOCK)
            }
            return (descriptor, SourceIdentity(info))
        } catch {
            close(descriptor)
            throw error
        }
    }

    private static func identity(of descriptor: Int32) throws -> SourceIdentity {
        var info = stat()
        guard fstat(descriptor, &info) == 0 else {
            throw CaptureImportError.unreadableSource(String(cString: strerror(errno)))
        }
        return SourceIdentity(info)
    }

    private static func headerPrefix(_ descriptor: Int32) throws -> [UInt8] {
        var buffer = [UInt8](repeating: 0, count: headerProbeLength)
        let read = try readFully(descriptor, into: &buffer, count: headerProbeLength)
        return Array(buffer.prefix(read))
    }

    /// Decides the format from the leading bytes alone.
    ///
    /// Compression is recognized before any length rule, so a short compressed
    /// file names its container rather than being reported as a truncated capture.
    /// A recognized magic then requires its *complete* fixed header: four matching
    /// bytes prove only that a header started.
    private static func format(ofHeader prefix: [UInt8]) throws -> CaptureContentFormat {
        if let container = compressedContainer(prefix) {
            throw CaptureImportError.compressed(container)
        }
        if PcapngReader.isPcapng(prefix) {
            guard prefix.count >= sectionHeaderBlockLength else {
                throw CaptureImportError.sourceIsTruncated
            }
            return .pcapng
        }
        guard prefix.count >= minimumMagicLength else {
            throw CaptureImportError.sourceIsTruncated
        }
        // The classic readers parse this magic big-endian and derive endianness
        // and timestamp resolution from it, so reusing `MagicFormat` keeps every
        // accepted variant (microsecond/nanosecond, either byte order) in one place.
        let rawMagic = UInt32(prefix[0]) << 24
            | UInt32(prefix[1]) << 16
            | UInt32(prefix[2]) << 8
            | UInt32(prefix[3])
        if MagicFormat(rawMagic: rawMagic) != nil {
            guard prefix.count >= classicGlobalHeaderLength else {
                throw CaptureImportError.sourceIsTruncated
            }
            return .pcap
        }
        throw CaptureImportError.unsupportedContent
    }

    /// Expands a recognized container and publishes its capture payload.
    ///
    /// The order is what makes this safe. Extraction completes and verifies
    /// itself first — checksums, declared sizes, quotas — then the *extracted*
    /// bytes must begin with a supported capture header, then the source must
    /// still be the file that was opened, and only then does the same
    /// `link(2)` publication run. Nothing partial is ever discoverable: the
    /// staging file is created exclusively at 0600 under a hidden name and is the
    /// only artifact any failure removes.
    ///
    /// The same-file and already-managed short-circuits are deliberately skipped.
    /// A container is not a managed capture, so "this is already in the Library"
    /// can never be the right answer for one; importing an archive that happens
    /// to sit in the Captures folder must still produce a real capture.
    private static func importArchive(
        _ container: CaptureArchiveContainer,
        from source: URL,
        opened: (descriptor: Int32, identity: SourceIdentity),
        intoDirectory directory: URL,
        limits: CaptureArchiveLimits,
        onProgress: @Sendable (PcapStreamProgress) -> Void,
        isCancelled: @Sendable () -> Bool
    )
        throws -> URL
    {
        let total = opened.identity.size
        guard total <= limits.maximumSourceBytes else {
            throw CaptureArchiveError.sourceTooLarge(limit: limits.maximumSourceBytes)
        }
        /// Compressed-source progress: monotonic by construction, since the
        /// extractor only ever reports the offset of the next unconsumed byte.
        func report(_ consumed: UInt64) {
            onProgress(PcapStreamProgress(bytesConsumed: min(consumed, total), totalBytes: total))
        }
        report(0)

        let temporary = directory.appendingPathComponent(".capture.import-\(UUID().uuidString).tmp")
        // Exclusive creation succeeded, so this exact staging file is ours: it is
        // the only path any failure below removes, and publication is a `link(2)`
        // that leaves the original to be cleaned up here either way.
        let output = try CaptureArchiveOutput(creating: temporary, limits: limits)
        defer {
            output.close()
            try? FileManager.default.removeItem(at: temporary)
        }
        try CaptureArchiveExtractor.extract(
            container,
            from: CaptureArchiveSource(descriptor: opened.descriptor, size: total),
            to: output,
            limits: limits,
            onProgress: report,
            isCancelled: isCancelled
        )
        try output.synchronize()
        output.close()

        if isCancelled() {
            throw CancellationError()
        }
        let format: CaptureContentFormat
        do {
            format = try Self.format(ofHeader: headerPrefix(ofFileAt: temporary))
        } catch {
            // A payload that is not a capture — including a nested archive — is
            // one refusal, not a second container round.
            throw CaptureArchiveError.extractedContentUnsupported
        }
        guard try identity(of: opened.descriptor) == opened.identity else {
            throw CaptureImportError.sourceChangedDuringImport
        }
        var current = stat()
        guard source.path.withCString({ stat($0, &current) }) == 0,
              SourceIdentity(current) == opened.identity else
        {
            throw CaptureImportError.sourceChangedDuringImport
        }
        report(total)
        let managedName = managedFileName(forExtractedFrom: source, container: container, format: format)
        return try publish(temporary, as: managedName, in: directory)
    }

    /// Reads the leading header of the staged extraction, through its own
    /// short-lived descriptor so the source descriptor's offset is untouched.
    private static func headerPrefix(ofFileAt url: URL) throws -> [UInt8] {
        let descriptor = url.path.withCString { open($0, O_RDONLY | O_CLOEXEC) }
        guard descriptor >= 0 else {
            throw CaptureImportError.unreadableSource(String(cString: strerror(errno)))
        }
        defer { close(descriptor) }
        return try headerPrefix(descriptor)
    }

    /// Copies exactly the validated source size into `temporary`, in bounded
    /// chunks, checking for cancellation before each one.
    ///
    /// A short read means the file shrank mid-copy and a late identity mismatch
    /// means it was rewritten; both refuse rather than publish a partial capture
    /// under a name that claims to be the whole one.
    private static func copyContents(
        of source: (descriptor: Int32, identity: SourceIdentity),
        to temporary: URL,
        onProgress: @Sendable (PcapStreamProgress) -> Void,
        isCancelled: @Sendable () -> Bool
    )
        throws
    {
        // The header probe above moved the offset; the copy owns the whole file.
        guard lseek(source.descriptor, 0, SEEK_SET) == 0 else {
            throw CaptureImportError.unreadableSource(String(cString: strerror(errno)))
        }
        let destination = temporary.path.withCString { open($0, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600) }
        guard destination >= 0 else {
            throw CaptureImportError.publicationFailed(String(cString: strerror(errno)))
        }
        var copiedSuccessfully = false
        defer {
            close(destination)
            if !copiedSuccessfully {
                try? FileManager.default.removeItem(at: temporary)
            }
        }

        let total = source.identity.size
        var buffer = [UInt8](repeating: 0, count: copyChunkLength)
        var copied: UInt64 = 0
        onProgress(PcapStreamProgress(bytesConsumed: 0, totalBytes: total))
        while copied < total {
            if isCancelled() {
                throw CancellationError()
            }
            let wanted = Int(min(UInt64(copyChunkLength), total - copied))
            let read = try readFully(source.descriptor, into: &buffer, count: wanted)
            guard read == wanted else {
                throw CaptureImportError.sourceChangedDuringImport
            }
            try writeFully(destination, from: buffer, count: read)
            copied += UInt64(read)
            onProgress(PcapStreamProgress(bytesConsumed: copied, totalBytes: total))
        }
        if isCancelled() {
            throw CancellationError()
        }
        guard fsync(destination) == 0 else {
            throw CaptureImportError.publicationFailed(String(cString: strerror(errno)))
        }
        guard try identity(of: source.descriptor) == source.identity else {
            throw CaptureImportError.sourceChangedDuringImport
        }
        copiedSuccessfully = true
    }

    /// Reads up to `count` bytes, retrying short reads and `EINTR`. Returns fewer
    /// than `count` only at end of file.
    private static func readFully(_ descriptor: Int32, into buffer: inout [UInt8], count: Int) throws -> Int {
        try buffer.withUnsafeMutableBytes { raw in
            guard count > 0, let base = raw.baseAddress else {
                return 0
            }
            var total = 0
            while total < count {
                let read = Darwin.read(descriptor, base + total, count - total)
                if read < 0 {
                    if errno == EINTR {
                        continue
                    }
                    throw CaptureImportError.unreadableSource(String(cString: strerror(errno)))
                }
                if read == 0 {
                    break
                }
                total += read
            }
            return total
        }
    }

    private static func writeFully(_ descriptor: Int32, from buffer: [UInt8], count: Int) throws {
        try buffer.withUnsafeBytes { raw in
            guard count > 0, let base = raw.baseAddress else {
                return
            }
            var total = 0
            while total < count {
                let written = Darwin.write(descriptor, base + total, count - total)
                if written < 0 {
                    if errno == EINTR {
                        continue
                    }
                    throw CaptureImportError.publicationFailed(String(cString: strerror(errno)))
                }
                guard written > 0 else {
                    throw CaptureImportError.publicationFailed("the Library accepted no more bytes")
                }
                total += written
            }
        }
    }

    private static func compressedContainer(_ prefix: [UInt8]) -> String? {
        compressedSignatures.first { prefix.starts(with: $0.bytes) }?.name
    }

    /// The name the managed copy takes.
    ///
    /// A name the Library can already discover is kept verbatim — including a
    /// `.pcap` file named `.pcapng`, which the content-sniffing reader opens
    /// correctly anyway. Only a name the Library would never list is normalized,
    /// by appending the detected extension rather than replacing the original
    /// one, so no part of the user's filename is silently dropped and a second
    /// import of the managed copy cannot append a further extension.
    private static func managedFileName(for source: URL, format: CaptureContentFormat) -> String {
        let name = source.lastPathComponent
        let existing = (name as NSString).pathExtension.lowercased()
        guard !libraryPathExtensions.contains(existing) else {
            return name
        }
        return "\(name).\(format.managedPathExtension)"
    }

    /// The name an extracted capture takes.
    ///
    /// Derived from the *source filename* only — never from a manifest field or
    /// an archive entry name, which are attacker-controlled strings that have no
    /// business reaching a path. A trailing extension that describes the
    /// container rather than the capture is dropped, so `session.pcapng.gz`
    /// becomes `session.pcapng` and `capture.tcpviewsession` becomes
    /// `capture.pcapng`; everything else goes through the same normalization a
    /// direct import uses. The result is stable for a given source, so a repeated
    /// import collides predictably and is uniquified rather than overwriting.
    private static func managedFileName(
        forExtractedFrom source: URL,
        container: CaptureArchiveContainer,
        format: CaptureContentFormat
    )
        -> String
    {
        let name = source.lastPathComponent
        let containerExtension = (name as NSString).pathExtension.lowercased()
        guard container.containerPathExtensions.contains(containerExtension) else {
            return managedFileName(for: source, format: format)
        }
        let stem = (name as NSString).deletingPathExtension
        guard !stem.isEmpty else {
            return managedFileName(for: source, format: format)
        }
        return managedFileName(for: URL(fileURLWithPath: stem), format: format)
    }

    /// Publishes the staged copy under the first free name, without ever
    /// overwriting. `link(2)` is atomic and fails with `EEXIST`, so two imports
    /// racing on the same name — or a name a concurrent Save just took — each end
    /// up with their own file instead of one silently replacing the other.
    private static func publish(_ temporary: URL, as managedName: String, in directory: URL) throws -> URL {
        let stem = (managedName as NSString).deletingPathExtension
        let pathExtension = (managedName as NSString).pathExtension
        for attempt in 0 ... maximumNameAttempts {
            let candidateName = switch attempt {
            case 0: managedName
            case maximumNameAttempts: "\(stem)-\(UUID().uuidString).\(pathExtension)"
            default: "\(stem)-\(attempt + 1).\(pathExtension)"
            }
            let candidate = directory.appendingPathComponent(candidateName)
            let outcome = temporary.path.withCString { from in
                candidate.path.withCString { to in (result: link(from, to), code: errno) }
            }
            if outcome.result == 0 {
                return candidate
            }
            guard outcome.code == EEXIST else {
                throw CaptureImportError.publicationFailed(String(cString: strerror(outcome.code)))
            }
        }
        throw CaptureImportError.noAvailableManagedName
    }

    /// The Library location `source` already occupies when it resolves to a
    /// discoverable managed file under some other name. Returned in the caller's
    /// directory space so it matches the URLs the Library listing produces.
    private static func existingManagedLocation(of source: URL, in directory: URL) -> URL? {
        let resolved = source.resolvingSymlinksInPath().standardizedFileURL
        let managedDirectory = directory.resolvingSymlinksInPath().standardizedFileURL
        guard resolved.deletingLastPathComponent().path == managedDirectory.path,
              libraryPathExtensions.contains(resolved.pathExtension.lowercased()),
              FileManager.default.fileExists(atPath: resolved.path) else
        {
            return nil
        }
        return directory.appendingPathComponent(resolved.lastPathComponent)
    }

    /// Whether two URLs point at the same underlying file. Compares resolved,
    /// standardized paths first (covers identical and symlinked paths), then
    /// falls back to on-disk file identity so hardlinks or otherwise-equivalent
    /// paths still count as the same file.
    private static func isSameFile(_ lhs: URL, _ rhs: URL) -> Bool {
        let resolvedLhs = lhs.resolvingSymlinksInPath().standardizedFileURL
        let resolvedRhs = rhs.resolvingSymlinksInPath().standardizedFileURL
        if resolvedLhs == resolvedRhs {
            return true
        }
        guard let idLhs = fileIdentifier(lhs), let idRhs = fileIdentifier(rhs) else {
            return false
        }
        return idLhs.isEqual(idRhs)
    }

    private static func fileIdentifier(_ url: URL) -> (any NSObjectProtocol)? {
        (try? url.resourceValues(forKeys: [.fileResourceIdentifierKey]))?.fileResourceIdentifier
    }
}
