import Darwin
import Foundation

// MARK: - CaptureArchiveContainer

/// A compressed container Tracexy expands on the user's behalf, recognized from
/// leading magic bytes rather than from a filename.
///
/// Every other compressed signature the importer knows stays a refusal that names
/// its container: expanding a format costs a validated, bounded, quota-checked
/// decoder, and only these two have one.
nonisolated enum CaptureArchiveContainer: Sendable, Equatable {
    /// A gzip stream — possibly several concatenated members — wrapping one capture.
    case gzip
    /// A ZIP archive. Only the exact `TCPViewerSession` schema-1 session layout is
    /// accepted; a ZIP is never searched for "some capture inside".
    case sessionZip

    // MARK: Lifecycle

    /// Recognizes a container from the same bounded header probe the importer
    /// already performs. Returns `nil` for anything that is not an expandable
    /// container, leaving the direct-copy path to decide.
    init?(header: [UInt8]) {
        if header.starts(with: [0x1F, 0x8B]) {
            self = .gzip
        } else if header.starts(with: [0x50, 0x4B, 0x03, 0x04]) {
            self = .sessionZip
        } else {
            return nil
        }
    }

    // MARK: Internal

    /// Filename extensions that describe *this container* rather than the capture
    /// inside it, and may therefore be dropped when naming the extracted copy.
    /// Nothing here is read from archive metadata — the name stays source-derived.
    var containerPathExtensions: Set<String> {
        switch self {
        case .gzip: ["gz", "gzip"]
        case .sessionZip: ["zip", "tcpviewsession"]
        }
    }
}

// MARK: - CaptureArchiveError

/// Why expanding a container was refused. Every case is raised *before* anything
/// reaches the Library, names the limit or defect that stopped it, and points at
/// the next thing the user can do.
///
/// These are deliberately separate from ``CaptureImportError``: the direct-copy
/// contract is unchanged, and archive faults describe a container rather than a
/// source file.
nonisolated enum CaptureArchiveError: LocalizedError, Equatable {
    /// The compressed file itself is larger than the import ceiling.
    case sourceTooLarge(limit: UInt64)
    /// Expanding would write more than the absolute output ceiling allows.
    case expandedTooLarge(limit: UInt64)
    /// Expansion outran the permitted ratio after the small-file grace — the
    /// classic decompression bomb.
    case expansionRatioExceeded(ratio: UInt64)
    /// A structural bound (entry count, index size, name length, manifest size).
    case exceedsBound(String)
    /// The container ends mid-stream.
    case truncated
    /// Bytes follow a complete container that are not another valid member.
    case trailingContent
    /// The container's own structure is inconsistent.
    case malformed(String)
    /// A structurally valid container using something Tracexy will not process.
    case unsupportedFeature(String)
    /// A ZIP that is not the recognized session archive layout.
    case unsupportedSessionArchive
    /// A session archive whose declared schema this build does not know.
    case unsupportedSessionSchema
    /// A session archive whose manifest names a capture the archive does not carry.
    case sessionCaptureMissing
    /// The expanded payload is not a PCAP or PCAPNG capture.
    case extractedContentUnsupported

    // MARK: Internal

    var errorDescription: String? {
        switch self {
        case let .sourceTooLarge(limit):
            "The compressed file is larger than \(Self.megabytes(limit)). Expand it yourself, then import the capture."
        case let .expandedTooLarge(limit):
            "The capture inside expands past \(Self.megabytes(limit)). Expand the file yourself, then import a smaller capture."
        case let .expansionRatioExceeded(ratio):
            "The file expands more than \(ratio)× its compressed size, so Tracexy stopped rather than fill the disk. "
                + "Expand it yourself if you trust it."
        case let .exceedsBound(detail):
            "The archive exceeds a safety limit — \(detail). Export a PCAP or PCAPNG capture from the original app instead."
        case .truncated:
            "The compressed file ends part way through. It may still be downloading."
        case .trailingContent:
            "The compressed file carries extra data after the end of its capture, so Tracexy can't trust it."
        case let .malformed(detail):
            "The archive is damaged — \(detail). Re-export or re-download it, then import it again."
        case let .unsupportedFeature(detail):
            "Tracexy doesn't open archives using \(detail). Expand the file yourself, then import the capture."
        case .unsupportedSessionArchive:
            "This ZIP isn't a session archive Tracexy can read. Open it in the app that made it and export a PCAPNG capture."
        case .unsupportedSessionSchema:
            "This session archive was written by a newer or different format than Tracexy knows. "
                + "Open it in the app that made it and export a PCAPNG capture."
        case .sessionCaptureMissing:
            "This session archive carries no capture file. Open it in the app that made it and export a PCAPNG capture."
        case .extractedContentUnsupported:
            "The file inside isn't a PCAP or PCAPNG capture, so there is nothing for Tracexy to open."
        }
    }

    // MARK: Private

    private static func megabytes(_ bytes: UInt64) -> String {
        let megabytes = bytes / (1_024 * 1_024)
        return megabytes >= 1_024 ? "\(megabytes / 1_024) GB" : "\(megabytes) MB"
    }
}

// MARK: - CaptureArchiveLimits

/// The bounds every expansion runs inside.
///
/// The initializer only ever *narrows*: each parameter is clamped against the
/// shipped ceiling, so a test can shrink a bound to reach a limit path cheaply
/// but no caller can widen one. ``standard`` is the shipped configuration.
nonisolated struct CaptureArchiveLimits: Sendable, Equatable {
    // MARK: Lifecycle

    init(
        maximumSourceBytes: UInt64 = .max,
        maximumOutputBytes: UInt64 = .max,
        expansionRatio: UInt64 = .max,
        expansionGraceBytes: UInt64 = .max,
        maximumCentralDirectoryBytes: UInt64 = .max,
        maximumEntryCount: Int = .max,
        maximumEntryNameBytes: Int = .max,
        maximumManifestBytes: Int = .max
    ) {
        self.maximumSourceBytes = min(maximumSourceBytes, Self.shippedSourceBytes)
        self.maximumOutputBytes = min(maximumOutputBytes, Self.shippedOutputBytes)
        self.expansionRatio = max(1, min(expansionRatio, Self.shippedExpansionRatio))
        self.expansionGraceBytes = min(expansionGraceBytes, Self.shippedExpansionGraceBytes)
        self.maximumCentralDirectoryBytes = min(maximumCentralDirectoryBytes, Self.shippedCentralDirectoryBytes)
        self.maximumEntryCount = max(1, min(maximumEntryCount, Self.shippedEntryCount))
        self.maximumEntryNameBytes = max(1, min(maximumEntryNameBytes, Self.shippedEntryNameBytes))
        self.maximumManifestBytes = max(1, min(maximumManifestBytes, Self.shippedManifestBytes))
    }

    // MARK: Internal

    /// The shipped configuration. Every field sits at its ceiling.
    static let standard = Self()

    /// Largest compressed file that will be expanded at all.
    let maximumSourceBytes: UInt64
    /// Largest capture that may be written out of a container.
    let maximumOutputBytes: UInt64
    /// Output may not exceed this multiple of the compressed bytes consumed…
    let expansionRatio: UInt64
    /// …until this much has been written, so small, legitimately dense captures
    /// are never judged by a ratio computed from a handful of bytes.
    let expansionGraceBytes: UInt64
    /// Largest ZIP central directory that will be read into memory.
    let maximumCentralDirectoryBytes: UInt64
    /// Most entries a ZIP may declare.
    let maximumEntryCount: Int
    /// Longest single entry name, in bytes.
    let maximumEntryNameBytes: Int
    /// Largest session manifest that will be parsed.
    let maximumManifestBytes: Int

    // MARK: Private

    private static let shippedSourceBytes: UInt64 = 512 * 1_024 * 1_024
    private static let shippedOutputBytes: UInt64 = 4 * 1_024 * 1_024 * 1_024
    private static let shippedExpansionRatio: UInt64 = 200
    private static let shippedExpansionGraceBytes: UInt64 = 64 * 1_024 * 1_024
    private static let shippedCentralDirectoryBytes: UInt64 = 4 * 1_024 * 1_024
    private static let shippedEntryCount = 4_096
    private static let shippedEntryNameBytes = 1_024
    private static let shippedManifestBytes = 64 * 1_024
}

// MARK: - CaptureArchiveSource

/// Random-access reads against the *already validated, still-held* source
/// descriptor.
///
/// Every read is a `pread`, so the file offset the importer's header probe left
/// behind is irrelevant and no seek state has to be coordinated. The descriptor
/// is owned by the importer for the whole import; this type never closes it.
nonisolated struct CaptureArchiveSource {
    let descriptor: Int32
    /// The size validated at open time. Reads never go past it, so a file that
    /// grows mid-import cannot extend the work; a file that shrinks short-reads
    /// and is caught by the closing identity check.
    let size: UInt64

    /// Reads up to `count` bytes at `offset` into `buffer[destination...]`,
    /// retrying `EINTR` and short reads. Returns fewer than `count` only at end
    /// of file.
    func read(at offset: UInt64, into buffer: inout [UInt8], destination: Int, count: Int) throws -> Int {
        guard count > 0 else {
            return 0
        }
        guard destination >= 0, count <= buffer.count - destination else {
            throw CaptureArchiveError.malformed("an internal read went past its buffer")
        }
        return try buffer.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else {
                return 0
            }
            var total = 0
            while total < count {
                let read = pread(
                    descriptor,
                    base + destination + total,
                    count - total,
                    off_t(bitPattern: UInt64(offset) &+ UInt64(total))
                )
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

    /// Reads exactly `count` bytes at `offset` into a fresh array, or refuses:
    /// a short read here means the archive's own index pointed past its end.
    func readExactly(at offset: UInt64, count: Int) throws -> [UInt8] {
        var buffer = [UInt8](repeating: 0, count: count)
        let read = try read(at: offset, into: &buffer, destination: 0, count: count)
        guard read == count else {
            throw CaptureArchiveError.truncated
        }
        return buffer
    }
}

// MARK: - CaptureArchiveOutput

/// The staged extraction file, with the output quotas enforced *before* every
/// write so a bomb is refused rather than partially written to the user's disk.
nonisolated final class CaptureArchiveOutput {
    // MARK: Lifecycle

    /// Creates the staging file exclusively at 0600. Exclusive creation is what
    /// makes the file unambiguously ours to remove on any failure.
    init(creating url: URL, limits: CaptureArchiveLimits) throws {
        let descriptor = url.path.withCString { open($0, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600) }
        guard descriptor >= 0 else {
            throw CaptureImportError.publicationFailed(String(cString: strerror(errno)))
        }
        self.descriptor = descriptor
        self.limits = limits
    }

    deinit {
        if descriptor >= 0 {
            Darwin.close(descriptor)
        }
    }

    // MARK: Internal

    private(set) var written: UInt64 = 0

    /// Appends `count` bytes from `buffer[offset...]`, having first checked that
    /// doing so stays inside both the absolute output ceiling and the expansion
    /// ratio implied by `compressedConsumed`.
    func write(_ buffer: [UInt8], offset: Int, count: Int, compressedConsumed: UInt64) throws {
        guard count > 0 else {
            return
        }
        try checkQuota(adding: count, compressedConsumed: compressedConsumed)
        try buffer.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else {
                return
            }
            var total = 0
            while total < count {
                let put = Darwin.write(descriptor, base + offset + total, count - total)
                if put < 0 {
                    if errno == EINTR {
                        continue
                    }
                    throw CaptureImportError.publicationFailed(String(cString: strerror(errno)))
                }
                guard put > 0 else {
                    throw CaptureImportError.publicationFailed("the Library accepted no more bytes")
                }
                total += put
            }
        }
        written &+= UInt64(count)
    }

    func synchronize() throws {
        guard fsync(descriptor) == 0 else {
            throw CaptureImportError.publicationFailed(String(cString: strerror(errno)))
        }
    }

    func close() {
        if descriptor >= 0 {
            Darwin.close(descriptor)
            descriptor = -1
        }
    }

    // MARK: Private

    private let limits: CaptureArchiveLimits
    private var descriptor: Int32

    /// Both quotas are overflow-safe and evaluated against the *projected* size,
    /// so the byte that would cross a limit is never written.
    private func checkQuota(adding count: Int, compressedConsumed: UInt64) throws {
        let (projected, overflowed) = written.addingReportingOverflow(UInt64(count))
        guard !overflowed, projected <= limits.maximumOutputBytes else {
            throw CaptureArchiveError.expandedTooLarge(limit: limits.maximumOutputBytes)
        }
        guard projected > limits.expansionGraceBytes else {
            return
        }
        let (allowance, ratioOverflowed) = compressedConsumed.multipliedReportingOverflow(by: limits.expansionRatio)
        guard ratioOverflowed || projected <= allowance else {
            throw CaptureArchiveError.expansionRatioExceeded(ratio: limits.expansionRatio)
        }
    }
}

// MARK: - ArchiveInputWindow

/// A bounded sliding window over one byte range of the source.
///
/// Compressed input is consumed in fixed chunks and never held whole, and the
/// window refuses to read outside `[start, end)` — which is how a ZIP entry is
/// kept inside its declared data span and how a gzip stream is kept inside the
/// file size validated at open time.
nonisolated struct ArchiveInputWindow {
    // MARK: Lifecycle

    init(capacity: Int, start: UInt64, end: UInt64) {
        bytes = [UInt8](repeating: 0, count: capacity)
        nextSourceOffset = start
        self.end = max(start, end)
    }

    // MARK: Internal

    private(set) var bytes: [UInt8]
    private(set) var offset = 0
    private(set) var count = 0
    private(set) var isAtEnd = false

    /// Unconsumed bytes currently buffered.
    var available: Int {
        count - offset
    }

    /// Absolute file offset of the next byte the decoder has *not* consumed.
    /// This is the progress measure: compressed bytes actually taken in.
    var consumedSourceOffset: UInt64 {
        nextSourceOffset - UInt64(available)
    }

    /// Tops the window up, compacting any unconsumed remainder to the front so a
    /// member boundary can always be inspected without a second buffer.
    mutating func fill(from source: CaptureArchiveSource) throws {
        if offset > 0 {
            let remaining = count - offset
            if remaining > 0 {
                for index in 0 ..< remaining {
                    bytes[index] = bytes[offset + index]
                }
            }
            count = remaining
            offset = 0
        }
        let ceiling = min(end, source.size)
        guard count < bytes.count, nextSourceOffset < ceiling else {
            if nextSourceOffset >= ceiling {
                isAtEnd = true
            }
            return
        }
        let wanted = Int(min(UInt64(bytes.count - count), ceiling - nextSourceOffset))
        let read = try source.read(at: nextSourceOffset, into: &bytes, destination: count, count: wanted)
        guard read > 0 else {
            // The file shrank under us. The closing identity check reports it.
            isAtEnd = true
            return
        }
        count += read
        nextSourceOffset &+= UInt64(read)
        if nextSourceOffset >= ceiling {
            isAtEnd = true
        }
    }

    mutating func consume(_ length: Int) {
        offset = min(count, offset + max(0, length))
    }

    // MARK: Private

    /// Absolute source offset immediately after the bytes currently buffered.
    private var nextSourceOffset: UInt64
    /// Exclusive end of the source range this window may read.
    private let end: UInt64
}
