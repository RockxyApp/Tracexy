import Foundation

// MARK: - CaptureArchiveExtractor

/// Expands a recognized container into one already-staged file, or refuses.
///
/// The extractor never publishes, never names a file and never touches the
/// Library: it is handed a source descriptor and an exclusively created staging
/// output, and it either fills that output with a complete, checksum-verified
/// payload or throws. ``CaptureImporter`` owns everything either side of that.
///
/// Three properties hold for both containers:
///
///  * **Nothing is held whole.** Compressed input arrives through a bounded
///    sliding window and expanded output leaves through a bounded chunk buffer,
///    so a 4 GB capture costs a few hundred kilobytes of memory.
///  * **Quotas are checked before the write.** The byte that would cross the
///    output ceiling or the expansion ratio is never written.
///  * **Progress is compressed-source progress.** Every report is the absolute
///    offset of the next *unconsumed* compressed byte, so it rises monotonically
///    from 0 towards the validated source size and never depends on how well the
///    payload happened to compress.
nonisolated enum CaptureArchiveExtractor {
    // MARK: Internal

    /// Expands `container` from `source` into `output`.
    ///
    /// - Throws: ``CaptureArchiveError`` for a damaged, unsupported or
    ///   over-limit container, `CancellationError` when abandoned between
    ///   chunks, or ``CaptureImportError`` for an I/O fault on either file.
    static func extract(
        _ container: CaptureArchiveContainer,
        from source: CaptureArchiveSource,
        to output: CaptureArchiveOutput,
        limits: CaptureArchiveLimits,
        onProgress: (UInt64) -> Void,
        isCancelled: () -> Bool
    )
        throws
    {
        switch container {
        case .gzip:
            try expandGzip(from: source, to: output, onProgress: onProgress, isCancelled: isCancelled)
        case .sessionZip:
            try expandSessionArchive(
                from: source,
                to: output,
                limits: limits,
                onProgress: onProgress,
                isCancelled: isCancelled
            )
        }
    }

    // MARK: Private

    /// The one session layout Tracexy reads, exactly as observed. Nothing here is
    /// inferred from a manifest: these are the only two entries ever opened, and
    /// they are matched by their full names.
    private enum SessionArchive {
        static let entryPrefix = "TCPViewerSession/"
        static let manifestEntryName = "TCPViewerSession/manifest.json"
        static let captureEntryName = "TCPViewerSession/capture.pcapng"
        static let captureFileName = "capture.pcapng"
        static let magic = "TCPViewerSession"
        static let schemaVersion = 1
    }

    /// The manifest fields that decide whether this archive is one Tracexy knows.
    /// Every other key in the file is ignored; `captureFile` is compared against
    /// a constant and never used as a path.
    private struct SessionManifest: Decodable {
        let magic: String
        let schemaVersion: Int
        let minimumCompatibleSchemaVersion: Int
        let captureFile: String
    }

    private static let inputChunkLength = 64 * 1_024
    private static let outputChunkLength = 256 * 1_024
    /// How many consecutive no-progress inflate calls are tolerated. zlib needs
    /// at most one to flush a full output buffer's tail; more means damage.
    private static let maximumUnproductiveSteps = 2

    // MARK: gzip

    /// Streams every gzip member in the file into `output`.
    ///
    /// zlib validates each member's header, CRC-32 and ISIZE. Concatenated
    /// members are supported because that is what `gzip` itself produces from
    /// several inputs; anything after the last member that does not begin a new
    /// member is refused rather than silently ignored, since trailing bytes mean
    /// the file is not what it claims to be.
    private static func expandGzip(
        from source: CaptureArchiveSource,
        to output: CaptureArchiveOutput,
        onProgress: (UInt64) -> Void,
        isCancelled: () -> Bool
    )
        throws
    {
        let stream = try ZlibInflateStream(mode: .gzip)
        var window = ArchiveInputWindow(capacity: inputChunkLength, start: 0, end: source.size)
        var buffer = [UInt8](repeating: 0, count: outputChunkLength)
        var unproductive = 0
        var members = 0
        while true {
            if isCancelled() {
                throw CancellationError()
            }
            try window.fill(from: source)
            let outcome = try stream.step(
                input: window.bytes,
                offset: window.offset,
                available: window.available,
                into: &buffer
            )
            window.consume(outcome.consumed)
            if outcome.produced > 0 {
                try output.write(
                    buffer,
                    offset: 0,
                    count: outcome.produced,
                    compressedConsumed: window.consumedSourceOffset
                )
            }
            onProgress(window.consumedSourceOffset)
            if outcome.finished {
                members += 1
                // Refill first: a member boundary can fall anywhere, and the
                // window compacts so the next member's magic is always readable.
                try window.fill(from: source)
                if window.available == 0 {
                    break
                }
                guard window.available >= 2,
                      window.bytes[window.offset] == 0x1F,
                      window.bytes[window.offset + 1] == 0x8B else
                {
                    throw CaptureArchiveError.trailingContent
                }
                try stream.reset()
                unproductive = 0
                continue
            }
            if outcome.madeProgress {
                unproductive = 0
            } else {
                unproductive += 1
                guard unproductive < maximumUnproductiveSteps, !(window.available == 0 && window.isAtEnd) else {
                    throw CaptureArchiveError.truncated
                }
            }
        }
        guard members > 0, output.written > 0 else {
            throw CaptureArchiveError.truncated
        }
    }

    // MARK: Session ZIP

    /// Reads the exact `TCPViewerSession` schema-1 layout and extracts only its
    /// capture payload.
    ///
    /// The whole archive is *indexed and validated* — every entry's name, method,
    /// flags, local header and byte span — but only `manifest.json` and
    /// `capture.pcapng` are ever opened. The session's own state, packet, client,
    /// annotation and icon entries are structurally checked and then ignored;
    /// none of their content is read, parsed or imported.
    ///
    /// There is no "find some capture inside" fallback and no nested-archive
    /// support: an unrecognized ZIP is a refusal that tells the user to export a
    /// PCAPNG from the app that wrote it.
    private static func expandSessionArchive(
        from source: CaptureArchiveSource,
        to output: CaptureArchiveOutput,
        limits: CaptureArchiveLimits,
        onProgress: (UInt64) -> Void,
        isCancelled: () -> Bool
    )
        throws
    {
        let index = try ZipArchiveIndex(source: source, limits: limits)
        guard let manifestEntry = index.entry(named: SessionArchive.manifestEntryName),
              !manifestEntry.isDirectory,
              index.entries.allSatisfy({ $0.name.hasPrefix(SessionArchive.entryPrefix) }) else
        {
            throw CaptureArchiveError.unsupportedSessionArchive
        }
        let manifestBytes = try index.extractToMemory(
            manifestEntry,
            limit: limits.maximumManifestBytes,
            describedAs: "a session manifest",
            isCancelled: isCancelled
        )
        try validate(manifestBytes)
        guard let captureEntry = index.entry(named: SessionArchive.captureEntryName), !captureEntry.isDirectory else {
            throw CaptureArchiveError.sessionCaptureMissing
        }
        let entryStart = captureEntry.dataOffset
        try index
            .extract(
                captureEntry,
                onProgress: onProgress,
                isCancelled: isCancelled
            ) { buffer, offset, count, consumed in
                // The ratio is judged against this entry's own compressed bytes, not
                // against its position in the file.
                try output.write(
                    buffer,
                    offset: offset,
                    count: count,
                    compressedConsumed: consumed &- entryStart
                )
            }
    }

    /// Requires the exact semantics that were observed, not merely a compatible
    /// minimum: a future schema this build has never seen is a refusal with an
    /// action, never a hopeful read.
    private static func validate(_ manifestBytes: [UInt8]) throws {
        guard let manifest = try? JSONDecoder().decode(SessionManifest.self, from: Data(manifestBytes)),
              manifest.magic == SessionArchive.magic else
        {
            throw CaptureArchiveError.unsupportedSessionArchive
        }
        guard manifest.schemaVersion == SessionArchive.schemaVersion,
              manifest.minimumCompatibleSchemaVersion == SessionArchive.schemaVersion,
              manifest.captureFile == SessionArchive.captureFileName else
        {
            throw CaptureArchiveError.unsupportedSessionSchema
        }
    }
}
