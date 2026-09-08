import Foundation

// MARK: - ZipArchiveEntry

/// One central-directory entry, already validated against its local header.
///
/// `dataOffset` is resolved from the *local* header (its name and extra fields
/// may legally differ in length from the central copy), and the whole span is
/// range-checked against the archive before any byte is read.
nonisolated struct ZipArchiveEntry: Equatable {
    let name: String
    let isDirectory: Bool
    let isStored: Bool
    let checksum: UInt32
    let compressedSize: UInt64
    let uncompressedSize: UInt64
    let localHeaderOffset: UInt64
    let dataOffset: UInt64

    var dataEnd: UInt64 {
        dataOffset &+ compressedSize
    }
}

// MARK: - ZipArchiveIndex

/// A bounded, read-only index over a ZIP archive.
///
/// Nothing is ever extracted to a path: entry names are validated and then used
/// only as *lookup keys*. Traversal, absolute, backslash-separated, NUL-bearing
/// and symlink entries are refused during indexing, so no later code has to
/// remember to re-check them.
///
/// The index is deliberately strict — an archive that disagrees with itself is a
/// refusal, not a best-effort read:
///
///  * exactly one structurally consistent End Of Central Directory record;
///  * no ZIP64, no multi-disk, no encryption, no unknown general-purpose flags,
///    no compression method other than stored or deflate;
///  * every entry's local header agrees with its central record on name, method
///    and the flag bits that change how data is read;
///  * every entry's bytes lie before the central directory and no two entries'
///    spans overlap.
nonisolated struct ZipArchiveIndex {
    // MARK: Lifecycle

    init(source: CaptureArchiveSource, limits: CaptureArchiveLimits) throws {
        self.source = source
        let end = try Self.locateEndOfCentralDirectory(source: source, limits: limits)
        let central = try source.readExactly(at: end.directoryOffset, count: Int(end.directorySize))
        entries = try Self.readEntries(
            central: central,
            expectedCount: end.entryCount,
            directoryOffset: end.directoryOffset,
            source: source,
            limits: limits
        )
    }

    // MARK: Internal

    /// What one extraction step handed over: a slice of a caller-owned buffer,
    /// plus the compressed bytes consumed so far so quotas and progress can both
    /// be derived from real input consumption.
    typealias Sink = (_ buffer: [UInt8], _ offset: Int, _ count: Int, _ compressedConsumed: UInt64) throws -> Void

    let entries: [ZipArchiveEntry]

    func entry(named name: String) -> ZipArchiveEntry? {
        entries.first { $0.name == name }
    }

    /// Streams one entry's expanded bytes to `sink`, verifying the declared
    /// uncompressed size and CRC-32 before returning. Cancellation is checked
    /// once per chunk, so a large entry can be abandoned promptly.
    func extract(
        _ entry: ZipArchiveEntry,
        onProgress: (UInt64) -> Void,
        isCancelled: () -> Bool,
        into sink: Sink
    )
        throws
    {
        guard !entry.isDirectory else {
            throw CaptureArchiveError.malformed("a folder entry was asked to produce data")
        }
        var window = ArchiveInputWindow(capacity: Self.inputChunkLength, start: entry.dataOffset, end: entry.dataEnd)
        var checksum = ZlibChecksum()
        var produced: UInt64 = 0
        if entry.isStored {
            try copyStored(
                entry,
                window: &window,
                checksum: &checksum,
                produced: &produced,
                onProgress: onProgress,
                isCancelled: isCancelled,
                into: sink
            )
        } else {
            try inflateDeflated(
                window: &window,
                checksum: &checksum,
                produced: &produced,
                onProgress: onProgress,
                isCancelled: isCancelled,
                into: sink
            )
        }
        guard window.available == 0, window.consumedSourceOffset == entry.dataEnd else {
            throw CaptureArchiveError.malformed("an entry carried data past the end of its compressed stream")
        }
        guard produced == entry.uncompressedSize else {
            throw CaptureArchiveError.malformed("an entry expanded to a different size than it declared")
        }
        guard checksum.value == entry.checksum else {
            throw CaptureArchiveError.malformed("an entry failed its checksum")
        }
    }

    /// Extracts a small entry entirely into memory, refusing anything above
    /// `limit` before a byte is read.
    func extractToMemory(
        _ entry: ZipArchiveEntry,
        limit: Int,
        describedAs description: String,
        isCancelled: () -> Bool
    )
        throws -> [UInt8]
    {
        guard entry.uncompressedSize <= UInt64(limit) else {
            throw CaptureArchiveError.exceedsBound("\(description) larger than \(limit) bytes")
        }
        var collected = [UInt8]()
        collected.reserveCapacity(Int(entry.uncompressedSize))
        try extract(entry, onProgress: { _ in }, isCancelled: isCancelled) { buffer, offset, count, _ in
            collected.append(contentsOf: buffer[offset ..< (offset + count)])
        }
        return collected
    }

    // MARK: Private

    /// The fixed part of an End Of Central Directory record.
    private struct DirectoryEnd {
        let entryCount: Int
        let directoryOffset: UInt64
        let directorySize: UInt64
    }

    private static let endOfCentralDirectorySignature: UInt32 = 0x06054B50
    private static let zip64LocatorSignature: UInt32 = 0x07064B50
    private static let centralHeaderSignature: UInt32 = 0x02014B50
    private static let localHeaderSignature: UInt32 = 0x04034B50
    private static let dataDescriptorSignature: UInt32 = 0x08074B50

    private static let endOfCentralDirectoryLength = 22
    private static let centralHeaderLength = 46
    private static let localHeaderLength = 30
    /// The EOCD record plus the largest comment a 16-bit length can describe.
    private static let maximumDirectoryEndSearch = 22 + 65_535

    /// General-purpose bits Tracexy understands: two compression hints, the
    /// data-descriptor bit, and the UTF-8 name bit. Anything else set is refused.
    private static let supportedFlags: UInt16 = 0x080E
    private static let encryptedFlag: UInt16 = 0x0001
    private static let strongEncryptionFlag: UInt16 = 0x0040
    private static let dataDescriptorFlag: UInt16 = 0x0008
    /// The flag bits that must agree between the local and central records
    /// because they change how the entry's bytes are read.
    private static let flagsThatMustMatch: UInt16 = 0x0849

    private static let storedMethod: UInt16 = 0
    private static let deflateMethod: UInt16 = 8
    private static let zip64Marker32: UInt32 = 0xFFFFFFFF
    private static let zip64Marker16: UInt16 = 0xFFFF

    private static let inputChunkLength = 64 * 1_024
    private static let outputChunkLength = 256 * 1_024
    /// How many consecutive no-progress inflate calls are tolerated before the
    /// entry is declared damaged. zlib needs at most one to flush its tail.
    private static let maximumUnproductiveSteps = 2

    private let source: CaptureArchiveSource

    // MARK: Locating the directory

    /// Finds the one End Of Central Directory record whose declared comment
    /// length reaches exactly the end of the file.
    ///
    /// Several byte sequences in a large archive can look like an EOCD; only a
    /// position whose comment length lands precisely on EOF is structurally
    /// consistent. If two positions both do, the archive is ambiguous and is
    /// refused rather than guessed at.
    private static func locateEndOfCentralDirectory(
        source: CaptureArchiveSource,
        limits: CaptureArchiveLimits
    )
        throws -> DirectoryEnd
    {
        guard source.size >= UInt64(endOfCentralDirectoryLength) else {
            throw CaptureArchiveError.truncated
        }
        let searchLength = Int(min(source.size, UInt64(maximumDirectoryEndSearch)))
        let searchStart = source.size - UInt64(searchLength)
        let tail = try source.readExactly(at: searchStart, count: searchLength)

        var candidates = [Int]()
        for index in stride(from: searchLength - endOfCentralDirectoryLength, through: 0, by: -1) {
            guard readU32(tail, index) == endOfCentralDirectorySignature else {
                continue
            }
            let commentLength = Int(readU16(tail, index + 20))
            if index + endOfCentralDirectoryLength + commentLength == searchLength {
                candidates.append(index)
            }
        }
        guard candidates.count == 1, let position = candidates.first else {
            throw CaptureArchiveError.malformed(
                candidates.isEmpty ? "it has no end-of-archive record" : "its end-of-archive record is ambiguous"
            )
        }
        let absolute = searchStart + UInt64(position)

        // A ZIP64 locator immediately before the record means 64-bit fields we
        // deliberately do not parse.
        if absolute >= 20 {
            let locator = try source.readExactly(at: absolute - 20, count: 4)
            guard readU32(locator, 0) != zip64LocatorSignature else {
                throw CaptureArchiveError.unsupportedFeature("the ZIP64 extension")
            }
        }

        guard readU16(tail, position + 4) == 0, readU16(tail, position + 6) == 0 else {
            throw CaptureArchiveError.unsupportedFeature("multiple disks")
        }
        let entriesHere = readU16(tail, position + 8)
        let entriesTotal = readU16(tail, position + 10)
        guard entriesHere == entriesTotal else {
            throw CaptureArchiveError.malformed("its entry counts disagree")
        }
        let directorySize = readU32(tail, position + 12)
        let directoryOffset = readU32(tail, position + 16)
        guard entriesTotal != zip64Marker16,
              directorySize != zip64Marker32,
              directoryOffset != zip64Marker32 else
        {
            throw CaptureArchiveError.unsupportedFeature("the ZIP64 extension")
        }
        guard Int(entriesTotal) <= limits.maximumEntryCount else {
            throw CaptureArchiveError.exceedsBound("more than \(limits.maximumEntryCount) entries")
        }
        guard UInt64(directorySize) <= limits.maximumCentralDirectoryBytes else {
            throw CaptureArchiveError
                .exceedsBound("an entry index larger than \(limits.maximumCentralDirectoryBytes) bytes")
        }
        let directoryEnd = UInt64(directoryOffset) &+ UInt64(directorySize)
        guard directoryEnd >= UInt64(directoryOffset), directoryEnd <= absolute else {
            throw CaptureArchiveError.malformed("its entry index lies outside the archive")
        }
        return DirectoryEnd(
            entryCount: Int(entriesTotal),
            directoryOffset: UInt64(directoryOffset),
            directorySize: UInt64(directorySize)
        )
    }

    // MARK: Reading the directory

    private static func readEntries(
        central: [UInt8],
        expectedCount: Int,
        directoryOffset: UInt64,
        source: CaptureArchiveSource,
        limits: CaptureArchiveLimits
    )
        throws -> [ZipArchiveEntry]
    {
        var entries = [ZipArchiveEntry]()
        var seen = Set<String>()
        var spans = [(start: UInt64, end: UInt64)]()
        var cursor = 0
        for _ in 0 ..< expectedCount {
            guard cursor + centralHeaderLength <= central.count,
                  readU32(central, cursor) == centralHeaderSignature else
            {
                throw CaptureArchiveError.malformed("its entry index is truncated")
            }
            let flags = readU16(central, cursor + 8)
            let method = readU16(central, cursor + 10)
            let checksum = readU32(central, cursor + 16)
            let compressedSize = readU32(central, cursor + 20)
            let uncompressedSize = readU32(central, cursor + 24)
            let nameLength = Int(readU16(central, cursor + 28))
            let extraLength = Int(readU16(central, cursor + 30))
            let commentLength = Int(readU16(central, cursor + 32))
            let diskStart = readU16(central, cursor + 34)
            let externalAttributes = readU32(central, cursor + 38)
            let localHeaderOffset = readU32(central, cursor + 42)

            guard nameLength <= limits.maximumEntryNameBytes else {
                throw CaptureArchiveError
                    .exceedsBound("an entry name longer than \(limits.maximumEntryNameBytes) bytes")
            }
            let recordLength = centralHeaderLength + nameLength + extraLength + commentLength
            guard cursor + recordLength <= central.count else {
                throw CaptureArchiveError.malformed("its entry index is truncated")
            }
            try validate(flags: flags, method: method, diskStart: diskStart)
            guard compressedSize != zip64Marker32, uncompressedSize != zip64Marker32,
                  localHeaderOffset != zip64Marker32 else
            {
                throw CaptureArchiveError.unsupportedFeature("the ZIP64 extension")
            }
            guard (externalAttributes >> 16) & 0xF000 != 0xA000 else {
                throw CaptureArchiveError.unsupportedFeature("symbolic-link entries")
            }
            let nameBytes =
                Array(central[(cursor + centralHeaderLength) ..< (cursor + centralHeaderLength + nameLength)])
            let name = try safeEntryName(nameBytes)
            guard seen.insert(name).inserted else {
                throw CaptureArchiveError.malformed("it lists the same entry twice")
            }
            let isDirectory = name.hasSuffix("/")
            if isDirectory {
                guard uncompressedSize == 0, checksum == 0 else {
                    throw CaptureArchiveError.malformed("a folder entry claims to hold data")
                }
            }
            let dataOffset = try resolveDataOffset(
                localHeaderOffset: UInt64(localHeaderOffset),
                name: nameBytes,
                flags: flags,
                method: method,
                checksum: checksum,
                compressedSize: compressedSize,
                uncompressedSize: uncompressedSize,
                source: source
            )
            let dataEnd = dataOffset &+ UInt64(compressedSize)
            guard dataEnd >= dataOffset, dataEnd <= source.size else {
                throw CaptureArchiveError.malformed("an entry's data lies outside the archive")
            }
            let descriptorLength = try dataDescriptorLength(
                after: dataEnd,
                flags: flags,
                checksum: checksum,
                compressedSize: compressedSize,
                uncompressedSize: uncompressedSize,
                source: source
            )
            let recordEnd = dataEnd &+ descriptorLength
            guard recordEnd >= dataEnd, recordEnd <= directoryOffset else {
                throw CaptureArchiveError.malformed("an entry's data runs into its entry index")
            }
            entries.append(ZipArchiveEntry(
                name: name,
                isDirectory: isDirectory,
                isStored: method == storedMethod,
                checksum: checksum,
                compressedSize: UInt64(compressedSize),
                uncompressedSize: UInt64(uncompressedSize),
                localHeaderOffset: UInt64(localHeaderOffset),
                dataOffset: dataOffset
            ))
            spans.append((UInt64(localHeaderOffset), recordEnd))
            cursor += recordLength
        }
        guard cursor == central.count else {
            throw CaptureArchiveError.malformed("its entry index has unexplained trailing bytes")
        }
        try checkNonOverlapping(spans)
        return entries
    }

    private static func validate(flags: UInt16, method: UInt16, diskStart: UInt16) throws {
        guard flags & (encryptedFlag | strongEncryptionFlag) == 0 else {
            throw CaptureArchiveError.unsupportedFeature("encryption")
        }
        guard flags & ~supportedFlags == 0 else {
            throw CaptureArchiveError.unsupportedFeature("archive options Tracexy doesn't process")
        }
        guard method == storedMethod || method == deflateMethod else {
            throw CaptureArchiveError.unsupportedFeature("compression method \(method)")
        }
        guard diskStart == 0 else {
            throw CaptureArchiveError.unsupportedFeature("multiple disks")
        }
    }

    /// Rejects every name shape that could escape a container, then keeps the
    /// name only as a lookup key — nothing here is ever handed to the filesystem.
    private static func safeEntryName(_ bytes: [UInt8]) throws -> String {
        guard !bytes.isEmpty else {
            throw CaptureArchiveError.malformed("it contains an unnamed entry")
        }
        guard !bytes.contains(0x00), !bytes.contains(0x5C) else {
            throw CaptureArchiveError.malformed("an entry name contains a forbidden character")
        }
        guard let name = String(bytes: bytes, encoding: .utf8) else {
            throw CaptureArchiveError.malformed("an entry name is not valid text")
        }
        guard !name.hasPrefix("/") else {
            throw CaptureArchiveError.malformed("an entry name is an absolute path")
        }
        guard name.dropFirst().first != ":" else {
            throw CaptureArchiveError.malformed("an entry name carries a drive letter")
        }
        for component in name.split(separator: "/", omittingEmptySubsequences: true)
            where component == ".." || component == "."
        {
            throw CaptureArchiveError.malformed("an entry name tries to step outside the archive")
        }
        return name
    }

    /// Reads the local header so the data offset comes from the record that
    /// actually precedes the bytes, and cross-checks it against the central copy.
    private static func resolveDataOffset(
        localHeaderOffset: UInt64,
        name: [UInt8],
        flags: UInt16,
        method: UInt16,
        checksum: UInt32,
        compressedSize: UInt32,
        uncompressedSize: UInt32,
        source: CaptureArchiveSource
    )
        throws -> UInt64
    {
        let header = try source.readExactly(at: localHeaderOffset, count: localHeaderLength)
        guard readU32(header, 0) == localHeaderSignature else {
            throw CaptureArchiveError.malformed("an entry has no local header where its index says")
        }
        let localFlags = readU16(header, 6)
        let localMethod = readU16(header, 8)
        guard localMethod == method else {
            throw CaptureArchiveError.malformed("an entry's local and index compression methods disagree")
        }
        guard localFlags & flagsThatMustMatch == flags & flagsThatMustMatch else {
            throw CaptureArchiveError.malformed("an entry's local and index options disagree")
        }
        let localChecksum = readU32(header, 14)
        let localCompressed = readU32(header, 18)
        let localUncompressed = readU32(header, 22)
        let deferredSizes = flags & dataDescriptorFlag != 0
            && localChecksum == 0 && localCompressed == 0 && localUncompressed == 0
        if !deferredSizes {
            guard localChecksum == checksum,
                  localCompressed == compressedSize,
                  localUncompressed == uncompressedSize else
            {
                throw CaptureArchiveError.malformed("an entry's local and index sizes disagree")
            }
        }
        let localNameLength = Int(readU16(header, 26))
        let localExtraLength = Int(readU16(header, 28))
        guard localNameLength == name.count else {
            throw CaptureArchiveError.malformed("an entry's local and index names disagree")
        }
        let localName = try source.readExactly(
            at: localHeaderOffset &+ UInt64(localHeaderLength),
            count: localNameLength
        )
        guard localName == name else {
            throw CaptureArchiveError.malformed("an entry's local and index names disagree")
        }
        let dataOffset = localHeaderOffset
            &+ UInt64(localHeaderLength)
            &+ UInt64(localNameLength)
            &+ UInt64(localExtraLength)
        guard dataOffset > localHeaderOffset, dataOffset <= source.size else {
            throw CaptureArchiveError.malformed("an entry's data starts outside the archive")
        }
        return dataOffset
    }

    /// Validates the optional ZIP data descriptor instead of treating the bytes
    /// between compressed data and the next record as unexplained padding. The
    /// descriptor may carry its conventional signature or omit it; when a CRC
    /// happens to equal the signature value, the central-directory values decide
    /// which interpretation is consistent.
    private static func dataDescriptorLength(
        after dataEnd: UInt64,
        flags: UInt16,
        checksum: UInt32,
        compressedSize: UInt32,
        uncompressedSize: UInt32,
        source: CaptureArchiveSource
    )
        throws -> UInt64
    {
        guard flags & dataDescriptorFlag != 0 else {
            return 0
        }
        let descriptor = try source.readExactly(at: dataEnd, count: 16)
        let unsignedMatches = readU32(descriptor, 0) == checksum
            && readU32(descriptor, 4) == compressedSize
            && readU32(descriptor, 8) == uncompressedSize
        if unsignedMatches {
            return 12
        }
        let signedMatches = readU32(descriptor, 0) == dataDescriptorSignature
            && readU32(descriptor, 4) == checksum
            && readU32(descriptor, 8) == compressedSize
            && readU32(descriptor, 12) == uncompressedSize
        guard signedMatches else {
            throw CaptureArchiveError.malformed("an entry's data descriptor disagrees with its index")
        }
        return 16
    }

    private static func checkNonOverlapping(_ spans: [(start: UInt64, end: UInt64)]) throws {
        let ordered = spans.sorted { $0.start < $1.start }
        var previousEnd: UInt64 = 0
        for span in ordered {
            guard span.start >= previousEnd else {
                throw CaptureArchiveError.malformed("two entries claim the same bytes")
            }
            previousEnd = span.end
        }
    }

    // MARK: Little-endian field reads

    /// The caller has already range-checked `offset`; these never read past the
    /// buffer because every use site validated the record length first.
    private static func readU16(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
        guard offset >= 0, offset + 2 <= bytes.count else {
            return 0
        }
        return UInt16(bytes[offset]) | (UInt16(bytes[offset + 1]) << 8)
    }

    private static func readU32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        guard offset >= 0, offset + 4 <= bytes.count else {
            return 0
        }
        return UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }

    // MARK: Extraction

    private func copyStored(
        _ entry: ZipArchiveEntry,
        window: inout ArchiveInputWindow,
        checksum: inout ZlibChecksum,
        produced: inout UInt64,
        onProgress: (UInt64) -> Void,
        isCancelled: () -> Bool,
        into sink: Sink
    )
        throws
    {
        guard entry.compressedSize == entry.uncompressedSize else {
            throw CaptureArchiveError.malformed("an uncompressed entry declares two different sizes")
        }
        while true {
            if isCancelled() {
                throw CancellationError()
            }
            try window.fill(from: source)
            let available = window.available
            guard available > 0 else {
                break
            }
            checksum.update(window.bytes, offset: window.offset, count: available)
            produced &+= UInt64(available)
            let consumed = window.consumedSourceOffset &+ UInt64(available)
            try sink(window.bytes, window.offset, available, consumed)
            window.consume(available)
            onProgress(window.consumedSourceOffset)
        }
        guard produced == entry.uncompressedSize else {
            throw CaptureArchiveError.truncated
        }
    }

    private func inflateDeflated(
        window: inout ArchiveInputWindow,
        checksum: inout ZlibChecksum,
        produced: inout UInt64,
        onProgress: (UInt64) -> Void,
        isCancelled: () -> Bool,
        into sink: Sink
    )
        throws
    {
        let stream = try ZlibInflateStream(mode: .rawDeflate)
        var output = [UInt8](repeating: 0, count: Self.outputChunkLength)
        var unproductive = 0
        // The only normal exit is zlib reporting the end of the raw stream; every
        // other way out of this loop is a throw.
        while true {
            if isCancelled() {
                throw CancellationError()
            }
            try window.fill(from: source)
            let outcome = try stream.step(
                input: window.bytes,
                offset: window.offset,
                available: window.available,
                into: &output
            )
            window.consume(outcome.consumed)
            if outcome.produced > 0 {
                checksum.update(output, offset: 0, count: outcome.produced)
                produced &+= UInt64(outcome.produced)
                try sink(output, 0, outcome.produced, window.consumedSourceOffset)
            }
            onProgress(window.consumedSourceOffset)
            if outcome.finished {
                break
            }
            if outcome.madeProgress {
                unproductive = 0
            } else {
                unproductive += 1
                guard unproductive < Self.maximumUnproductiveSteps, !(window.available == 0 && window.isAtEnd) else {
                    throw CaptureArchiveError.truncated
                }
            }
        }
        // The declared size and CRC-32 are verified by `extract`; nothing about
        // the entry is trusted from the compressed stream itself.
    }
}
