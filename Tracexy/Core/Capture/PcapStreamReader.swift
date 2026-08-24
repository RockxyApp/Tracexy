import Foundation
#if canImport(Darwin)
import Darwin
#endif

// MARK: - PcapFileIdentity

/// A snapshot of the on-disk identity of an opened classic `.pcap` file, taken
/// once when the stream is opened. Frame payload offsets emitted by a
/// ``PcapStreamReader`` are only meaningful against the exact file this identity
/// describes: if the file is replaced or rewritten out from under the reader the
/// snapshot no longer matches, and offsets from a stale stream must not be reused
/// to reopen and seek. `size`/`modifiedAt` are the cheap change witnesses; the
/// descriptor identity (device + inode, where the platform provides it) is the
/// stable handle-level identity independent of path.
nonisolated struct PcapFileIdentity: Sendable, Equatable {
    /// File length in bytes at open time.
    let size: UInt64
    /// Last-modification instant at open time, when the platform reports one.
    let modifiedAt: Date?
    /// Filesystem device number at open time, when available (`0` otherwise).
    let device: UInt64
    /// Filesystem inode at open time, when available (`0` otherwise). Together with
    /// `device` this is the stable descriptor-level identity of the opened file.
    let inode: UInt64
}

// MARK: - PcapStreamMetadata

/// Immutable description of a classic `.pcap` stream: the byte order and timestamp
/// resolution implied by its magic, its single link-layer type and snap length,
/// and the identity of the file it was read from. A ``PcapFrameReference``'s
/// offsets are valid only against the `identity` carried here.
nonisolated struct PcapStreamMetadata: Sendable, Equatable {
    /// The file's single link-layer type (`DLT_*`).
    let linkType: UInt32
    /// Declared snapshot length from the global header.
    let snapLength: UInt32
    /// Whether record fields are little-endian.
    let littleEndian: Bool
    /// Whether timestamp fractions are nanoseconds (`true`) or microseconds.
    let nanosecond: Bool
    /// Byte offset at which the first record header begins (past the global header).
    let firstRecordOffset: UInt64
    /// Identity of the file these offsets are valid against.
    let identity: PcapFileIdentity
}

// MARK: - PcapFrameReference

/// A pointer to one captured frame *within a specific stream*, carrying no bytes.
///
/// The offsets are absolute byte positions in the file described by the owning
/// ``PcapStreamMetadata``'s identity, and are valid only for that identity — they
/// are for correlating a frame with its location in the sequential stream, not a
/// license to reopen the file and seek randomly.
nonisolated struct PcapFrameReference: Sendable, Equatable {
    /// Absolute offset of the 16-byte record header.
    let recordHeaderOffset: UInt64
    /// Absolute offset of the captured payload (`recordHeaderOffset + 16`).
    let payloadOffset: UInt64
    /// `incl_len`: number of bytes actually captured for this frame.
    let capturedLength: Int
    /// `orig_len`: the frame's original on-wire length (>= `capturedLength`).
    let originalLength: Int
    /// Decoded capture timestamp.
    let timestamp: Date
}

// MARK: - PcapStreamProgress

/// Monotonic progress through the opened file. `totalBytes` is the file-size
/// snapshot in ``PcapStreamMetadata``; the terminal reason remains authoritative
/// when every available byte was consumed from a truncated file.
nonisolated struct PcapStreamProgress: Sendable, Equatable {
    let bytesConsumed: UInt64
    let totalBytes: UInt64
}

// MARK: - PcapFrameEvent

/// One successfully read frame: its ``PcapFrameReference``, the captured bytes,
/// and the monotonic cumulative byte progress through the file after consuming it.
nonisolated struct PcapFrameEvent: Sendable, Equatable {
    let reference: PcapFrameReference
    let bytes: [UInt8]
    /// Total bytes consumed from the file so far (record header + payload of this
    /// and every prior frame, plus the global header). Increases monotonically.
    let progress: PcapStreamProgress
}

// MARK: - PcapStreamTermination

/// Why a ``PcapStreamReader`` walk ended. All three are ordinary, non-error
/// outcomes: a well-formed file ends with `cleanEndOfFile`, and a file whose tail
/// was cut mid-record ends with a partial terminal while every complete prior
/// frame remains valid.
nonisolated enum PcapStreamTermination: Sendable, Equatable {
    /// The file ended exactly on a record boundary.
    case cleanEndOfFile
    /// Fewer than a full 16-byte record header remained at the end of the file.
    case partialRecordHeader
    /// A complete record header declared a payload longer than the bytes remaining.
    case partialPayload
}

// MARK: - PcapStreamCompletion

/// A terminal reason paired with the final byte progress. Truncated terminals
/// therefore remain distinguishable from successful completion even though both
/// consume every byte that is physically present.
nonisolated struct PcapStreamCompletion: Sendable, Equatable {
    let reason: PcapStreamTermination
    let progress: PcapStreamProgress
}

// MARK: - PcapStreamOutcome

/// The result of a single ``PcapStreamReader/next()`` pull: either a frame or a
/// terminal reason. Once a terminal is reached it is returned again on every
/// further pull.
nonisolated enum PcapStreamOutcome: Sendable, Equatable {
    case frame(PcapFrameEvent)
    case end(PcapStreamCompletion)
}

// MARK: - PcapStreamReader

/// A synchronous, pull-based reader for the classic libpcap (`.pcap`) format that
/// streams one record at a time straight from a `FileHandle`.
///
/// This is deliberately **not** `Sendable`: it owns a mutable file cursor and a
/// live descriptor and must be driven by a single task/executor. Unlike
/// ``PcapReader/read(_:)``, which parses a byte array already resident in memory,
/// this reader never allocates anything file-sized — it reads the fixed 24-byte
/// global header and then, per frame, a fixed 16-byte record header followed by a
/// single payload allocation bounded by the configured captured-length cap. There
/// is no whole-file `Data`/`[UInt8]` load and no `mmap`.
///
/// Only the newer pcapng block format is out of scope; both classic byte orders
/// and the microsecond/nanosecond timestamp variants are handled here.
nonisolated final class PcapStreamReader {
    // MARK: Lifecycle

    /// Open `url` and parse its global header, snapshotting file identity.
    ///
    /// - Throws: `PacketError.malformed` on a short/absent global header or an
    ///   unrecognised magic; rethrows any `FileHandle` open/read error.
    init(contentsOf url: URL, configuration: Configuration = Configuration()) throws {
        self.configuration = configuration
        let handle = try FileHandle(forReadingFrom: url)
        self.handle = handle

        // Read exactly the 24-byte global header. A shorter read means the file is
        // truncated before the header even completes — a hard malformed error,
        // matching the array reader's "shorter than 24-byte global header".
        let headerData = try Self.readFully(handle, count: Self.globalHeaderSize)
        guard headerData.count == Self.globalHeaderSize else {
            try? handle.close()
            throw PacketError.malformed("pcap: file shorter than 24-byte global header")
        }

        let header = PacketBuffer([UInt8](headerData))
        let rawMagic = try header.u32(0)
        guard let format = MagicFormat(rawMagic: rawMagic) else {
            try? handle.close()
            throw PacketError.malformed(String(format: "pcap: unknown magic 0x%08X", rawMagic))
        }
        self.format = format

        let snapLength = format.littleEndian ? try header.u32le(16) : try header.u32(16)
        let linkType = format.littleEndian ? try header.u32le(20) : try header.u32(20)

        metadata = PcapStreamMetadata(
            linkType: linkType,
            snapLength: snapLength,
            littleEndian: format.littleEndian,
            nanosecond: format.nanosecond,
            firstRecordOffset: UInt64(Self.globalHeaderSize),
            identity: Self.identity(of: handle)
        )
        offset = UInt64(Self.globalHeaderSize)
    }

    deinit {
        try? handle.close()
    }

    // MARK: Internal

    /// Tunables for a stream read.
    nonisolated struct Configuration: Sendable {
        // MARK: Lifecycle

        init(
            maxCapturedLength: Int = CapturedFrame.maxReasonableLength,
            isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }
        ) {
            self.maxCapturedLength = maxCapturedLength
            self.isCancelled = isCancelled
        }

        // MARK: Internal

        /// Upper bound on an accepted `incl_len`. A record declaring more is
        /// rejected as malformed *before* any payload allocation, so a corrupt
        /// length can never be trusted into a huge allocation.
        let maxCapturedLength: Int
        /// Cooperative cancellation predicate, consulted before each record's IO
        /// and again between its header and payload. Defaults to `Task.isCancelled`.
        let isCancelled: @Sendable () -> Bool
    }

    /// Immutable description of the opened stream.
    let metadata: PcapStreamMetadata

    /// Pull the next record.
    ///
    /// - Returns: `.frame` for a fully read record, or `.end` once the walk ends.
    ///   After any `.end` the same terminal is returned on every further call.
    /// - Throws: `CancellationError` if cancellation is observed (before the
    ///   record's IO or between its header and payload); `PacketError.malformed`
    ///   for corrupt record metadata (over-limit captured length, `orig < incl`,
    ///   or an impossible timestamp fraction).
    func next() throws -> PcapStreamOutcome {
        if let termination {
            return .end(termination)
        }
        if let failure {
            throw failure
        }

        do {
            return try readNext()
        } catch {
            // A failed read may have advanced the descriptor (for example when
            // cancellation arrives after the record header). Poison the reader so
            // a caller cannot catch the error and resume from a mismatched cursor.
            failure = error
            throw error
        }
    }

    // MARK: Private

    private static let globalHeaderSize = 24
    private static let recordHeaderSize = 16

    private let handle: FileHandle
    private let format: MagicFormat
    private let configuration: Configuration
    /// Absolute offset of the next record header to read; also the file cursor,
    /// since the handle is only ever read sequentially forward (no seeking).
    private var offset: UInt64
    /// Once set, the walk has ended and this terminal is replayed on every pull.
    private var termination: PcapStreamCompletion?
    /// Any thrown cancellation, malformed-input, arithmetic, or IO error poisons
    /// the mutable reader. Replaying it is safer than resuming after unknown cursor
    /// movement.
    private var failure: Error?

    /// Read exactly `count` bytes, looping until satisfied or the file ends. Returns
    /// however many bytes were available (`< count` only at EOF); allocates at most
    /// `count` bytes, which for payloads is bounded by the captured-length cap.
    private static func readFully(_ handle: FileHandle, count: Int) throws -> Data {
        guard count > 0 else {
            return Data()
        }
        var collected = Data()
        collected.reserveCapacity(count)
        while collected.count < count {
            guard let chunk = try handle.read(upToCount: count - collected.count), !chunk.isEmpty else {
                break
            }
            collected.append(chunk)
        }
        return collected
    }

    /// Checked unsigned addition; throws rather than wrapping on overflow.
    private static func checkedAdd(_ lhs: UInt64, _ rhs: UInt64) throws -> UInt64 {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        guard !overflow else {
            throw PacketError.malformed("pcap: offset arithmetic overflow")
        }
        return sum
    }

    /// Snapshot the opened file's identity from its descriptor where the platform
    /// allows; fall back to the empty identity when `fstat` is unavailable.
    private static func identity(of handle: FileHandle) -> PcapFileIdentity {
        #if canImport(Darwin)
        var info = stat()
        if fstat(handle.fileDescriptor, &info) == 0 {
            let modified = Date(
                timeIntervalSince1970: Double(info.st_mtimespec.tv_sec)
                    + Double(info.st_mtimespec.tv_nsec) / 1_000_000_000
            )
            return PcapFileIdentity(
                size: UInt64(max(0, info.st_size)),
                modifiedAt: modified,
                device: UInt64(bitPattern: Int64(info.st_dev)),
                inode: info.st_ino
            )
        }
        #endif
        return PcapFileIdentity(size: 0, modifiedAt: nil, device: 0, inode: 0)
    }

    private func readNext() throws -> PcapStreamOutcome {
        try checkCancellation()

        let recordHeaderOffset = offset
        let headerData = try Self.readFully(handle, count: Self.recordHeaderSize)
        if headerData.isEmpty {
            return try finish(.cleanEndOfFile, bytesConsumed: recordHeaderOffset)
        }
        guard headerData.count == Self.recordHeaderSize else {
            let consumed = try Self.checkedAdd(recordHeaderOffset, UInt64(headerData.count))
            return finish(.partialRecordHeader, bytesConsumed: consumed)
        }

        let record = PacketBuffer([UInt8](headerData))
        let tsSeconds = format.littleEndian ? try record.u32le(0) : try record.u32(0)
        let tsFraction = format.littleEndian ? try record.u32le(4) : try record.u32(4)
        let inclLen = try Int(format.littleEndian ? record.u32le(8) : record.u32(8))
        let origLen = try Int(format.littleEndian ? record.u32le(12) : record.u32(12))

        // Reject corrupt metadata before allocating or reading any payload.
        let fractionLimit: UInt32 = format.nanosecond ? 1_000_000_000 : 1_000_000
        guard tsFraction < fractionLimit else {
            throw PacketError.malformed("pcap: timestamp fraction \(tsFraction) out of range")
        }
        guard inclLen <= configuration.maxCapturedLength else {
            throw PacketError.malformed(
                "pcap: captured length \(inclLen) exceeds limit \(configuration.maxCapturedLength)"
            )
        }
        guard origLen >= inclLen else {
            throw PacketError.malformed("pcap: original length \(origLen) below captured length \(inclLen)")
        }

        // Cancellation check #2: header parsed and validated, before the payload IO.
        try checkCancellation()

        let payloadOffset = try Self.checkedAdd(recordHeaderOffset, UInt64(Self.recordHeaderSize))
        let payloadData = try Self.readFully(handle, count: inclLen)
        guard payloadData.count == inclLen else {
            let consumed = try Self.checkedAdd(payloadOffset, UInt64(payloadData.count))
            return finish(.partialPayload, bytesConsumed: consumed)
        }

        let nextOffset = try Self.checkedAdd(payloadOffset, UInt64(inclLen))
        offset = nextOffset

        let reference = PcapFrameReference(
            recordHeaderOffset: recordHeaderOffset,
            payloadOffset: payloadOffset,
            capturedLength: inclLen,
            originalLength: origLen,
            timestamp: format.timestamp(seconds: tsSeconds, fraction: tsFraction)
        )
        return .frame(PcapFrameEvent(
            reference: reference,
            bytes: [UInt8](payloadData),
            progress: progress(bytesConsumed: nextOffset)
        ))
    }

    private func checkCancellation() throws {
        if configuration.isCancelled() {
            throw CancellationError()
        }
    }

    private func progress(bytesConsumed: UInt64) -> PcapStreamProgress {
        PcapStreamProgress(
            bytesConsumed: bytesConsumed,
            totalBytes: metadata.identity.size
        )
    }

    /// Record the terminal reason and exact final progress, then replay that same
    /// completion on every later pull.
    private func finish(
        _ reason: PcapStreamTermination,
        bytesConsumed: UInt64
    )
        -> PcapStreamOutcome
    {
        offset = bytesConsumed
        let completion = PcapStreamCompletion(
            reason: reason,
            progress: progress(bytesConsumed: bytesConsumed)
        )
        termination = completion
        return .end(completion)
    }
}
