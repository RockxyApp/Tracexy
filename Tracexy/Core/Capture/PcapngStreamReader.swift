import Foundation
#if canImport(Darwin)
import Darwin
#endif

// MARK: - PcapngStreamMetadata

/// Immutable description of an opened pcapng stream. pcapng carries no single
/// file-wide link type or timestamp resolution — those are per-interface and can
/// change between sections — so the only stream-wide fact stored here is the
/// identity of the file the emitted offsets are valid against. A
/// ``PcapngFrameReference``'s offsets are meaningful only for this `identity`.
nonisolated struct PcapngStreamMetadata: Sendable, Equatable {
    /// Identity of the file these offsets are valid against.
    let identity: PcapFileIdentity
}

// MARK: - PcapngFrameReference

/// A pointer to one captured frame *within a specific pcapng stream*, carrying no
/// bytes. Offsets are absolute byte positions in the file described by the owning
/// ``PcapngStreamMetadata``'s identity, valid only for that identity.
nonisolated struct PcapngFrameReference: Sendable, Equatable {
    /// Absolute offset of the enclosing block's leading type field.
    let blockOffset: UInt64
    /// Absolute offset of the captured payload bytes inside the block.
    let payloadOffset: UInt64
    /// Number of bytes actually captured for this frame.
    let capturedLength: Int
    /// The frame's original on-wire length (>= `capturedLength`).
    let originalLength: Int
    /// Decoded capture timestamp (Unix epoch for a Simple Packet Block).
    let timestamp: Date
    /// Zero-based index of the section this frame was found in.
    let sectionIndex: Int
    /// Declaration-order interface id within the current section.
    let interfaceID: Int
    /// Link type of the interface this frame was captured on.
    let linkType: UInt32
}

// MARK: - PcapngFrameEvent

/// One successfully read frame: its ``PcapngFrameReference``, the captured bytes,
/// and the monotonic cumulative byte progress through the file after consuming its
/// enclosing block.
nonisolated struct PcapngFrameEvent: Sendable, Equatable {
    let reference: PcapngFrameReference
    let bytes: [UInt8]
    /// Total bytes consumed from the file so far. Increases monotonically.
    let progress: PcapStreamProgress
}

// MARK: - PcapngStreamTermination

/// Why a ``PcapngStreamReader`` walk ended. All three are ordinary, non-error
/// outcomes reached only after a valid first Section Header Block: a well-formed
/// file ends `cleanEndOfFile`, and a file whose tail was cut ends with a partial
/// terminal while every complete prior frame remains valid.
nonisolated enum PcapngStreamTermination: Sendable, Equatable {
    /// The file ended exactly on a block boundary.
    case cleanEndOfFile
    /// One to seven bytes — too few for a block header — remained at the end.
    case partialBlockHeader
    /// A declared block (including a later section header with only 8...11 bytes
    /// available) extended past the end of the file.
    case partialBlockBody
}

// MARK: - PcapngStreamCompletion

/// A terminal reason paired with the final byte progress, so truncated terminals
/// remain distinguishable from success even though both consume every byte present.
nonisolated struct PcapngStreamCompletion: Sendable, Equatable {
    let reason: PcapngStreamTermination
    let progress: PcapStreamProgress
}

// MARK: - PcapngStreamOutcome

/// The result of a single ``PcapngStreamReader/next()`` pull: either a frame or a
/// terminal reason. Once a terminal is reached it is returned again on every
/// further pull.
nonisolated enum PcapngStreamOutcome: Sendable, Equatable {
    case frame(PcapngFrameEvent)
    case end(PcapngStreamCompletion)
}

// MARK: - PcapngStreamReader

/// A synchronous, pull-based reader for the pcapng (`.pcapng`) block format that
/// streams one block at a time straight from a `FileHandle`.
///
/// This is deliberately **not** `Sendable`: it owns a mutable file cursor and a
/// live descriptor and must be driven by a single task/executor. It never
/// allocates anything file-sized. A block's declared length is validated against
/// the opened file's size snapshot but never drives an allocation; unknown blocks
/// and option regions are size-checked and seeked past rather than read into
/// memory. The only file-derived allocation is a single accepted packet payload,
/// bounded by the configured captured-length cap.
///
/// Multiple sections are supported: every Section Header Block may switch byte
/// order and resets the section-local interface table. Enhanced and Simple Packet
/// Blocks become frames; Interface Description Blocks contribute link type, snap
/// length and timestamp resolution/offset.
nonisolated final class PcapngStreamReader {
    // MARK: Lifecycle

    /// Open `url`, snapshotting file identity. No block bytes are read until the
    /// first ``next()``; the first block is required to be a valid Section Header
    /// Block and that is enforced on the first pull.
    ///
    /// - Throws: rethrows any `FileHandle` open error.
    init(contentsOf url: URL, configuration: Configuration = Configuration()) throws {
        self.configuration = configuration
        let handle = try FileHandle(forReadingFrom: url)
        self.handle = handle
        metadata = PcapngStreamMetadata(identity: Self.identity(of: handle))
        offset = 0
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

        /// Upper bound on an accepted captured length. A block declaring more is
        /// rejected as malformed *before* any payload allocation.
        let maxCapturedLength: Int
        /// Cooperative cancellation predicate, consulted before each block's IO and
        /// between its fixed header, payload, option and trailer operations.
        let isCancelled: @Sendable () -> Bool
    }

    /// Immutable description of the opened stream.
    let metadata: PcapngStreamMetadata

    /// Link type of the first Interface Description Block seen anywhere in the
    /// file, or `nil` until one is parsed. Used by the collecting compatibility
    /// adapter, which must report a file-level link type.
    private(set) var firstDeclaredLinkType: UInt32?

    /// Pull the next frame.
    ///
    /// Non-frame blocks (section headers, interface descriptions, unknown blocks)
    /// are consumed internally; this returns `.frame` for the next packet block or
    /// `.end` once the walk ends. After any `.end` the same terminal is returned on
    /// every further call.
    ///
    /// - Throws: `CancellationError` if cancellation is observed;
    ///   `PacketError.malformed` for structurally impossible metadata. Either
    ///   poisons the reader so a caller cannot resume from a mismatched cursor.
    func next() throws -> PcapngStreamOutcome {
        if let termination {
            return .end(termination)
        }
        if let failure {
            throw failure
        }

        do {
            while true {
                switch try readBlock() {
                case let .frame(event):
                    return .frame(event)
                case let .terminated(completion):
                    termination = completion
                    return .end(completion)
                case .advanced:
                    continue
                }
            }
        } catch {
            // A failed read may have advanced the descriptor. Poison the reader so
            // a caller cannot catch the error and resume from a mismatched cursor.
            failure = error
            throw error
        }
    }

    // MARK: Private

    /// One step of the block walk.
    private enum Step {
        case frame(PcapngFrameEvent)
        case terminated(PcapngStreamCompletion)
        case advanced
    }

    /// Result of validating a block's declared leading length.
    private enum LengthValidation {
        case ok(blockEndTotal: UInt64)
        case truncated(PcapngStreamCompletion)
    }

    /// One interface declared within the current section.
    private struct SectionInterface {
        let linkType: UInt32
        let snapLength: UInt32
        /// Timestamp ticks per second (10^6 for the microsecond default).
        let ticksPerSecond: UInt64
        /// Signed seconds added to every timestamp on this interface.
        let timestampOffsetSeconds: Int64
    }

    private static let blockHeaderPrefix = 8
    private static let sectionHeaderTypeBytes: [UInt8] = [0x0A, 0x0D, 0x0D, 0x0A]
    private static let interfaceDescriptionType: UInt32 = 0x00000001
    private static let simplePacketType: UInt32 = 0x00000003
    private static let enhancedPacketType: UInt32 = 0x00000006
    private static let byteOrderMagicBig: UInt32 = 0x1A2B3C4D
    private static let byteOrderMagicLittle: UInt32 = 0x4D3C2B1A
    private static let minSectionHeaderLength: UInt64 = 28
    private static let optionEndOfOptions: UInt16 = 0
    private static let optionTimestampResolution: UInt16 = 9
    private static let optionTimestampOffset: UInt16 = 14

    private let handle: FileHandle
    private let configuration: Configuration
    /// Absolute offset of the next byte to read. Kept in lock-step with the handle
    /// position by every ``readFully(_:)`` and ``seek(to:)`` call.
    private var offset: UInt64
    /// Once set, the walk has ended and this terminal replays on every pull.
    private var termination: PcapngStreamCompletion?
    /// Any thrown error poisons the mutable reader; replaying it is safer than
    /// resuming after unknown cursor movement.
    private var failure: Error?
    /// Whether a valid first Section Header Block has been parsed.
    private var haveSection = false
    /// Byte order of the current section (set by its Section Header Block).
    private var littleEndian = false
    /// Zero-based index of the current section; `-1` before the first SHB.
    private var sectionIndex = -1
    /// Interfaces declared in the current section, in declaration order. Reset on
    /// every new section header.
    private var interfaces: [SectionInterface] = []

    /// Minimum aligned total length for a block of the given type.
    private static func minimumLength(forType type: UInt32) -> UInt64 {
        switch type {
        case interfaceDescriptionType: 20
        case enhancedPacketType: 32
        case simplePacketType: 16
        default: 12
        }
    }

    /// Ticks-per-second for a raw `if_tsresol` byte: high bit selects a power of
    /// two, otherwise a power of ten. Both exponents are range-checked so an
    /// out-of-range or overflowing resolution is malformed rather than normalized.
    private static func timestampTicksPerSecond(raw: UInt8) throws -> UInt64 {
        let exponent = raw & 0x7F
        if raw & 0x80 != 0 {
            guard exponent <= 63 else {
                throw PacketError.malformed("pcapng: binary if_tsresol exponent \(exponent) out of range")
            }
            return UInt64(1) << UInt64(exponent)
        }
        guard exponent <= 19 else {
            throw PacketError.malformed("pcapng: decimal if_tsresol exponent \(exponent) out of range")
        }
        var result: UInt64 = 1
        for _ in 0 ..< exponent {
            let (product, overflow) = result.multipliedReportingOverflow(by: 10)
            guard !overflow else {
                throw PacketError.malformed("pcapng: if_tsresol overflow")
            }
            result = product
        }
        return result
    }

    /// Combine a 64-bit tick count with a resolution and signed offset into a
    /// `Date`, rejecting a non-finite result rather than yielding NaN/±inf.
    private static func timestamp(
        ticksHigh: UInt64,
        ticksLow: UInt64,
        ticksPerSecond: UInt64,
        offsetSeconds: Int64
    )
        throws -> Date
    {
        let ticks = (ticksHigh << 32) | ticksLow
        let seconds = Double(ticks) / Double(ticksPerSecond) + Double(offsetSeconds)
        guard seconds.isFinite else {
            throw PacketError.malformed("pcapng: non-finite timestamp")
        }
        return Date(timeIntervalSince1970: seconds)
    }

    /// Round `value` up to the next 32-bit boundary, throwing on a negative value
    /// or arithmetic overflow.
    private static func roundUpToWord(_ value: Int) throws -> Int {
        guard value >= 0 else {
            throw PacketError.malformed("pcapng: negative length \(value)")
        }
        let (sum, overflow) = value.addingReportingOverflow(3)
        guard !overflow else {
            throw PacketError.malformed("pcapng: length overflow")
        }
        return sum & ~3
    }

    /// Checked unsigned addition; throws rather than wrapping on overflow.
    private static func checkedAdd(_ lhs: UInt64, _ rhs: UInt64) throws -> UInt64 {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        guard !overflow else {
            throw PacketError.malformed("pcapng: offset arithmetic overflow")
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

    private func readBlock() throws -> Step {
        try checkCancellation()
        let blockStart = offset
        let head = try readFully(Self.blockHeaderPrefix)
        if head.isEmpty {
            guard haveSection else {
                throw PacketError.malformed("pcapng: missing section header block")
            }
            return .terminated(completion(reason: .cleanEndOfFile, bytesConsumed: blockStart))
        }
        if head.count < Self.blockHeaderPrefix {
            guard haveSection else {
                throw PacketError.malformed("pcapng: truncated first section header block")
            }
            return try .terminated(completion(
                reason: .partialBlockHeader,
                bytesConsumed: Self.checkedAdd(blockStart, UInt64(head.count))
            ))
        }

        let prefix = [UInt8](head)
        if Array(prefix[0 ..< 4]) == Self.sectionHeaderTypeBytes {
            return try beginSection(blockStart: blockStart, prefix: prefix)
        }
        guard haveSection else {
            throw PacketError.malformed("pcapng: first block is not a section header block")
        }
        return try continueSection(blockStart: blockStart, prefix: prefix)
    }

    /// Handle a Section Header Block, bootstrapping this section's byte order from
    /// its own byte-order magic before interpreting its declared length.
    private func beginSection(blockStart: UInt64, prefix: [UInt8]) throws -> Step {
        let bomData = try readFully(4)
        if bomData.count < 4 {
            guard haveSection else {
                throw PacketError.malformed("pcapng: truncated first section header block")
            }
            return try .terminated(completion(
                reason: .partialBlockBody,
                bytesConsumed: Self.checkedAdd(blockStart, UInt64(Self.blockHeaderPrefix + bomData.count))
            ))
        }
        let magic = try PacketBuffer([UInt8](bomData)).u32(0)
        let little: Bool
        switch magic {
        case Self.byteOrderMagicBig: little = false
        case Self.byteOrderMagicLittle: little = true
        default:
            throw PacketError.malformed(String(format: "pcapng: bad byte-order magic 0x%08X", magic))
        }
        let prefixBuffer = PacketBuffer(prefix)
        let totalLength = try UInt64(little ? prefixBuffer.u32le(4) : prefixBuffer.u32(4))
        switch try validatedLength(totalLength, blockStart: blockStart, minimum: Self.minSectionHeaderLength) {
        case let .truncated(completion):
            return .terminated(completion)
        case let .ok(blockEndTotal):
            return try finishSectionHeader(
                blockStart: blockStart,
                totalLength: totalLength,
                blockEndTotal: blockEndTotal,
                little: little
            )
        }
    }

    private func finishSectionHeader(
        blockStart: UInt64,
        totalLength: UInt64,
        blockEndTotal: UInt64,
        little: Bool
    )
        throws -> Step
    {
        try checkCancellation()
        let versionData = try readFully(4)
        guard versionData.count == 4 else {
            throw PacketError.malformed("pcapng: truncated section header block")
        }
        let versionBuffer = PacketBuffer([UInt8](versionData))
        let major = try little ? versionBuffer.u16le(0) : versionBuffer.u16(0)
        guard major == 1 else {
            throw PacketError.malformed("pcapng: unsupported version \(major)")
        }
        // The 8-byte section length at blockStart+16 is intentionally ignored: it
        // never drives allocation or bounds.
        try validateTrailer(blockStart: blockStart, totalLength: totalLength, little: little)
        littleEndian = little
        haveSection = true
        sectionIndex += 1
        interfaces.removeAll(keepingCapacity: true)
        offset = blockEndTotal
        return .advanced
    }

    /// Dispatch a non-section block using the current section's byte order.
    private func continueSection(blockStart: UInt64, prefix: [UInt8]) throws -> Step {
        let little = littleEndian
        let buffer = PacketBuffer(prefix)
        let type = try little ? buffer.u32le(0) : buffer.u32(0)
        let totalLength = try UInt64(little ? buffer.u32le(4) : buffer.u32(4))
        switch try validatedLength(totalLength, blockStart: blockStart, minimum: Self.minimumLength(forType: type)) {
        case let .truncated(completion):
            return .terminated(completion)
        case let .ok(blockEndTotal):
            switch type {
            case Self.interfaceDescriptionType:
                return try readInterfaceDescription(
                    blockStart: blockStart, totalLength: totalLength, blockEndTotal: blockEndTotal, little: little
                )
            case Self.enhancedPacketType:
                return try readEnhancedPacket(
                    blockStart: blockStart, totalLength: totalLength, blockEndTotal: blockEndTotal, little: little
                )
            case Self.simplePacketType:
                return try readSimplePacket(
                    blockStart: blockStart, totalLength: totalLength, blockEndTotal: blockEndTotal, little: little
                )
            default:
                return try skipUnknown(
                    blockStart: blockStart, totalLength: totalLength, blockEndTotal: blockEndTotal, little: little
                )
            }
        }
    }

    /// Validate a declared block length: aligned, at least the per-type minimum,
    /// and contained by the file snapshot. A structurally impossible length is a
    /// malformed error; a length that merely runs past the file end is a truncation
    /// terminal (unless it is the incomplete first section header, which is hard
    /// malformed).
    private func validatedLength(
        _ totalLength: UInt64,
        blockStart: UInt64,
        minimum: UInt64
    )
        throws -> LengthValidation
    {
        guard totalLength % 4 == 0 else {
            throw PacketError.malformed("pcapng: block length \(totalLength) is not 32-bit aligned")
        }
        guard totalLength >= minimum else {
            throw PacketError.malformed("pcapng: block length \(totalLength) below minimum \(minimum)")
        }
        let blockEndTotal = try Self.checkedAdd(blockStart, totalLength)
        if blockEndTotal > metadata.identity.size {
            guard haveSection else {
                throw PacketError.malformed("pcapng: truncated first section header block")
            }
            return .truncated(completion(reason: .partialBlockBody, bytesConsumed: metadata.identity.size))
        }
        return .ok(blockEndTotal: blockEndTotal)
    }

    private func readInterfaceDescription(
        blockStart: UInt64,
        totalLength: UInt64,
        blockEndTotal: UInt64,
        little: Bool
    )
        throws -> Step
    {
        try checkCancellation()
        let fixed = try readFully(8)
        guard fixed.count == 8 else {
            throw PacketError.malformed("pcapng: truncated interface description block")
        }
        let buffer = PacketBuffer([UInt8](fixed))
        let linkType = try UInt32(little ? buffer.u16le(0) : buffer.u16(0))
        let snapLength = try little ? buffer.u32le(4) : buffer.u32(4)
        let optionsStart = try Self.checkedAdd(blockStart, 16)
        let optionsEnd = try Self.checkedAdd(blockStart, totalLength - 4)
        let resolution = try readInterfaceOptions(optionsStart: optionsStart, optionsEnd: optionsEnd, little: little)
        try validateTrailer(blockStart: blockStart, totalLength: totalLength, little: little)
        interfaces.append(SectionInterface(
            linkType: linkType,
            snapLength: snapLength,
            ticksPerSecond: resolution.ticksPerSecond,
            timestampOffsetSeconds: resolution.offsetSeconds
        ))
        if firstDeclaredLinkType == nil {
            firstDeclaredLinkType = linkType
        }
        offset = blockEndTotal
        return .advanced
    }

    /// Walk an interface's options for `if_tsresol` (9) and `if_tsoffset` (14),
    /// reading only the tiny values it needs and seeking past everything else.
    private func readInterfaceOptions(
        optionsStart: UInt64,
        optionsEnd: UInt64,
        little: Bool
    )
        throws -> (ticksPerSecond: UInt64, offsetSeconds: Int64)
    {
        var ticksPerSecond: UInt64 = 1_000_000
        var offsetSeconds: Int64 = 0
        var cursor = optionsStart
        while try Self.checkedAdd(cursor, 4) <= optionsEnd {
            try checkCancellation()
            try seek(to: cursor)
            let header = try readFully(4)
            guard header.count == 4 else {
                break
            }
            let buffer = PacketBuffer([UInt8](header))
            let code = try little ? buffer.u16le(0) : buffer.u16(0)
            let length = try Int(little ? buffer.u16le(2) : buffer.u16(2))
            cursor = try Self.checkedAdd(cursor, 4)
            if code == Self.optionEndOfOptions {
                guard length == 0 else {
                    throw PacketError.malformed("pcapng: opt_endofopt length \(length)")
                }
                break
            }
            let valueEnd = try Self.checkedAdd(cursor, UInt64(Self.roundUpToWord(length)))
            guard valueEnd <= optionsEnd else {
                throw PacketError.malformed("pcapng: interface option length overruns block")
            }
            switch code {
            case Self.optionTimestampResolution:
                ticksPerSecond = try readTimestampResolution(length: length)
            case Self.optionTimestampOffset:
                offsetSeconds = try readTimestampOffset(length: length, little: little)
            default:
                break
            }
            cursor = valueEnd
        }
        return (ticksPerSecond, offsetSeconds)
    }

    private func readTimestampResolution(length: Int) throws -> UInt64 {
        guard length == 1 else {
            throw PacketError.malformed("pcapng: if_tsresol length \(length)")
        }
        let value = try readFully(1)
        guard value.count == 1 else {
            throw PacketError.malformed("pcapng: truncated if_tsresol")
        }
        return try Self.timestampTicksPerSecond(raw: [UInt8](value)[0])
    }

    private func readTimestampOffset(length: Int, little: Bool) throws -> Int64 {
        guard length == 8 else {
            throw PacketError.malformed("pcapng: if_tsoffset length \(length)")
        }
        let value = try readFully(8)
        guard value.count == 8 else {
            throw PacketError.malformed("pcapng: truncated if_tsoffset")
        }
        let buffer = PacketBuffer([UInt8](value))
        let high: UInt64
        let low: UInt64
        if little {
            low = try UInt64(buffer.u32le(0))
            high = try UInt64(buffer.u32le(4))
        } else {
            high = try UInt64(buffer.u32(0))
            low = try UInt64(buffer.u32(4))
        }
        return Int64(bitPattern: (high << 32) | low)
    }

    private func readEnhancedPacket(
        blockStart: UInt64,
        totalLength: UInt64,
        blockEndTotal: UInt64,
        little: Bool
    )
        throws -> Step
    {
        try checkCancellation()
        let fixed = try readFully(20)
        guard fixed.count == 20 else {
            throw PacketError.malformed("pcapng: truncated enhanced packet block")
        }
        let buffer = PacketBuffer([UInt8](fixed))
        let interfaceID = try Int(little ? buffer.u32le(0) : buffer.u32(0))
        let ticksHigh = try UInt64(little ? buffer.u32le(4) : buffer.u32(4))
        let ticksLow = try UInt64(little ? buffer.u32le(8) : buffer.u32(8))
        let capturedLength = try Int(little ? buffer.u32le(12) : buffer.u32(12))
        let originalLength = try Int(little ? buffer.u32le(16) : buffer.u32(16))
        guard interfaces.indices.contains(interfaceID) else {
            throw PacketError.malformed("pcapng: enhanced packet references undeclared interface \(interfaceID)")
        }
        let interface = interfaces[interfaceID]
        guard capturedLength <= configuration.maxCapturedLength else {
            throw PacketError.malformed(
                "pcapng: captured length \(capturedLength) exceeds limit \(configuration.maxCapturedLength)"
            )
        }
        guard originalLength >= capturedLength else {
            throw PacketError.malformed(
                "pcapng: original length \(originalLength) below captured length \(capturedLength)"
            )
        }
        let payloadOffset = try Self.checkedAdd(blockStart, 28)
        let paddedEnd = try Self.checkedAdd(payloadOffset, UInt64(Self.roundUpToWord(capturedLength)))
        let blockEnd = try Self.checkedAdd(blockStart, totalLength - 4)
        guard paddedEnd <= blockEnd else {
            throw PacketError.malformed("pcapng: enhanced packet payload overruns block")
        }
        try checkCancellation()
        let payload = try readFully(capturedLength)
        guard payload.count == capturedLength else {
            throw PacketError.malformed("pcapng: truncated enhanced packet payload")
        }
        let timestamp = try Self.timestamp(
            ticksHigh: ticksHigh,
            ticksLow: ticksLow,
            ticksPerSecond: interface.ticksPerSecond,
            offsetSeconds: interface.timestampOffsetSeconds
        )
        try validateTrailer(blockStart: blockStart, totalLength: totalLength, little: little)
        offset = blockEndTotal
        let reference = PcapngFrameReference(
            blockOffset: blockStart,
            payloadOffset: payloadOffset,
            capturedLength: capturedLength,
            originalLength: originalLength,
            timestamp: timestamp,
            sectionIndex: sectionIndex,
            interfaceID: interfaceID,
            linkType: interface.linkType
        )
        return .frame(PcapngFrameEvent(
            reference: reference,
            bytes: [UInt8](payload),
            progress: progress(bytesConsumed: blockEndTotal)
        ))
    }

    private func readSimplePacket(
        blockStart: UInt64,
        totalLength: UInt64,
        blockEndTotal: UInt64,
        little: Bool
    )
        throws -> Step
    {
        try checkCancellation()
        let fixed = try readFully(4)
        guard fixed.count == 4 else {
            throw PacketError.malformed("pcapng: truncated simple packet block")
        }
        let buffer = PacketBuffer([UInt8](fixed))
        let originalLength = try Int(little ? buffer.u32le(0) : buffer.u32(0))
        guard let interface = interfaces.first else {
            throw PacketError.malformed("pcapng: simple packet without interface 0")
        }
        // A Simple Packet Block carries no captured length or timestamp: the
        // captured length is derived from the interface snap length, and the frame
        // is honestly stamped at the Unix epoch.
        let capturedLength = interface.snapLength == 0
            ? originalLength
            : min(originalLength, Int(interface.snapLength))
        guard capturedLength <= configuration.maxCapturedLength else {
            throw PacketError.malformed(
                "pcapng: captured length \(capturedLength) exceeds limit \(configuration.maxCapturedLength)"
            )
        }
        let payloadOffset = try Self.checkedAdd(blockStart, 12)
        let paddedEnd = try Self.checkedAdd(payloadOffset, UInt64(Self.roundUpToWord(capturedLength)))
        let blockEnd = try Self.checkedAdd(blockStart, totalLength - 4)
        guard paddedEnd == blockEnd else {
            throw PacketError.malformed("pcapng: simple packet length mismatch")
        }
        try checkCancellation()
        let payload = try readFully(capturedLength)
        guard payload.count == capturedLength else {
            throw PacketError.malformed("pcapng: truncated simple packet payload")
        }
        try validateTrailer(blockStart: blockStart, totalLength: totalLength, little: little)
        offset = blockEndTotal
        let reference = PcapngFrameReference(
            blockOffset: blockStart,
            payloadOffset: payloadOffset,
            capturedLength: capturedLength,
            originalLength: originalLength,
            timestamp: Date(timeIntervalSince1970: 0),
            sectionIndex: sectionIndex,
            interfaceID: 0,
            linkType: interface.linkType
        )
        return .frame(PcapngFrameEvent(
            reference: reference,
            bytes: [UInt8](payload),
            progress: progress(bytesConsumed: blockEndTotal)
        ))
    }

    /// A block Tracexy does not decode (name resolution, statistics, custom, …):
    /// validate its trailer and seek past it without allocating its body.
    private func skipUnknown(
        blockStart: UInt64,
        totalLength: UInt64,
        blockEndTotal: UInt64,
        little: Bool
    )
        throws -> Step
    {
        try checkCancellation()
        try validateTrailer(blockStart: blockStart, totalLength: totalLength, little: little)
        offset = blockEndTotal
        return .advanced
    }

    private func validateTrailer(blockStart: UInt64, totalLength: UInt64, little: Bool) throws {
        let trailerOffset = try Self.checkedAdd(blockStart, totalLength - 4)
        try seek(to: trailerOffset)
        let data = try readFully(4)
        guard data.count == 4 else {
            throw PacketError.malformed("pcapng: truncated block trailer")
        }
        let buffer = PacketBuffer([UInt8](data))
        let trailer = try little ? buffer.u32le(0) : buffer.u32(0)
        guard UInt64(trailer) == totalLength else {
            throw PacketError.malformed("pcapng: block trailer \(trailer) does not equal length \(totalLength)")
        }
    }

    /// Read exactly `count` bytes from the current position, looping until
    /// satisfied or EOF. Returns however many bytes were available (`< count` only
    /// at EOF) and advances the tracked offset by that amount.
    private func readFully(_ count: Int) throws -> Data {
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
        offset += UInt64(collected.count)
        return collected
    }

    private func seek(to newOffset: UInt64) throws {
        try handle.seek(toOffset: newOffset)
        offset = newOffset
    }

    private func checkCancellation() throws {
        if configuration.isCancelled() {
            throw CancellationError()
        }
    }

    private func progress(bytesConsumed: UInt64) -> PcapStreamProgress {
        PcapStreamProgress(bytesConsumed: bytesConsumed, totalBytes: metadata.identity.size)
    }

    private func completion(reason: PcapngStreamTermination, bytesConsumed: UInt64) -> PcapngStreamCompletion {
        PcapngStreamCompletion(reason: reason, progress: progress(bytesConsumed: bytesConsumed))
    }
}
