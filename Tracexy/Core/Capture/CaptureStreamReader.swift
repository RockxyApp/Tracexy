import Foundation
#if canImport(Darwin)
import Darwin
#endif

// MARK: - CaptureStreamFormat

/// Which accepted on-disk format a ``CaptureStreamReader`` chose after sniffing the
/// leading magic bytes.
nonisolated enum CaptureStreamFormat: Sendable, Equatable {
    case pcap
    case pcapng
}

// MARK: - CaptureFrameReference

/// A format-neutral pointer to one captured frame within the opened file, carrying
/// no bytes. Both the classic-`.pcap` and `.pcapng` readers are adapted onto this
/// single shape so the saved-open pipeline never branches on format. Offsets are
/// absolute byte positions in the file described by the owning stream's identity
/// and are valid only for that identity.
nonisolated struct CaptureFrameReference: Sendable, Equatable {
    /// Absolute offset of the captured payload bytes.
    let payloadOffset: UInt64
    /// Number of bytes actually captured for this frame.
    let capturedLength: Int
    /// The frame's original on-wire length (>= `capturedLength`).
    let originalLength: Int
    /// Decoded capture timestamp.
    let timestamp: Date
    /// Link type of this specific frame. For classic `.pcap` this is the file's
    /// single link type; for `.pcapng` it is the frame's own interface link type,
    /// so a mixed-interface capture keeps each frame's real DLT.
    let linkType: UInt32
}

// MARK: - CaptureFrameEvent

/// One successfully read frame: its ``CaptureFrameReference``, the captured bytes,
/// and the monotonic cumulative byte progress after consuming it.
nonisolated struct CaptureFrameEvent: Sendable, Equatable {
    let reference: CaptureFrameReference
    let bytes: [UInt8]
    let progress: PcapStreamProgress
}

// MARK: - CaptureStreamTermination

/// Why a ``CaptureStreamReader`` walk ended, unified across both formats. A
/// well-formed file ends `cleanEndOfFile`; a file whose tail was cut mid-record or
/// mid-block ends with a partial terminal while every complete prior frame remains
/// valid.
nonisolated enum CaptureStreamTermination: Sendable, Equatable {
    case cleanEndOfFile
    /// Too few bytes remained for the next record/block header.
    case partialHeader
    /// A declared record/block extended past the end of the file.
    case partialBody
}

// MARK: - CaptureStreamCompletion

/// A unified terminal reason paired with the final byte progress, so a truncated
/// terminal stays distinguishable from success.
nonisolated struct CaptureStreamCompletion: Sendable, Equatable {
    let reason: CaptureStreamTermination
    let progress: PcapStreamProgress
}

// MARK: - CaptureStreamOutcome

/// The result of one ``CaptureStreamReader/next()`` pull: a frame or a terminal.
nonisolated enum CaptureStreamOutcome: Sendable, Equatable {
    case frame(CaptureFrameEvent)
    case end(CaptureStreamCompletion)
}

// MARK: - CaptureStreamReader

/// A synchronous, pull-based, format-neutral reader that owns exactly one accepted
/// PCAP or PCAPNG stream reader and adapts it onto a single uniform frame /
/// reference / progress / completeness API.
///
/// It sniffs only the fixed leading magic needed to choose PCAP versus PCAPNG and
/// then lets the selected accepted reader validate its own header/SHB; there is no
/// whole-file IO. Like the readers it wraps, it is deliberately **not** `Sendable`:
/// it owns a live descriptor and a mutable cursor and must be driven by one
/// task/executor (N1C runs it inside one detached task).
nonisolated final class CaptureStreamReader {
    // MARK: Lifecycle

    /// Open `url`, sniff its leading magic, and construct the matching accepted
    /// stream reader.
    ///
    /// - Throws: rethrows the selected reader's construction error (for example a
    ///   classic `.pcap` bad magic or short global header). A file that is neither
    ///   a pcapng section header nor short is handed to the classic reader, which
    ///   validates its own magic.
    init(contentsOf url: URL, configuration: Configuration = Configuration()) throws {
        let magic = try Self.sniffLeadingMagic(url)
        if magic == Self.pcapngSectionHeaderMagic {
            let reader = try PcapngStreamReader(
                contentsOf: url,
                configuration: .init(
                    maxCapturedLength: configuration.maxCapturedLength,
                    isCancelled: configuration.isCancelled
                )
            )
            backing = .pcapng(reader)
            format = .pcapng
            identity = reader.metadata.identity
        } else {
            let reader = try PcapStreamReader(
                contentsOf: url,
                configuration: .init(
                    maxCapturedLength: configuration.maxCapturedLength,
                    isCancelled: configuration.isCancelled
                )
            )
            backing = .pcap(reader)
            format = .pcap
            identity = reader.metadata.identity
        }
    }

    // MARK: Internal

    /// Tunables for a stream read, forwarded verbatim to the accepted reader.
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

        let maxCapturedLength: Int
        let isCancelled: @Sendable () -> Bool
    }

    /// The format chosen by sniffing.
    let format: CaptureStreamFormat
    /// Identity of the opened file, snapshotted once. Frame references and evidence
    /// references are valid only against this identity.
    let identity: PcapFileIdentity

    /// The file's compatibility-default link type: the classic single link type
    /// for `.pcap`, or the first declared IDB link type for `.pcapng` (`nil` until
    /// an interface has been parsed). Per-frame link types on the references remain
    /// authoritative for a mixed-interface capture.
    var defaultLinkType: UInt32? {
        switch backing {
        case let .pcap(reader): reader.metadata.linkType
        case let .pcapng(reader): reader.firstDeclaredLinkType
        }
    }

    /// Pull the next frame or the terminal, adapting the backing reader's outcome
    /// onto the uniform shape. After any terminal the same terminal is replayed.
    ///
    /// - Throws: rethrows the backing reader's `CancellationError` /
    ///   `PacketError.malformed`; the backing reader is poisoned on failure.
    func next() throws -> CaptureStreamOutcome {
        switch backing {
        case let .pcap(reader):
            switch try reader.next() {
            case let .frame(event):
                .frame(CaptureFrameEvent(
                    reference: CaptureFrameReference(
                        payloadOffset: event.reference.payloadOffset,
                        capturedLength: event.reference.capturedLength,
                        originalLength: event.reference.originalLength,
                        timestamp: event.reference.timestamp,
                        linkType: reader.metadata.linkType
                    ),
                    bytes: event.bytes,
                    progress: event.progress
                ))
            case let .end(completion):
                .end(CaptureStreamCompletion(
                    reason: Self.map(completion.reason), progress: completion.progress
                ))
            }
        case let .pcapng(reader):
            switch try reader.next() {
            case let .frame(event):
                .frame(CaptureFrameEvent(
                    reference: CaptureFrameReference(
                        payloadOffset: event.reference.payloadOffset,
                        capturedLength: event.reference.capturedLength,
                        originalLength: event.reference.originalLength,
                        timestamp: event.reference.timestamp,
                        linkType: event.reference.linkType
                    ),
                    bytes: event.bytes,
                    progress: event.progress
                ))
            case let .end(completion):
                .end(CaptureStreamCompletion(
                    reason: Self.map(completion.reason), progress: completion.progress
                ))
            }
        }
    }

    // MARK: Private

    /// The single owned accepted reader, chosen at construction.
    private enum Backing {
        case pcap(PcapStreamReader)
        case pcapng(PcapngStreamReader)
    }

    /// The pcapng Section Header Block's leading type bytes, which are byte-order
    /// independent and therefore usable as a raw sniff signature.
    private static let pcapngSectionHeaderMagic: [UInt8] = [0x0A, 0x0D, 0x0D, 0x0A]

    private let backing: Backing

    /// Read only the leading four magic bytes needed to choose a format. Returns
    /// however many bytes are present (fewer than four only for a tiny file), which
    /// falls through to the classic reader's own controlled validation.
    private static func sniffLeadingMagic(_ url: URL) throws -> [UInt8] {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: 4) ?? Data()
        return [UInt8](data)
    }

    private static func map(_ reason: PcapStreamTermination) -> CaptureStreamTermination {
        switch reason {
        case .cleanEndOfFile: .cleanEndOfFile
        case .partialRecordHeader: .partialHeader
        case .partialPayload: .partialBody
        }
    }

    private static func map(_ reason: PcapngStreamTermination) -> CaptureStreamTermination {
        switch reason {
        case .cleanEndOfFile: .cleanEndOfFile
        case .partialBlockHeader: .partialHeader
        case .partialBlockBody: .partialBody
        }
    }
}

// MARK: - PcapFileIdentity revalidation

extension PcapFileIdentity {
    /// Snapshot a currently-open descriptor's identity, using the same `fstat`
    /// fields the accepted readers capture at open time. Falls back to the empty
    /// identity where `fstat` is unavailable.
    nonisolated static func snapshot(of handle: FileHandle) -> PcapFileIdentity {
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

    /// Whether `self` (a fresh snapshot) still describes the same file that
    /// `reference` was taken from. Size and modification time are the cheap change
    /// witnesses; device+inode, when the platform reported them, are the stable
    /// descriptor-level identity. A replaced file (new inode/mtime) or a truncated
    /// or grown file (different size) fails this check, so a stale offset can never
    /// be trusted into a mismatched read.
    nonisolated func matches(_ reference: PcapFileIdentity) -> Bool {
        guard size == reference.size, modifiedAt == reference.modifiedAt else {
            return false
        }
        if reference.device != 0 || reference.inode != 0 {
            guard device == reference.device, inode == reference.inode else {
                return false
            }
        }
        return true
    }
}
