import Foundation

// MARK: - CapturedFrame

/// One captured packet: the captured bytes, its timestamp, and the original
/// on-wire length (which may exceed the captured length when a snaplen truncated
/// the packet). Read from a `.pcap` file, or converted from a live helper frame.
nonisolated struct CapturedFrame: Sendable {
    // MARK: Lifecycle

    init(
        bytes: [UInt8],
        timestamp: Date,
        originalLength: Int,
        capturedLength: Int? = nil,
        linkType: UInt32? = nil,
        processName: String? = nil
    ) {
        self.bytes = bytes
        self.timestamp = timestamp
        self.originalLength = originalLength
        // The captured length is the number of bytes we actually hold. File and
        // programmatic frames don't report it separately, so it defaults to the
        // bytes present; a live helper frame passes its validated `caplen`.
        self.capturedLength = capturedLength ?? bytes.count
        self.linkType = linkType
        self.processName = processName
    }

    /// Builds a `CapturedFrame` from a helper's `NSSecureCoding` DTO, validating
    /// defensively: impossible, negative, or overflowing metadata is rejected
    /// truthfully (returns `nil`). A captured-length that disagrees with the bytes
    /// actually present is corrupt metadata and is likewise rejected — not
    /// normalized — because a frame whose header and payload disagree cannot be
    /// trusted. Never traps on malformed input.
    init?(message: CapturedFrameMessage) {
        let byteArray = [UInt8](message.bytes)
        // Timestamp must be a real instant: non-negative seconds and a
        // microsecond fraction within one second. A bad clock value is rejected
        // rather than folded into a nonsense `Date`.
        guard message.timestampSeconds >= 0,
              message.timestampMicroseconds >= 0,
              message.timestampMicroseconds < 1_000_000 else
        {
            return nil
        }
        // Captured length is the helper's `pcap_pkthdr.caplen`. It must be
        // non-negative, representable, bounded well below any real frame (so a
        // huge value can't be trusted into an overflow), and — because the bytes
        // *are* the captured payload — exactly equal to the bytes present. Any
        // disagreement is corrupt metadata and the frame is rejected truthfully.
        let reportedCaptured = message.capturedLength
        guard reportedCaptured >= 0,
              reportedCaptured <= Int64(CapturedFrame.maxReasonableLength),
              Int(reportedCaptured) == byteArray.count else
        {
            return nil
        }
        // On-wire length must be non-negative and sane. It may legitimately
        // exceed the captured bytes (snaplen truncation), but never fall below
        // them. Reject an impossible value instead of inferring a replacement
        // from the captured payload size.
        let reportedOriginal = message.originalLength
        guard reportedOriginal >= 0,
              reportedOriginal <= Int64(CapturedFrame.maxReasonableLength),
              reportedOriginal >= reportedCaptured else
        {
            return nil
        }
        let interval = Double(message.timestampSeconds)
            + Double(message.timestampMicroseconds) / 1_000_000
        self.init(
            bytes: byteArray,
            timestamp: Date(timeIntervalSince1970: interval),
            originalLength: Int(reportedOriginal),
            capturedLength: byteArray.count,
            linkType: message.linkType
        )
    }

    // MARK: Internal

    /// Maximum on-wire length the app will accept from a helper frame. Well above
    /// any real frame (jumbo/LRO segments stay under ~64 KiB), so a larger value
    /// is corrupt metadata to be rejected rather than trusted into overflow.
    static let maxReasonableLength = 1_000_000

    let bytes: [UInt8]
    let timestamp: Date
    let originalLength: Int
    /// Bytes actually captured for this frame (`pcap_pkthdr.caplen` for a live
    /// helper frame; the bytes present for a file frame). Kept distinct from
    /// `originalLength`, which may be larger when a snaplen truncated the packet.
    let capturedLength: Int
    /// The frame's own link type when it came from a live helper batch (each
    /// frame carries its own DLT); `nil` for file frames, which decode under the
    /// file's single link type.
    var linkType: UInt32?
    /// Originating process name from pktap, when capturing live (nil = unknown).
    var processName: String?
}

// MARK: - PcapReader

/// Reader for the classic libpcap (`.pcap`) capture file format.
///
/// This handles the *classic* format only (24-byte global header + 16-byte
/// per-packet records), not the newer pcapng block format. Both byte orders and
/// the microsecond / nanosecond timestamp variants are supported.
nonisolated enum PcapReader {
    // MARK: Internal

    /// Sentinel link type returned when a file declares one we don't map.
    static let linkTypeUnknown: UInt32 = 0xFFFFFFFF

    /// Parse a classic `.pcap` file's bytes.
    ///
    /// - Returns: the file's link-layer type and every fully captured frame.
    /// - Throws: `PacketError.malformed` on a bad magic or truncated global header.
    static func read(_ data: [UInt8]) throws -> (linkType: UInt32, frames: [CapturedFrame]) {
        let buffer = PacketBuffer(data)
        guard buffer.length >= globalHeaderSize else {
            throw PacketError.malformed("pcap: file shorter than 24-byte global header")
        }

        let rawMagic = try buffer.u32(0)
        guard let format = MagicFormat(rawMagic: rawMagic) else {
            throw PacketError.malformed(String(format: "pcap: unknown magic 0x%08X", rawMagic))
        }

        let linkType = format.littleEndian ? try buffer.u32le(20) : try buffer.u32(20)

        var frames: [CapturedFrame] = []
        var offset = globalHeaderSize
        while offset + recordHeaderSize <= buffer.length {
            let tsSec = format.littleEndian ? try buffer.u32le(offset) : try buffer.u32(offset)
            let tsFrac = format.littleEndian ? try buffer.u32le(offset + 4) : try buffer.u32(offset + 4)
            let inclLen = try Int(format.littleEndian ? buffer.u32le(offset + 8) : buffer.u32(offset + 8))
            let origLen = try Int(format.littleEndian ? buffer.u32le(offset + 12) : buffer.u32(offset + 12))

            let dataStart = offset + recordHeaderSize
            // A truncated final record (declared length exceeds what remains): stop cleanly.
            guard inclLen >= 0, dataStart + inclLen <= buffer.length else {
                break
            }

            let bytes = try buffer.bytes(dataStart, inclLen)
            frames.append(CapturedFrame(
                bytes: bytes,
                timestamp: format.timestamp(seconds: tsSec, fraction: tsFrac),
                originalLength: origLen
            ))
            offset = dataStart + inclLen
        }

        return (linkType, frames)
    }

    /// Convenience: read and parse a classic `.pcap` file from a URL.
    ///
    /// Unlike ``read(_:)`` — which parses a byte array already resident in memory
    /// and is kept behaviourally frozen — this path streams the file one record at
    /// a time through ``PcapStreamReader`` so a large capture is never loaded whole.
    /// A truncated tail (a partial final record header or payload) is *not* an
    /// error here: the reader stops and every complete prior frame is returned,
    /// matching the legacy array reader's tolerant final-record behaviour. Genuinely
    /// corrupt metadata (bad magic, an over-limit captured length, `orig < incl`,
    /// or an impossible timestamp fraction) still throws a controlled error.
    static func read(contentsOf url: URL) throws -> (linkType: UInt32, frames: [CapturedFrame]) {
        let reader = try PcapStreamReader(contentsOf: url)
        var frames: [CapturedFrame] = []
        loop: while true {
            switch try reader.next() {
            case let .frame(event):
                frames.append(CapturedFrame(
                    bytes: event.bytes,
                    timestamp: event.reference.timestamp,
                    originalLength: event.reference.originalLength
                ))
            case .end:
                // Clean EOF, a partial record header, or a partial payload all stop
                // the walk while preserving the complete frames read so far.
                break loop
            }
        }
        return (reader.metadata.linkType, frames)
    }

    // MARK: Private

    private static let globalHeaderSize = 24
    private static let recordHeaderSize = 16
}

// MARK: - MagicFormat

/// The byte order and timestamp resolution implied by a global header's magic.
nonisolated struct MagicFormat {
    // MARK: Lifecycle

    init?(rawMagic: UInt32) {
        switch rawMagic {
        case 0xA1B2C3D4: // big-endian, microsecond
            littleEndian = false
            nanosecond = false
        case 0xD4C3B2A1: // little-endian, microsecond
            littleEndian = true
            nanosecond = false
        case 0xA1B23C4D: // big-endian, nanosecond
            littleEndian = false
            nanosecond = true
        case 0x4D3CB2A1: // little-endian, nanosecond
            littleEndian = true
            nanosecond = true
        default:
            return nil
        }
    }

    // MARK: Internal

    let littleEndian: Bool
    let nanosecond: Bool

    /// Convert a record's seconds + fractional field into a `Date`.
    func timestamp(seconds: UInt32, fraction: UInt32) -> Date {
        let denominator = nanosecond ? 1_000_000_000.0 : 1_000_000.0
        let interval = Double(seconds) + Double(fraction) / denominator
        return Date(timeIntervalSince1970: interval)
    }
}
